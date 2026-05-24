---
title: "Secret In Log Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

## Secret In Log Rule Overview

The `secret-in-log` rule detects GitHub Actions workflow steps that print shell-derived secret values to build logs via `echo` or `printf`. GitHub Actions automatically masks the original `secrets.*` values in logs, but **does not mask derived values** produced by shell operations such as `jq`, `sed`, `awk`, `base64`, or command substitution. These derived values appear in plaintext in build logs.

### Rule ID

`secret-in-log`

### Severity

- **High**: Shell variable derived from a secret-sourced environment variable is printed via `echo` or `printf` without prior masking.

### Vulnerable Pattern

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      GCP_SERVICE_ACCOUNT_KEY: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
    steps:
      - name: Extract private key
        run: |
          PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
          echo "GCP Private Key: $PRIVATE_KEY"  # leaked in plaintext
```

GitHub Actions masks `${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}` but has no knowledge of `PRIVATE_KEY`, so it appears verbatim in the log.

**Detection Output:**

```text
workflow.yaml:29:24: secret in log: variable $PRIVATE_KEY (origin: shellvar:GCP_SERVICE_ACCOUNT_KEY) is printed via 'echo' without masking.
GitHub Actions only masks direct secrets.* values; values derived via shell expansion or tools like jq are not masked and will appear in plaintext in build logs.
Add 'echo "::add-mask::$PRIVATE_KEY"' before any usage, or avoid printing the value.
See https://sisaku-security.github.io/lint/docs/rules/secretinlogrule/ [secret-in-log]
```

### Safe Pattern

Add an `::add-mask::` command immediately after deriving the value:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      GCP_SERVICE_ACCOUNT_KEY: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
    steps:
      - name: Extract private key
        run: |
          PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
          echo "::add-mask::$PRIVATE_KEY"
          echo "GCP Private Key: $PRIVATE_KEY"  # now masked as ***
```

### Why This Rule Matters

| Value | Masking Behavior |
|-------|-----------------|
| `${{ secrets.TOKEN }}` used directly | Automatically masked |
| Shell variable derived via `jq`, `sed`, `awk`, `base64`, etc. | **NOT masked** |

Derived values flow through standard shell variable assignment and GitHub Actions has no awareness of them. Any `echo`/`printf` of such a variable writes the plaintext value into the publicly-visible build log.

### Detection Logic

The rule performs taint propagation within a single `run` step, across steps that
belong to the same job via `$GITHUB_ENV` / `$GITHUB_OUTPUT`, and across jobs when a
secret-derived job output is consumed through `needs.*.outputs.*`:

1. **Taint sources** — environment variables whose value either (a) contains `${{ secrets.* }}` declared at workflow-level, job-level, or step-level `env`, or (b) is assigned a tainted `${{ steps.<id>.outputs.<name> }}` or `${{ needs.<job>.outputs.<name> }}` expression at step-level `env`. All five sources — workflow `env` / job `env` / cross-step `$GITHUB_ENV` propagation / step-level output-derived `env` / step-level secrets `env` — are merged in that order, with later entries overriding earlier ones on name conflict (so step-level entries always win).
2. **Taint propagation** — shell assignments that reference a tainted variable, including command substitutions (`VAR=$(cmd $TAINTED)`). Propagation is **order-aware**: a single forward pass records the byte offset of each assignment, and sinks that appear *before* the assignment are not flagged (avoids false positives on `a=1; echo $a; a=$SECRET`). Environment-sourced variables are treated as set before the script begins (offset `-1`) and always considered valid.
3. **Shell function argument propagation** — when a shell function is called with tainted arguments, positional parameters (`$1`, `$2`, `$@`, `$*`) inside the function body inherit that taint. Composite words such as `"$TOKEN-$KEY"` keep all upstream variables, so a partial mask does not suppress an unmasked upstream value.
4. **Cross-step propagation via `$GITHUB_ENV`** — if a tainted shell variable is written to `$GITHUB_ENV` (via `echo "NAME=$VAR" >> $GITHUB_ENV`, `echo "NAME=$VAR" > $GITHUB_ENV`, or `cat <<EOF >> $GITHUB_ENV ... EOF`), the environment variable `NAME` becomes tainted for subsequent steps in the same job.
5. **Cross-step and cross-job propagation via `$GITHUB_OUTPUT`** — if a tainted shell variable is written to `$GITHUB_OUTPUT` by a step with an `id`, the corresponding `${{ steps.<id>.outputs.<name> }}` expression is treated as secret-derived for subsequent steps in the same job. If the job exposes that step output through `jobs.<job>.outputs`, downstream `${{ needs.<job>.outputs.<name> }}` expressions are also treated as secret-derived. Direct `run:` interpolation into `echo` / `printf` is flagged, and assigning either expression form to `env:` taints the shell variable used by the step. Reusable-workflow propagation remains a separate follow-up item.
6. **Sink detection** — the following commands are treated as sinks when they reference a tainted variable without a preceding `::add-mask::` for that variable:
   - `echo` / `printf` with a tainted argument
   - `cat` / `tee` / `dd` receiving tainted data via here-string (`<<<`) or heredoc (`<<EOF ... EOF`)
   - writes of tainted values to `$GITHUB_STEP_SUMMARY`, because the value is rendered in the job summary UI

   Masks that appear *after* the sink are not considered protective, since GitHub Actions applies masking only to subsequent log output.

#### Non-detection cases (not reported as leaks)

The following patterns are intentionally excluded from detection because their output does not reach *the current step's* build log directly:

- **Stdout redirected to a file** — `echo "$TOKEN" > secret.txt`, `echo "$TOKEN" 1> out.txt` etc. Redirects to `/dev/stderr`, `/dev/stdout`, `/dev/tty`, or `/dev/fd/{1,2}` are *not* excluded because they are still shown in the log.
- **Stdout redirected to `$GITHUB_OUTPUT`** — the current step's log does not receive the value, so no warning is raised for the redirect itself. If a subsequent step or downstream job (a) prints the resulting `${{ steps.<id>.outputs.<name> }}` / `${{ needs.<job>.outputs.<name> }}` value directly, or (b) assigns that expression to a step-level `env:` and prints the resulting shell variable, downstream uses are reported.
- **Direct `${{ secrets.X }}` expression written to `$GITHUB_OUTPUT`** — when a producer step has no env-derived shell taint and writes `${{ secrets.X }}` directly (e.g. `echo "token=${{ secrets.X }}" >> $GITHUB_OUTPUT`), no leak is reported for downstream `${{ steps.<id>.outputs.* }}` or `${{ needs.<job>.outputs.* }}` expansion. GitHub Actions auto-masks any occurrence of a `secrets.*` value across the entire run, so the same value is masked when the downstream step expands the output. This rule only tracks shell-derived values whose auto-mask coverage is broken (jq / sed / base64 / etc.).
- **`printf -v VAR ...`** — captures to a shell variable instead of printing.
- **Inside command substitutions** — `VAR=$(echo "$SECRET")` does not leak because the inner stdout is captured by `$(...)`.

#### Patterns the rule does not analyze at all (known blind spots)

These are real leakage paths that this rule does **not** currently detect. They are listed here so users do not assume a clean report means "no secret ever reaches a log":

- **Shell trace mode (`set -x` / `set -o xtrace` / `PS4`)** — when trace is enabled, bash prints every expanded command to stderr, which goes to the build log. Any command referencing a tainted variable leaks under trace mode. The rule only looks at `echo` / `printf` / `cat` / `tee` / `dd`, so trace-mode leaks are not flagged.
- **File-based cross-step leakage (non-`$GITHUB_ENV`)** — `echo "$VAL" > /tmp/x` in one step followed by `cat /tmp/x` in another step. Taint is not tracked across the filesystem, and `cat file` (without heredoc / here-string) is not treated as a sink.
- **Composite actions and JavaScript/Docker actions (`uses:`)** — only `run:` scripts in the caller workflow are analyzed. A vulnerable `echo` inside an external action's internals is invisible to this rule.
- **`eval` / `bash -c '...'` / `trap '...' ERR|EXIT`** — sinks embedded inside a string argument to `eval` or `bash -c`, or inside `trap` handler bodies, are not parsed as `CallExpr` nodes and are therefore not recognized.
- **Process substitution `>(cmd)` / `<(cmd)`** — sink detection does not descend into process substitutions.
- **Environment-dumping commands** — `env`, `printenv`, `declare -p`, `set` (with no args), `export -p`, and similar commands print every environment variable (including tainted derived values written to `$GITHUB_ENV`) but are not sinks in this rule.
- **Indirect expansion / arrays** — `${!VAR}` indirect expansion resolves a variable name stored in another variable, and array element reads (`${arr[i]}`) are not followed back to the array's source assignment. Taint on these forms can be missed.
- **Pipeline downstream commands** — for `cmd1 | cmd2`, only `cmd1` is analyzed as a possible sink (when it is `echo` / `printf`). `cmd2` is not individually inspected.
- **`logger`, `xargs`, `systemd-cat`, `wall`, and other log-emitting sinks** — not yet in the sink list.

### Auto-Fix

When run with `-fix on`, the rule inserts `echo "::add-mask::$VAR"` into the `run` script.

- For shell-derived variables (e.g., `KEY=$(jq ...)`), the mask line is inserted **immediately after the assignment** so that `$KEY` is non-empty when masked.
- For direct env-var references (origin `secrets.*`), the mask line is inserted at the **top of the script** because the env var is set before the script starts.
- For positional-parameter leaks inside shell functions (e.g., `leak "$TOKEN"` followed by `echo "$1"` inside `leak`), the fixer resolves the upstream shell variable and masks that variable (`$TOKEN`), not the positional name (`$1`). If a positional value combines multiple upstreams (for example `"$TOKEN-$KEY"`), all upstream variables must be masked before the diagnostic is suppressed.

Before:
```yaml
run: |
  KEY=$(echo $SECRET_JSON | jq -r '.key')
  echo "key=$KEY"
```

After `sisakulint -fix on`:
```yaml
run: |
  KEY=$(echo $SECRET_JSON | jq -r '.key')
  echo "::add-mask::$KEY"
  echo "key=$KEY"
```

#### Auto-fix safety caveat

If an assignment and a sink share the same physical line as a compound statement (e.g., `KEY=$(...); echo "$KEY"`), the rule cannot safely locate an insertion point between them from the shell AST alone. In that case the rule reports the warning **but leaves the script unchanged**; the user is expected to split the compound onto multiple lines and rerun `-fix on`, or add `::add-mask::` manually.

### Cross-step propagation example

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      GCP_SERVICE_ACCOUNT_KEY: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
    steps:
      - name: Derive and export via GITHUB_ENV
        run: |
          DERIVED=$(echo "$GCP_SERVICE_ACCOUNT_KEY" | jq -r '.access_token')
          echo "TOKEN=$DERIVED" >> $GITHUB_ENV
      - name: Leak propagated token
        run: |
          echo "got token: $TOKEN"   # flagged (origin: shellvar:GCP_SERVICE_ACCOUNT_KEY)
```

The first step's derivation (`DERIVED`) is tainted, and writing `TOKEN=$DERIVED` to `$GITHUB_ENV`
marks `TOKEN` as a tainted environment variable for the next step. The next step's `echo "$TOKEN"`
is therefore flagged even though neither the step nor the job declares `TOKEN` in `env:`.

### Step output propagation example

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      SECRET_JSON: ${{ secrets.SECRET_JSON }}
    steps:
      - id: derive
        run: |
          TOKEN=$(echo "$SECRET_JSON" | jq -r '.token')
          echo "token=$TOKEN" >> $GITHUB_OUTPUT
      - run: |
          echo "got: ${{ steps.derive.outputs.token }}"   # flagged
```

Writing to `$GITHUB_OUTPUT` does not print the value in the producing step, but GitHub Actions
does not automatically mask the derived output when a later step expands
`${{ steps.derive.outputs.token }}`. The rule tracks this same-job path.

### Cross-job `$GITHUB_OUTPUT` example

```yaml
jobs:
  extract:
    runs-on: ubuntu-latest
    env:
      SECRET_JSON: ${{ secrets.SECRET_JSON }}
    outputs:
      token: ${{ steps.derive.outputs.token }}
    steps:
      - id: derive
        run: |
          TOKEN=$(echo "$SECRET_JSON" | jq -r '.token')
          echo "token=$TOKEN" >> $GITHUB_OUTPUT

  deploy:
    runs-on: ubuntu-latest
    needs: extract
    steps:
      - run: |
          echo "got: ${{ needs.extract.outputs.token }}"   # flagged
```

When a job output forwards a secret-derived step output, the same derived value can
reach later jobs through `needs.*.outputs.*`. The rule carries that taint across
the job output boundary and reports direct prints or step-level `env:` assignments
that are later printed.

### Shell function argument example

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      TOKEN_JSON: ${{ secrets.TOKEN_JSON }}
      KEY_JSON: ${{ secrets.KEY_JSON }}
    steps:
      - run: |
          TOKEN=$(echo "$TOKEN_JSON" | jq -r '.token')
          KEY=$(echo "$KEY_JSON" | jq -r '.key')
          echo "::add-mask::$TOKEN"
          leak() { echo "$1"; }
          leak "$TOKEN-$KEY"   # flagged: KEY remains unmasked
```

The function body prints `$1`, but the rule traces `$1` back to both `TOKEN` and `KEY`.
Masking only `TOKEN` is not enough; every upstream shell variable in the composite argument
must be masked before the leak is suppressed.

### Scope Limitations

- **Cross-job output propagation depends on explicit job outputs** — the rule tracks values that flow from `steps.<id>.outputs.*` into `jobs.<job>.outputs` and then into `needs.<job>.outputs.*`. It does not infer arbitrary filesystem, artifact, cache, or service-container transfer between jobs.
- **`logger` and pipe-consuming commands not yet covered** — `logger`, `xargs`, and similar sinks are not yet detected. Pipes (`cmd1 | cmd2`) flag the upstream source if it is `echo`/`printf`, but the downstream command is not individually analyzed.
- **Reusable workflow boundaries** — taint does not cross `workflow_call` boundaries; that is a planned follow-up (see #433).
- **Composite / JS / Docker action internals are not parsed** — only `run:` blocks in the analyzed workflow are inspected. Leaks inside a `uses:`-referenced action are invisible.
- **Dynamic shell function dispatch is not resolved** — direct function calls are analyzed, but variable-driven calls such as `$cmd "$TOKEN"` are treated as statically unresolved.
- **Shell trace mode, `eval` / `bash -c` strings, `trap` handlers, process substitution, env-dumping commands, and indirect expansion are not modeled** — see "Patterns the rule does not analyze at all" above.

### Related Rules

- [`unmasked-secret-exposure`](unmaskedsecretexposure.md) — detects derived secrets from `fromJson()` expressions that are not masked.
- [`secret-exfiltration`](secretexfiltration.md) — detects secrets sent to external services via network commands (`curl`, `wget`, `nc`, etc.).
- [`secret-exposure`](secretexposure.md) — detects excessive secret exposure via `toJSON(secrets)` or `secrets[dynamic-access]`.

### References

- [GitHub: Masking a value in a log](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#masking-a-value-in-a-log)
- [GitHub: Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP CI/CD Security Risk CICD-SEC-6: Insufficient Credential Hygiene](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

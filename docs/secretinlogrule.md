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

The rule performs taint propagation within a single `run` step:

1. **Taint sources** — environment variables whose value contains `${{ secrets.* }}` declared at the workflow-level, job-level, or step-level `env` (all three scopes are merged, with step-level entries overriding the outer scopes on name conflict).
2. **Taint propagation** — shell assignments that reference a tainted variable, including command substitutions (`VAR=$(cmd $TAINTED)`).
3. **Sink detection** — the following commands are treated as sinks when they reference a tainted variable without a preceding `::add-mask::` for that variable:
   - `echo` / `printf` with a tainted argument
   - `cat` / `tee` / `dd` receiving tainted data via here-string (`<<<`) or heredoc (`<<EOF ... EOF`)

   Masks that appear *after* the sink are not considered protective, since GitHub Actions applies masking only to subsequent log output.

#### Non-detection cases (not reported as leaks)

The following patterns are intentionally excluded from detection because their output does not reach the build log:

- **Stdout redirected to a file** — `echo "$TOKEN" >> "$GITHUB_OUTPUT"`, `echo "$TOKEN" > secret.txt`, `echo "$TOKEN" 1> out.txt` etc. (redirects to `/dev/stderr`, `/dev/stdout`, `/dev/tty`, or `/dev/fd/{1,2}` are *not* excluded because they are still shown in the log.)
- **`printf -v VAR ...`** — captures to a shell variable instead of printing.
- **Inside command substitutions** — `VAR=$(echo "$SECRET")` does not leak because the inner stdout is captured by `$(...)`.

### Auto-Fix

When run with `-fix on`, the rule inserts `echo "::add-mask::$VAR"` into the `run` script.

- For shell-derived variables (e.g., `KEY=$(jq ...)`), the mask line is inserted **immediately after the assignment** so that `$KEY` is non-empty when masked.
- For direct env-var references (origin `secrets.*`), the mask line is inserted at the **top of the script** because the env var is set before the script starts.

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

### Scope Limitations (MVP)

- **Single-step scope only** — taint does not cross step boundaries or job outputs (`needs.*.outputs.*`); cross-job propagation is a planned follow-up (see #432 / #437).
- **`logger` and pipe-consuming commands not yet covered** — `logger`, `xargs`, and similar sinks are not yet detected. Pipes (`cmd1 | cmd2`) flag the upstream source if it is `echo`/`printf`, but the downstream command is not individually analyzed.
- **Reusable workflow boundaries** — taint does not cross `workflow_call` boundaries; that is a planned follow-up (see #433).

### Related Rules

- [`unmasked-secret-exposure`](unmaskedsecretexposure.md) — detects derived secrets from `fromJson()` expressions that are not masked.
- [`secret-exfiltration`](secretexfiltration.md) — detects secrets sent to external services via network commands (`curl`, `wget`, `nc`, etc.).
- [`secret-exposure`](secretexposure.md) — detects excessive secret exposure via `toJSON(secrets)` or `secrets[dynamic-access]`.

### References

- [GitHub: Masking a value in a log](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#masking-a-value-in-a-log)
- [GitHub: Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP CI/CD Security Risk CICD-SEC-6: Insufficient Credential Hygiene](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

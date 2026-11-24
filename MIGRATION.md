# Migrating from sisakulint 0.x

This guide is for people who use sisakulint 0.x in CI or on a local machine and who move to v0.4.0, which is not compatible with 0.x. In this guide, "0.x" means the versions up to v0.3.8, not v0.4.0 and later. The 0.x version in this guide is v0.3.8, commit `9f674f0705461c0aff874b8f719256eb121ef791`. The implementation at the root of this repository has been replaced by the new implementation (the "v1 linter"). v0.4.0 is the first release of the v1 linter; "v1" is the name of the implementation, not a version number. The v1 linter does not inherit the flags, exit codes, output, or configuration files of 0.x, and no compatibility wrapper exists. Some flags have the same name as in 0.x but a different meaning, so a migration that only copies flag names produces a command that runs but returns different results.

The command, the command package (`cmd/sisakulint`), and the SARIF tool name (`sisakulint`) are the same as in 0.x. The module path is not the same: the organization `sisaku-security` was renamed to `gh-intel`, and the module path changed from `github.com/sisaku-security/sisakulint` (0.x) to `github.com/gh-intel/sisakulint` (the v1 linter). Install the v1 linter with `go install github.com/gh-intel/sisakulint/cmd/sisakulint@latest`. From v0.4.0, the Homebrew tap also installs the v1 linter. To keep using 0.x with `go install`, write the 0.x module path and the 0.x version: `go install github.com/sisaku-security/sisakulint/cmd/sisakulint@v0.3.8`. The 0.x versions declare the 0.x module path, so `go install github.com/gh-intel/sisakulint/cmd/sisakulint@v0.3.8` fails. The schema identifier of the Report, the facts file, and the acceptance file is `sisakulint/<name>/v0` (for example `sisakulint/report/v0`). Inside this repository, the command is `go run ./cmd/sisakulint` (see `README.md`).

## 1. Items with the same name or the same value but a different meaning

With the v1 linter, the following items either keep running without an error or stop for a different reason than in 0.x. Check this section first when you review a CI script.

| What you wrote for 0.x | Meaning in 0.x | Behavior of the v1 linter | Replacement |
|---|---|---|---|
| `-verbose` | Writes a log of progress and timing to stderr | The same as `--detail full` (in the text output, prints every `Finding` one by one). The v1 linter writes no log. The exit code does not change | No log exists. An input that could not be read and an internal error appear in `inputs[]` and `errors[]` of the Report (`--format json`) |
| `-init` | Writes the default configuration file to `.github/sisakulint.yaml` | Writes a template of the configuration file to stdout and creates no file. Exit code 0 | `--init > FILE`. To migrate from a 0.x configuration file, use `--init --legacy-configuration .github/sisakulint.yaml --root .` (see section 7) |
| `-fix on`, `-fix off`, `-fix dry-run` | Applies fixes, does not apply fixes, or writes the whole fixed file to stdout | `-fix` takes no value, so the v1 linter reads `on` and similar words as a PATH (a file to check). That file does not exist, so the v1 linter stops with exit code 66. `-fix=on` gives exit code 64 | `--fix` (safe fixes only), `--fix=review` (all fixes), `--fix --dry-run` (writes a diff that `git apply` accepts to stdout). The equivalent of `-fix off` of 0.x is to pass no `--fix` |
| `-remote` | Reads one repository, or the repositories of a GitHub search query. A repository that could not be fetched is skipped, and the exit code is 0 | Reads one repository only (`OWNER/REPO[@REF]` or a URL). A search query (for example `-remote 'org:kubernetes'`) gives exit code 64. If the repository cannot be read, the exit code is 66 | No replacement for a search query exists |
| exit code 2 | A flag error | A `conditional` `Finding` exists, or no input remains after the excluded inputs are removed (bit 2) | A flag error is 64 (see section 4) |
| exit code 3 | A fatal error | The sum of bit 1 and bit 2 (both `confirmed` and `conditional` `Finding` exist) | A fatal error is 66, 70, 74, 75, or bit 4 (see section 4) |
| A rule that became a quality rule (`missing-timeout-minutes`, `archived-uses`, `deprecated-node-runtime`, `cache-bloat`, `dependabot-github-actions`, `dependency-review-settings`, `env-var`, `cond`, `uses-path` (which carries the `uses` path part of the 0.x `obfuscation`), and part of `expression` and of `deprecated-commands`. See the table in section 6) | A finding gives exit code 1 | A finding for which no attacker exists is reported as a quality rule finding in `quality_findings` of the Report, and sets no bit of the exit code | Do not use the finding as a CI gate. To see the finding, read `quality_findings` in the `--format json` output |

## 2. How inputs are selected

| 0.x | The v1 linter |
|---|---|
| A run without arguments takes the first directory that has both `.github/workflows` and `.git`, searching from the working directory toward the ancestors, as the root | The v1 linter takes `--root` (default `.`) as the root and does not search ancestors. When the command runs in a directory below the repository root, no input exists and bit 2 is set (`inputs  no input`). Pass `--root <repository root>` |
| Reads `.yml` and `.yaml` files in directories below `.github/workflows` as workflows | Takes only the `.yml` and `.yaml` files directly under `.github/workflows` as workflows (GitHub does not run a file in a lower directory as a workflow). Also takes every `action.yml` of the repository (or `action.yaml` when no `action.yml` exists) as an input |
| A file argument reads that file and looks up the caller side and the called side on disk | Reads only the PATH (a file relative to `--root`), and the input is not complete. To read the whole repository and report only the locations related to the PATH, use `--read-all PATH...` |
| `-stdin-filename` only accepts a value and does not read stdin | `--stdin-name NAME` reads one file from stdin as an input with that name (a feature that has no counterpart in 0.x) |

## 3. Flag mapping

When a flag that exists only in 0.x is passed, the v1 linter writes the following two lines to stderr and stops with exit code 64. The v1 linter writes nothing to stdout.

```
flag provided but not defined: -ignore
usage: sisakulint [flags] [PATH...]
(the list of flags follows)
```

| 0.x flag | The v1 linter |
|---|---|
| `-ignore REGEX` | `--skip-rule ID[,ID...]`. Only an exact match of the rule ID works, and a regex cannot be written. 0.x discards the findings of the matched rule afterward, while the v1 linter does not run the rule. Rewrite the IDs with the table in section 6 |
| `-enable-rule NAME` | `--rule ID[,ID...]` runs only the named rules, and no other rule runs. No flag adds one rule to the default rules, as `-enable-rule missing-timeout-minutes` does in 0.x. To add a rule, list all IDs in `--rule` (the rule IDs are in the JSON of `--registry`) |
| `-format TEMPLATE` | `--format text` (default), `line`, `json`, `sarif`. A Go template cannot be written (see section 5) |
| `-config-file FILE` | `--config FILE` (see section 7) |
| `-init` | `--init` (see section 1) |
| `-generate-action-list` | None. Write the list of allowed actions as the fact `repo.action-list` in the key `fact` of the configuration file (see section 7) |
| `-boilerplate` | None |
| `-verbose`, `-debug` | None (for `-verbose`, see section 1) |
| `-version` | `--version`. Writes the module version, the commit, the Go version and platform, and the JSON schemas that this binary writes and reads |
| `-stdin-filename NAME` | None (see section 2) |
| `-fix on\|off\|dry-run` | See section 1 |
| `-remote OWNER/REPO` | `--remote OWNER/REPO[@REF]` or a repository URL. The v1 linter does not clone, resolves the ref to a commit, and reads the files of that commit with the Git blob API |
| `-remote QUERY`, `-l`, `-p` | None |
| `-r`, `-D` | None. A `--online` run reads the reusable workflows of other repositories that a job calls down to depth 3, and the actions of other repositories that a step calls down to depth 4, and reports a `Finding` on the `uses` of the caller |
| `-pr N` | `--remote OWNER/REPO --pull-request N` (or a PR URL). Reports only the locations related to the workflows and `action.yml` files that the PR changed |
| `-expected-head-sha SHA` | `--pull-request-head SHA`. When the head differs, the exit code is 75 (3 in 0.x) |
| `-remote-checkout-dir DIR` | `--write-snapshot DIR` (DIR must be a path that does not exist). To apply fixes, use `--write-snapshot DIR --fix` |
| `-remote-target PATH` | A positional argument PATH. The locations outside PATH are not printed, but the locations outside PATH are counted in the exit code and in `unreported_count` of the Report |
| `-github-token TOKEN` | None. The v1 linter reads only the environment variable `GITHUB_TOKEN` (see section 8) |

## 4. Exit codes

The exit codes of 0.x are 0 (no finding), 1 (findings exist), 2 (flag error), and 3 (fatal error). When the v1 linter has written the Report to stdout and has done everything that was requested, the v1 linter returns the sum of the following bits (0 to 31). The bits are the constants in `actions/lint/classify.go`.

| bit | Set when |
|---|---|
| 1 | A `confirmed` `Finding` at or above `--fail-on` exists |
| 2 | A `conditional` `Finding` at or above `--fail-on` (a `Finding` that depends on a fact with no answer) exists, or no input remains after the excluded inputs are removed (this includes a run that finds no input) |
| 4 | An internal error occurred |
| 8 | An `Inconclusive` (a location that could not be decided) of a rule at or above `--fail-on` exists, and the `Inconclusive` is not accepted with `--accept` |
| 16 | An input cannot be read or is invalid, or an input that an input calls (`uses: ./x`) cannot be read or is invalid |

Any other result is exactly one of the following codes. With 64, 66, and 75, the v1 linter writes nothing to stdout.

| exit code | When |
|---|---|
| 64 | An argument error (corresponds to 2 of 0.x) |
| 66 | An input, a facts file, an acceptance file, or a configuration file cannot be read or is invalid, or the repository, the commit, or the PR of `--remote` cannot be read |
| 70 | Not all fixes can be written (this does not apply to `--dry-run`) |
| 74 | A facts file, a Report file, a SARIF file, or a similar output file cannot be written |
| 75 | The head of the PR is not the value of `--pull-request-head` |

Points to check in a CI gate:

- A gate that fails on every non-zero exit code works without change. Because of bit 2 and bit 8, more runs fail than with 0.x.
- A script that maps an exit code of the v1 linter to 0 or 1 of 0.x (for example, a script that checks only `code & 1` and returns 1) maps bit 2 to 0. Then the gate passes silently on a `Finding` that depends on a fact with no answer (for example, a `Finding` in a run that does not answer whether the repository is public). When such a mapping is needed, return 1 if any of the bits 1, 2, 8, and 16 is set. Bit 4 and the exit codes 64, 66, 70, 74, and 75 mean that the run failed, so do not map those codes to 0. A gate that accepts `conditional` findings should still check bit 1 and bit 16 to fail on an input that cannot be read.
- `--fail-on SEVERITY` (info, low, medium, high, critical) is the lowest severity that sets bit 1, bit 2, and bit 8.
- An `Inconclusive` that a person reviewed and accepted is not counted in bit 8 when the acceptance file is passed with `--accept` (see `README.md`).

## 5. Output

| 0.x | The v1 linter |
|---|---|
| Default: `path:line:col: message [rule]` and the source line | The default `--format text` is a summary folded by kind. For one line per finding, use `--format line` (`path:line:column: severity kind: message`) |
| A Go template such as `-format '{{json .}}'` | `--format json` is the Report (`actions/lint/schema/report-v0.json`). `--report FILE` writes the Report to a file in addition to the stdout output. The Report contains the `Condition` (the fact with no answer on which a `Finding` depends), the `Inconclusive`, and the `Fix`, which a template could not output. To get again a value that a template extracted, use `jq` on the Report |
| `-format '{{sarif .}}'` (the level is always warning, and no rule description, fingerprint, or fix exists) | `--format sarif` or `--sarif FILE`. A rule (`reportingDescriptor`) exists for each `FindingKind`, and the ID is `<rule>.<kind>` (`code-injection.controlled`). The level and `security-severity` are written from `Severity`, and `partialFingerprints.primaryLocationLineHash` is written from `Fingerprint` |
| A documentation URL and a severity word such as `(critical)` in the message, and a severity in the rule name (`code-injection-critical`) | The rule description is held by `--explain ID` and `--registry`. A `Finding` has `Severity` as a field, and the v1 linter writes no severity in the message or in the rule ID |
| Color: no flag exists | `--color auto\|always\|never` |

If you passed the output to reviewdog, rewrite `sisakulint -format "{{sarif .}}" | reviewdog -f=sarif …` to `sisakulint --format sarif | reviewdog -f=sarif …`. The reviewdog workflow of this repository (reviewdog v0.20.1) reads the SARIF of the v1 linter and posts the results as review comments. Whether reviewdog handles the SARIF of the v1 linter in the same way as the SARIF of 0.x (for example, which results reviewdog filters out) has not been verified.

If you uploaded to code scanning, the ruleId (`<rule>.<kind>`) and the fingerprint differ from 0.x. This guide infers that an alert opened after the upload is a different alert from the 0.x alert, even for the same harm at the same location. The SARIF tool name of the v1 linter is `sisakulint`, the same as in 0.x. Therefore, when you upload with the same category as 0.x, the results of 0.x are overwritten (the GitHub documentation says: "If you upload a second SARIF file for a commit with the same category and from the same tool, the earlier results are overwritten.", https://github.com/github/docs/blob/d59b2631959db46d71ca5f7748ec04311c6d0870/content/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file.md, line 156, English, retrieved on 2026-11-15). This guide also infers that, in that case, all 0.x alerts are closed, and a location where the v1 linter reports the same harm opens as a new alert. Neither inference has been verified. To verify them, an experiment is needed that uploads the SARIF of 0.x and then the SARIF of the v1 linter to the same repository. If the inference is correct, a location that only 0.x reports and where the vulnerability remains has no open alert after the upload. To keep the 0.x alerts open for comparison, upload with a value of the input `category` of `github/codeql-action/upload-sarif` that differs from the value used for 0.x. When you stop the 0.x upload, the 0.x alerts of that category stay open until the 0.x configuration is deleted (the GitHub documentation says: "stale configurations that no longer run will display outdated alert statuses, and the stale alerts will stay open indefinitely.", https://github.com/github/docs/blob/d59b2631959db46d71ca5f7748ec04311c6d0870/data/reusables/code-scanning/troubleshooting-multiple-configurations.md, line 1, English, retrieved on 2026-11-15). For the upload procedure, see `README.md`.

## 6. Rule names and the rules that run

Rewrite the rule names that you wrote in `-ignore` of 0.x to the IDs of the v1 linter with the following table. A "—" in the ID column of the v1 linter means that the rule does not exist in the v1 linter. A pair of `-critical` and `-medium` of 0.x becomes one ID, and the `Finding` holds the severity. A "model `Diagnostic`" is not a rule. A model `Diagnostic` is a report of a form that GitHub rejects when GitHub reads a workflow, and `--skip-rule` cannot exclude a model `Diagnostic` (the input becomes `invalid`, and bit 16 is set). The 0.x rule `syntax` also corresponds to a model `Diagnostic`.

| 0.x ID | ID of the v1 linter |
|---|---|
| `code-injection-critical`, `code-injection-medium` | `code-injection` |
| `envvar-injection-critical`, `envvar-injection-medium` | `envvar-injection` |
| `output-clobbering-critical`, `output-clobbering-medium` | `output-clobbering` |
| `commit-sha` | `commit-sha` |
| `impostor-commit` | `impostor-commit` |
| `untrusted-checkout` | `untrusted-checkout` |
| `cache-poisoning-poisonable-step` | `untrusted-checkout` |
| `untrusted-checkout-toctou/critical`, `untrusted-checkout-toctou/high` | `untrusted-checkout-toctou` |
| `cache-poisoning` | `cache-poisoning` |
| `improper-access-control` | `untrusted-checkout`, `untrusted-checkout-toctou` |
| `argument-injection-critical`, `argument-injection-medium` | `argument-injection` |
| `request-forgery-critical`, `request-forgery-medium` | `request-forgery` |
| `envpath-injection-critical`, `envpath-injection-medium` | `envpath-injection` |
| `artifact-poisoning-critical`, `artifact-poisoning-medium` | `artifact-poisoning` |
| `artipacked` | `artipacked` |
| `dangerous-triggers-critical`, `dangerous-triggers-medium` | `dangerous-triggers` |
| `reusable-workflow-taint` | `code-injection`, `envvar-injection`, `output-clobbering`, `envpath-injection` |
| `secrets-inherit` | `secrets-inherit` |
| `secret-exposure` | `secret-exposure` |
| `unmasked-secret-exposure` | `unmasked-secret-exposure` |
| `secret-exfiltration` | `secret-exfiltration` |
| `secret-in-log` | `secret-in-log` |
| `secrets-in-artifacts` | `secrets-in-artifacts` |
| `ref-confusion` | `commit-sha` |
| `known-vulnerable-actions` | `known-vulnerable-actions` |
| `archived-uses` | `archived-uses` (quality rule) |
| `deprecated-node-runtime` | `deprecated-node-runtime` (quality rule) |
| `unpinned-images` | `unpinned-images` |
| `bot-conditions` | `bot-conditions` |
| `unsound-contains` | `unsound-contains` |
| `self-hosted-runner` | `self-hosted-runner` |
| `obfuscation` | `uses-path` (quality rule) |
| `permissions` | `permissions` |
| `missing-timeout-minutes` | `missing-timeout-minutes` (quality rule) |
| `cache-bloat` | `cache-bloat` (quality rule) |
| `dependabot-github-actions` | `dependabot-github-actions` (quality rule) |
| `dependabot-ecosystem` | — |
| `dependency-review-settings` | `dependency-review-settings` (quality rule) |
| `action-list` | `action-list` |
| `ai-action-unrestricted-trigger` | `ai-action-unrestricted-trigger` |
| `ai-action-excessive-tools` | `ai-action-excessive-tools` |
| `ai-action-prompt-injection` | `ai-action-prompt-injection` |
| `ai-action-unsafe-sandbox` | `ai-action-unsafe-sandbox` |
| `ai-action-execution-order` | `ai-action-execution-order` |
| `credentials` | `credentials` |
| `needs` | model `Diagnostic` |
| `env-var` | `env-var` (quality rule) |
| `id` | model `Diagnostic` |
| `workflow-call` | model `Diagnostic` |
| `expression` | model `Diagnostic`, `expression` (quality rule) |
| `deprecated-commands` | `unsecure-commands` (an attacker value in `set-env` or `add-path`), `deprecated-commands` (quality rule) |
| `cond` | `cond` (quality rule) |

Defaults for the rules that run (`default_run` in the JSON of the registry):

- `missing-timeout-minutes` does not run by default, as in 0.x. The rule runs only when you name the rule with `--rule missing-timeout-minutes`.
- `known-vulnerable-actions`, `impostor-commit`, `archived-uses`, and `deprecated-node-runtime` run when `--online` is given, when a facts file or `--fact` answers the facts that the rule needs, or when the rule is named with `--rule` (0.x always called the GitHub API).
- `action-list` runs when `--facts` or `--fact` (including `facts` and `fact` of the configuration file) answers the fact `repo.action-list`, or when the rule is named with `--rule`. `--online` alone does not run `action-list`.
- `dependabot-ecosystem` does not exist in the v1 linter.

## 7. Configuration file

| 0.x | The v1 linter |
|---|---|
| Searches for `.github/sisakulint.yaml` (or `.yml` if the `.yaml` file does not exist) in the project root and reads the file. Also reads the file when `-config-file` is passed | Does not search a fixed path. Reads the file only when the file is passed with `--config FILE`. The keys are `exclude`, `fail-on`, `rule`, `skip-rule`, `accept`, `facts`, `repo`, `fact`, and `add-attacker`, and each key works in the same way as the flag with the same name |
| The keys `action-list`, `config-variables`, and `secret-exfiltration.allowed-hosts`, and the workflow comment directive `# sisakulint:secret-exfiltration.allowed-hosts: …` | `--init --legacy-configuration .github/sisakulint.yaml --root .` reads the 0.x configuration file and the workflows under `--root`, and writes to stdout a configuration file whose key `fact` holds the entries that the v1 linter can migrate. `action-list` becomes the fact `repo.action-list`, `config-variables` becomes the fact `repo.configuration-variables`, and the permission of a destination becomes the fact `request.destination-trusted`, for each pair in which a current workflow sends a secret and the host matches an entry |
| The key `self-hosted-runner.labels` | Not migrated (no reader of the key existed in 0.x either) |

For the details of the migration and for the handling of entries that cannot be migrated, see `README.md`. After the migration, a `Finding` appears when a workflow sends a different secret to the same host (0.x allowed the destination by the host).

## 8. GitHub API and token

| 0.x | The v1 linter |
|---|---|
| Always calls the API (no offline mode exists). Each rule calls the API separately | Calls the API only with `--online`. The answers can be written to a facts file with `--write-facts FILE` and read from the facts file in the next run with `--facts FILE` |
| The token is taken in the order `-github-token`, `SISAKULINT_GITHUB_TOKEN`, `GITHUB_TOKEN`, `GH_TOKEN`. If none exists, the token is borrowed from `gh auth token` and `git credential fill` | Reads only the environment variable `GITHUB_TOKEN`. Does not borrow a token from `gh` or from a Git credential helper. In CI, write `GITHUB_TOKEN` in the `env` of the step. On a local machine, pass `GITHUB_TOKEN=$(gh auth token)` |
| A step in which the API failed passes without a finding (this row was not checked against the line numbers of the 0.x code) | A `Finding` that depends on a fact with no answer becomes `conditional` and sets bit 2 |
| When the fix of `commit-sha` hits the API rate limit, 0.x does not write the file and ends with exit code 3 | The facts that a fix needs are answered before the run (`--online`, `--facts`, `--fact`). When no answer exists, the v1 linter does not produce a `Fix` |

The v1 linter queries the API for facts of the repository (whether the repository is public, whether the default token can write, and so on) only when `--repo OWNER/NAME` is passed. In CI, write `--repo "$GITHUB_REPOSITORY"`.

## 9. Detection differences on the same workflows

0.x and the v1 linter were run on the same inputs on 2026-11-15, and the findings of both were compared. The inputs were the `Example` inputs of all rules and the inputs of the all-rules example, as of 2026-11-15. Because these inputs are the `Example` inputs of the rules, the differences below are not the differences on the workflows of a user. A difference that comes from missing GitHub API answers can change when the API answers are available.

Large groups of findings that only 0.x reports, with the reason:

- The step findings of `missing-timeout-minutes`: 0.x reported the findings on a job, on a step, and on a job that calls a reusable workflow. The v1 linter reports a finding only on a job that has `runs-on` (the `timeout-minutes` of the job applies to the steps).
- The findings of `artipacked` on a checkout without an upload: the v1 linter reports a finding only on a form in which credentials enter an artifact.
- The findings of `deprecated-node-runtime`: when 0.x could not call the API, 0.x inferred the Node.js version of an action from an embedded table. The v1 linter queries the fact `action.runs-using`, and the rule does not run when no answer exists. For a local action (`uses: ./x`), the v1 linter reports the finding on `runs.using` of `x/action.yml`, not on the step that has `uses`.
- The findings in which 0.x reported one harm many times: 0.x reported `cache-poisoning-poisonable-step` for each later step that runs the code of a PR, and sometimes reported two sentences on the same line. The v1 linter reports one `Finding` for each harm, and holds the later steps in `Evidence` or `Related`.

## 10. Users of sisakulint-action and Homebrew

- `gh-intel/sisakulint-action` (HEAD `604b94b3526b39662d2109e0259223beeac36136`) installs 0.3.0 by default in the input `version`, and always passes `-fix "$SISAKULINT_AUTOFIX"` and `-format '{{sarif .}}'` (lines 176 to 179 of `action.yml`). When you set `version` to 0.4.0 or later, the action stops with 64 or 66, as described in sections 1 and 3.
- The gate of this action is not an exit code. The function `classify` of `scripts/sarif_gate.py` infers a severity for each result of the SARIF. The function looks for the end of the ruleId (`-critical`, `-high`, `-medium`, `-low`) and for words such as `[critical]`, `(critical)`, and ` critical:` in the message, and uses `low` when none exists (lines 21 to 27 of the same file). None of these appears in the ruleId and the message of the v1 linter. The authors of this guide copied this condition into a script and applied the script to the SARIF that the v1 linter wrote for the all-rules example (`--facts actions/rules/testdata/all-rules/facts.json --format sarif`). Of 237 results, 233 became `low` (125 results have the SARIF level `error`). Therefore, even if only the flags of the action are rewritten, the default gate `fail-on: high` passes silently on most results of the v1 linter (verified on 2026-11-14).
- Set `version` of the action to 0.4.0 or later only with a version of the action whose `action.yml` passes the flags of the v1 linter (`--format sarif`, `--fix`) and whose gate reads the severity of the v1 linter. The action at the HEAD named above does neither.
- The Homebrew tap distributes v0.4.0 and later, so `brew upgrade` from 0.x changes the behavior of 0.x scripts as described in sections 1 to 4. Rewrite the scripts before the upgrade.

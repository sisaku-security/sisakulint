# CLAUDE.md

sisakulint is a static analysis tool for GitHub Actions workflow files and action.yml files. README.md describes the rules, the flags, and the output. MIGRATION.md describes the differences from the 0.x versions.

## Commands

```bash
go build ./cmd/sisakulint
go test ./...                           # the default tests; CI runs go test -timeout 30m ./...
gofmt -l .                              # CI fails when gofmt lists a file
go run ./cmd/sisakulint --help          # the flags
go run ./cmd/sisakulint --explain all   # every rule, as Markdown
```

CI also runs govulncheck v1.6.0. Keep gofmt, the tests, and govulncheck green locally before committing.

## Package layout

| Path | Contents |
|---|---|
| `yaml/cst/v1` | A lossless syntax tree of YAML 1.2.2. `scalar` (values and tags), `anchor` (alias resolution), `edit` (byte rewrites) |
| `actions/workflow` | Reads workflows and action.yml files into typed elements (including job `container` and `services` and image strings) |
| `actions/analysis` | Shared analysis, and the enumerations and `Event` that rules read |
| `actions/expr`, `actions/shell` | Parsers of `${{ }}` expressions and of bash and sh scripts |
| `actions/taint` | Analysis shared by the injection rules: attacker-controlled contexts, the places where those contexts are written into code or into the words of a `run` command, and the requests that a `run` script sends |
| `actions/prcode` | Analysis shared by the checkout rules and the artifact-poisoning rules |
| `actions/artifact` | Analysis shared by the artifact rules |
| `actions/agent` | Analysis shared by the rules for AI agent actions |
| `actions/job` | Analysis shared by the job rules (privileged events, approvals, token writes, secrets, `runs-on` labels) |
| `actions/ir` | The intermediate representation (IR) that rules read, and the per-group `View` readers generated from `views.json`. Rules read only the IR |
| `actions/cvss4` | CVSS v4.0 scoring, a port of the FIRST reference implementation |
| `actions/facts`, `actions/facts/github` | The external facts that rules ask about, and the answers from the GitHub API |
| `actions/repofile` | Answers facts from repository files that are not inputs (`.github/dependabot.yml`, Renovate configuration) |
| `actions/remote` | `--remote` runs: reads the tree of a commit of a GitHub repository as an `fs.FS` |
| `actions/internal/githubapi` | The GitHub API client (token, base URL, redirects, rate limit) |
| `actions/boundary` | Permission boundaries, with the evidence (quotes of GitHub documentation and observations) for each table row |
| `actions/lint` | Runs the rules, builds the Report, and applies fixes |
| `actions/rules` | The rules, one rule per file |
| `actions/reportview` | The HTML report view and the example catalog |
| `actions/internal/releasetable` | The drift check of the release tables of `actions/prcode` and `actions/artifact` |
| `actions/cli`, `cmd/sisakulint` | The command |
| `yaml/1.2.2`, `yaml/yaml-test-suite` | The YAML specification and the yaml-test-suite (third-party files that tests read) |
| `internal/regexpcalls` | Counts the regular-expression calls per file and compares the counts with `allowed.tsv` |
| `internal/copytest` | Counts and hashes the copies of third-party files that tests read |
| `internal/corpus` | Where tests look for a corpus of workflow files (`CORPUS_DIR`). This repository has no corpus, so the corpus tests skip |

## Regenerating generated files

Run the steps in this order after changing a schema, a table, or a rule:

```bash
go generate ./...
go test -update ./actions/cli ./actions/internal/jsonschema ./actions/ir/internal/irgen ./actions/lint ./actions/rules ./internal/regexpcalls
go test ./...
```

`go test -update` rewrites the golden files of those packages. Review the golden file diff before committing.

## Checks in the tests

- `internal/regexpcalls`: `allowed.tsv` may only shrink. Read `${{ }}` expressions with `actions/expr` and scripts with `actions/shell`. A regular expression only checks the form of one token that the parser took out. `TestNoGrowth` compares `allowed.tsv` with the `allowed.tsv` of the merge base with `main`, and skips when git has no `main` branch, as in the pull request checkout of CI. Reviewers look at any growth of `allowed.tsv` in a pull request.
- `TestThirdPartyCopies` (in `actions/workflow`, `actions/taint`, and `yaml/cst/v1/internal/suitetest`): the copies of third-party files must stay as the copies were made. The README.md at the top of each copy gives the origin, the license, the number of files, and the hash.
- `TestContractHasNoRepoPaths` (`actions/lint`), and `TestRegistry` and the e2e test in `actions/rules`: the JSON schemas, the comments in the Go files of `actions/lint`, `actions/facts`, and `actions/facts/github`, the registry JSON, and the Report JSON must not point to `docs/` paths. Point to public `https://` URLs instead.
- Drift check: `ACTIONS_UPSTREAM=1` (with `GH_TOKEN`) runs the tests that compare the data taken from other projects with those projects. `.github/workflows/upstream-drift.yaml` runs the same tests every week.

## Conventions in the code

- Give strings a real type. Rule IDs, fact kinds, and input names are not plain `string` values or `type X string` values. A closed set is an enumeration type. An open set is a struct with unexported fields and one constructor that checks the value.
- Read `${{ }}` expressions and shell scripts with their parsers (`actions/expr`, `actions/shell`), not with string comparison. String comparison misses other spellings of the same meaning, such as `always ()`.
- When a change adds, removes, or renames a type, a file, a layer, or a step that the `doc.go` of a package names, update that `doc.go` in the same commit.
- Releases fire only on a `v*.*.*` tag push. `go build` takes the version that `--version` prints from the VCS tag.

## Before opening a pull request

Reviews of earlier pull requests found the same kinds of defect many times. Ask each question below of your own diff before you open a pull request. Fix what does not hold, or say in the pull request body why the question does not apply. The numbers in parentheses are pull requests where a review found the defect.

The input:

- Equivalent spellings: does the rule find every spelling that has the same meaning (a wrapper such as `env`, `sudo` or `timeout`; quoting; `a['b']` for `a.b`; a here-document; `|&`; a command substitution inside double quotes), by walking the syntax tree, with a test for each spelling? (#292, #659)
- Near misses: does every decision about trust or membership compare whole normalized tokens, and is there a test with a near miss that must not match, such as `openai/codex-action-malicious`, `${{ runner.temp }}/../x`, or a bucket host under `storage.googleapis.com`? (#427, #538)
- Effective values: does the rule read the value that GitHub uses, such as the default activity types when `types` is absent, the `if` of the job, or the event of the caller, and not only the value that the file writes? (#238)
- Closed lists: is each list of known things (events, actions, hosts, git configuration keys that run code) complete, the same list for the rules that need the same list, and no shorter than the list that the change replaces? (#644, #750)

The analysis:

- Order and scope: does the analysis follow the order of statements and steps, the scope of shells and functions, and the case rules of the runner (environment variable names differ only in case on Linux and macOS), and does the analysis read two variables that one branch sets together as one pair of values, not as any combination of the values of each variable? (#434, #758, #788)
- Calls across files: for a reusable workflow or a composite action, does the change tell a value of the caller from a value of the callee that has the same name, and handle a callee whose caller is not among the inputs, a middle workflow that also runs on its own event, a workflow of another repository with the same path as a local file, and each caller of one callee? (#729, #747, #757)
- Unknown input: when the rule cannot read an input, a pattern or a fact (the rule does not parse the input or the pattern, the API gives no answer, or no source answers the fact), does the rule give an `Inconclusive` or a declared `UndetectedForm`, and not a Finding or nothing? (#356, #728, #744)
- Bounded work: can the work grow exponentially or quadratically with the shape of the input (the number of jobs to the power of the levels of calls, a chain of merges, a chain of assignments) when the depth is the only bound? Then bound the total, give an `Inconclusive` past the bound, and add a test with the worst shape. (#434, #784)
- Stable identity: can one defect give two Findings (two matrix combinations, two jobs that use one composite action), and does an anchor or a fingerprint (the values that identify a Finding from one run to the next) depend on what the rule computed for other elements, so that the anchor or the fingerprint moves when an unrelated element changes? (#744, #754, #785)
- Shared state: is state that lives across files, jobs or runs (a package variable, a shared slice) reset or copied before the next file, job or run reads the state? (#492, #672)

Fixes:

- Fix output: at the place where a `Fix` writes text (inside `bash -c '...'`, inside a quoted string literal, with several fixes on one step), does the script still parse after the `Fix`, and does the script still mean the same? Run the script before the `Fix` and the script after the `Fix`, each with harmless values and with an attack value, and compare the results. (#513, #748)
- New names: does a name that a `Fix` adds avoid every name that the step, the job, the workflow or the script already binds, in any letter case? (#514)

Claims and declarations:

- Primary source: is each claim about GitHub, a runner, an action or a command-line tool backed by the primary text (the GitHub documentation, or the source code of the action or the tool) or by a run on a runner, and does the test or the comment say which? (#374, #748, #780)
- Meta: when a change narrows or removes a declared `UndetectedForm` or `FalsePositiveForm`, is every form that the rule still misses, or still reports wrongly, still declared with an example? (#748, #750, #758)
- Text: do the text of the Finding, `--help`, `--explain` and README.md still match the code after the last change? (#477, #728)
- Tests: does each new test fail when the change is reverted, and does the test cover every path that the change touches (each severity, the composite and reusable forms)? Does a new detection also add an example under `actions/rules/examples/`? (#426, #728)

The pull request:

- Other open pull requests: does the pull request still build and pass the tests when it is merged together with the other open pull requests, and does the pull request avoid adding a function that computes the same value as a function that another open pull request adds? (#795, #798, #808)
- Closing keywords: does the body say `Refs #N`, not `Closes #N`, when the pull request finishes only part of the issue? (#785, #798)

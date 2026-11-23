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

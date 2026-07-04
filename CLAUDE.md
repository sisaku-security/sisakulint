# CLAUDE.md

sisakulint is a static analysis tool for GitHub Actions workflow files under .github/workflows. It implements checks aligned with the OWASP Top 10 CI/CD Security Risks, and most rules support auto-fix and SARIF output.

## Commands

```bash
go build ./cmd/sisakulint
go test ./...                          # quality assurance is local-only; CI runs no tests
sisakulint script/actions/<file>.yaml  # manual fixture verification
sisakulint -fix dry-run                # preview fixes
sisakulint -debug
```

## Architecture

Scan workflows → build the AST in pkg/ast and pkg/core/parse_*.go → apply rules in pkg/core through a depth-first visitor ordered WorkflowPre → JobPre → Step → JobPost → WorkflowPost → report → auto-fix on request. The ${{ }} expression parser lives in pkg/expressions, shell taint analysis in pkg/shell, and GitHub API access in pkg/remote. Package-specific conventions live in each directory's CLAUDE.md.

The source of truth for the rule inventory is the slice returned by makeRules in pkg/core/linter.go plus the per-rule docs in docs/. This file intentionally carries no rule list — a duplicated list always goes stale.

## Project-wide facts that are easy to misread but correct

- CI runs neither go test nor any linter. CI.yaml only echoes the gofmt diff and never fails. A push verifies nothing, so passing go test ./... locally before committing is part of the definition of done.
- Adding a rule is a multi-file sync contract: register in makeRules, add docs/<slug>.md, update the manually tallied severity counts table in docs/_index.md, add script/actions/<rule>.yaml and <rule>-safe.yaml, and update the table in script/README.md. Code plus tests alone is incomplete.
- The effective config file is .github/sisakulint.yaml or .yml. The .github/action.yaml that -init generates is never read by the loader; this mismatch is known and the file is gitignored.
- Two GitHub API token resolution paths coexist. The primary CLI path is ResolveGitHubToken in pkg/core/github_token.go with priority -github-token > SISAKULINT_GITHUB_TOKEN > GITHUB_TOKEN > GH_TOKEN and no subprocess probing per #484. getToken in pkg/remote/fetcher.go is the legacy path that still probes gh auth token and git credential fill; it serves -remote scans and the RemoteActionsMetadataCache. Identify which path you are on before touching auth.
- Exit codes: 0 = clean / 1 = findings / 2 = invalid options / 3 = fatal error, which also covers a GitHub API rate limit hit during -fix on per #474.
- The missing-timeout-minutes rule is opt-in: it stays registered but disabled until -enable-rule missing-timeout-minutes is passed.
- The authoritative Go version is go.mod and .go-version, currently 1.25.10. CI.yaml and the Dockerfile pin 1.24.0 and release.yml pins 1.25; they lag behind, so do not treat them as reference.
- Releases fire only on a v*.*.* tag push. A push to main deploys nothing.
- Some documents still reference docs/RULES_GUIDE.md, docs/ARCHITECTURE.md, and script/github_to_aws/; none of these exist. Do not go looking for them.

## Minimal steps for a new rule

Create pkg/core/myrule.go with a struct embedding BaseRule and call rule.Errorf from the Visit* methods. Register it in makeRules in pkg/core/linter.go, add pkg/core/myrule_test.go, and complete the sync contract above. Implementation conventions are in pkg/core/CLAUDE.md.

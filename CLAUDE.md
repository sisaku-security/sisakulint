# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## What is sisakulint?

sisakulint is a static analysis tool for GitHub Actions workflow files. It analyzes `.github/workflows/*.yml` files for security issues and best practices, implementing OWASP Top 10 CI/CD Security Risks checks.

**Key Features:**
- Detects injection vulnerabilities, credential exposure, and supply chain attacks
- Validates permissions, timeouts, and workflow configurations
- Supports auto-fixing for many security issues (26 rules with auto-fix as of Jan 2026)
- SARIF output format for CI/CD integration (e.g., reviewdog)
- Fast parallel analysis with Go concurrency
- Specialized detection for privileged workflow contexts (pull_request_target, issue_comment, workflow_run)
- Artifact and cache poisoning detection

## Quick Start

```bash
# Build and run
go build ./cmd/sisakulint
sisakulint

# Run with debug output
sisakulint -debug

# Run tests
go test ./...

# Auto-fix issues (dry-run shows changes without modifying files)
sisakulint -fix dry-run
sisakulint -fix on

# SARIF output for CI/CD
sisakulint -format "{{sarif .}}"

# Analyze specific files
sisakulint .github/workflows/ci.yml

# Generate config file
sisakulint -init
```

## Code Architecture

### Key Components

- **Command Structure**: `cmd/sisakulint/main.go`, `pkg/core/command.go`
- **Linting Engine**: `pkg/core/linter.go`, `pkg/core/validate.go`
- **Rules System**: Each rule in `pkg/core/*rule.go` implements `Rule` interface
- **AST Processing**: `pkg/ast/`, `pkg/core/visitor.go`, `pkg/core/parse_*.go`
- **Expression Handling**: `pkg/expressions/` (parser, tokenizer, semantic analysis)
- **Output Handling**: `pkg/core/errorformatter.go`, `pkg/core/sarif.go`
- **Auto-fixing**: `pkg/core/autofixer.go` (StepFixer, JobFixer interfaces)
- **Remote Analysis**: `pkg/remote/` (GitHub API integration)

### Data Flow

- Scan directory for workflow files → Parse into AST → Apply rules → Report issues → Auto-fix if requested

## Configuration

The tool can be configured using a `.github/action.yaml` file (created using `sisakulint -init`).


### The Rule Interface

All rules embed `BaseRule` and implement the `TreeVisitor` interface:

```go
type Rule interface {
    TreeVisitor                      // Visit AST nodes
    Errors() []*LintingError        // Return collected errors
    RuleNames() string              // Return rule identifier
    AddAutoFixer(AutoFixer)         // Add auto-fixer (optional)
    // ... other methods
}
```

### The Visitor Pattern

Rules implement visitor methods for depth-first AST traversal:

- `VisitWorkflowPre/Post(*Workflow)` - Visit workflow node
- `VisitJobPre/Post(*Job)` - Visit job node (Pre/Post for setup/validation)
- `VisitStep(*Step)` - Visit step node

The `SyntaxTreeVisitor` (`pkg/core/visitor.go`) orchestrates traversal and calls each rule's visitor methods.

## Adding a New Rule

- Create `pkg/core/myrule.go`:
```go
type MyRule struct {
    BaseRule
}

func (rule *MyRule) VisitJobPre(node *ast.Job) error {
    if /* condition */ {
        rule.Errorf(node.Pos, "error message")
    }
    return nil
}
```

- Register rule in `pkg/core/linter.go`
- Add tests in `pkg/core/myrule_test.go`
- Optional: Implement `StepFixer` or `JobFixer` for auto-fix

See `docs/RULES_GUIDE.md` for detailed guide.

### Rule Implementation Guidelines

Use AST/Tokenizer instead of string-based parsing:
- **Expressions**: `pkg/expressions` (`AnalyzeExpressionSyntax`, `NewTokenizer`)
- **Shell**: `pkg/shell` with `mvdan.cc/sh/v3/syntax` (`NewShellParser`, `FindVarUsageAsCommandArg`)
- **Taint analysis** (#446): `pkg/shell/taint.go` provides shared, state-less primitives reused by `TaintTracker` (code-injection chain) and `SecretInLogRule`:
  - `shell.Entry` — taint origin (`Sources`) plus byte `Offset` for order-aware FP suppression
  - `shell.PropagateTaint(file, initial)` — single forward pass; derived vars get `shellvar:X` chain markers
  - `shell.WalkAssignments(file)` / `shell.WordReferencesEntry(word, tainted)` / `shell.WordReferencesEntries(word, tainted)` — AST-aware lookups (treats heredoc bodies and comments correctly); `Entries` returns all tainted ParamExp in a word for composite-word multi-upstream cases (#461)
  - `shell.WalkRedirectWrites(file, target)` — collects `>> $TARGET` writes (echo / printf format / heredoc, including `printf 'name=%s\n' "$VAR"` form)
  - `shell.MergeSources(dst, src)` — order-preserving deduped slice merge; the single shared implementation used by both intra-package taint propagation and pkg/core consumers (#462; replaced the duplicate `pkg/core::mergeUnique`)
  - `shell.WordLitPrefix(word)` — concatenates leading `Lit` parts (including `Lit` nodes inside top-level `DblQuoted`) for literal prefix extraction such as `NAME=` scanning (#462). Do not use it for strict command/flag identity checks where quoted expansions such as `"echo$SUFFIX"` must remain dynamic.
  - GitHub Actions `${{ ... }}` substitutions are not valid bash syntax. `pkg/core/taint.go` sanitizes them via `sanitizeForShellParse` (length-non-preserving placeholder + `exprMap`) before parsing. `secretinlog.go` does not need this because its taint sources come from the YAML `env:` section, not script literals.
- **Scope-aware propagation (#447)**: `shell.PropagateTaint` は scope frame stack ベースで walk し、`*syntax.Subshell` / `*syntax.CmdSubst` は entry 時に親 visible を snapshot copy して隔離、`*syntax.FuncDecl` 本体は parent への lookup chain で bash dynamic scoping を近似 (`local` / 装飾なし `declare` は本体ローカル、その他は簡略案 A により親に漏らさない)。戻り値は `*shell.ScopedTaint` で、`Final` (script 末尾の親スコープ) と `At(stmt)` (per-stmt visible) を持つ。`taint.go` は per-stmt 展開で `recordRedirWrite` に渡す。`secretinlog.go` は `shellvar:X` マーカーを autofix のため raw 保持する (展開しない)
  - **Function argument taint propagation (#448/#460/#461)**: `pkg/shell/taint.go::PropagateTaint` は **lazy walk** で関数本体内の `$1` / `$2` / `$@` / `$*` を解決する。FuncDecl 出現時には body を walk せず関数テーブルに登録のみ、CallExpr 検出時に call-site の args の taint state (`shellvar:UPSTREAM` 形式) を `tainted["1"]/.../["@"]` として inject した上で body を walk する。複数 call-site は visibleAt[stmt] を保守的 union (FP 寄り)、再帰呼び出しは visited[name] で depth=1 制限、forward reference (定義前 call) は bash 一致で untracked。`WordReferencesEntries` により `foo "$T1-$T2"` のような composite word は全 upstream を保持する (#461)。`$@` / `$*` は引数のいずれかが tainted なら tainted。`secretinlog.go` の autofix は positional ($1) のリークに対し `resolveMaskTarget` で origin chain (`shellvar:1` → `shellvar:TOKEN` など) から upstream 変数名 (TOKEN) を抽出してマスク対象にする。検出抑制側は positional の全 `shellvar:*` upstream が mask 済みの場合のみ抑制する (#460)。`$@` / `$*` のリークは best-effort 不能で autofix off (lint 警告は出る)。
  - **Function side-effect**: 関数本体内の non-local 代入 (`X="$T"`) は #447 / #448 とも簡略案 A により親フレームには漏らさない。完全対応は別 issue。
  - **Known limitation**: `seedTaintFromExpressions` (in `pkg/core/taint.go`) is NOT scope-aware — direct `${{ untrusted }}` assignment inside a subshell will still seed `t.taintedVars`/`Final` regardless of scope. Scope-awareness applies fully to shell-variable derivation paths (`X="$Y"`) but seed leaks via the direct expression path remain. Tracked as follow-up.

## Implemented Rules

sisakulint includes the following security rules (as of pkg/core/linter.go:500-542):

- **CredentialsRule** - Detects hardcoded credentials and tokens (auto-fix supported)
- **JobNeedsRule** - Validates job dependencies
- **EnvironmentVariableRule** - Checks environment variable usage
- **IDRule** - Validates workflow/job/step IDs
- **PermissionsRule** - Enforces least privilege permissions
- **WorkflowCall** - Validates reusable workflow calls
- **ExpressionRule** - Parses and validates `${{ }}` expressions
- **DeprecatedCommandsRule** - Detects deprecated GitHub Actions commands
- **ConditionalRule** - Validates conditional expressions
- **TimeoutMinuteRule** - Enforces timeout configurations (auto-fix supported, **opt-in: requires `-enable-rule missing-timeout-minutes`**)
- **CodeInjectionCriticalRule** - Detects code injection in privileged triggers (auto-fix supported)
- **CodeInjectionMediumRule** - Detects code injection in normal triggers (auto-fix supported)
- **EnvVarInjectionCriticalRule** - Detects environment variable injection in privileged triggers (auto-fix supported)
- **EnvVarInjectionMediumRule** - Detects environment variable injection in normal triggers (auto-fix supported)
- **EnvPathInjectionCriticalRule** - Detects PATH injection in privileged triggers (auto-fix supported)
- **EnvPathInjectionMediumRule** - Detects PATH injection in normal triggers (auto-fix supported)
- **OutputClobberingCriticalRule** - Detects output clobbering in privileged triggers (auto-fix supported)
- **OutputClobberingMediumRule** - Detects output clobbering in normal triggers (auto-fix supported)
- **CommitShaRule** - Validates action version pinning (auto-fix supported)
- **ArtifactPoisoningRule** - Detects artifact poisoning risks (auto-fix supported)
- **ActionListRule** - Validates allowed/blocked actions
- **CachePoisoningRule** - Detects cache poisoning vulnerabilities
- **UntrustedCheckoutRule** - Detects checkout of untrusted PR code in privileged contexts (auto-fix supported)
- **ImproperAccessControlRule** - Detects improper access control with label-based approval and synchronize events (auto-fix supported)
- **SecretsInArtifactsRule** - Detects sensitive information in artifact uploads (CWE-312, auto-fix supported)
- **UnmaskedSecretExposureRule** - Detects unmasked secret exposure when secrets are derived using fromJson() (auto-fix supported)
- **UntrustedCheckoutTOCTOUCriticalRule** - Detects TOCTOU vulnerabilities with labeled event type and mutable refs (auto-fix supported)
- **UntrustedCheckoutTOCTOUHighRule** - Detects TOCTOU vulnerabilities with deployment environment and mutable refs (auto-fix supported)
- **BotConditionsRule** - Detects spoofable bot detection conditions using github.actor or similar contexts (auto-fix supported)
- **ArtifactPoisoningMediumRule** - Detects third-party artifact download actions in untrusted triggers (auto-fix supported)
- **CachePoisoningPoisonableStepRule** - Detects cache poisoning via execution of untrusted code after unsafe checkout (auto-fix supported)
- **SecretExposureRule** - Detects excessive secrets exposure via toJSON(secrets) or secrets[dynamic-access] (auto-fix supported)
- **ArtipackedRule** - Detects credential leakage when checkout credentials are persisted and workspace is uploaded (auto-fix supported)
- **UnsoundContainsRule** - Detects bypassable contains() function usage in conditions (auto-fix supported)
- **ImpostorCommitRule** - Detects impostor commits from fork network that could be supply chain attacks (auto-fix supported)
- **RefConfusionRule** - Detects ref confusion attacks where both branch and tag have same name (auto-fix supported)
- **ObfuscationRule** - Detects obfuscated workflow patterns that may evade security scanners (auto-fix supported)
- **KnownVulnerableActionsRule** - Detects actions with known security vulnerabilities via GitHub Security Advisories (auto-fix supported)
- **SelfHostedRunnersRule** - Detects self-hosted runner usage which poses security risks in public repos
- **ArchivedUsesRule** - Detects usage of archived actions/reusable workflows that are no longer maintained
- **UnpinnedImagesRule** - Detects container images not pinned by SHA256 digest
- **SecretExfiltrationRule** - Detects secret exfiltration via network commands (curl, wget, nc, etc.). Supports a `secret-exfiltration.allowed-hosts` allowlist in `.github/sisakulint.yaml` (exact host or `*.suffix` wildcard, case-insensitive) plus a per-workflow comment override `# sisakulint:secret-exfiltration.allowed-hosts: a.example.com, *.b.example.com`. Unused allowlist entries are surfaced as "dead allow" warnings so the list does not silently rot. The allowlist applies only to this rule; `secret-in-log` is intentionally unaffected.
- **ReusableWorkflowTaintRule** - Detects untrusted inputs flowing through reusable workflow boundaries via cross-file taint correlation (#392). Records caller-side `with:` taint and callee-side `inputs.*` sinks (run / github-script / env), then joins them in a post-validate phase. Reports chain warnings at caller's `with:` line (Critical for privileged triggers, Medium otherwise). When no caller in the same project passes untrusted data, falls back to a Medium standalone warning at the callee sink. Auto-fix lifts callee `${{ inputs.X }}` into a step-level `env:` (auto-fix supported for SinkRun and SinkGitHubScript; SinkEnv is warning-only in Phase 1)
- **SecretsInheritRule** - Detects excessive secret inheritance using 'secrets: inherit' in reusable workflow calls (auto-fix supported)
- **DependabotGitHubActionsRule** - Checks if dependabot.yaml has github-actions ecosystem configured when unpinned actions are detected (auto-fix supported)
- **ArgumentInjectionCriticalRule** - Detects argument injection in command-line args with privileged triggers (auto-fix supported)
- **ArgumentInjectionMediumRule** - Detects argument injection in command-line args with normal triggers (auto-fix supported)
- **RequestForgeryCriticalRule** - Detects SSRF vulnerabilities when untrusted input is used in network requests with privileged triggers (auto-fix supported)
- **RequestForgeryMediumRule** - Detects SSRF vulnerabilities when untrusted input is used in network requests with normal triggers (auto-fix supported)
- **SecretInLogRule** - Detects secret values printed to build logs via `echo`/`printf` of shell variables derived from secret-sourced environment variables (e.g., `jq`-derived values); taint is also propagated across steps within the same job through `$GITHUB_ENV` (auto-fix supported)
- **CacheBloatRule** - Detects cache bloat risk with actions/cache/restore and actions/cache/save without proper conditions (auto-fix supported)
- **AIActionUnrestrictedTriggerRule** - Detects AI agent actions (claude-code-action, etc.) configured with `allowed_non_write_users: "*"` allowing any GitHub user to trigger AI execution (Clinejection attack pattern)
- **AIActionExcessiveToolsRule** - Detects AI agent actions with dangerous tools (Bash/Write/Edit) enabled in workflows triggered by untrusted users (issues, issue_comment, discussion) (Clinejection attack pattern)
- **AIActionPromptInjectionRule** - Detects untrusted user input (github.event.issue.title, github.event.comment.body, etc.) directly interpolated into AI agent prompt parameters, enabling prompt injection attacks (Clinejection attack pattern)
- **AIActionUnsafeSandboxRule** - Detects unsafe sandbox or safety-strategy settings (e.g., `safety-strategy: unsafe`, `--dangerouslySkipPermissions`) in AI agent actions that disable sandbox protections
- **AIActionExecutionOrderRule** - Detects AI agent actions that are not the last step in a job, risking subsequent steps inheriting compromised state

## Key Files

- `pkg/core/rule.go` - Rule interface and BaseRule
- `pkg/core/visitor.go` - SyntaxTreeVisitor orchestration
- `pkg/core/linter.go` - Main linting engine (rule registration at line ~500)
- `pkg/core/command.go` - CLI handling
- `pkg/ast/ast_type.go` - AST node definitions
- `pkg/expressions/` - GitHub Actions expression parser (`${{ }}` syntax)
- `script/actions/` - Example vulnerable/safe workflow files for testing

## Common Commands

```bash
# Build
go build ./cmd/sisakulint

# Test
go test ./...
go test -v ./pkg/core -run TestSpecificFunction
go test -coverprofile=coverage.out ./...

# Test with example workflows
sisakulint script/actions/
sisakulint script/actions/codeinjection-critical.yaml
sisakulint script/actions/codeinjection-medium.yaml

# Debug
sisakulint -debug
sisakulint -fix dry-run -debug

# Generate config
sisakulint -init

# Ignore specific errors
sisakulint -ignore "SC2086" -ignore "permissions"

# Generate boilerplate workflow
sisakulint -boilerplate

# Enable an opt-in rule (currently available: missing-timeout-minutes)
sisakulint -enable-rule missing-timeout-minutes
```

## Exit Codes

- **0** - Success, no problems found
- **1** - Success, problems found
- **2** - Invalid command-line options
- **3** - Fatal error

## Project Structure

```
.
├── cmd/sisakulint/        # CLI entry point
├── pkg/
│   ├── ast/               # AST definitions (workflow, job, step nodes)
│   ├── core/              # Linting engine + rules implementation
│   ├── expressions/       # ${{ }} expression parser
│   └── remote/            # Remote repository analysis
├── script/
│   ├── actions/           # Example vulnerable/safe workflows for testing
├── docs/                  # Rule-specific documentation
└── .github/workflows/     # CI/CD workflows
```

## Development Workflow

### Testing a New Rule

- Create example workflows in `script/actions/`
   - `myrule.yaml` - Demonstrates the vulnerability
   - `myrule-safe.yaml` - Shows the correct pattern

- Implement the rule in `pkg/core/myrule.go`

- Add tests in `pkg/core/myrule_test.go`

- Register the rule in `pkg/core/linter.go` (around line 500)

- Test with: `sisakulint script/actions/myrule.yaml`

### Debugging Tips

- Use `-debug` flag to see AST traversal
- Check `pkg/core/visitor.go` to understand visitor pattern execution
- Use `script/actions/` examples to test edge cases
- Run specific tests: `go test -v ./pkg/core -run TestYourRule`

## Auto-Fix System

Rules can implement auto-fix by:

- Implementing `StepFixer` or `JobFixer` interface
- Registering the fixer: `rule.AddAutoFixer(fixer)`
- Testing with: `sisakulint -fix dry-run`

See `pkg/core/permissionrule.go` for auto-fix example.

### Current Auto-Fix Implementations

- **TimeoutMinutesRule** (`timeout_minutes.go`) - Adds default timeout-minutes: 5 (only runs when the rule is enabled via `-enable-rule missing-timeout-minutes`)
- **CommitSHARule** (`commitsha.go`) - Converts action tags to commit SHAs with comment preservation
- **CredentialRule** (`credential.go`) - Removes hardcoded passwords from container configs
- **CodeInjectionRule** (`codeinjection.go`) - Moves untrusted expressions to environment variables
- **EnvVarInjectionRule** (`envvarinjection.go`) - Sanitizes untrusted input with `tr -d '\n'` before writing to $GITHUB_ENV
- **EnvPathInjectionRule** (`envpathinjection.go`) - Validates untrusted paths with `realpath` before writing to $GITHUB_PATH
- **UntrustedCheckoutRule** (`untrustedcheckout.go`) - Adds explicit ref to checkout in privileged contexts
- **ArtifactPoisoningRule** (`artifactpoisoningcritical.go`) - Adds validation steps for artifact downloads
- **UnmaskedSecretExposureRule** (`unmasked_secret_exposure.go`) - Adds `::add-mask::` command for derived secrets from fromJson()
- **ImproperAccessControlRule** (`improper_access_control.go`) - Adds safe conditions for label-based and synchronize events
- **UntrustedCheckoutTOCTOUCriticalRule** (`untrustedcheckouttoctoucritical.go`) - Fixes TOCTOU vulnerabilities with labeled event type
- **UntrustedCheckoutTOCTOUHighRule** (`untrustedcheckouttoctouhigh.go`) - Fixes TOCTOU vulnerabilities with deployment environment
- **BotConditionsRule** (`botconditionsrule.go`) - Replaces spoofable bot conditions with safe alternatives
- **ArtifactPoisoningMediumRule** (`artifactpoisoningmedium.go`) - Adds safe extraction path to `${{ runner.temp }}/artifacts`
- **CachePoisoningPoisonableStepRule** (`cachepoisoningpoisonablestep.go`) - Removes unsafe ref from checkout step
- **SecretExposureRule** (`secretexposure.go`) - Replaces bracket notation secrets['NAME'] with dot notation secrets.NAME
- **ArtipackedRule** (`artipacked.go`) - Adds `persist-credentials: false` to checkout steps
- **UnsoundContainsRule** (`unsoundcontainsrule.go`) - Converts string literal to fromJSON() array format
- **CachePoisoningRule** (`cachepoisoningrule.go`) - Removes unsafe ref from checkout step
- **ConditionalRule** (`conditionalrule.go`) - Fixes conditional expression formatting
- **RefConfusionRule** (`refconfusion.go`) - Pins action to commit SHA when ref confusion is detected
- **ObfuscationRule** (`obfuscation.go`) - Normalizes obfuscated paths and shell commands
- **KnownVulnerableActionsRule** (`known_vulnerable_actions.go`) - Updates vulnerable actions to patched versions
- **SecretsInArtifactsRule** (`secretsinartifacts.go`) - Fixes unsafe artifact uploads by adding include-hidden-files: false for v3, or updating unsafe paths
- **ArgumentInjectionRule** (`argumentinjection.go`) - Moves untrusted input to environment variables and adds `--` end-of-options marker
- **RequestForgeryRule** (`requestforgery.go`) - Moves untrusted input to environment variables for network commands
- **CacheBloatRule** (`cachebloatrule.go`) - Adds `if: github.event_name != 'push'` to restore and `if: github.event_name == 'push'` to save steps
- **SecretInLogRule** (`secretinlog.go`) - Inserts `echo "::add-mask::$VAR"` before any usage of tainted shell variables
- **ChainFixer** (`cross_file_taint.go`) - Lifts callee `${{ inputs.X }}` into step-level `env:` and rewrites `run:` references to `$INPUT_X` (or `process.env.INPUT_X` in github-script). Activated by `ResolvePendingChains` after cross-file chain confirmation; SinkEnv is warning-only in Phase 1

## Recent Security Enhancements

### Privileged Workflow Context Detection
The tool now has specialized detection for dangerous patterns in privileged workflow contexts:
- **pull_request_target** - Has write access and secrets, but triggered by untrusted PRs
- **issue_comment** - Triggered by untrusted issue/PR comments
- **workflow_run** - Executes with elevated privileges

These contexts are risky because they combine elevated privileges with untrusted input.

### Untrusted Checkout Rule
Detects when `actions/checkout` in privileged contexts doesn't specify an explicit `ref`, which could lead to checking out untrusted PR code with elevated privileges. The auto-fix adds appropriate ref specifications.

### Poisoning Attack Detection
Two rules detect supply chain attacks:

- **Artifact Poisoning** - Detects unsafe artifact download patterns and path traversal risks
   - Checks for validation of downloaded artifacts
   - Detects use of artifacts in privileged operations
   - Auto-fix adds validation steps

- **Cache Poisoning** - Detects unsafe cache patterns with untrusted inputs
   - Validates cache key construction
   - Identifies untrusted inputs in cache keys (e.g., `github.event.pull_request.head.ref`)
   - Prevents attackers from poisoning build caches

### Cross-File Taint Tracking for Reusable Workflows (#392)

Phase 1 of cross-file correlation between caller and callee reusable workflows. Eliminates duplicate per-file warnings, suppresses false positives where caller passes constants (callee silent) or callee never reaches a sink (caller silent), and surfaces a chain narrative naming the source, the `with:` boundary, and the callee sink. Implementation lives in `pkg/core/cross_file_taint.go` and extends `LocalReusableWorkflowCache` with bidirectional indexes (`callerTaints`, `calleeSinks`). The post-Wait `ResolvePendingChains` phase runs single-threaded after `errgroup.Wait()` to safely mutate per-workspace results.

Phase 1 sinks: `run:`, `actions/github-script` `script:`, and `env:` direct interpolation. Severity follows caller trigger context (Critical for privileged, Medium otherwise). Auto-fix lifts callee `${{ inputs.X }}` into a step-level `env:` for SinkRun and SinkGitHubScript; SinkEnv is warning-only (auto-fix deferred to Phase 2).

Out of scope (tracked as future issues): transitive chains (callee_A → callee_B), `with:` passthrough sinks, step-output taint sources at caller, SinkEnv auto-fix, and remote reusable workflows.

## Additional Documentation

- **Rule-specific docs**: `docs/*.md` (cachepoisoningrule.md, credentialrules.md, etc.)
- **Example workflows**: `script/actions/` (see script/README.md)
- **Main website**: https://sisaku-security.github.io/lint/
- **GitHub Actions docs**: https://docs.github.com/en/actions
- **OWASP CI/CD Top 10**: https://owasp.org/www-project-top-10-ci-cd-security-risks/

## Important Notes for Claude Code

- When adding/modifying rules, ALWAYS update the rule list in this file
- When adding example workflows to `script/actions/`, document them in `script/README.md`
- Rule registration happens in `pkg/core/linter.go` around line 500-542
- The visitor pattern is depth-first: WorkflowPre → JobPre → Step → JobPost → WorkflowPost
- Auto-fix is optional but highly recommended for actionable rules

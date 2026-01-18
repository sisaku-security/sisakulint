# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## What is sisakulint?

sisakulint is a static analysis tool for GitHub Actions workflow files. It analyzes `.github/workflows/*.yml` files for security issues and best practices, implementing OWASP Top 10 CI/CD Security Risks checks.

**Key Features:**
- Detects injection vulnerabilities, credential exposure, and supply chain attacks
- Validates permissions, timeouts, and workflow configurations
- Supports auto-fixing for many security issues (20 rules with auto-fix as of Jan 2026)
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

## Core Concepts

### Architecture


## Code Architecture

sisakulint is a static analysis tool for GitHub Actions workflow files (.github/workflows/*.yml or .yaml). It analyzes these files for security issues and best practices.

### Key Components

1. **Command Structure**:
   - Entry point is in `cmd/sisakulint/main.go`
   - Core command handling in `pkg/core/command.go`

2. **Linting Engine**:
   - `pkg/core/linter.go` - Main linting logic
   - `pkg/core/validate.go` - Workflow validation

3. **Rules System**:
   - Each rule is implemented in a separate file (all implementing the `Rule` interface):
     - `pkg/core/idrule.go` - **RuleID**: ID collision detection for jobs and environment variables
     - `pkg/core/credential.go` - **CredentialRule**: Hardcoded credentials detection (with auto-fix)
     - `pkg/core/permissionrule.go` - **PermissionRule**: Permissions scope and value validation
     - `pkg/core/commitsha.go` - **CommitSHARule**: Validates commit SHA usage in actions (with auto-fix)
     - `pkg/core/workflowcall.go` - **RuleWorkflowCall**: Reusable workflow call validation
     - `pkg/core/timeout_minutes.go` - **TimeoutMinutesRule**: Ensures timeout-minutes is set (with auto-fix)
     - `pkg/core/environmentvariablerule.go` - **EnvironmentVariableRule**: Environment variable name formatting
     - `pkg/core/exprrule.go` - **ExprRule**: GitHub Actions expression syntax validation
     - `pkg/core/conditionalrule.go` - **ConditionalRule**: Conditional expression validation
     - `pkg/core/codeinjection.go` - **CodeInjectionRule**: Shared implementation for code injection detection (with auto-fix)
       - `pkg/core/codeinjectioncritical.go` - **CodeInjectionCritical**: Detects untrusted input in privileged workflow triggers (pull_request_target, workflow_run, issue_comment)
       - `pkg/core/codeinjectionmedium.go` - **CodeInjectionMedium**: Detects untrusted input in normal workflow triggers (pull_request, push, schedule)
     - `pkg/core/envvarinjection.go` - **EnvVarInjectionRule**: Shared implementation for environment variable injection detection (with auto-fix)
       - `pkg/core/envvarinjectioncritical.go` - **EnvVarInjectionCritical**: Detects untrusted input written to $GITHUB_ENV in privileged triggers
       - `pkg/core/envvarinjectionmedium.go` - **EnvVarInjectionMedium**: Detects untrusted input written to $GITHUB_ENV in normal triggers
     - `pkg/core/envpathinjection.go` - **EnvPathInjectionRule**: Shared implementation for PATH injection detection (with auto-fix)
       - `pkg/core/envpathinjectioncritical.go` - **EnvPathInjectionCritical**: Detects untrusted input written to $GITHUB_PATH in privileged triggers
       - `pkg/core/envpathinjectionmedium.go` - **EnvPathInjectionMedium**: Detects untrusted input written to $GITHUB_PATH in normal triggers
     - `pkg/core/untrustedcheckout.go` - **UntrustedCheckoutRule**: Detects checkout of untrusted PR code in privileged workflow contexts (with auto-fix)
     - `pkg/core/duprecate_commands_pattern.go` - **RuleDeprecatedCommands**: Deprecated workflow commands detection
     - `pkg/core/actionlist.go` - **ActionList**: Action whitelist/blacklist enforcement
     - `pkg/core/artifactpoisoningcritical.go` - **ArtifactPoisoningRule**: Detects artifact poisoning and path traversal vulnerabilities (with auto-fix)
     - `pkg/core/cachepoisoningrule.go` - **CachePoisoningRule**: Detects cache poisoning with untrusted inputs
     - `pkg/core/improper_access_control.go` - **ImproperAccessControlRule**: Detects improper access control with label-based approval and synchronize events (with auto-fix)
     - `pkg/core/untrustedcheckouttoctoucritical.go` - **UntrustedCheckoutTOCTOUCriticalRule**: Detects TOCTOU vulnerabilities with labeled event type and mutable refs (with auto-fix)
     - `pkg/core/untrustedcheckouttoctouhigh.go` - **UntrustedCheckoutTOCTOUHighRule**: Detects TOCTOU vulnerabilities with deployment environment and mutable refs (with auto-fix)
     - `pkg/core/botconditionsrule.go` - **BotConditionsRule**: Detects spoofable bot detection conditions using github.actor or similar contexts (with auto-fix)
     - `pkg/core/artifactpoisoningmedium.go` - **ArtifactPoisoningMediumRule**: Detects third-party artifact download actions in untrusted triggers (with auto-fix)
     - `pkg/core/cachepoisoningpoisonablestep.go` - **CachePoisoningPoisonableStepRule**: Detects cache poisoning via execution of untrusted code after unsafe checkout (with auto-fix)
     - `pkg/core/secretexposure.go` - **SecretExposureRule**: Detects excessive secrets exposure via toJSON(secrets) or secrets[dynamic-access] (with auto-fix)
     - `pkg/core/artipacked.go` - **ArtipackedRule**: Detects credential leakage when checkout credentials are persisted and workspace is uploaded (with auto-fix)
     - `pkg/core/unsoundcontainsrule.go` - **UnsoundContainsRule**: Detects bypassable contains() function usage in conditions (with auto-fix)
     - `pkg/core/impostorcommit.go` - **ImpostorCommitRule**: Detects impostor commits from fork network - supply chain attack vector (with auto-fix)
     - `pkg/core/rule_add_temp_normal.go` - **AddRule**: Template rule for adding new rules

4. **AST Processing**:
   - `pkg/ast/ast_type.go` - AST node type definitions (Workflow, Job, Step, etc.)
   - `pkg/ast/ast_func.go` - AST utility functions
   - `pkg/core/visitor.go` - **SyntaxTreeVisitor**: Orchestrates tree traversal with depth-first order
   - `pkg/core/visit.go` - Visit helper functions
   - `pkg/core/parse_main.go` - Main workflow file parsing
   - `pkg/core/parse_sub.go` - Sub-component parsing (jobs, steps, etc.)
   - `pkg/core/parse_sbom.go` - SBOM (Software Bill of Materials) parsing

5. **Expression Handling**:
   - `pkg/expressions/parser.go` - Expression parser for `${{ }}` syntax
   - `pkg/expressions/expression.go` - Expression evaluation logic
   - `pkg/expressions/semantic.go` - Semantic analysis
   - `pkg/expressions/tokenizer.go` - Tokenization of expressions
   - `pkg/expressions/ast.go` - Expression AST nodes
   - `pkg/expressions/anti_untrustedchecker.go` - Untrusted input detection
   - `pkg/expressions/anti_untrustedmap.go` - Mapping of untrusted contexts
   - `pkg/core/exprchecker.go` - Expression validation logic
   - `pkg/core/needs.go` - Job dependency (needs) validation

6. **Output Handling**:
   - `pkg/core/errorformatter.go` - Formatting error output
   - `pkg/core/sarif.go` - SARIF output support for reviewdog integration

7. **Auto-fixing**:
   - `pkg/core/autofixer.go` - Auto-fixing framework with three fixer types:
     - **AutoFixer** interface - Base interface for all fixers
     - **StepFixer** interface - Fixes issues at the step level
     - **JobFixer** interface - Fixes issues at the job level
     - **funcFixer** - Generic function-based fixer
   - Rules implementing auto-fix: TimeoutMinutesRule, CommitSHARule, CredentialRule, UntrustedCheckoutRule, ArtifactPoisoningRule, ImproperAccessControlRule

8. **Remote Analysis**:
   - `pkg/remote/fetcher.go` - GitHub API integration for fetching workflows
   - `pkg/remote/scanner.go` - Remote repository scanning logic
   - `pkg/remote/input.go` - Input parsing for remote repository specifications
   - Supports multiple input formats:
     - `owner/repo` - Single repository
     - `org:organization` - All repositories in an organization
     - With flags for recursive scanning and depth control

### Data Flow

1. The tool scans a directory for GitHub Actions workflow files
2. Files are parsed into AST representation
3. Rules are applied to the AST
4. Issues are collected and reported
5. Auto-fix is applied if requested

## Configuration

The tool can be configured using a `.github/action.yaml` file (created using `sisakulint -init`).

1. **Entry point**: `cmd/sisakulint/main.go` → `pkg/core/command.go`
2. **Workflow files** are parsed into **AST** (`pkg/ast/`)
3. **Rules** (`pkg/core/*rule.go`) visit the AST using the **Visitor pattern**
4. **Issues** are collected and reported (optionally in SARIF format)
5. **Auto-fix** can apply corrections to the AST


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

1. Create `pkg/core/myrule.go`:
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

2. Register rule in `pkg/core/linter.go`
3. Add tests in `pkg/core/myrule_test.go`
4. Optional: Implement `StepFixer` or `JobFixer` for auto-fix

See `docs/RULES_GUIDE.md` for detailed guide.

## Implemented Rules

sisakulint includes the following security rules (as of pkg/core/linter.go:500-531):

1. **CredentialsRule** - Detects hardcoded credentials and tokens (auto-fix supported)
2. **JobNeedsRule** - Validates job dependencies
3. **EnvironmentVariableRule** - Checks environment variable usage
4. **IDRule** - Validates workflow/job/step IDs
5. **PermissionsRule** - Enforces least privilege permissions
6. **WorkflowCall** - Validates reusable workflow calls
7. **ExpressionRule** - Parses and validates `${{ }}` expressions
8. **DeprecatedCommandsRule** - Detects deprecated GitHub Actions commands
9. **ConditionalRule** - Validates conditional expressions
10. **TimeoutMinuteRule** - Enforces timeout configurations (auto-fix supported)
11. **CodeInjectionCriticalRule** - Detects code injection in privileged triggers (auto-fix supported)
12. **CodeInjectionMediumRule** - Detects code injection in normal triggers (auto-fix supported)
13. **EnvVarInjectionCriticalRule** - Detects environment variable injection in privileged triggers (auto-fix supported)
14. **EnvVarInjectionMediumRule** - Detects environment variable injection in normal triggers (auto-fix supported)
15. **EnvPathInjectionCriticalRule** - Detects PATH injection in privileged triggers (auto-fix supported)
16. **EnvPathInjectionMediumRule** - Detects PATH injection in normal triggers (auto-fix supported)
17. **CommitShaRule** - Validates action version pinning (auto-fix supported)
18. **ArtifactPoisoningRule** - Detects artifact poisoning risks (auto-fix supported)
19. **ActionListRule** - Validates allowed/blocked actions
20. **CachePoisoningRule** - Detects cache poisoning vulnerabilities
21. **UntrustedCheckoutRule** - Detects checkout of untrusted PR code in privileged contexts (auto-fix supported)
22. **ImproperAccessControlRule** - Detects improper access control with label-based approval and synchronize events (auto-fix supported)
23. **UnmaskedSecretExposureRule** - Detects unmasked secret exposure when secrets are derived using fromJson() (auto-fix supported)
24. **UntrustedCheckoutTOCTOUCriticalRule** - Detects TOCTOU vulnerabilities with labeled event type and mutable refs (auto-fix supported)
25. **UntrustedCheckoutTOCTOUHighRule** - Detects TOCTOU vulnerabilities with deployment environment and mutable refs (auto-fix supported)
26. **BotConditionsRule** - Detects spoofable bot detection conditions using github.actor or similar contexts (auto-fix supported)
27. **ArtifactPoisoningMediumRule** - Detects third-party artifact download actions in untrusted triggers (auto-fix supported)
28. **CachePoisoningPoisonableStepRule** - Detects cache poisoning via execution of untrusted code after unsafe checkout (auto-fix supported)
29. **SecretExposureRule** - Detects excessive secrets exposure via toJSON(secrets) or secrets[dynamic-access] (auto-fix supported)
30. **ArtipackedRule** - Detects credential leakage when checkout credentials are persisted and workspace is uploaded (auto-fix supported)
31. **UnsoundContainsRule** - Detects bypassable contains() function usage in conditions (auto-fix supported)
32. **ImpostorCommitRule** - Detects impostor commits from fork network that could be supply chain attacks (auto-fix supported)

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

1. Create example workflows in `script/actions/`
   - `myrule.yaml` - Demonstrates the vulnerability
   - `myrule-safe.yaml` - Shows the correct pattern

2. Implement the rule in `pkg/core/myrule.go`

3. Add tests in `pkg/core/myrule_test.go`

4. Register the rule in `pkg/core/linter.go` (around line 500)

5. Test with: `sisakulint script/actions/myrule.yaml`

### Debugging Tips

- Use `-debug` flag to see AST traversal
- Check `pkg/core/visitor.go` to understand visitor pattern execution
- Use `script/actions/` examples to test edge cases
- Run specific tests: `go test -v ./pkg/core -run TestYourRule`

## Auto-Fix System

Rules can implement auto-fix by:

1. Implementing `StepFixer` or `JobFixer` interface
2. Registering the fixer: `rule.AddAutoFixer(fixer)`
3. Testing with: `sisakulint -fix dry-run`

See `pkg/core/permissionrule.go` for auto-fix example.

### Current Auto-Fix Implementations

1. **TimeoutMinutesRule** (`timeout_minutes.go`) - Adds default timeout-minutes: 5
2. **CommitSHARule** (`commitsha.go`) - Converts action tags to commit SHAs with comment preservation
3. **CredentialRule** (`credential.go`) - Removes hardcoded passwords from container configs
4. **CodeInjectionRule** (`codeinjection.go`) - Moves untrusted expressions to environment variables
5. **EnvVarInjectionRule** (`envvarinjection.go`) - Sanitizes untrusted input with `tr -d '\n'` before writing to $GITHUB_ENV
6. **EnvPathInjectionRule** (`envpathinjection.go`) - Validates untrusted paths with `realpath` before writing to $GITHUB_PATH
7. **UntrustedCheckoutRule** (`untrustedcheckout.go`) - Adds explicit ref to checkout in privileged contexts
8. **ArtifactPoisoningRule** (`artifactpoisoningcritical.go`) - Adds validation steps for artifact downloads
9. **UnmaskedSecretExposureRule** (`unmasked_secret_exposure.go`) - Adds `::add-mask::` command for derived secrets from fromJson()
10. **ImproperAccessControlRule** (`improper_access_control.go`) - Adds safe conditions for label-based and synchronize events
11. **UntrustedCheckoutTOCTOUCriticalRule** (`untrustedcheckouttoctoucritical.go`) - Fixes TOCTOU vulnerabilities with labeled event type
12. **UntrustedCheckoutTOCTOUHighRule** (`untrustedcheckouttoctouhigh.go`) - Fixes TOCTOU vulnerabilities with deployment environment
13. **BotConditionsRule** (`botconditionsrule.go`) - Replaces spoofable bot conditions with safe alternatives
14. **ArtifactPoisoningMediumRule** (`artifactpoisoningmedium.go`) - Adds safe extraction path to `${{ runner.temp }}/artifacts`
15. **CachePoisoningPoisonableStepRule** (`cachepoisoningpoisonablestep.go`) - Removes unsafe ref from checkout step
16. **SecretExposureRule** (`secretexposure.go`) - Replaces bracket notation secrets['NAME'] with dot notation secrets.NAME
17. **ArtipackedRule** (`artipacked.go`) - Adds `persist-credentials: false` to checkout steps
18. **UnsoundContainsRule** (`unsoundcontainsrule.go`) - Converts string literal to fromJSON() array format
19. **CachePoisoningRule** (`cachepoisoningrule.go`) - Removes unsafe ref from checkout step
20. **ConditionalRule** (`conditionalrule.go`) - Fixes conditional expression formatting

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
Two new rules detect supply chain attacks:

1. **Artifact Poisoning** - Detects unsafe artifact download patterns and path traversal risks
   - Checks for validation of downloaded artifacts
   - Detects use of artifacts in privileged operations
   - Auto-fix adds validation steps

2. **Cache Poisoning** - Detects unsafe cache patterns with untrusted inputs
   - Validates cache key construction
   - Identifies untrusted inputs in cache keys (e.g., `github.event.pull_request.head.ref`)
   - Prevents attackers from poisoning build caches

## Additional Documentation

- **Rule-specific docs**: `docs/*.md` (cachepoisoningrule.md, credentialrules.md, etc.)
- **Example workflows**: `script/actions/` (see script/README.md)
- **Main website**: https://sisaku-security.github.io/lint/
- **GitHub Actions docs**: https://docs.github.com/en/actions
- **OWASP CI/CD Top 10**: https://owasp.org/www-project-top-10-ci-cd-security-risks/

## Important Notes for Claude Code

- When adding/modifying rules, ALWAYS update the rule list in this file
- When adding example workflows to `script/actions/`, document them in `script/README.md`
- Rule registration happens in `pkg/core/linter.go` around line 500-519
- The visitor pattern is depth-first: WorkflowPre → JobPre → Step → JobPost → WorkflowPost
- Auto-fix is optional but highly recommended for actionable rules

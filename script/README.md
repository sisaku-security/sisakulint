# Script Directory

This directory contains example workflows and utility scripts for the sisakulint project.

## Directory Structure

```
script/
├── actions/           # Example GitHub Actions workflow files
└── github_to_aws/     # AWS deployment infrastructure (Terraform)
```

## actions/

Contains example GitHub Actions workflow files that demonstrate various security issues and patterns that sisakulint can detect. These files are used for:

- **Testing**: Validating that sisakulint correctly identifies security vulnerabilities
- **Documentation**: Showing examples of vulnerable and safe workflow patterns
- **Development**: Testing new rules during development

### Example Files

| File | Description |
|------|-------------|
| `cache-poisoning.yaml` | Demonstrates cache poisoning vulnerabilities |
| `cache-poisoning-safe.yaml` | Safe cache configuration example |
| `credential.yaml` | Credential exposure patterns |
| `issueinjection.yaml` | Script injection via GitHub context |
| `issueinjection-multiline.yaml` | Multi-line injection patterns |
| `issueinjection-all-untrusted.yaml` | Comprehensive untrusted input examples |
| `pull_req_target_checkout.yaml` | `pull_request_target` checkout vulnerabilities |
| `permission.yaml` | Permission configuration examples |
| `timeout-minutes.yaml` | Timeout configuration patterns |
| `supply_chain_protection.yaml` | Supply chain security examples |
| `test-actionlist.yaml` | Action list rule testing |
| `test-actionlist-blacklist.yaml` | Blacklist validation testing |
| `cross-job-taint.yaml` | Cross-job taint propagation via `needs.*.outputs.*` (code-injection-critical) |
| `cross-job-taint-safe.yaml` | Safe pattern: untrusted needs output moved to `env:` and referenced with double quotes (e.g. `echo "$PR_TITLE"` not `echo $PR_TITLE`) to avoid shell expansion; see `pkg/core/codeinjection_shell_test.go` for unquoted env detection |
| `ai-action-unsafe-sandbox-vulnerable.yaml` | AI action with unsafe sandbox settings (`safety-strategy: unsafe`) |
| `ai-action-unsafe-sandbox-safe.yaml` | Safe AI action sandbox configuration (`safety-strategy: drop-sudo`) |
| `ai-action-execution-order-vulnerable.yaml` | AI action followed by additional steps (compromised state risk) |
| `ai-action-execution-order-safe.yaml` | AI action as the last step in the job (recommended pattern) |
| `secret-in-log-vulnerable.yaml` | Secrets leaked to build logs via `echo`/`printf` of shell variables derived from secret-sourced environment variables (chained assignment, direct echo patterns) |
| `secret-in-log-safe.yaml` | Safe counterparts using `::add-mask::` before printing derived variables, unrelated echo, and no-echo (curl-only) patterns |
| `taint-scope-fp-safe.yaml` | TaintTracker scope-aware (#447): subshell 内の変数上書きが親スコープに漏れないことを示す |
| `taint-scope-fn-vulnerable.yaml` | TaintTracker scope-aware (#447): 関数本体内 local 変数の secret-in-log 検出を示す |

### Usage

These workflows can be used to test sisakulint:

```bash
# Test a specific workflow file
sisakulint script/actions/issueinjection.yaml

# Test all example workflows
sisakulint script/actions/

# Test with debug output
sisakulint -debug script/actions/credential.yaml

# Test auto-fix functionality
sisakulint -fix dry-run script/actions/permission.yaml
```

### Adding New Examples

When adding new example workflows:

1. **Vulnerable patterns**: Name the file descriptively (e.g., `new-vulnerability.yaml`)
2. **Safe patterns**: Use `-safe` suffix (e.g., `new-vulnerability-safe.yaml`)
3. **Add comments**: Include inline comments explaining the security issue
4. **Update tests**: Add corresponding test cases in `pkg/core/*_test.go`

Example structure:

```yaml
# new-vulnerability.yaml
name: Example Vulnerability

on: [pull_request]

jobs:
  vulnerable:
    runs-on: ubuntu-latest
    steps:
      # VULNERABLE: This allows script injection
      - name: Unsafe use of PR title
        run: echo "${{ github.event.pull_request.title }}"
```

### github-actions-goat Verification Workflows

Workflow files from [step-security/github-actions-goat](https://github.com/step-security/github-actions-goat), a deliberately vulnerable GitHub Actions CI/CD environment. These are used to verify sisakulint's detection coverage against real-world vulnerability scenarios. See the [full verification report](../docs/goat/_index.md) for details.

| File | Vulnerability Scenario | Detection Status |
|------|----------------------|-----------------|
| `goat-pr-target-workflow.yml` | Dangerous `pull_request_target` trigger without mitigations | Detected |
| `goat-toc-tou.yml` | TOCTOU vulnerability with label-gated `pull_request_target` | Detected |
| `goat-changed-files-vulnerability-without-hr.yml` | Code injection via action output (no harden-runner) | Partially detected |
| `goat-changed-files-vulnerability-with-hr.yml` | Code injection via action output (with harden-runner) | Partially detected |
| `goat-tj-actions-changed-files-incident.yaml` | tj-actions supply chain incident simulation | Detected |
| `goat-baseline-checks.yml` | Build pipeline with known vulnerable actions | Detected |
| `goat-secret-in-build-log.yml` | Secret exposure in build logs | Not detected |
| `goat-anomalous-outbound-calls.yaml` | Anomalous outbound HTTP calls (runtime) | Out of scope |
| `goat-unexpected-outbound-calls.yml` | Unexpected outbound calls to attacker.com (runtime) | Out of scope |
| `goat-hosted-network-without-hr.yml` | Network exfiltration without protection (runtime) | Out of scope |
| `goat-hosted-network-monitoring-hr.yml` | Network monitoring with harden-runner audit mode | Out of scope |
| `goat-hosted-network-filtering-hr.yml` | Network filtering with harden-runner block mode (secure) | Out of scope |
| `goat-hosted-https-monitoring-hr.yml` | HTTPS-based exfiltration monitoring | Out of scope |
| `goat-hosted-file-monitor-with-hr.yml` | SolarWinds-style build tampering with file monitoring | Out of scope |
| `goat-hosted-file-monitor-without-hr.yml` | SolarWinds-style build tampering without monitoring | Out of scope |
| `goat-block-dns-exfiltration.yaml` | DNS exfiltration with egress blocking (secure) | Out of scope |
| `goat-publish.yml` | Puzzle: exfiltration via compromised dependency | Out of scope |
| `goat-arc-codecov-simulation.yml` | Codecov breach simulation on ARC runners | Out of scope |
| `goat-arc-secure-by-default.yml` | Direct IP exfiltration comparison (hosted vs ARC) | Out of scope |
| `goat-arc-solarwinds-simulation.yml` | SolarWinds SUNSPOT simulation on ARC runners | Out of scope |
| `goat-arc-zero-effort-observability.yml` | Zero observability on ARC runners | Out of scope |
| `goat-self-hosted-file-monitor-with-hr.yml` | Build tampering on self-hosted runners | Out of scope |
| `goat-self-hosted-network-filtering-hr.yml` | Network filtering on self-hosted runners (secure) | Out of scope |
| `goat-self-hosted-network-monitoring-hr.yml` | Network monitoring on self-hosted runners | Out of scope |

## github_to_aws/

Contains Terraform infrastructure code for deploying from GitHub Actions to AWS using OIDC authentication. This is used for the sisakulint project's own CI/CD pipeline.

### Features

- GitHub OIDC authentication with AWS
- IAM roles for S3, Lambda, and ECS deployments
- Least privilege access configuration

### Setup

See the [Terraform documentation](github_to_aws/) for setup instructions.

## Related Documentation

- [Main Documentation](https://sisaku-security.github.io/lint/)
- [Development Guide](../docs/DEVELOPMENT.md)
- [Rules Guide](../docs/RULES_GUIDE.md)
- [Architecture](../docs/ARCHITECTURE.md)

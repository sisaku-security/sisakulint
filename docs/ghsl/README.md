# GitHub Security Lab (GHSL) Vulnerability Detection

sisakulint can detect vulnerability patterns reported by [GitHub Security Lab](https://securitylab.github.com/). This directory contains documentation for each GHSL advisory that sisakulint can detect.

## Supported GHSL Advisories

| Advisory ID | Severity | Description | Detection Rules |
|-------------|----------|-------------|-----------------|
| [GHSL-2024-325](./GHSL-2024-325.md) | Critical | Arbitrary code execution via untrusted fork checkout | `cache-poisoning-poisonable-step`, `dangerous-triggers-critical` |
| [GHSL-2024-326](./GHSL-2024-326.md) | Critical | Code injection via branch name | `code-injection-critical`, `argument-injection-critical` |
| [GHSL-2025-099](./GHSL-2025-099.md) | Critical | Code injection via workflow_run head_branch | `code-injection-critical` |

## Detection Capabilities

sisakulint provides comprehensive detection for these vulnerability patterns through multiple rules:

### Core Detection Rules

| Rule | Description | Auto-fix |
|------|-------------|----------|
| `code-injection-critical` | Detects untrusted input in shell commands | Yes |
| `argument-injection-critical` | Detects untrusted input in command arguments | Yes |
| `dangerous-triggers-critical` | Identifies privileged triggers without mitigations | No |
| `cache-poisoning-poisonable-step` | Detects execution of untrusted code after checkout | Yes |

### Taint Tracking

sisakulint implements sophisticated taint tracking to detect indirect code injection:

1. **Direct Context Tracking**: Identifies untrusted GitHub context variables
2. **Action Output Tracking**: Tracks taint through known actions (e.g., `xt0rted/pull-request-comment-branch`)
3. **Step Output Propagation**: Follows taint through `actions/github-script` outputs

## Testing

Test files for each GHSL pattern are available in `script/actions/ghsl/`:

```bash
# Test GHSL-2024-325 and GHSL-2024-326 combined pattern
./sisakulint script/actions/ghsl/ghsl-2024-325-326.yaml

# Test GHSL-2024-326 direct injection
./sisakulint script/actions/ghsl/ghsl-2024-326-direct.yaml

# Test GHSL-2024-326 via known action
./sisakulint script/actions/ghsl/ghsl-2024-326-known-action.yaml

# Test GHSL-2025-099
./sisakulint script/actions/ghsl/ghsl-2025-099.yaml
```

## Common Vulnerability Patterns

### Privileged Triggers

These triggers grant elevated permissions and are prime targets for attacks:

| Trigger | Risk | Reason |
|---------|------|--------|
| `issue_comment` | Critical | Triggered by anyone who can comment |
| `pull_request_target` | Critical | Runs with target repo permissions on PR from fork |
| `workflow_run` | Critical | Inherits elevated permissions from triggering workflow |

### Untrusted Inputs

Common untrusted inputs that can be exploited:

```
github.event.pull_request.head.ref
github.event.pull_request.title
github.event.pull_request.body
github.event.issue.title
github.event.issue.body
github.event.comment.body
github.event.workflow_run.head_branch
github.event.workflow_run.head_repository.full_name
steps.*.outputs.* (from tainted actions)
```

## References

- [GitHub Security Lab Advisories](https://securitylab.github.com/advisories/)
- [Keeping your GitHub Actions and workflows secure](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Top 10 Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

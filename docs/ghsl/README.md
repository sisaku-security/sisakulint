# GitHub Security Lab (GHSL) Vulnerability Detection

This document summarizes sisakulint's detection capability against GitHub Security Lab advisories for the GitHub Actions ecosystem.

## Summary

| Metric | Value |
|--------|-------|
| Total Advisories | 18 |
| Detected (Direct) | 18 |
| Detection Rate | 100% |

## Detection Categories

| Rule | Detections |
|------|-----------:|
| code-injection-critical | 13 |
| untrusted-checkout | 7 |
| cache-poisoning-poisonable-step | 6 |
| dangerous-triggers-critical | 2 |
| argument-injection-critical | 1 |
| output-clobbering-critical | 1 |

## Detection Results

### Code Injection Vulnerabilities

| Advisory ID | Affected Component | Severity | Detected | Detection Rules | Doc |
|-------------|-------------------|----------|----------|-----------------|-----|
| [GHSL-2024-326](./GHSL-2024-326.md) | Actual | Critical | Yes | CodeInjectionCriticalRule, ArgumentInjectionCriticalRule | [Link](./GHSL-2024-326.md) |
| [GHSL-2025-087](./GHSL-2025-087.md) | PX4-Autopilot | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-087.md) |
| [GHSL-2025-089](./GHSL-2025-089.md) | YDB | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-089.md) |
| [GHSL-2025-090](./GHSL-2025-090.md) | harvester | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-090.md) |
| [GHSL-2025-091](./GHSL-2025-091.md) | pymapdl | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-091.md) |
| [GHSL-2025-099](./GHSL-2025-099.md) | cross-platform-actions | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-099.md) |
| [GHSL-2025-101](./GHSL-2025-101.md) | homeassistant-tapo-control | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-101.md) |
| [GHSL-2025-102](./GHSL-2025-102.md) | acl-anthology | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-102.md) |
| [GHSL-2025-103](./GHSL-2025-103.md) | acl-anthology | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-103.md) |
| [GHSL-2025-104](./GHSL-2025-104.md) | weaviate | Critical | Yes | CodeInjectionCriticalRule, DangerousTriggersRule | [Link](./GHSL-2025-104.md) |
| [GHSL-2025-105](./GHSL-2025-105.md) | vets-api | Critical | Yes | CodeInjectionCriticalRule, OutputClobberingCriticalRule | [Link](./GHSL-2025-105.md) |
| [GHSL-2025-106](./GHSL-2025-106.md) | esphome-docs | Critical | Yes | CodeInjectionCriticalRule | [Link](./GHSL-2025-106.md) |
| [GHSL-2025-111](./GHSL-2025-111.md) | nrwl/nx | High | Yes | UntrustedCheckoutRule, CodeInjectionCriticalRule | [Link](./GHSL-2025-111.md) |

### Untrusted Code Execution Vulnerabilities

| Advisory ID | Affected Component | Severity | Detected | Detection Rules | Doc |
|-------------|-------------------|----------|----------|-----------------|-----|
| [GHSL-2024-325](./GHSL-2024-325.md) | Actual | Critical | Yes | CachePoisoningPoisonableStepRule, DangerousTriggersRule | [Link](./GHSL-2024-325.md) |
| [GHSL-2025-006](./GHSL-2025-006.md) | homeassistant-powercalc | Critical | Yes | UntrustedCheckoutRule, CachePoisoningPoisonableStepRule | [Link](./GHSL-2025-006.md) |
| [GHSL-2025-077](./GHSL-2025-077.md) | beeware | Critical | Yes | UntrustedCheckoutRule, CachePoisoningPoisonableStepRule | [Link](./GHSL-2025-077.md) |
| [GHSL-2025-082](./GHSL-2025-082.md) | ag-grid | Critical | Yes | UntrustedCheckoutRule, CachePoisoningPoisonableStepRule | [Link](./GHSL-2025-082.md) |
| [GHSL-2025-084](./GHSL-2025-084.md) | datadog-actions-metrics | Critical | Yes | UntrustedCheckoutRule | [Link](./GHSL-2025-084.md) |
| [GHSL-2025-094](./GHSL-2025-094.md) | faststream | Critical | Yes | UntrustedCheckoutRule, CachePoisoningPoisonableStepRule | [Link](./GHSL-2025-094.md) |

### TOCTOU / Approval Bypass Vulnerabilities

| Advisory ID | Affected Component | Severity | Detected | Detection Rules | Doc |
|-------------|-------------------|----------|----------|-----------------|-----|
| [GHSL-2025-038](./GHSL-2025-038.md) | github/branch-deploy | High | Yes | CachePoisoningPoisonableStepRule | [Link](./GHSL-2025-038.md) |

## Key Findings

1. **100% Detection Rate**: sisakulint successfully detects all 18 GHSL advisories for GitHub Actions workflows.

2. **Code Injection Dominance**: 13 of 18 advisories (72%) involve code injection vulnerabilities via untrusted input in shell commands.

3. **Untrusted Checkout Patterns**: 7 advisories involve checking out untrusted PR code in privileged contexts.

4. **Cache/Supply Chain Risks**: 6 advisories involve cache poisoning or supply chain attack vectors.

5. **Privileged Trigger Exploitation**: All advisories exploit privileged triggers (`pull_request_target`, `issue_comment`, `workflow_run`).

## Core Detection Rules

| Rule | Description | Auto-fix |
|------|-------------|----------|
| `code-injection-critical` | Detects untrusted input in shell commands | Yes |
| `argument-injection-critical` | Detects untrusted input in command arguments | Yes |
| `dangerous-triggers-critical` | Identifies privileged triggers without mitigations | No |
| `cache-poisoning-poisonable-step` | Detects execution of untrusted code after checkout | Yes |
| `untrusted-checkout` | Detects checkout of PR code in privileged contexts | Yes |
| `output-clobbering-critical` | Detects untrusted input written to GITHUB_OUTPUT | Yes |

## Taint Tracking

sisakulint implements sophisticated taint tracking to detect indirect code injection:

1. **Direct Context Tracking**: Identifies untrusted GitHub context variables
2. **Action Output Tracking**: Tracks taint through known actions (e.g., `xt0rted/pull-request-comment-branch`)
3. **Step Output Propagation**: Follows taint through `actions/github-script` outputs

## Running Verification

```bash
# Build sisakulint
go build ./cmd/sisakulint

# Test all GHSL patterns
./sisakulint script/actions/ghsl/

# Test GHSL-2024 advisories
./sisakulint script/actions/ghsl/ghsl-2024-325-326.yaml
./sisakulint script/actions/ghsl/ghsl-2024-326-direct.yaml
./sisakulint script/actions/ghsl/ghsl-2024-326-known-action.yaml

# Test GHSL-2025 advisories
./sisakulint script/actions/ghsl/ghsl-2025-006.yaml   # homeassistant-powercalc
./sisakulint script/actions/ghsl/ghsl-2025-038.yaml   # branch-deploy TOCTOU
./sisakulint script/actions/ghsl/ghsl-2025-077.yaml   # beeware
./sisakulint script/actions/ghsl/ghsl-2025-082.yaml   # ag-grid
./sisakulint script/actions/ghsl/ghsl-2025-084.yaml   # datadog-actions-metrics
./sisakulint script/actions/ghsl/ghsl-2025-087.yaml   # PX4-Autopilot
./sisakulint script/actions/ghsl/ghsl-2025-089.yaml   # YDB
./sisakulint script/actions/ghsl/ghsl-2025-090.yaml   # harvester
./sisakulint script/actions/ghsl/ghsl-2025-091.yaml   # pymapdl
./sisakulint script/actions/ghsl/ghsl-2025-094.yaml   # faststream
./sisakulint script/actions/ghsl/ghsl-2025-099.yaml   # cross-platform-actions
./sisakulint script/actions/ghsl/ghsl-2025-101.yaml   # homeassistant-tapo-control
./sisakulint script/actions/ghsl/ghsl-2025-102.yaml   # acl-anthology (link-to-checklist)
./sisakulint script/actions/ghsl/ghsl-2025-103.yaml   # acl-anthology (print-info)
./sisakulint script/actions/ghsl/ghsl-2025-104.yaml   # weaviate
./sisakulint script/actions/ghsl/ghsl-2025-105.yaml   # vets-api
./sisakulint script/actions/ghsl/ghsl-2025-106.yaml   # esphome-docs
./sisakulint script/actions/ghsl/ghsl-2025-111.yaml   # nrwl/nx
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

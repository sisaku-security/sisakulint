+++
title = 'Case 01: Dangerous Triggers (pull_request_target)'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 1
+++

# Case 01: Dangerous Triggers (pull_request_target)

## Target File

- `PRTargetWorkflow.yml` → [`script/actions/goat-pr-target-workflow.yml`](../../script/actions/goat-pr-target-workflow.yml)

## Vulnerability Overview

The `pull_request_target` trigger executes in the context of the PR's base branch, granting write permissions and access to secrets. This workflow uses `actions/checkout@v4` without specifying an explicit `ref`, and lacks any security mitigations (no permission restrictions, no label conditions, no environment protection). An attacker can execute code in a privileged context by submitting a malicious PR.

## Attack Scenario

1. Attacker creates a PR from a forked repository containing malicious code
2. The `pull_request_target` trigger fires the workflow
3. No permission restrictions or label conditions → any PR triggers execution
4. Write permissions + secrets access → repository tampering or secret exfiltration

## sisakulint Detection Results

### Rules Triggered

| Rule | Severity | Description |
|---|---|---|
| `dangerous-triggers-critical` | Critical | `pull_request_target` used without security mitigations |
| `permissions` | High | No explicit `permissions` block |
| `artipacked` | Medium | `persist-credentials: false` not set |
| `commit-sha` | High | Action not pinned to commit SHA |
| `missing-timeout-minutes` | Low | No timeout configured |

### Detection Message

```
PRTargetWorkflow.yml:4:3: dangerous trigger (critical): workflow uses privileged trigger(s)
[pull_request_target] without any security mitigations. These triggers grant write access and
secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions
(permissions: read-all or permissions: {}), use environment protection, add label conditions,
or check github.actor. [dangerous-triggers-critical]
```

## Recommended Fix

- Add `permissions: {}` to enforce least privilege
- Add label conditions (`if: github.event.label.name == 'safe-to-test'`)
- Use environment protection rules
- Specify explicit `ref` for checkout

## Verdict: DETECTED

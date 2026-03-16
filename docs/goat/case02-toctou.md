+++
title = 'Case 02: TOCTOU Vulnerability'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 2
+++

# Case 02: TOCTOU (Time-of-Check-Time-of-Use) Vulnerability

## Target File

- `toc-tou.yml` → [`script/actions/goat-toc-tou.yml`](../../script/actions/goat-toc-tou.yml)

## Vulnerability Overview

A TOCTOU vulnerability occurs when an attacker can modify code between the approval check and the actual code execution. This workflow uses `pull_request_target` with a `labeled` event type and checks for the `approved` label. The `vulnerable-pattern` job uses `gh pr checkout` to fetch the latest code, meaning an attacker can push malicious commits after label approval but before code execution.

## Attack Scenario

1. Attacker creates a benign PR
2. Reviewer inspects the code and applies the `approved` label
3. Workflow starts, waits 2 minutes (`sleep 120`)
4. During the wait, attacker pushes a malicious commit
5. `gh pr checkout` fetches the latest code → unapproved code executes in a privileged context

## sisakulint Detection Results

### Rules Triggered

| Rule | Severity | Description |
|---|---|---|
| `untrusted-checkout` | Critical | Untrusted checkout in `pull_request_target` context |
| `commit-sha` | High | Actions not pinned to commit SHA |
| `artipacked` | Medium | `persist-credentials: false` not set |
| `missing-timeout-minutes` | Low | No timeout configured |

### Secure vs. Vulnerable Pattern

The workflow contains both patterns for comparison:

```yaml
# VULNERABLE: Could get different code than what was approved
- name: Checkout PR (Vulnerable)
  run: gh pr checkout ${{ github.event.pull_request.number }}

# SECURE: Gets exactly the code that was approved
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}
```

## Verdict: DETECTED

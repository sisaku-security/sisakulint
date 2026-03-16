+++
title = 'Case 03: Supply Chain - Vulnerable Third-Party Actions'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 3
+++

# Case 03: Supply Chain - Vulnerable Third-Party Actions

## Target Files

- `changed-files-vulnerability-with-hr.yml` → [`script/actions/goat-changed-files-vulnerability-with-hr.yml`](../../script/actions/goat-changed-files-vulnerability-with-hr.yml)
- `changed-files-vulnerability-without-hr.yml` → [`script/actions/goat-changed-files-vulnerability-without-hr.yml`](../../script/actions/goat-changed-files-vulnerability-without-hr.yml)
- `tj-actions-changed-files-incident.yaml` → [`script/actions/goat-tj-actions-changed-files-incident.yaml`](../../script/actions/goat-tj-actions-changed-files-incident.yaml)
- `baseline_checks.yml` → [`script/actions/goat-baseline-checks.yml`](../../script/actions/goat-baseline-checks.yml)

## Vulnerability Overview

`tj-actions/changed-files` v35 and v40 have known vulnerabilities (GHSL-2023-271). Additionally, `step-security/harden-runner@int-sh` has known vulnerabilities (GHSA-cpmj-h4f6-r6pq, GHSA-g85v-wf27-67xc).

### tj-actions/changed-files Incident

A real-world supply chain attack that occurred in March 2023. An attacker compromised the `tj-actions/changed-files` action and injected code to exfiltrate secrets from CI/CD pipelines.

## sisakulint Detection Results

### Rules Triggered

| Rule | Severity | Target File |
|---|---|---|
| `known-vulnerable-actions` | Medium/Low | baseline_checks.yml (harden-runner GHSA-cpmj-h4f6-r6pq, GHSA-g85v-wf27-67xc) |
| `known-vulnerable-actions` | Medium/Low | changed-files-vulnerability-with-hr.yml (GHSL-2023-271) |
| `known-vulnerable-actions` | Medium/Low | changed-files-vulnerability-without-hr.yml (GHSL-2023-271) |
| `known-vulnerable-actions` | Medium/Low | tj-actions-changed-files-incident.yaml (compromised version) |

### Detection Message Example

```
baseline_checks.yml:10:9: Action 'step-security/harden-runner@int-sh' has a known medium
severity vulnerability (GHSA-cpmj-h4f6-r6pq): Harden-Runner: Bypassing Logging of Outbound
Connections Using sendto, sendmsg, and sendmmsg in Harden-Runner (Community Tier).
Upgrade to version 2.14.2 or later. [known-vulnerable-actions]
```

## Recommended Fix

- Update `tj-actions/changed-files` to a patched version
- Update `step-security/harden-runner` to v2.14.2 or later
- Pin all actions to commit SHA

## Verdict: DETECTED

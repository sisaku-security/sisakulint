+++
title = 'Case 07: Self-Hosted Runner Risks'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 7
+++

# Case 07: Self-Hosted Runner Risks

## Target Files

- `arc-codecov-simulation.yml` → [`script/actions/goat-arc-codecov-simulation.yml`](../../script/actions/goat-arc-codecov-simulation.yml)
- `arc-secure-by-default.yml` → [`script/actions/goat-arc-secure-by-default.yml`](../../script/actions/goat-arc-secure-by-default.yml)
- `arc-solarwinds-simulation.yml` → [`script/actions/goat-arc-solarwinds-simulation.yml`](../../script/actions/goat-arc-solarwinds-simulation.yml)
- `arc-zero-effort-observability.yml` → [`script/actions/goat-arc-zero-effort-observability.yml`](../../script/actions/goat-arc-zero-effort-observability.yml)
- `self-hosted-file-monitor-with-hr.yml` → [`script/actions/goat-self-hosted-file-monitor-with-hr.yml`](../../script/actions/goat-self-hosted-file-monitor-with-hr.yml)
- `self-hosted-network-filtering-hr.yml` → [`script/actions/goat-self-hosted-network-filtering-hr.yml`](../../script/actions/goat-self-hosted-network-filtering-hr.yml)
- `self-hosted-network-monitoring-hr.yml` → [`script/actions/goat-self-hosted-network-monitoring-hr.yml`](../../script/actions/goat-self-hosted-network-monitoring-hr.yml)

## Vulnerability Overview

Using self-hosted runners in public repositories is dangerous because state persists between workflow runs. An attacker can execute arbitrary code via a PR and plant a backdoor on the runner that persists across future workflow runs.

## Detection Example

```
arc-codecov-simulation.yml:7:14: job "build" uses self-hosted runner (direct label specification).
Self-hosted runners are dangerous in public repositories because they can persist state between
workflow runs and allow arbitrary code execution from pull requests. [self-hosted-runner]
```

## Recommended Fix

- Use ephemeral runners (e.g., ARC with ephemeral mode)
- Migrate to GitHub-hosted runners
- Restrict runner access for `pull_request` triggers

## Verdict: DETECTED

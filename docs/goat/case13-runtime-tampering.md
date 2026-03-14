+++
title = 'Case 13: Build-Time File Tampering (Runtime)'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 13
+++

# Case 13: Build-Time File Tampering (Runtime)

## Target Files

- `arc-solarwinds-simulation.yml` → [`script/actions/goat-arc-solarwinds-simulation.yml`](../../script/actions/goat-arc-solarwinds-simulation.yml)
- `hosted-file-monitor-with-hr.yml` → [`script/actions/goat-hosted-file-monitor-with-hr.yml`](../../script/actions/goat-hosted-file-monitor-with-hr.yml)
- `hosted-file-monitor-without-hr.yml` → [`script/actions/goat-hosted-file-monitor-without-hr.yml`](../../script/actions/goat-hosted-file-monitor-without-hr.yml)
- `self-hosted-file-monitor-with-hr.yml` → [`script/actions/goat-self-hosted-file-monitor-with-hr.yml`](../../script/actions/goat-self-hosted-file-monitor-with-hr.yml)

## Vulnerability Overview

This scenario simulates the SolarWinds SUNSPOT attack. During the build process (e.g., `npm install`), a compromised package tampers with source code or build artifacts. The workflow YAML itself appears normal — tampering occurs inside the build tool, invisible to code review or file diffs.

## Why Out of Scope

Build-time file tampering is a runtime problem. Tampering occurs inside npm package `postinstall` scripts, not in the workflow YAML. Static analysis of workflow files cannot detect this.

### Indirect Mitigation by sisakulint

- `commit-sha`: Pinning dependency actions
- `artipacked`: Preventing credential persistence

## Recommended Defense

- **harden-runner** file monitoring to detect file modifications during build
- SLSA framework for build artifact provenance
- Reproducible builds

## Verdict: OUT OF SCOPE (Runtime Security)

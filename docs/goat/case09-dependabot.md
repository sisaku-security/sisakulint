+++
title = 'Case 09: Missing Dependabot Configuration'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 9
+++

# Case 09: Missing Dependabot Configuration

## Target Files

All 24 files

## Vulnerability Overview

Without a `.github/dependabot.yaml` configuring the `github-actions` ecosystem, major version updates for GitHub Actions (e.g., v3 → v4) are not automated. This increases the risk of continuing to use vulnerable action versions.

## Detection Example

```
PRTargetWorkflow.yml:1:1: dependabot.yaml does not exist. Without Dependabot, major version
updates (e.g., v3 -> v4) for GitHub Actions won't be automated. [dependabot-github-actions]
```

## Auto-Fix

sisakulint can auto-generate `.github/dependabot.yaml` using `-fix on`.

## Verdict: DETECTED

+++
title = 'github-actions-goat Verification Report'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 100
+++

# github-actions-goat Verification Report

## Overview

[github-actions-goat](https://github.com/step-security/github-actions-goat) is a deliberately vulnerable GitHub Actions CI/CD environment provided by StepSecurity. It reproduces threat scenarios based on the CISA/NSA CI/CD Security Guidance and serves as an educational project for learning defense strategies.

This report documents the results of static analysis performed by sisakulint on all 24 workflow files in the repository, evaluating detection coverage for each vulnerability scenario.

## Detection Rate Summary

| Category | Detected | Missed | Rate |
|---|---|---|---|
| Statically detectable scenarios (12) | 10 | 2 | **83%** |
| Runtime/operational scenarios (5) | 0 | 5 | 0% (out of scope by design) |
| **All scenarios (17)** | **10** | **7** | **59%** |

## Detection Statistics

- **Total findings**: 295
- **Files analyzed**: 24
- **Rules triggered**: 10 distinct rules

| Rule | Count | Description |
|---|---|---|
| `missing-timeout-minutes` | 134 | Missing timeout configuration |
| `commit-sha` | 72 | Actions not pinned to commit SHA |
| `artipacked` | 25 | Credential persistence in .git/config |
| `dependabot-github-actions` | 24 | Missing Dependabot configuration |
| `permissions` | 20 | Missing or overly broad permissions |
| `known-vulnerable-actions` | 8 | Actions with known CVEs/GHSAs |
| `self-hosted-runner` | 7 | Self-hosted runner risks |
| `dangerous-triggers-critical` | 1 | Dangerous privileged trigger |
| `untrusted-checkout` | 1 | Untrusted checkout in privileged context |

## Case Index

| # | Case | Status | Details |
|---|---|---|---|
| 1 | [Dangerous Triggers (pull_request_target)]({{< ref "case01-dangerous-triggers.md" >}}) | Detected | PRTargetWorkflow.yml |
| 2 | [TOCTOU Vulnerability]({{< ref "case02-toctou.md" >}}) | Detected | toc-tou.yml |
| 3 | [Supply Chain: Vulnerable Third-Party Actions]({{< ref "case03-vulnerable-actions.md" >}}) | Detected | tj-actions, changed-files |
| 4 | [Supply Chain: Unpinned Actions]({{< ref "case04-unpinned-actions.md" >}}) | Detected | All 24 files |
| 5 | [Overly Broad Permissions]({{< ref "case05-permissions.md" >}}) | Detected | 20 files |
| 6 | [Credential Persistence (Artipacked)]({{< ref "case06-artipacked.md" >}}) | Detected | 22 files |
| 7 | [Self-Hosted Runner Risks]({{< ref "case07-self-hosted-runners.md" >}}) | Detected | 7 files |
| 8 | [Missing Timeout]({{< ref "case08-timeout.md" >}}) | Detected | All 24 files |
| 9 | [Missing Dependabot]({{< ref "case09-dependabot.md" >}}) | Detected | All 24 files |
| 10 | [Code Injection via Action Output]({{< ref "case10-code-injection-output.md" >}}) | Not Detected | changed-files workflows |
| 11 | [Secret Exposure in Build Logs]({{< ref "case11-secret-in-log.md" >}}) | Not Detected | secret-in-build-log.yml |
| 12 | [Network Exfiltration (Runtime)]({{< ref "case12-runtime-network.md" >}}) | Out of Scope | exfiltration-demo workflows |
| 13 | [Build-Time File Tampering (Runtime)]({{< ref "case13-runtime-tampering.md" >}}) | Out of Scope | backdoor-demo workflows |

## Complementary Relationship: sisakulint and harden-runner

github-actions-goat is specifically designed to demonstrate StepSecurity's harden-runner, a runtime security tool. sisakulint is a static analysis tool, so runtime scenarios such as network filtering, file tampering detection, and DNS exfiltration prevention are out of scope by design.

The two tools are **complementary** — defense in depth is best achieved by combining static analysis (sisakulint) with runtime protection (harden-runner).

## Verification Workflows

All github-actions-goat workflow files used for verification are stored in `script/actions/goat-*.yml` and `script/actions/goat-*.yaml`.

## Verification Environment

- **sisakulint version**: main branch latest (2026-03-14)
- **github-actions-goat**: https://github.com/step-security/github-actions-goat (latest)
- **Date**: 2026-03-14

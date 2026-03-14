+++
title = 'Case 04: Supply Chain - Unpinned Actions'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 4
+++

# Case 04: Supply Chain - Unpinned Actions

## Target Files

All 24 workflow files (72 findings)

## Vulnerability Overview

Using tag references (`actions/checkout@v4`) in GitHub Actions makes workflows vulnerable to supply chain attacks if the tag is redirected to a malicious commit. Pinning to a commit SHA (`actions/checkout@b4ffde65f...`) ensures an immutable reference.

## Detection Example

```
PRTargetWorkflow.yml:15:9: the action ref in 'uses' for step 'Check out code' should be a
full length commit SHA for immutability and security. [commit-sha]
```

## Affected Actions

| Action | Version Used | File Count |
|---|---|---|
| `actions/checkout` | v3, v4 | 22 |
| `step-security/harden-runner` | v2 | 12 |
| `elgohr/Publish-Docker-Github-Action` | v5 | 8 |
| `actions/setup-node` | v3 | 5 |
| `martinbeentjes/npm-get-version-action` | v1.3.1 | 3 |
| `crazy-max/ghaction-github-status` | v4 | 3 |
| `madhead/semver-utils` | latest | 3 |
| `tj-actions/changed-files` | v35, v40 | 3 |
| `JasonEtco/create-an-issue` | v2 | 1 |

### Most Dangerous Case

`madhead/semver-utils@latest` uses the `latest` tag, always pointing to the most recent release. This is the most dangerous pattern — if the maintainer's account is compromised, the workflow is immediately affected.

## Auto-Fix

sisakulint can automatically convert tag references to commit SHAs using `-fix on` (requires GitHub API access; be aware of rate limits).

## Verdict: DETECTED

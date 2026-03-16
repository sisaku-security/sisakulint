+++
title = 'Case 06: Credential Persistence (Artipacked)'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 6
+++

# Case 06: Credential Persistence (Artipacked)

## Target Files

22 files (25 findings)

## Vulnerability Overview

`actions/checkout` persists authentication credentials in `.git/config` by default. If the workspace is uploaded using `actions/upload-artifact`, the authentication token in `.git/config` leaks (CVE-2023-51664, discovered by Palo Alto Unit42).

## Detection Example

```
PRTargetWorkflow.yml:15:9: [Medium] actions/checkout without 'persist-credentials: false'
at step "Check out code". Credentials are stored in .git/config. [artipacked]
```

## Recommended Fix

```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: false
```

## Auto-Fix

sisakulint can automatically add `persist-credentials: false` using `-fix on`.

## Verdict: DETECTED

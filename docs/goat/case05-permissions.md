+++
title = 'Case 05: Overly Broad Permissions'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 5
+++

# Case 05: Overly Broad Permissions

## Target Files

20 files (missing explicit `permissions` block)

## Vulnerability Overview

When the `permissions` block is omitted, the repository's default permissions apply. In many repositories, the default is read-write, granting workflows more access than necessary. If an attacker compromises the workflow, they gain write access to repository contents and access to secrets.

## Detection Example

```
PRTargetWorkflow.yml:1:1: workflow does not have explicit 'permissions' block. Without explicit
permissions, the workflow uses the default repository permissions which may be overly broad.
Add a 'permissions:' block to follow the principle of least privilege. [permissions]
```

## Files with Proper Permissions (Not Flagged)

These 4 files correctly set explicit permissions:

- `changed-files-vulnerability-with-hr.yml`: `permissions: { pull-requests: read }`
- `changed-files-vulnerability-without-hr.yml`: `permissions: { pull-requests: read }`
- `tj-actions-changed-files-incident.yaml`: `permissions: { pull-requests: read }`
- `toc-tou.yml`: `permissions: {}` (least privilege)

## Auto-Fix

sisakulint can automatically add `permissions: {}` using `-fix on`.

## Verdict: DETECTED

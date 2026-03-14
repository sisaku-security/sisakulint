+++
title = 'Case 10: Code Injection via Action Output'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 10
+++

# Case 10: Code Injection via Action Output

## Target Files

- `changed-files-vulnerability-without-hr.yml` → [`script/actions/goat-changed-files-vulnerability-without-hr.yml`](../../script/actions/goat-changed-files-vulnerability-without-hr.yml)
- `changed-files-vulnerability-with-hr.yml` → [`script/actions/goat-changed-files-vulnerability-with-hr.yml`](../../script/actions/goat-changed-files-vulnerability-with-hr.yml)
- `tj-actions-changed-files-incident.yaml` → [`script/actions/goat-tj-actions-changed-files-incident.yaml`](../../script/actions/goat-tj-actions-changed-files-incident.yaml)

## Vulnerability Overview

The output of `tj-actions/changed-files` (`steps.changed-files.outputs.all_changed_files`) is directly interpolated in a `run` step using `${{ }}`. An attacker can create a PR with specially crafted filenames to inject and execute arbitrary code.

```yaml
# VULNERABLE: action output directly interpolated
- name: List all changed files
  run: |
    for file in ${{ steps.changed-files.outputs.all_changed_files }}; do
      echo "$file was changed"
    done
```

## sisakulint Detection Status

### Indirect Detection

The `known-vulnerable-actions` rule detected the known vulnerabilities in `tj-actions/changed-files@v40` and `@v35` (see Case 03).

### Why Not Directly Detected

sisakulint's `code-injection` rule tracks known untrusted input contexts such as `github.event.pull_request.title`, `github.event.issue.body`, etc. However, it does not track indirect taint propagation from third-party action outputs (`steps.*.outputs.*`).

This is a fundamental limitation of static analysis — determining whether an action's output is derived from untrusted input requires analyzing the action's internal implementation, which is beyond workflow-level YAML analysis.

## Future Improvement Ideas

- Build a database of known dangerous action outputs
- Add a warning rule for `steps.*.outputs.*` usage in `${{ }}` within `run` steps

## Verdict: NOT DETECTED (indirectly detected via known-vulnerable-actions)

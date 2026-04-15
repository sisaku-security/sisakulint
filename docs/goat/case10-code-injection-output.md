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

### Direct Detection (code-injection rule via Phase 3 Known Tainted Actions)

The `code-injection` rule detects this pattern via the Phase 3 Known Tainted Actions database. `tj-actions/changed-files` is registered as a known tainted action because its file-list outputs (`all_changed_files`, `modified_files`, etc.) reflect PR filenames, which are attacker-controlled.

```
code injection (medium): "steps.changed-files.outputs.all_changed_files (tainted via PR filenames
(attacker-controlled via pull request))" is potentially untrusted. Avoid using it directly in
inline scripts. Instead, pass it through an environment variable.
```

### Additional Detection

The `known-vulnerable-actions` rule also detects known CVEs in `tj-actions/changed-files@v40` and `@v35` (GHSA-mrrh-fwg8-r2c3, GHSA-mcph-m25j-8j63).

## Verdict: DETECTED

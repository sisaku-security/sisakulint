+++
title = 'Case 11: Secret Exposure in Build Logs'
date = 2026-03-14T00:00:00+09:00
draft = false
weight = 11
+++

# Case 11: Secret Exposure in Build Logs

## Target File

- `secret-in-build-log.yml` → [`script/actions/goat-secret-in-build-log.yml`](../../script/actions/goat-secret-in-build-log.yml)

## Vulnerability Overview

A secret value is extracted via `jq`, stored in a shell variable, and then printed to stdout using `echo`. GitHub Actions automatically masks `secrets.*` values, but derived values (extracted via `jq` or other tools) are not masked, appearing in plaintext in build logs.

```yaml
- name: Extract and use GCP private key
  env:
    GCP_SERVICE_ACCOUNT_KEY: ${{ secrets.GCP_SERVICE_ACCOUNT_KEY }}
  run: |
    PRIVATE_KEY=$(echo $GCP_SERVICE_ACCOUNT_KEY | jq -r '.private_key')
    # This will appear in plaintext in build logs!
    echo "GCP Private Key: $PRIVATE_KEY"
```

## sisakulint Detection Status

### Gap in Prior Rules (Historical)

sisakulint's `secret-exfiltration` rule detected secret transmission via network commands (`curl`, `wget`, `nc`, etc.), but did not cover `echo` output to stdout.

The `unmasked-secret-exposure` rule detected unmasked secrets derived from `fromJson()` in GitHub Actions expressions, but did not track shell-level `jq` derivation.

The `secret-in-log` rule was added (Issue #388) to close this gap.

## Detection Implementation

The `secret-in-log` rule tracks taint propagation from `${{ secrets.* }}`-sourced
environment variables through shell variable assignments (including command
substitutions like `$(jq ...)`) and reports `echo`/`printf` calls that reference
any tainted variable. The auto-fix inserts `echo "::add-mask::$VAR"` before the
first use.

## Verdict: DETECTED

Detected by the `secret-in-log` rule (added in response to Issue #388).

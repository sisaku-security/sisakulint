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

### Why Not Detected

sisakulint's `secret-exfiltration` rule detects secret transmission via network commands (`curl`, `wget`, `nc`, etc.), but does not cover `echo` output to stdout.

The `unmasked-secret-exposure` rule detects unmasked secrets derived from `fromJson()` in GitHub Actions expressions, but does not track shell-level `jq` derivation.

## Future Improvement Ideas

- Detect `echo $SECRET_VAR` patterns in shell scripts
- Track `jq`-derived values from secrets environment variables

## Verdict: NOT DETECTED

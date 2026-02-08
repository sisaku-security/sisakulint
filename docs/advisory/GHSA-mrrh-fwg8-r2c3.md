# GHSA-mrrh-fwg8-r2c3

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2025-30066 |
| Affected Action | tj-actions/changed-files |
| Severity | High |
| CVSS Score | 8.6/10 |
| Vulnerability Type | Embedded Malicious Code (CWE-506) |
| Published | March 14-15, 2025 |
| Affected Repositories | Over 23,000 |

## Vulnerability Description

A supply chain attack compromised the `tj-actions/changed-files` GitHub Action between March 14-15, 2025, affecting over 23,000 repositories. Attackers retroactively modified version tags to reference a malicious commit that executed a Python script to extract secrets from the Runner Worker process memory and expose them in GitHub Actions logs.

**Attack Method:**
- Malicious commit: `0e58ed8671d6b60d0890c21b07f8835ace038e67`
- Compromised tags: `v1.0.0`, `v35.7.7-sec`, `v44.5.1`
- The malicious code downloaded and executed a Python script that "scanned memory for secrets, base64-encoded them, and logged them in the build logs"

**Impact:**
- Theft of CI/CD secrets (API keys, cloud credentials, SSH keys)
- Unauthorized access to source code and infrastructure
- Public exposure of credentials in repositories with public workflow logs

**EPSS Score:** 90.353% (100th percentile) - indicating very high probability of exploitation

**Additional Context:** This vulnerability is listed in CISA's Known Exploited Vulnerabilities Catalog, indicating active exploitation in the wild.

**Affected versions:** All versions ≤ 45.0.7
**Patched versions:** v46.0.1 (released after March 15, 2025)

## Vulnerable Pattern

```yaml
name: Vulnerable Pattern
on:
  pull_request:

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Vulnerable: v45 was compromised
      # Dumps secrets from memory to attacker server
      - uses: tj-actions/changed-files@v45
        with:
          files: |
            **/*.go
            **/*.ts

      - name: Process changed files
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          echo "Changed files: ${{ steps.changed-files.outputs.all_changed_files }}"
```

**Why this is vulnerable:**
- Version 45 contains malicious code
- Exfiltrates secrets from workflow memory
- Works even if secrets aren't explicitly passed to the action
- Affects all secrets available to the workflow

## Safe Pattern

```yaml
name: Safe Pattern
on:
  pull_request:

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Safe: Pinned to v44 (safe) or v46+ (patched)
      - uses: tj-actions/changed-files@a59f9d159fb5d5c1a3e5e2dcc51cb90f8b9b4c3e # v44
        with:
          files: |
            **/*.go
            **/*.ts

      - name: Process changed files
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: |
          echo "Changed files: ${{ steps.changed-files.outputs.all_changed_files }}"
```

**Why this is safe:**
- Pinned to commit SHA of safe version (v44 or earlier)
- Or use v46+ which removed malicious code
- Immutable commit SHA prevents automatic updates to v45

## sisakulint Detection Result

```
script/actions/advisory/GHSA-mrrh-fwg8-r2c3-vulnerable.yaml:19:9: Action 'tj-actions/changed-files@v45' has a known high severity vulnerability (GHSA-mrrh-fwg8-r2c3): tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs.. Upgrade to version 46.0.1 or later. See: https://github.com/advisories/GHSA-mrrh-fwg8-r2c3 [known-vulnerable-actions]
       19 👈|      - uses: tj-actions/changed-files@v45
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes |
| Yes | CommitShaRule | Yes |

**Detection successful!** sisakulint accurately detects this vulnerability using the `KnownVulnerableActionsRule`. The detection message is as follows:

```
Action 'tj-actions/changed-files@v45' has a known high severity vulnerability (GHSA-mrrh-fwg8-r2c3):
tj-actions changed-files through 45.0.7 allows remote attackers to discover secrets by reading actions logs.
Upgrade to version 46.0.1 or later.
```

**Detection Details:**
- `KnownVulnerableActionsRule`: Detects `tj-actions/changed-files@v45` from vulnerability database ✅
- `CommitShaRule`: Detects usage of mutable version tag ✅
- Auto-fix available: Update to safe version or pin to safe commit SHA

## Mitigation Recommendations

1. **Immediate action**: Replace v45 with v44 SHA or upgrade to v46+
2. **Rotate all secrets**: Assume all secrets in workflows using v45 were compromised
3. **Review audit logs**: Check for unauthorized access using exposed tokens
4. **Pin to commit SHAs**: Prevent automatic updates to compromised versions
5. **Enable Dependabot**: Monitor for security updates to actions
6. **Limit secret scope**: Only expose secrets to steps that need them
7. **Use environment protection**: Require manual approval for sensitive deployments

## References
- [GitHub Advisory: GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3)
- [tj-actions Security Advisory](https://github.com/tj-actions/changed-files/security/advisories/GHSA-mw4p-6x4p-x5m5)
- [Malicious Commit](https://github.com/tj-actions/changed-files/commit/0e58ed8671d6b60d0890c21b07f8835ace038e67)
- [Issue #2463](https://github.com/tj-actions/changed-files/issues/2463)
- [Issue #2464](https://github.com/tj-actions/changed-files/issues/2464)
- [Issue #2477](https://github.com/tj-actions/changed-files/issues/2477)
- [Release v46.0.1](https://github.com/tj-actions/changed-files/releases/tag/v46.0.1)
- [CVE-2025-30066](https://nvd.nist.gov/vuln/detail/CVE-2025-30066)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [sisakulint: KnownVulnerableActionsRule](../known_vulnerable_actions.md)
- [sisakulint: CommitShaRule](../commitsha.md)
- [GitHub: Security hardening for Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

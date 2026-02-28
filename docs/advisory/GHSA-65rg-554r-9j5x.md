# GHSA-65rg-554r-9j5x

## Summary

| Field | Value |
|-------|-------|
| CVE | CVE-2024-48908 |
| Affected Action | lycheeverse/lychee-action |
| Severity | Moderate (CVSS 6.9) |
| Vulnerability Type | Code Injection (CWE-94) |
| Published | 2025-01-29 |

## Vulnerability Description

The lycheeverse/lychee-action GitHub Action (versions < 2.0.2) contains a code injection vulnerability in the `lychee-setup` component affecting the `inputs.lycheeVersion` parameter. An attacker can inject arbitrary shell commands through the version string that are executed within the action's context.

**Technical Details:**
- CVSS v4 Score: 6.9/10 (CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N/E:U)
- CWE-94: Improper Control of Generation of Code (Code Injection)
- EPSS: 0.012% (1st percentile)
- The vulnerability exists in `action.yml` where `inputs.lycheeVersion` is directly interpolated into shell regex conditions

**Proof of Concept:**
```yaml
lycheeVersion: $(printenv >> $GITHUB_STEP_SUMMARY && echo "v0.16.1")
```

This example prints environment variables to the workflow summary, but attackers could execute arbitrary commands to compromise repository security while allowing the action to continue normally.

**The Fix (v2.0.2):**
The security patch moves GitHub Actions expressions to environment variables:
- Before: `if [[ '${{ inputs.lycheeVersion }}' =~ ^v0\.0|^v0\.1[0-5]\. ]]; then`
- After: `if [[ "${LYCHEE_VERSION}" =~ ^v0\.0|^v0\.1[0-5]\. ]]; then` with `env: LYCHEE_VERSION: ${{ inputs.lycheeVersion }}`

## Vulnerable Pattern

```yaml
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  link-check:
    runs-on: ubuntu-latest

    steps:
      - name: Link Checker
        uses: lycheeverse/lychee-action@v1.9.0
        with:
          # Attacker can inject: $(printenv >> $GITHUB_STEP_SUMMARY && echo "v0.16.1")
          lycheeVersion: ${{ github.event.inputs.lycheeVersion || 'v0.16.1' }}
          args: '--verbose --no-progress .'
```

**Attack Vector**: An attacker can trigger the workflow with:
- `lycheeVersion: $(printenv >> $GITHUB_STEP_SUMMARY && echo "v0.16.1")`
- This executes arbitrary commands in the workflow context

## sisakulint Detection Result

```
script/actions/advisory/GHSA-65rg-554r-9j5x-vulnerable.yaml:24:9: Action 'lycheeverse/lychee-action@v1.9.0' has a known medium severity vulnerability (GHSA-65rg-554r-9j5x): lychee link checking action affected by arbitrary code injection in composite action. Upgrade to version 2.0.2 or later. See: https://github.com/advisories/GHSA-65rg-554r-9j5x [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes - Exact match |
| Yes | CommitShaRule | Yes (for version pinning) |

**Detection Details:**
- `KnownVulnerableActionsRule` **directly detects this specific vulnerability** (GHSA-65rg-554r-9j5x) and recommends upgrading to patched version
- The rule identifies the vulnerable lychee-action version and provides remediation guidance
- Auto-fix available: Updates to safe version (v2.0.2 or later)

## Mitigation

1. **Use fixed version strings**: Avoid user-controlled input
   ```yaml
   with:
     lycheeVersion: 'v0.16.1'
     args: '--verbose --no-progress .'
   ```

2. **Validate version format**: Use regex validation in environment variables
   ```yaml
   env:
     LYCHEE_VERSION: ${{ github.event.inputs.lycheeVersion }}
   run: |
     if [[ "$LYCHEE_VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
       echo "Valid version: $LYCHEE_VERSION"
     else
       echo "Using default version: v0.16.1"
     fi
   ```

3. **Update to patched version**: Use lychee-action@v1.10.0 or later with security fixes

## References

- [GitHub Advisory](https://github.com/advisories/GHSA-65rg-554r-9j5x)
- [Repository Security Advisory](https://github.com/lycheeverse/lychee-action/security/advisories/GHSA-65rg-554r-9j5x)
- [Security Patch Commit](https://github.com/lycheeverse/lychee-action/commit/7cd0af4c74a61395d455af97419279d86aafaede)
- [lycheeverse/lychee-action Repository](https://github.com/lycheeverse/lychee-action)
- [sisakulint: Code Injection Rules](../codeinjection.md)
- [Sample Vulnerable Workflow](../../script/actions/advisory/GHSA-65rg-554r-9j5x-vulnerable.yaml)
- [Sample Safe Workflow](../../script/actions/advisory/GHSA-65rg-554r-9j5x-safe.yaml)

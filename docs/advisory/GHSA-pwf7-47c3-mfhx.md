# GHSA-pwf7-47c3-mfhx

## Summary

| Field | Value |
|-------|-------|
| CVE | Not assigned |
| Affected Action | j178/prek-action |
| Severity | Critical (CVSS 10.0) |
| Vulnerability Type | Code Injection (CWE-94) |
| Published | 2025-01-29 |

## Vulnerability Description

The j178/prek-action GitHub Action (versions ≤ v1.0.5) contains a critical code injection vulnerability affecting three input parameters: `inputs.prek-version`, `inputs.extra_args`, and `inputs.extra-args`. Attackers can inject arbitrary shell commands that execute in the action's context with access to secrets and repository write permissions.

**Technical Details:**
- The vulnerability exists in the composite action's `action.yml` file where user inputs are directly interpolated into shell commands without sanitization
- CVSS Score: 10.0/10 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)
- Attack Vector: Network-based, requires low privileges (ability to trigger workflows)
- Scope Change: Yes - impacts resources beyond the component's security scope

**Proof of Concept:**
The advisory demonstrates a sophisticated exploit that:
1. Dumps all environment variables to the workflow summary via `printenv >> $GITHUB_STEP_SUMMARY`
2. Extracts secrets character-by-character to bypass detection: `${MY_SECRET:0:1}a${MY_SECRET:1}`
3. Allows the action to continue normally, potentially evading detection

**The Fix (v1.0.6):**
The patch implements three security measures:
1. Input validation using whitelist regex: `^[a-zA-Z0-9._/\\- ]+$`
2. Moving user inputs to environment variables instead of direct substitution
3. Proper quoting around all variable expansions

## Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  setup-prek:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write

    steps:
      - uses: j178/prek-action@v0.2.0
        with:
          # Attacker can inject: $(printenv >> $GITHUB_STEP_SUMMARY && echo "0.2.2")
          prek-version: ${{ github.event.inputs.prek-version || '0.2.2' }}
          extra_args: ${{ github.event.inputs.extra_args }}
```

**Attack Vector**: An attacker can trigger the workflow with crafted input:
- `prek-version: $(printenv >> $GITHUB_STEP_SUMMARY && echo "0.2.2")`
- This executes `printenv` and leaks all environment variables including secrets

## sisakulint Detection Result

```
script/actions/advisory/GHSA-pwf7-47c3-mfhx-vulnerable.yaml:26:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 12). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
script/actions/advisory/GHSA-pwf7-47c3-mfhx-vulnerable.yaml:29:9: Action 'j178/prek-action@v0.2.0' has a known critical severity vulnerability (GHSA-pwf7-47c3-mfhx): j178/prek-action vulnerable to arbitrary code injection in composite action. Upgrade to version 1.0.6 or later. See: https://github.com/advisories/GHSA-pwf7-47c3-mfhx [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes |
| Yes | UntrustedCheckoutRule | Yes |

sisakulint successfully detects this vulnerability through the KnownVulnerableActionsRule, which identifies the specific vulnerable version (v0.2.0) of j178/prek-action and recommends upgrading to version 1.0.6 or later. Additionally, it detects the untrusted checkout pattern and other security issues in the workflow.

## Mitigation

1. **Use fixed version strings**: Avoid dynamic input interpolation
   ```yaml
   with:
     prek-version: '0.2.2'
     extra_args: '--verbose'
   ```

2. **Validate inputs**: Use environment variables and validate format
   ```yaml
   env:
     PREK_VERSION: ${{ github.event.inputs.prek-version }}
   run: |
     if [[ "$PREK_VERSION" =~ ^[a-zA-Z0-9.\-]+$ ]]; then
       echo "Valid version: $PREK_VERSION"
     else
       echo "Invalid version format"
       exit 1
     fi
   ```

3. **Update to patched version**: Use the latest version of prek-action with security fixes

## References

- [GitHub Advisory](https://github.com/advisories/GHSA-pwf7-47c3-mfhx)
- [Repository Security Advisory](https://github.com/j178/prek-action/security/advisories/GHSA-pwf7-47c3-mfhx)
- [Security Patch Commit](https://github.com/j178/prek-action/commit/6b7c6ef5c3875c766893b881b40773cd5605bde3)
- [j178/prek-action Repository](https://github.com/j178/prek-action)
- [sisakulint: Code Injection Rules](../codeinjection.md)
- [sisakulint: Argument Injection Rules](../argumentinjection.md)
- [Sample Vulnerable Workflow](../../script/actions/advisory/GHSA-pwf7-47c3-mfhx-vulnerable.yaml)
- [Sample Safe Workflow](../../script/actions/advisory/GHSA-pwf7-47c3-mfhx-safe.yaml)

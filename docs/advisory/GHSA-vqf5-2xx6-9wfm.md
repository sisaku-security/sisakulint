# GHSA-vqf5-2xx6-9wfm: GitHub PAT Written to Debug Artifacts

## Advisory Information

- **Advisory ID**: GHSA-vqf5-2xx6-9wfm
- **Package**: github/codeql-action (GitHub Action)
- **Severity**: High (CVSS 7.1)
- **CVE ID**: CVE-2025-24362
- **CWE IDs**:
  - CWE-215 (Insertion of Sensitive Information Into Debugging Code)
  - CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Versions**:
  - CodeQL Action: 3.26.11 - 3.28.2, 2.26.11 - 2.x.x
  - CodeQL CLI: 2.9.2 - 2.20.2
- **Patched Versions**:
  - CodeQL Action: 3.28.3+
  - CodeQL CLI: 2.20.3+
- **Published**: January 24, 2025
- **URL**: https://github.com/advisories/GHSA-vqf5-2xx6-9wfm

## Vulnerability Description

In some circumstances, debug artifacts uploaded by the CodeQL Action after a failed code scanning workflow run may contain the environment variables from the workflow run, including any secrets that were exposed as environment variables to the workflow.

The root cause: **the CodeQL Kotlin extractor logs all environment variables by default** into an intermediate file during the process of creating a CodeQL database for Kotlin code. These intermediate files are normally deleted upon successful database finalization but remain in debug artifacts when workflows fail prematurely.

## Impact

Attackers with repository read access could:
1. Access exposed secrets from environment variables
2. Obtain valid `GITHUB_TOKEN` (valid until job completion or 24 hours)
3. Gain unauthorized repository access with workflow permissions
4. Exfiltrate custom secrets exposed as environment variables

### Token Validity Window

- **Actions v4 library** (versions 3.26.11+): Token valid during artifact upload
- **Other workflows**: Token revoked before artifact upload
- Custom secrets remain valid until manually revoked

## Conditions Required for Exploitation

All conditions must be satisfied:

### Required Conditions (All Environments)
1. ✅ Java/Kotlin language scanning enabled
2. ✅ Repository contains Kotlin source code
3. ✅ Debug artifacts enabled
4. ✅ Workflow fails before database finalization
5. ✅ Affected CodeQL versions in use

### Additional Conditions (For GITHUB_TOKEN Exposure)
6. ✅ CodeQL Action versions 3.26.11-3.28.2 or 2.26.11-2.x.x
7. ✅ GitHub.com or GitHub Enterprise Cloud only

## Vulnerable Code Pattern

```yaml
name: Vulnerable CodeQL Analysis

on:
  push:
    branches: [main]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      # VULNERABLE: CodeQL Action 3.26.11 - 3.28.2
      # with CodeQL CLI 2.9.2 - 2.20.2
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3.26.11
        with:
          languages: java  # Includes Kotlin
          debug: true      # Debug artifacts enabled

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3.26.11

      # If this fails, debug artifacts may contain environment variables
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3.26.11
        env:
          CUSTOM_SECRET: ${{ secrets.CUSTOM_SECRET }}
```

### What Gets Exposed

When the workflow fails during Kotlin code analysis, debug artifacts may contain:

```
# Intermediate file created by Kotlin extractor
Environment Variables:
GITHUB_TOKEN=ghs_16C7e42F292c6912E4b1c8F...
CUSTOM_SECRET=super_secret_value
CI=true
RUNNER_OS=Linux
...
```

These intermediate files are:
- Created during CodeQL database generation
- Normally deleted upon successful completion
- Preserved in debug artifacts when workflow fails
- Accessible to anyone with repository read permissions

## Safe Implementation

```yaml
name: Safe CodeQL Analysis

on:
  push:
    branches: [main]

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      # SAFE: CodeQL Action 3.28.3+ with patched CLI
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3.28.3
        with:
          languages: java  # Includes Kotlin
          debug: true      # Safe in patched version

      - name: Autobuild
        uses: github/codeql-action/autobuild@v3.28.3

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3.28.3
        env:
          CUSTOM_SECRET: ${{ secrets.CUSTOM_SECRET }}
```

## Detection by sisakulint

### Detectability Status: ❌ NOT DIRECTLY DETECTABLE

This vulnerability is **NOT detectable** by static analysis because:

1. **Internal Implementation**: The vulnerability is in CodeQL CLI's Kotlin extractor, not in the workflow YAML
2. **Conditional Behavior**: Only occurs when workflow fails during specific phase
3. **Debug Artifact Content**: Static analysis cannot inspect artifact contents
4. **Runtime Dependency**: Depends on CodeQL CLI version, which is dynamically downloaded
5. **Language-Specific**: Requires presence of Kotlin code in repository

### Indirect Detection via Advisory Database

sisakulint implements **KnownVulnerableActionsRule** to detect vulnerable versions:

```bash
$ sisakulint script/actions/advisory/GHSA-vqf5-2xx6-9wfm-vulnerable.yaml
```

Actual output:
```
script/actions/advisory/GHSA-vqf5-2xx6-9wfm-vulnerable.yaml:33:9: Action 'github/codeql-action/init@v3.26.11' has a known high severity vulnerability (GHSA-vqf5-2xx6-9wfm): GitHub PAT written to debug artifacts. Upgrade to version 3.28.3 or later. See: https://github.com/advisories/GHSA-vqf5-2xx6-9wfm [known-vulnerable-actions]
script/actions/advisory/GHSA-vqf5-2xx6-9wfm-vulnerable.yaml:39:9: Action 'github/codeql-action/autobuild@v3.26.11' has a known high severity vulnerability (GHSA-vqf5-2xx6-9wfm): GitHub PAT written to debug artifacts. Upgrade to version 3.28.3 or later. See: https://github.com/advisories/GHSA-vqf5-2xx6-9wfm [known-vulnerable-actions]
script/actions/advisory/GHSA-vqf5-2xx6-9wfm-vulnerable.yaml:43:9: Action 'github/codeql-action/analyze@v3.26.11' has a known high severity vulnerability (GHSA-vqf5-2xx6-9wfm): GitHub PAT written to debug artifacts. Upgrade to version 3.28.3 or later. See: https://github.com/advisories/GHSA-vqf5-2xx6-9wfm [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes |

sisakulint successfully detects all three vulnerable CodeQL action versions (init, autobuild, analyze) at lines 33, 39, and 43, identifying them as having the known vulnerability GHSA-vqf5-2xx6-9wfm and recommending upgrade to version 3.28.3 or later.

### Enhanced Detection Possibilities

sisakulint could provide additional context when:
1. Detecting vulnerable CodeQL Action versions
2. AND `debug: true` is present
3. AND `languages` includes `java` (which includes Kotlin)

### Current Rule Coverage

- **KnownVulnerableActionsRule**: Could detect if advisory database includes this CVE ⚠️
- **CommitShaRule**: Recommends SHA pinning ✅
- **PermissionsRule**: Could recommend minimal permissions ✅

## Mitigation Recommendations

### Immediate Actions

1. **Upgrade CodeQL Action**
   ```yaml
   # Update all CodeQL action references
   - uses: github/codeql-action/init@v3.28.3
   - uses: github/codeql-action/autobuild@v3.28.3
   - uses: github/codeql-action/analyze@v3.28.3
   ```

2. **Update CodeQL CLI** (if using custom CLI)
   ```bash
   # Install patched CLI version
   wget https://github.com/github/codeql-cli-binaries/releases/download/v2.20.3/codeql-linux64.zip
   ```

3. **Audit Debug Artifacts**
   ```bash
   # List workflow runs with failures
   gh run list --workflow=codeql-analysis.yml --status=failure --limit=50

   # Download and inspect debug artifacts
   gh run download <run-id> --name codeql-debug
   ```
   - Check for environment variable exposure
   - Verify if artifacts were accessed by unauthorized users
   - Review access logs for anomalies

4. **Revoke Exposed Secrets**
   - Rotate any custom secrets that may have been exposed
   - Review audit logs for unauthorized access using leaked credentials
   - For `GITHUB_TOKEN`: Review repository activity during token validity window

### Long-term Hardening

1. **Pin Actions by Commit SHA**
   ```yaml
   # Pin to specific commit for v3.28.3
   - uses: github/codeql-action/init@<commit-sha-for-v3.28.3>
   ```

2. **Minimize Environment Variable Exposure**
   ```yaml
   # Only expose secrets to steps that need them
   - name: Perform CodeQL Analysis
     uses: github/codeql-action/analyze@v3.28.3
     # Don't expose unnecessary secrets
   ```

3. **Disable Debug Mode in Production**
   ```yaml
   # Only enable debug mode when troubleshooting
   - name: Initialize CodeQL
     uses: github/codeql-action/init@v3.28.3
     with:
       languages: java
       # debug: true  # Comment out for production
   ```

4. **Implement Secret Scanning**
   - Enable GitHub Secret Scanning for repository
   - Add custom patterns for application-specific secrets
   - Monitor alerts for exposed credentials

5. **Automated Dependency Updates**
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "github-actions"
       directory: "/"
       schedule:
         interval: "weekly"
   ```

## Risk Assessment

### Likelihood
- **Low to Medium**: Requires specific conditions (Kotlin code, debug enabled, failure at specific point)
- **Higher for Kotlin Projects**: Projects with Kotlin code are at higher risk
- **Debug Mode Increases Risk**: Debug artifacts must be enabled

### Impact
- **High**: Full secret exposure if conditions are met
- **Repository Compromise**: Valid tokens enable unauthorized access
- **Persistent Secrets**: Custom secrets remain valid until revoked

## Affected Environments

- ✅ **GitHub.com**: Affected for GITHUB_TOKEN exposure
- ✅ **GitHub Enterprise Cloud**: Affected for GITHUB_TOKEN exposure
- ⚠️ **GitHub Enterprise Server**: Custom secrets may be exposed, but GITHUB_TOKEN handling differs

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-vqf5-2xx6-9wfm
- Repository: https://github.com/github/codeql-action
- Repository Security Advisory: https://github.com/github/codeql-action/security/advisories/GHSA-vqf5-2xx6-9wfm
- Related CLI Advisory: https://github.com/github/codeql-cli-binaries/security/advisories/GHSA-gqh3-9prg-j95m
- Patch Commit: https://github.com/github/codeql-action/commit/519de26711ecad48bde264c51e414658a82ef3fa
- PR Introducing Issue: https://github.com/github/codeql-action/pull/1074
- PR Enabling Token Exposure: https://github.com/github/codeql-action/pull/2482

### External References
- CVE-2025-24362: https://nvd.nist.gov/vuln/detail/CVE-2025-24362
- CWE-215: Insertion of Sensitive Information Into Debugging Code
- CWE-532: Insertion of Sensitive Information into Log File
- Debug Artifacts Documentation: https://docs.github.com/en/code-security/code-scanning/troubleshooting-code-scanning/logs-not-detailed-enough
- External Analysis: https://www.praetorian.com/blog/codeqleaked-public-secrets-exposure-leads-to-supply-chain-attack-on-github-codeql/
- Hacker News Discussion: https://news.ycombinator.com/item?id=43527044

## Patches Applied

### CodeQL Action 3.28.3
- **Fix**: "No longer uploads database artifacts in debug mode"
- **Rationale**: Prevents exposure of intermediate files containing environment variables

### CodeQL CLI 2.20.3
- **Fix**: "Database creation for all languages no longer logs the complete environment by default"
- **Rationale**: Eliminates root cause by not logging environment variables

## Timeline

- **Discovered**: Late 2024
- **Disclosed**: January 24, 2025
- **CVE Assigned**: CVE-2025-24362
- **CodeQL Action Patched**: Version 3.28.3
- **CodeQL CLI Patched**: Version 2.20.3

## Lessons Learned

1. **Debug Modes are High-Risk**: Debug artifacts can expose sensitive information
2. **Intermediate Files Can Persist**: Failed workflows may leave sensitive data in artifacts
3. **Environment Variables = Secrets**: All environment variables should be treated as potentially sensitive
4. **Language-Specific Risks**: Different language extractors have different behaviors
5. **Cleanup is Critical**: Proper cleanup must occur even when workflows fail
6. **Artifact Access Control**: Debug artifacts should have restricted access

## Similar Vulnerabilities

- Debug logging vulnerabilities are common in CI/CD tools
- Environment variable leakage is a persistent issue across platforms
- Intermediate file exposure affects multiple code analysis tools

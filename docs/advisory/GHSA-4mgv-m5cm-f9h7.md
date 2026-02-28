# GHSA-4mgv-m5cm-f9h7: Multi-Line Secrets Not Properly Masked

## Advisory Information

- **Advisory ID**: GHSA-4mgv-m5cm-f9h7
- **Package**: hashicorp/vault-action (GitHub Action)
- **Severity**: High (CVSS 7.5)
- **CVE ID**: CVE-2021-32074
- **CWE ID**: CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Versions**: < 2.2.0
- **Patched Version**: 2.2.0
- **Published**: 2021
- **URL**: https://github.com/advisories/GHSA-4mgv-m5cm-f9h7

## Vulnerability Description

The HashiCorp `vault-action` had a critical flaw where **multi-line secrets were not correctly masked** in vault-action output. The implementation did not correctly handle the marking of multi-line variables, allowing attackers to obtain sensitive information from log files because multi-line secrets weren't properly registered with GitHub Actions' log masking feature.

When secrets containing line breaks were retrieved from Vault and set as GitHub Actions output variables, the action failed to process each line individually for masking, resulting in **only the first line being hidden** while subsequent lines appeared in plaintext in workflow logs.

## Impact

This vulnerability affects secrets that commonly span multiple lines:
- **Private Keys**: RSA, ECDSA, Ed25519 keys
- **Certificates**: X.509 certificates, certificate chains
- **Configuration Files**: Multi-line JSON, YAML, or other config data
- **License Keys**: Some license keys with embedded newlines

Any workflow using this action with multi-line secrets from Vault has potentially exposed those secrets in workflow logs, accessible to anyone with repository read permissions (including public repositories).

## Vulnerable Code Pattern

```yaml
name: Vulnerable Vault Secrets

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # VULNERABLE: Version < 2.2.0 does not mask multi-line secrets properly
      - name: Get Secrets from Vault
        uses: hashicorp/vault-action@v2.1.0
        with:
          url: ${{ secrets.VAULT_ADDR }}
          token: ${{ secrets.VAULT_TOKEN }}
          secrets: |
            secret/data/prod/app private_key | PRIVATE_KEY ;
            secret/data/prod/app certificate | CERTIFICATE

      # Multi-line secrets are partially exposed
      - name: Use Secrets
        run: |
          echo "$PRIVATE_KEY" | head -5
```

### Example Log Output (Vulnerable)

```
Run echo "$PRIVATE_KEY" | head -5
***                              # First line masked
MIIEvQIBADANBgkqhkiG9w0BAQEF   # EXPOSED
AASCBKcwggSjAgEAAoIBAQC7V    # EXPOSED
3gFZJ8P9k2LqJ1vHxYz5rQxYw    # EXPOSED
...                              # EXPOSED
```

Only the first line is masked (shown as `***`), but all subsequent lines appear in plaintext.

## Safe Implementation

```yaml
name: Safe Vault Secrets

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # SAFE: Version 2.2.0+ properly masks all lines
      - name: Get Secrets from Vault
        uses: hashicorp/vault-action@v2.2.0
        with:
          url: ${{ secrets.VAULT_ADDR }}
          token: ${{ secrets.VAULT_TOKEN }}
          secrets: |
            secret/data/prod/app private_key | PRIVATE_KEY ;
            secret/data/prod/app certificate | CERTIFICATE

      - name: Use Secrets
        run: |
          echo "$PRIVATE_KEY" | head -5
```

### Example Log Output (Safe)

```
Run echo "$PRIVATE_KEY" | head -5
***                              # All lines properly masked
***
***
***
***
```

All lines are masked correctly.

## Detection in sisakulint

### Detectability Status: ❌ NOT DIRECTLY DETECTABLE

This vulnerability is **NOT detectable** by static analysis because:

1. **Runtime Masking Behavior**: The vulnerability is in how the action registers secrets with GitHub Actions' masking system
2. **Action Internal Implementation**: The masking logic is inside the action's code, not visible in YAML
3. **Content-Dependent**: Depends on whether secrets from Vault contain newlines (unknowable from workflow YAML)
4. **No Syntactic Markers**: The workflow syntax is correct and gives no indication of the problem

### Detection Result

sisakulint **successfully detects** this vulnerability via the **KnownVulnerableActionsRule**:

```
script/actions/advisory/GHSA-4mgv-m5cm-f9h7-vulnerable.yaml:25:9: Action 'hashicorp/vault-action@v2.1.0' has a known high severity vulnerability (GHSA-4mgv-m5cm-f9h7): Vault GitHub Action did not correctly mask multi-line secrets in output. Upgrade to version 2.2.0 or later. See: https://github.com/advisories/GHSA-4mgv-m5cm-f9h7 [known-vulnerable-actions]
```

### Analysis

| Expected | Detected | Rule |
|----------|----------|------|
| Multi-line secrets not masked | Yes | known-vulnerable-actions |

sisakulint detected this vulnerability through the advisory database. While direct static analysis cannot detect this issue, matching against the known vulnerability database allows warning about the use of this specific version.

### Current Rule Coverage

- **KnownVulnerableActionsRule**: Detection via advisory database ✅
- **CommitShaRule**: Recommends SHA pinning (general best practice) ✅

## Mitigation Recommendations

### Immediate Actions

1. **Upgrade to Patched Version**
   ```yaml
   # Update vault-action reference
   - uses: hashicorp/vault-action@v2.2.0  # or later
   ```

2. **Audit Historical Logs**
   ```bash
   # List workflow runs that used vulnerable versions
   gh run list --workflow=deploy.yml --limit=100
   ```
   - Review logs from runs using versions < 2.2.0
   - Check if multi-line secrets were retrieved
   - Verify if logs were accessed by unauthorized users

3. **Rotate Exposed Secrets**
   - **Private Keys**: Generate new key pairs, update certificates
   - **API Keys**: Regenerate through provider interface
   - **Certificates**: Reissue from certificate authority
   - **Configuration Secrets**: Update in Vault and dependent systems

4. **Review Access Logs**
   - Check Vault audit logs for unauthorized access
   - Review GitHub repository access logs
   - Monitor for suspicious activity using potentially compromised credentials

### Long-term Hardening

1. **Pin Actions by Commit SHA**
   ```yaml
   # Pin to specific commit for v2.2.0
   - uses: hashicorp/vault-action@3526e1be65cf8faf42d6088bc5da8bff596c718a
   ```

2. **Implement Secret Rotation**
   - Automate regular secret rotation in Vault
   - Use dynamic secrets where possible
   - Set short TTLs for sensitive credentials

3. **Minimize Secret Exposure**
   ```yaml
   # Only retrieve secrets in steps that need them
   - name: Deploy Application
     env:
       PRIVATE_KEY: ${{ steps.vault.outputs.PRIVATE_KEY }}
     run: |
       # Use secret only in this step
   ```

4. **Use File-Based Secrets** (when appropriate)
   ```yaml
   - name: Write Secret to File
     run: |
       echo "$PRIVATE_KEY" > /tmp/key.pem
       chmod 600 /tmp/key.pem
     env:
       PRIVATE_KEY: ${{ steps.vault.outputs.PRIVATE_KEY }}

   - name: Use Secret File
     run: |
       ssh -i /tmp/key.pem user@host

   - name: Cleanup
     if: always()
     run: rm -f /tmp/key.pem
   ```

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

### CVSS v4 Metrics
- **Attack Vector**: Network (remote access to logs)
- **Attack Complexity**: Low (simply view logs)
- **Privileges Required**: None (for public repos)
- **User Interaction**: None
- **Confidentiality Impact**: High (full secret exposure)

### Likelihood
- **High**: Trivial to exploit (read public logs)
- **Persistent**: Historical logs remain accessible
- **Widespread**: Affects all workflows using multi-line secrets

### Impact
- **Complete Secret Compromise**: Private keys, certificates fully exposed
- **System Access**: SSH keys enable unauthorized server access
- **Man-in-the-Middle**: Exposed certificates enable MITM attacks
- **Persistent Access**: Long-lived credentials remain valid until rotated

## Technical Details

### GitHub Actions Masking Mechanism

GitHub Actions uses `::add-mask::` to register secrets:
```
::add-mask::secret_value
```

**Vulnerable Implementation** (< 2.2.0):
```javascript
// Only registers the entire multi-line string as one mask
core.setSecret(multiLineSecret);
// Result: Only the complete string is masked, not individual lines
```

**Fixed Implementation** (>= 2.2.0):
```javascript
// Splits multi-line secrets and registers each line
const lines = multiLineSecret.split('\n');
lines.forEach(line => {
  if (line.trim()) {
    core.setSecret(line);
  }
});
// Result: Each line is individually masked
```

### Why This Matters

GitHub's masking looks for exact matches. If only the complete multi-line string is registered, partial matches (individual lines) won't be caught.

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-4mgv-m5cm-f9h7
- Repository: https://github.com/hashicorp/vault-action
- Patch Commit: https://github.com/hashicorp/vault-action/commit/3526e1be65cf8faf42d6088bc5da8bff596c718a
- Issue #205: https://github.com/hashicorp/vault-action/issues/205
- Pull Request #208: https://github.com/hashicorp/vault-action/pull/208
- Changelog: https://github.com/hashicorp/vault-action/blob/master/CHANGELOG.md

### External References
- CVE-2021-32074: https://nvd.nist.gov/vuln/detail/CVE-2021-32074
- CWE-532: Insertion of Sensitive Information into Log File
- HashiCorp Security Advisory: https://discuss.hashicorp.com/t/hcsec-2021-13-vault-github-action-did-not-correctly-mask-multi-line-secrets-in-output/24128
- HCSEC-2021-13

### Credits
- Analysts: @tdunlap607, @Gentoli

## Timeline

- **Discovered**: 2021
- **CVE Assigned**: CVE-2021-32074
- **Disclosed**: 2021 (HCSEC-2021-13)
- **Patched**: Version 2.2.0 (commit 3526e1b)
- **Public Advisory**: 2021

## Lessons Learned

1. **Multi-Line Secrets are Common**: Private keys, certificates often span multiple lines
2. **Masking Must Handle All Formats**: Secret masking must account for multi-line content
3. **Test Edge Cases**: Security features must be tested with realistic secret formats
4. **Line-by-Line Registration**: Multi-line secrets should be split and masked individually
5. **Default Assume Compromise**: When in doubt, rotate potentially exposed credentials

## Similar Vulnerabilities

Multi-line secret masking issues have affected multiple GitHub Actions:
- Pattern: Actions that retrieve and output multi-line secrets
- Common in: Vault, secrets management, certificate handling actions
- Best practice: Always split and mask multi-line content line-by-line

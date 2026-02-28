# GHSA-mj96-mh85-r574: Token Leakage in Job Output Logs

## Advisory Information

- **Advisory ID**: GHSA-mj96-mh85-r574
- **Package**: buildalon/setup-steamcmd (GitHub Action)
- **Severity**: High (CVSS 8.7)
- **CVE ID**: None assigned
- **CWE ID**: CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Versions**: < 1.1.0
- **Patched Version**: 1.1.0
- **Published**: 2024
- **URL**: https://github.com/advisories/GHSA-mj96-mh85-r574

## Vulnerability Description

The `buildalon/setup-steamcmd` GitHub Action (versions < 1.1.0) exposes Steam authentication tokens in public job logs through its post-job cleanup phase. The action prints the complete contents of `config/config.vdf`, which contains saved authentication tokens that provide full account access on other machines. Additionally, `userdata/$user_id$/config/localconfig.vdf` may contain sensitive user configuration data.

**Technical Root Cause:** The action's logging mechanism in `src/logging.ts` outputs these configuration files during post-job cleanup without any sanitization or filtering. The `config.vdf` file contains authentication tokens in the `ConnectCache` section that remain valid for extended periods, and the action inadvertently exposes this sensitive data in workflow logs visible to anyone with a GitHub account (for public repositories).

**Attack Impact:**
- **Full Account Access**: Extracted tokens provide complete Steam account access from any machine
- **Public Exposure**: Job logs in public repositories are accessible to all GitHub users
- **Persistent Validity**: Tokens remain valid until explicitly revoked
- **Historical Vulnerability**: All previous workflow runs with vulnerable versions have exposed credentials

This vulnerability is identical to **GHSA-c5qx-p38x-qf5w** in the `RageAgainstThePixel/setup-steamcmd` action, indicating a common pattern of post-job logging vulnerabilities in Steam-related GitHub Actions.

## Impact

Any public repository using this action with Steam credentials has leaked valid authentication tokens in their workflow logs. Since GitHub Actions logs are publicly accessible for public repositories, attackers can retrieve these tokens and gain unauthorized access to Steam accounts.

### CVSS v4 Metrics
- **Attack Vector**: Network (remote exploitation)
- **Attack Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: None
- **Confidentiality Impact**: High

## Vulnerable Code Pattern

```yaml
name: Vulnerable buildalon SteamCMD Setup

on:
  push:
    branches: [main]

jobs:
  deploy-workshop:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # VULNERABLE: Versions < 1.1.0 log config.vdf in post-job
      - name: Setup SteamCMD
        uses: buildalon/setup-steamcmd@v1.0.0

      - name: Authenticate with Steam
        run: |
          steamcmd +login ${{ secrets.STEAM_USERNAME }} ${{ secrets.STEAM_PASSWORD }} +quit
```

### What Gets Exposed

The post-job output includes:
- **config/config.vdf**: Contains `ConnectCache` with authentication tokens
- **userdata/$user_id$/config/localconfig.vdf**: May contain additional sensitive user configuration

Example token structure:
```
"InstallConfigStore"
{
    "Software"
    {
        "Valve"
        {
            "Steam"
            {
                "ConnectCache"
                {
                    "XXXXXX"
                    {
                        "token"  "BASE64_AUTH_TOKEN_HERE"
                    }
                }
            }
        }
    }
}
```

## Safe Implementation

```yaml
name: Safe buildalon SteamCMD Setup

on:
  push:
    branches: [main]

jobs:
  deploy-workshop:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # SAFE: Version 1.1.0+ does not log sensitive config files
      - name: Setup SteamCMD
        uses: buildalon/setup-steamcmd@v1.1.0

      - name: Authenticate with Steam
        run: |
          steamcmd +login ${{ secrets.STEAM_USERNAME }} ${{ secrets.STEAM_PASSWORD }} +quit
```

## Detection by sisakulint

### Detection Result

```
script/actions/advisory/GHSA-mj96-mh85-r574-vulnerable.yaml:23:9: Action 'buildalon/setup-steamcmd@v1.0.0' has a known high severity vulnerability (GHSA-mj96-mh85-r574): buildalon/setup-steamcmd leaked authentication token in job output logs. Upgrade to version 1.1.0 or later. See: https://github.com/advisories/GHSA-mj96-mh85-r574 [known-vulnerable-actions]
       23 👈|      - name: Setup SteamCMD
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes |

**Detection successful!** sisakulint accurately detects this vulnerability using the `KnownVulnerableActionsRule`. The detection message is as follows:

```
Action 'buildalon/setup-steamcmd@v1.0.0' has a known high severity vulnerability (GHSA-mj96-mh85-r574):
buildalon/setup-steamcmd leaked authentication token in job output logs.
Upgrade to version 1.1.0 or later.
```

### Detectability Status: ✅ DETECTED

While this vulnerability cannot be detected directly through static analysis, sisakulint detects it from the advisory database using the **KnownVulnerableActionsRule**.

1. **Post-Job Runtime Behavior**: Occurs during post-job cleanup, invisible from workflow YAML
2. **Action Internal Implementation**: Logging is implemented inside the action, undetectable via YAML parsing
3. **Advisory Database Detection**: sisakulint uses the GitHub Security Advisories database to detect known vulnerable actions

### Current Rule Coverage

- **KnownVulnerableActionsRule**: Detects from advisory database ✅
- **CommitShaRule**: Recommends commit SHA pinning ✅
- **ActionListRule**: Can block if configured ⚠️

## Mitigation Recommendations

### Immediate Actions

1. **Upgrade to Patched Version**
   ```yaml
   - uses: buildalon/setup-steamcmd@v1.1.0  # or later
   ```

2. **Revoke Exposed Credentials**
   - Change Steam account passwords immediately
   - Sign out all active sessions
   - Revoke any Steam API keys
   - Enable Steam Guard two-factor authentication

3. **Audit Workflow Logs**
   ```bash
   # Search for exposed credentials in historical logs
   gh run list --workflow=deploy.yml --limit=100
   ```
   - Review all runs using vulnerable versions
   - Check if logs were accessed by unauthorized users
   - Consider deleting historical runs if possible

### Long-term Hardening

1. **Pin Actions by Commit SHA**
   ```yaml
   - uses: buildalon/setup-steamcmd@c330196  # v1.1.0
   ```

2. **Automated Dependency Updates**
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "github-actions"
       directory: "/"
       schedule:
         interval: "weekly"
       labels:
         - "dependencies"
         - "security"
   ```

3. **Dedicated CI/CD Accounts**
   - Use separate Steam accounts for automation
   - Apply minimal permissions (workshop upload only)
   - Implement credential rotation policies
   - Monitor account activity for anomalies

4. **Security Monitoring**
   - Subscribe to GitHub Security Advisories
   - Set up alerts for new action vulnerabilities
   - Regularly scan workflows with updated tools

## Risk Assessment

### Likelihood
- **High**: Trivial to exploit (just read public logs)
- **No Prerequisites**: No authentication required for public repos
- **Persistent**: Historical logs may contain years of credentials

### Impact
- **Account Takeover**: Full Steam account access
- **Financial Risk**: Unauthorized purchases, item transfers
- **Reputation Damage**: Compromised developer accounts
- **Supply Chain Risk**: Malicious workshop item uploads

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-mj96-mh85-r574
- Repository: https://github.com/buildalon/setup-steamcmd
- Repository Security Advisory: https://github.com/buildalon/setup-steamcmd/security/advisories/GHSA-mj96-mh85-r574
- Patch Commit: https://github.com/buildalon/setup-steamcmd/commit/c3301963a182b14fd7a5b4991e6ae91ed39e4a5c
- Related Pull Request: https://github.com/buildalon/setup-steamcmd/pull/9

### External References
- CWE-532: Insertion of Sensitive Information into Log File
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- Related Advisory: GHSA-c5qx-p38x-qf5w (same pattern in RageAgainstThePixel/setup-steamcmd)

### Credits
- Reporter: @BrknRobot

## Related Vulnerabilities

- **GHSA-c5qx-p38x-qf5w**: Identical vulnerability in `RageAgainstThePixel/setup-steamcmd`
- Both actions shared the same problematic pattern of logging config files in post-job

## Timeline

- **Discovered**: 2024
- **Reported by**: @BrknRobot
- **Fixed**: Version 1.1.0 (commit c330196)
- **Public Disclosure**: 2024

## Lessons Learned

1. **Post-Job Actions are High-Risk**: Cleanup phases can inadvertently expose secrets
2. **Configuration Files = Secrets**: Treat all config files as potentially sensitive
3. **Public Logs are Forever**: Once exposed, credentials must be revoked
4. **Similar Actions, Similar Bugs**: Common patterns lead to common vulnerabilities
5. **Third-Party Actions Need Auditing**: Review action source before using in production

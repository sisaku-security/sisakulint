# GHSA-c5qx-p38x-qf5w: Token Leakage in Post-Job Logs

## Advisory Information

- **Advisory ID**: GHSA-c5qx-p38x-qf5w
- **Package**: RageAgainstThePixel/setup-steamcmd (GitHub Action)
- **Severity**: High (CVSS 8.7)
- **CVE ID**: None assigned
- **CWE ID**: CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Versions**: < 1.3.0
- **Patched Version**: 1.3.0
- **Published**: 2024
- **URL**: https://github.com/advisories/GHSA-c5qx-p38x-qf5w

## Vulnerability Description

The `RageAgainstThePixel/setup-steamcmd` action's post-job cleanup phase logs the contents of `config/config.vdf`, which contains saved Steam authentication tokens capable of providing full account access on different machines. Additionally, `userdata/$user_id$/config/localconfig.vdf` may contain other sensitive user configuration data that is also exposed in public logs.

**Technical Root Cause:** The action's logging mechanism in `src/logging.ts` outputs the complete contents of these configuration files during post-job cleanup without sanitization or filtering. The `config.vdf` file stores authentication tokens in the `ConnectCache` section that remain valid for extended periods, and the action inadvertently exposes this sensitive data in workflow logs.

**Attack Impact:**
- **Public Repository Exposure**: Anyone with a GitHub account can view public workflow logs and extract valid authentication tokens
- **Full Account Access**: Leaked tokens provide complete Steam account access from any machine
- **Persistent Access**: Tokens remain valid until explicitly revoked, allowing long-term unauthorized access
- **Historical Exposure**: All previous workflow runs with vulnerable versions have leaked credentials in their archived logs

## Impact

Any workflow using this action with Steam credentials has leaked valid authentication tokens in job logs. For **public repositories**, anyone with a GitHub account can access these logs and retrieve the tokens to gain unauthorized access to Steam accounts.

## Vulnerable Code Pattern

```yaml
name: Vulnerable SteamCMD Setup

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # VULNERABLE: Versions < 1.3.0 log config.vdf in post-job
      - name: Setup SteamCMD
        uses: RageAgainstThePixel/setup-steamcmd@v1.2.0

      - name: Login to Steam
        run: |
          steamcmd +login ${{ secrets.WORKSHOP_USERNAME }} ${{ secrets.WORKSHOP_PASSWORD }} +quit
```

### What Gets Exposed

In the post-job logs:
```
Post job cleanup
...
Contents of config/config.vdf:
"InstallConfigStore"
{
	"Software"
	{
		"Valve"
		{
			"Steam"
			{
				"Accounts"
				{
					"username"
					{
						"SteamID"		"76561198XXXXXXXXX"
						"AccountName"	"username"
						"PersonaName"	"DisplayName"
						"RememberPassword"		"1"
						"MostRecent"		"1"
						"Timestamp"		"1234567890"
						"WantsOfflineMode"		"0"
						"SkipOfflineModeWarning"		"0"
					}
				}
				"ConnectCache"
				{
					"XXXXXX"
					{
						"token"		"AUTHENTICATION_TOKEN_HERE"
						...
					}
				}
			}
		}
	}
}
```

## Safe Implementation

```yaml
name: Safe SteamCMD Setup

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # SAFE: Version 1.3.0+ does not log sensitive config files
      - name: Setup SteamCMD
        uses: RageAgainstThePixel/setup-steamcmd@v1.3.0

      - name: Login to Steam
        run: |
          steamcmd +login ${{ secrets.WORKSHOP_USERNAME }} ${{ secrets.WORKSHOP_PASSWORD }} +quit
```

## Detection by sisakulint

### Detectability Status: ✅ DETECTED via KnownVulnerableActionsRule

```
script/actions/advisory/GHSA-c5qx-p38x-qf5w-vulnerable.yaml:23:9: Action 'RageAgainstThePixel/setup-steamcmd@v1.2.0' has a known high severity vulnerability (GHSA-c5qx-p38x-qf5w): RageAgainstThePixel/setup-steamcmd leaked authentication token in job output logs. Upgrade to version 1.3.0 or later. See: https://github.com/advisories/GHSA-c5qx-p38x-qf5w [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes |

sisakulint successfully detected this vulnerability using the **KnownVulnerableActionsRule**:
- Line 23: Detects `RageAgainstThePixel/setup-steamcmd@v1.2.0` as having known vulnerability GHSA-c5qx-p38x-qf5w
- Provides specific advisory information about token leakage
- Recommends upgrading to version 1.3.0 or later

While the actual vulnerability occurs in the action's runtime behavior (post-job logging), sisakulint can detect usage of vulnerable action versions through its advisory database.

### Detection Approach

sisakulint implements a **KnownVulnerableActionsRule** that:
- Maintains a database of action versions with known vulnerabilities
- Checks `uses:` statements against this database
- Warns when vulnerable versions are detected
- Provides remediation guidance

### Current Rule Coverage

- **KnownVulnerableActionsRule**: Detects the vulnerable action version in the advisory database ✅
- **CommitShaRule**: Recommends pinning to commit SHA (general best practice) ✅
- **ActionListRule**: Can block usage if configured in allowlist/blocklist ✅

## Mitigation Recommendations

### Immediate Actions

1. **Upgrade to Patched Version**
   ```yaml
   - uses: RageAgainstThePixel/setup-steamcmd@v1.3.0  # or later
   ```

2. **Revoke and Regenerate Tokens**
   - Log into Steam accounts that were used with vulnerable versions
   - Sign out all sessions
   - Change account passwords
   - Revoke any API keys or tokens
   - Enable Steam Guard if not already enabled

3. **Audit Historical Logs**
   - Review all workflow runs that used vulnerable versions
   - Check if logs are publicly accessible
   - Determine if tokens were accessed by unauthorized parties

### Long-term Hardening

1. **Pin Actions by Commit SHA**
   ```yaml
   - uses: RageAgainstThePixel/setup-steamcmd@3e4e408  # v1.3.0
   ```

2. **Use Dependabot for Action Updates**
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "github-actions"
       directory: "/"
       schedule:
         interval: "weekly"
   ```

3. **Monitor for New Advisories**
   - Subscribe to GitHub Security Advisories
   - Regularly scan workflows with updated advisory databases

4. **Principle of Least Privilege**
   - Use dedicated Steam accounts for CI/CD with minimal permissions
   - Implement token rotation policies
   - Avoid using personal Steam accounts in workflows

## Risk Assessment

### Attack Complexity
- **Low**: Simply view public workflow logs to extract tokens
- **No Authentication Required**: Public repositories expose logs to all GitHub users
- **High Impact**: Full Steam account access

### Exploitation Timeline
- Tokens remain valid indefinitely unless explicitly revoked
- Historical logs persist unless manually deleted
- Attacker can access months or years of leaked credentials

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-c5qx-p38x-qf5w
- Repository: https://github.com/RageAgainstThePixel/setup-steamcmd
- Repository Security Advisory: https://github.com/RageAgainstThePixel/setup-steamcmd/security/advisories/GHSA-c5qx-p38x-qf5w
- Patch Commit: https://github.com/RageAgainstThePixel/setup-steamcmd/commit/3e4e408e73bdd46822f1147b45eeeab050fd1ead

### External References
- CWE-532: Insertion of Sensitive Information into Log File
- OWASP CI/CD Top 10: CICD-SEC-7 (Insecure System Configuration)

## Similar Vulnerabilities

- **GHSA-mj96-mh85-r574**: Similar issue in `buildalon/setup-steamcmd`
- Pattern: Post-job actions logging sensitive configuration files

## Timeline

- **Discovered**: 2024
- **Disclosed**: 2024
- **Patched**: Version 1.3.0 (commit 3e4e408)
- **Public**: 2024

## Lessons Learned

1. **Post-Job Actions are Dangerous**: Cleanup phases can inadvertently log sensitive data
2. **Configuration Files Often Contain Secrets**: Files like `config.vdf` should never be logged
3. **Public Logs are Permanent**: Once exposed, credentials should be considered compromised
4. **Third-Party Actions Need Scrutiny**: Always review action source code before use

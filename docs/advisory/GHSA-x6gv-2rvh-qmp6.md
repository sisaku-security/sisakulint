# GHSA-x6gv-2rvh-qmp6

## Summary
| Field | Value |
|-------|-------|
| CVE | N/A |
| Affected Action | BoldestDungeon/steam-workshop-deploy, m00nl1ght-dev/steam-workshop-deploy |
| Severity | Critical (CVSS 10.0) |
| Vulnerability Type | Exposure of Version-Control Repository and Insufficiently Protected Credentials (CWE-212, CWE-522, CWE-527) |
| Published | August 13, 2025 |

## Vulnerability Description

The `steam-workshop-deploy` GitHub Action (both BoldestDungeon and m00nl1ght-dev variants) fails to exclude `.git` directories during content packaging, leading to exposure of repository metadata and credentials, including GitHub personal access tokens (PATs).

**Root Cause:** The action packages content for deployment without filtering `.git` directories or implementing built-in exclusion mechanisms. When `.git` folders exist in target directories, they are silently included in the output package, resulting in exposure of repository metadata and potentially long-lived credentials stored in `.git/config`.

**Affected Versions:**
- BoldestDungeon/steam-workshop-deploy: v1, v1.0.1
- m00nl1ght-dev/steam-workshop-deploy: v1, v2, v3

**Patched Versions:**
- BoldestDungeon/steam-workshop-deploy: v2.0.0
- m00nl1ght-dev/steam-workshop-deploy: v4

This vulnerability is a variant of the "Artipacked" attack pattern where:
1. `actions/checkout` stores `GITHUB_TOKEN` in `.git/config` (default behavior with `persist-credentials: true`)
2. Deployment action uploads entire workspace including `.git` directory
3. `.git/config` contains credential helper with valid GitHub token or PAT
4. Anyone downloading the Workshop item can extract the token
5. Token grants access to the repository with original workflow permissions

**Severity Assessment (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N):**
- **Critical (7.0-10.0):** Long-lived tokens, organization-wide credentials, or credentials with administrative privileges were exposed
- **Medium (4.0-6.9):** Credentials with limited repository access and/or short lifespan (e.g., ephemeral tokens) were exposed
- **Low (0.0-3.9):** Only non-sensitive metadata exposed

**Attack Scenarios with Elevated Risk:**
- Self-hosted runners storing long-lived tokens
- Developers maintaining `.git` folders with embedded PATs in `.git/config`
- Workflows running without `actions/checkout` but with existing `.git` directories
- Use of non-ephemeral tokens passed to `actions/checkout`

**Security Consequences:**
- Unauthorized repository access via exposed PATs
- Repository code or metadata tampering
- Malicious CI behavior triggering through workflow_dispatch
- Disclosure of commit history and internal repository structure

This is particularly critical because:
- Steam Workshop items are often public
- `.git/config` is plaintext and easy to extract
- `GITHUB_TOKEN` may have write permissions
- Attack can be automated to extract credentials from public Workshop items
- While GitHub hosted runners revoke ephemeral credentials automatically, risk increases significantly with self-hosted runners

## Vulnerable Pattern

```yaml
name: Vulnerable Pattern
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # Vulnerable: Default checkout persists credentials
      # .git/config will contain credential helper with GITHUB_TOKEN
      - uses: actions/checkout@v4
        # persist-credentials: true (default)

      - name: Build mod
        run: |
          npm install
          npm run build

      # Vulnerable: Deploys entire workspace including .git
      # .git/config with credentials is uploaded to Steam Workshop
      - uses: BoldestDungeon/steam-workshop-deploy@v1
        with:
          username: ${{ secrets.STEAM_USERNAME }}
          password: ${{ secrets.STEAM_PASSWORD }}
          app_id: '123456'
          workshop_id: '789012'
          path: .  # Uploads everything including .git
```

**Why this is vulnerable:**
- `actions/checkout` default: `persist-credentials: true`
- `.git/config` contains credential helper with `GITHUB_TOKEN`
- Entire workspace (including `.git`) uploaded to Steam Workshop
- Public Workshop item exposes credentials to anyone

**Example `.git/config` content:**
```ini
[credential "https://github.com"]
    helper = !gh auth git-credential
[credential]
    helper = store --file=/home/runner/work/_temp/.git-credentials
```

The credentials file contains:
```
https://x-access-token:ghs_xxxxxxxxxxxxxxxxxxxxx@github.com
```

## Safe Pattern

```yaml
name: Safe Pattern
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      # Safe: Disable credential persistence
      - uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Build mod
        run: |
          npm install
          npm run build

      # Safe: Deploy only build output, not source
      - uses: BoldestDungeon/steam-workshop-deploy@v1
        with:
          username: ${{ secrets.STEAM_USERNAME }}
          password: ${{ secrets.STEAM_PASSWORD }}
          app_id: '123456'
          workshop_id: '789012'
          path: ./dist  # Only deploy build artifacts
```

**Why this is safe:**
- `persist-credentials: false` prevents credential storage in `.git`
- Deploy only `./dist` directory (build output), not source code
- No `.git` directory in deployed content
- Credentials never leave GitHub Actions runner

**Alternative Safe Pattern (if source needed):**
```yaml
- name: Remove .git before deploy
  run: rm -rf .git

- uses: BoldestDungeon/steam-workshop-deploy@v1
  with:
    path: .
```

## sisakulint Detection Result

```
script/actions/advisory/GHSA-x6gv-2rvh-qmp6-vulnerable.yaml:27:9: Action 'BoldestDungeon/steam-workshop-deploy@v1' has a known critical severity vulnerability (GHSA-x6gv-2rvh-qmp6): m00nl1ght-dev/steam-workshop-deploy: Exposure of Version-Control Repository to an Unauthorized Control Sphere and Insufficiently Protected Credentials. Upgrade to version 2.0.0 or later. See: https://github.com/advisories/GHSA-x6gv-2rvh-qmp6 [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | KnownVulnerableActionsRule | Yes |

**Detection Details:**
- `KnownVulnerableActionsRule` detects the specific vulnerable action version at line 27 and recommends upgrading to version 2.0.0 or later
- The rule correctly identifies this as a critical severity vulnerability related to credential exposure
- Auto-fix available: Suggests upgrading to the patched version

**Detection Logic:**
1. Identifies the use of `BoldestDungeon/steam-workshop-deploy@v1`
2. Matches against the known vulnerability database (GHSA-x6gv-2rvh-qmp6)
3. Reports the specific vulnerability with upgrade recommendation

## Mitigation Recommendations

1. **Always set `persist-credentials: false`**: Unless you need Git operations with authentication
2. **Deploy only build artifacts**: Use `path: ./dist` not `path: .`
3. **Audit deployed content**: Check if `.git` was included in past deployments
4. **Rotate GITHUB_TOKEN**: Impossible (automatic), but review repository access logs
5. **Review Workshop items**: Check if credentials were exposed in public items
6. **Add pre-deploy validation**: Verify `.git` directory is not present
7. **Use deployment protection**: Require manual approval for production deploys
8. **Limit token permissions**: Use minimal `permissions:` in workflow

## Attack Scenario

1. **Deployment Phase:**
   ```yaml
   - uses: actions/checkout@v4  # persist-credentials: true (default)
   - run: npm run build
   - uses: steam-workshop-deploy@v1
     with:
       path: .  # Uploads .git directory
   ```

2. **Attacker Phase:**
   ```bash
   # Download Workshop item
   steamcmd +workshop_download_item 123456 789012

   # Extract credentials
   cd mod_directory
   cat .git/config
   # [credential "https://github.com"]
   #     helper = store --file=/tmp/.git-credentials

   cat /tmp/.git-credentials
   # https://x-access-token:ghs_xxxxxxxxx@github.com

   # Use stolen token
   git clone https://x-access-token:ghs_xxxxxxxxx@github.com/victim/repo.git
   cd repo
   git commit --allow-empty -m "backdoor"
   git push  # Success - token has write permission
   ```

3. **Impact:**
   - Attacker gains repository write access
   - Can inject malicious code
   - Access to repository secrets (in subsequent workflow runs)
   - Potential for supply chain attack

## Technical Details

**Why credentials are persisted:**
GitHub's `actions/checkout` uses credential helpers to enable seamless Git operations:

```bash
# What checkout does (simplified)
git config credential.helper "store --file=$RUNNER_TEMP/.git-credentials"
echo "https://x-access-token:$GITHUB_TOKEN@github.com" > $RUNNER_TEMP/.git-credentials
```

**Token Permissions:**
`GITHUB_TOKEN` typically has:
- `contents: write` (push commits)
- `metadata: read` (read repository metadata)
- Can trigger workflows (workflow_dispatch)

## Technical Fix Details

**Version 2.0.0 (BoldestDungeon) and v4 (m00nl1ght-dev) implemented:**

1. **Built-in `.deployignore` mechanism** - A new exclusion system similar to `.gitignore` that filters sensitive files before packaging:
   - Git directories and configuration (`.git/`, `.gitignore`, `.gitattributes`, `.github/`)
   - Steam credentials (`config.vdf`, `localconfig.vdf`, `DialogConfig.vdf`, `ssfn*`, `*.acf`)
   - Common sensitive files (`.env`, `.env.*`, `.pem`, `.key`, `.crt`)

2. **New Action Parameters:**
   - `deployIgnore`: Path to custom exclusion file
   - `useBuiltinDeployIgnore`: Toggle for built-in exclusions (default: `true`)
   - `stagingPath`: Temporary directory for filtered content
   - `concurrentStaging`: Support for concurrent deployments using `$GITHUB_SHA` subdirectories
   - `verbosity`: Control output level (`NORMAL` or `TRACE`)

3. **Implementation using rsync:**
   - Uses `rsync` with exclude parameters to copy only approved files to staging directory
   - Staged content is then packaged and uploaded to Steam Workshop
   - Prevents accidental inclusion of sensitive files

**Changed Files:**
- `.deployignore` (new file, +46 lines) - Default exclusion rules
- `Dockerfile` (+2 lines) - Updated environment
- `action.yml` (+26/-1 lines) - Added new parameters
- `steam_deploy.sh` (+66/-1 lines) - Implemented rsync-based filtering

## References
- [GitHub Advisory: GHSA-x6gv-2rvh-qmp6](https://github.com/advisories/GHSA-x6gv-2rvh-qmp6)
- [BoldestDungeon Security Advisory](https://github.com/BoldestDungeon/steam-workshop-deploy/security/advisories/GHSA-x6gv-2rvh-qmp6)
- [Real-world Example: GHSA-7j9v-72w9-ww6w](https://github.com/BoldestDungeon/wildermyth-drauven-pcs/security/advisories/GHSA-7j9v-72w9-ww6w) - Affected mod example
- [Fix Commit (BoldestDungeon)](https://github.com/BoldestDungeon/steam-workshop-deploy/commit/0ba85729da32108e1cc498d1b3d6760857b5c04d)
- [Fix Commit (m00nl1ght-dev)](https://github.com/m00nl1ght-dev/steam-workshop-deploy/commit/913f0844e2153d798189397036918f4ceb0911e0)
- [Release v2.0.0 (BoldestDungeon)](https://github.com/BoldestDungeon/steam-workshop-deploy/releases/tag/V2.0.0)
- [Release v4 (m00nl1ght-dev)](https://github.com/m00nl1ght-dev/steam-workshop-deploy/releases/tag/v4)
- [sisakulint: ArtipackedRule](../artipacked.md)
- [actions/checkout: persist-credentials](https://github.com/actions/checkout#persist-credentials)
- [Artipacked Attack Pattern](https://www.chainguard.dev/unchained/the-novel-artipacked-attack-pattern)
- [GitHub: Security hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

# GHSA-g86g-chm8-7r2p: GITHUB_TOKEN Exposure via Symlink Attack

## Advisory Information

- **Advisory ID**: GHSA-g86g-chm8-7r2p
- **Package**: check-spelling/check-spelling (GitHub Action)
- **Severity**: Critical (CVSS 9.6)
- **CVE ID**: CVE-2021-32724
- **CWE ID**: CWE-532 (Insertion of Sensitive Information into Log File)
- **Affected Versions**: < 0.0.19
- **Patched Version**: 0.0.19
- **Published**: 2021
- **URL**: https://github.com/advisories/GHSA-g86g-chm8-7r2p

## Vulnerability Description

The `check-spelling/check-spelling` GitHub Action is vulnerable to token leakage through a **symlink attack** when configured to trigger on `pull_request_target` or `schedule` events. An attacker can send a crafted Pull Request that causes a `GITHUB_TOKEN` to be exposed.

The combination of:
1. **pull_request_target** trigger (provides write permissions)
2. **Untrusted code checkout** (checking out PR head without explicit ref)
3. **Symlink processing** (action follows symlinks in vulnerable versions)

Creates a critical security vulnerability allowing attackers to:
- Exfiltrate `GITHUB_TOKEN` with write permissions
- Push commits to the repository bypassing approval processes
- Steal any/all secrets available to the repository

## Impact

### Attack Capabilities

With the exposed `GITHUB_TOKEN`, an attacker can:
1. **Push Commits**: Bypass branch protection and push malicious code
2. **Steal Secrets**: Access all repository secrets
3. **Modify Workflows**: Update workflow files to establish persistence
4. **Access Private Data**: Read private repository contents
5. **Escalate Privileges**: Use repository as launching point for supply chain attacks

### CVSS v3 Metrics (9.6 Critical)
- **Attack Vector**: Network
- **Attack Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: None
- **Scope**: Changed
- **Confidentiality**: High
- **Integrity**: High
- **Availability**: High

## Vulnerable Code Pattern

```yaml
name: Vulnerable Check Spelling

on:
  pull_request_target:  # DANGEROUS: Write permissions
  schedule:
    - cron: '0 0 * * *'

jobs:
  spelling:
    runs-on: ubuntu-latest
    steps:
      # VULNERABLE: Checking out untrusted code in privileged context
      - name: Checkout PR
        uses: actions/checkout@v4
        # No explicit ref = checks out PR head with write token access

      # VULNERABLE: v0.0.18 or earlier processes symlinks unsafely
      - name: Check Spelling
        uses: check-spelling/check-spelling@v0.0.18
        with:
          suppress_push_for_open_pull_requests: 1
```

### Attack Scenario

**Step 1**: Attacker creates malicious PR with crafted symlinks
```bash
# In attacker's PR
ln -s /proc/self/environ .github/malicious-link
```

**Step 2**: Workflow runs on `pull_request_target` (with write permissions)

**Step 3**: Action processes files, following the symlink

**Step 4**: Token appears in logs or is exfiltrated via symlink manipulation

**Step 5**: Attacker uses token to push commits or steal secrets

## Safe Implementation

### Option 1: Use pull_request Trigger (Recommended)

```yaml
name: Safe Check Spelling

on:
  pull_request:  # SAFE: Read-only permissions

jobs:
  spelling:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR
        uses: actions/checkout@v4

      # Safe: pull_request has no write permissions
      - name: Check Spelling
        uses: check-spelling/check-spelling@v0.0.19
```

### Option 2: Use Patched Version with Restricted Permissions

```yaml
name: Safe Check Spelling (Restricted)

on:
  pull_request_target:

jobs:
  spelling:
    runs-on: ubuntu-latest
    permissions:
      contents: read           # Read-only
      pull-requests: write     # Only for posting comments
    steps:
      - name: Checkout PR
        uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # Safe: v0.0.19+ fixes symlink vulnerability
      - name: Check Spelling
        uses: check-spelling/check-spelling@v0.0.19
```

### Option 3: Disable Workflow Temporarily

```yaml
# Temporarily disable by changing trigger
on:
  workflow_dispatch:  # Manual trigger only
```

## Detection by sisakulint

### Detectability Status: ✅ DETECTABLE

This vulnerability **IS detectable** by static analysis because it involves:
1. Dangerous trigger (`pull_request_target`)
2. Untrusted code checkout pattern
3. Overly broad permissions

### Rules that Detect This Pattern

1. **UntrustedCheckoutRule** ✅
   - Detects checkout without explicit `ref` in `pull_request_target` context
   - Severity: Critical
   - Auto-fix: Adds explicit ref to checkout

2. **PermissionsRule** ✅
   - Detects missing or overly broad permissions
   - Recommends least privilege
   - Severity: Medium

3. **KnownVulnerableActionsRule** ✅
   - Detects `check-spelling/check-spelling@v0.0.18` or earlier
   - Recommends upgrade to v0.0.19
   - Severity: Critical

### sisakulint Detection Result

```
script/actions/advisory/GHSA-g86g-chm8-7r2p-vulnerable.yaml:13:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-g86g-chm8-7r2p-vulnerable.yaml:30:9: Action 'check-spelling/check-spelling@v0.0.18' has a known critical severity vulnerability (GHSA-g86g-chm8-7r2p): check-spelling workflow vulnerable to token leakage via symlink attack. Upgrade to version 0.0.19 or later. See: https://github.com/advisories/GHSA-g86g-chm8-7r2p [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | known-vulnerable-actions | Yes |
| Yes | dangerous-triggers-critical | Yes |

sisakulint **successfully detects** this vulnerability through multiple rules:
1. **KnownVulnerableActionsRule** - Identifies the specific vulnerable version with CVE-2021-32724
2. **DangerousTriggersCriticalRule** - Flags the unsafe `pull_request_target` trigger without mitigations

### Auto-fix Capability

```bash
$ sisakulint -fix on script/actions/advisory/GHSA-g86g-chm8-7r2p-vulnerable.yaml
```

The auto-fix will:
1. Add explicit ref to checkout step:
   ```yaml
   - uses: actions/checkout@v4
     with:
       ref: ${{ github.event.pull_request.head.sha }}
   ```

2. Suggest adding restricted permissions (manual review required):
   ```yaml
   permissions:
     contents: read
   ```

## Mitigation Recommendations

### Immediate Actions

1. **Option A: Change Trigger to pull_request**
   ```yaml
   on:
     pull_request:  # Use instead of pull_request_target
   ```
   - **Pros**: Simplest fix, no token exposure risk
   - **Cons**: Cannot post PR comments (no write permissions)

2. **Option B: Upgrade to Patched Version**
   ```yaml
   - uses: check-spelling/check-spelling@v0.0.19  # or later
   ```
   - **Pros**: Fixes symlink vulnerability
   - **Still Risky**: Still uses pull_request_target

3. **Option C: Restrict Permissions**
   ```yaml
   permissions:
     contents: read
     pull-requests: write  # Only if needed for comments
   ```
   - **Pros**: Limits damage even if vulnerability is exploited
   - **Cons**: Requires careful permission planning

4. **Option D: Temporary Disable**
   - Disable the workflow until all branches are fixed
   - Set repository to "Allow specific actions" excluding unverified creators
   - Set Workflow permissions to "Read repository contents permission"

### Long-term Hardening

1. **Pin Actions by Commit SHA**
   ```yaml
   # Pin check-spelling to v0.0.19 commit
   - uses: check-spelling/check-spelling@<commit-sha-for-v0.0.19>
   ```

2. **Use Two-Stage Workflow Pattern**
   ```yaml
   # Workflow 1: pull_request (untrusted code, no permissions)
   on: pull_request
   jobs:
     spell-check:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: check-spelling/check-spelling@v0.0.19

   # Workflow 2: workflow_run (trusted, with permissions)
   on:
     workflow_run:
       workflows: ["Spell Check"]
       types: [completed]
   jobs:
     post-results:
       runs-on: ubuntu-latest
       permissions:
         pull-requests: write
       steps:
         - name: Post PR Comment
           # Post results using workflow_run context
   ```

3. **Complex Branch Management**
   For repositories with many branches:
   - Rename vulnerable workflow file to disable it
   - Create a disabled dummy workflow with original name
   - This prevents vulnerable versions from running on unpatched branches

4. **Automated Dependency Updates**
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
- **High**: Easy to exploit (create malicious PR)
- **No Authentication Required**: Any GitHub user can create PR
- **Widespread**: Affects all workflows using vulnerable pattern

### Impact
- **Critical**: Full repository compromise
- **Persistent**: Attacker can establish backdoors
- **Supply Chain Risk**: Repository used as attack vector

### Exploitation Complexity
- **Low**: Craft symlink in PR
- **No Special Skills Required**: Standard Unix symlink knowledge
- **Automated Exploitation**: Can be scripted and mass-exploited

## Workarounds

If upgrading is not immediately possible:

1. **Repository Settings**
   ```
   Settings → Actions → General → Workflow permissions
   → Select "Read repository contents and packages permissions"
   ```

2. **Allow Specific Actions Only**
   ```
   Settings → Actions → General → Actions permissions
   → Allow select actions and reusable workflows
   → Add specific verified actions
   ```

3. **Branch Protection**
   - Enable branch protection rules
   - Require review for all PRs
   - Prevent direct pushes (even with tokens)

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-g86g-chm8-7r2p
- Repository: https://github.com/check-spelling/check-spelling
- Repository Security Advisory: https://github.com/check-spelling/check-spelling/security/advisories/GHSA-g86g-chm8-7r2p
- Patch Commit: https://github.com/check-spelling/check-spelling/commit/436362fc6b588d9d561cbdb575260ca593c8dc56
- Release: https://github.com/check-spelling/check-spelling/releases/tag/v0.0.19
- Workflow Example: https://github.com/check-spelling/check-spelling/actions/workflows/spelling.yml

### External References
- CVE-2021-32724: https://nvd.nist.gov/vuln/detail/CVE-2021-32724
- CWE-532: Insertion of Sensitive Information into Log File
- OWASP CI/CD Top 10: CICD-SEC-4 (Poisoned Pipeline Execution - PPE)
- GitHub Security Lab Research: https://securitylab.github.com/research/github-actions-preventing-pwn-requests/
- Marketplace: https://github.com/marketplace/actions/check-spelling

### Credits
- Reporter: @justinsteven (https://twitter.com/justinsteven)
- Contact: check-spelling@check-spelling.dev

## Timeline

- **Discovered**: 2021
- **Reported by**: @justinsteven
- **CVE Assigned**: CVE-2021-32724
- **Patched**: Version 0.0.19
- **Public Advisory**: 2021

## Lessons Learned

1. **pull_request_target is Dangerous**: Only use when absolutely necessary
2. **Symlinks are Attack Vectors**: Actions must handle symlinks carefully
3. **Untrusted Code + Write Permissions = Critical**: Never mix these
4. **Defense in Depth**: Multiple layers of protection needed
5. **Branch Management Matters**: Old branches can run vulnerable workflows

## Related Vulnerabilities

Similar patterns affect many GitHub Actions:
- **pull_request_target** + untrusted checkout = common anti-pattern
- Symlink handling issues affect file processing actions
- Token exposure through various side channels

## Similar Advisories

- Multiple actions have similar pull_request_target vulnerabilities
- Pattern: Privileged trigger + untrusted code execution
- Best practice: Separate untrusted code execution from privileged operations

# GHSA-g85v-wf27-67xc

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2024-52587 |
| Affected Action | step-security/harden-runner |
| Severity | Low (CVSS 2.7) |
| Vulnerability Type | OS Command Injection (CWE-78) |
| Published | November 18, 2024 |

## Vulnerability Description

The `step-security/harden-runner` action (versions prior to v2.10.2) contains multiple command injection vulnerabilities in its internal implementation through environment variable manipulation. The action uses Node.js's `execSync` function with shell-interpreted commands that include unsanitized environment variables.

**CVSS v4 Metrics:**
- Severity: Low (2.7/10)
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Impact: Low across Confidentiality, Integrity, and Availability

**Affected Versions:** All versions < 2.10.2

**Patched Version:** 2.10.2

**Likelihood of Exploitation:** Low

The advisory states: "due to the current execution order of pre-steps in GitHub Actions and the placement of harden-runner as the first step in a job, the likelihood of exploitation is low as the Harden-Runner action reads the environment variable during the pre-step stage."

**Current Status:** No known exploits exist.

**Six Specific Injection Points Identified:**

1. **setup.ts:169** - Uses `execSync` with interpolated `process.env.USER` variable, allowing shell expression injection through user variable manipulation

2. **setup.ts:229** - Similar vulnerability using `$USER` for shell-level interpolation

3. **arc-runner.ts:40-44** - `execSync` with multiple string interpolations, potentially injectable via `RUNNER_TEMP` through `getRunnerTempDir()`

4. **arc-runner.ts:53** - Same weakness pattern as item 3

5. **arc-runner.ts:57** - Identical vulnerability to items 3-4

6. **arc-runner.ts:61** - Same injection vector as previous arc-runner instances

**Vulnerable Code Pattern:**
```javascript
// Vulnerable code inside the action
execSync(`command ${process.env.USER} ${process.env.RUNNER_TEMP}`)
```

If an attacker can control the `USER` or `RUNNER_TEMP` environment variables (e.g., through a compromised runner or malicious actions running before `harden-runner`), they can inject arbitrary commands.

## Vulnerable Pattern

```yaml
- name: Harden Runner
  uses: step-security/harden-runner@v2.6.0
  with:
    egress-policy: audit

# The vulnerability is internal to the action's implementation
# There's no visible vulnerable pattern in the workflow file
```

The workflow appears normal, but the action contains vulnerable code internally.

## sisakulint Detection Result

```
script/actions/advisory/GHSA-g85v-wf27-67xc-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-g85v-wf27-67xc-vulnerable.yaml:15:9: Action 'step-security/harden-runner@v2.6.0' has a known medium severity vulnerability (GHSA-mxr3-8whj-j74r): Harden-Runner allows evasion of 'disable-sudo' policy. Upgrade to version 2.12.0 or later. See: https://github.com/advisories/GHSA-mxr3-8whj-j74r [known-vulnerable-actions]
script/actions/advisory/GHSA-g85v-wf27-67xc-vulnerable.yaml:15:9: Action 'step-security/harden-runner@v2.6.0' has a known low severity vulnerability (GHSA-g85v-wf27-67xc): Harden-Runner has a command injection weaknesses in `setup.ts` and `arc-runner.ts`. Upgrade to version 2.10.2 or later. See: https://github.com/advisories/GHSA-g85v-wf27-67xc [known-vulnerable-actions]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | known-vulnerable-actions | Yes |
| Yes | dangerous-triggers-critical | Yes |

sisakulint **successfully detects** this vulnerability through multiple rules:
1. **KnownVulnerableActionsRule** - Identifies `step-security/harden-runner@v2.6.0` as having the known vulnerability GHSA-g85v-wf27-67xc and alerts users to upgrade to version 2.10.2 or later
2. **DangerousTriggersCriticalRule** - Flags the unsafe `pull_request_target` trigger without security mitigations

## Reason for Detection

This vulnerability **CAN be detected by static analysis** because:

1. **Known Vulnerable Actions Database**: sisakulint maintains a database of known vulnerable actions from GitHub Security Advisories
2. **Version-based detection**: The vulnerability affects specific version ranges that can be identified from the `uses:` declaration
3. **Action-specific advisory**: The advisory specifically identifies the vulnerable action and version
4. **Automated remediation**: The tool can suggest upgrading to the patched version

## Mitigation

The vulnerability was fixed in version 2.10.2 of `step-security/harden-runner`. Users should:

1. **Update to version 2.10.2 or later:**
   ```yaml
   - uses: step-security/harden-runner@v2.10.2
     with:
       egress-policy: audit
   ```

2. **Pin actions to specific commit SHAs** to prevent version rollback attacks

3. **Audit the order of actions in workflows** - Actions running before security tools can potentially manipulate the environment

4. **Use trusted runners** and avoid running untrusted code on the same runner as security tools

## Technical Fix Details

**Recommended Remediation Approach:**

The advisory suggests:
- Replace `execSync` calls with `execFileSync` to bypass shell evaluation and prevent command injection
- For file operations in arc-runner, use native NodeJS `fs` API calls instead of subprocess invocations
- Eliminate shell interpretation of untrusted environment variables

**Version 2.10.2 Changes:**

**Files Modified:**
- `src/arc-runner.test.ts` - Test file modifications, removed vulnerable test patterns
- `src/arc-runner.ts` - Core functionality updates with sanitized execution
- `src/cleanup.ts` - Cleanup process changes
- `src/index.ts` - Main entry point updates
- `src/setup.ts` - Setup process modifications with proper sanitization
- `dist/index.js`, `dist/post/index.js`, `dist/pre/index.js` (and source maps) - Compiled bundles

**Key Implementation Changes:**
- Removed test code that referenced `process.env["isTest"]` and unsafe endpoint handling
- Simplified ARC (Actions Runner Controller) runner detection functionality
- Applied proper sanitization to environment variable usage before shell execution
- Updated bundled JavaScript files to reflect source code security improvements

**EPSS Score:** 1.158% (78th percentile) - Low probability of exploitation in the next 30 days

**Credits:**
Vulnerability discovered and reported by [@woodruffw](https://github.com/woodruffw), who provided thorough analysis and collaborated on the fix.

## References
- [GitHub Advisory: GHSA-g85v-wf27-67xc](https://github.com/advisories/GHSA-g85v-wf27-67xc)
- [step-security/harden-runner Security Advisory](https://github.com/step-security/harden-runner/security/advisories/GHSA-g85v-wf27-67xc)
- [Source Code References - setup.ts:169](https://github.com/step-security/harden-runner/blob/951b48540b429070694bc8abd82fd6901eb123ca/src/setup.ts#L169)
- [Source Code References - setup.ts:229](https://github.com/step-security/harden-runner/blob/951b48540b429070694bc8abd82fd6901eb123ca/src/setup.ts#L229)
- [Source Code References - arc-runner.ts:40-44](https://github.com/step-security/harden-runner/blob/951b48540b429070694bc8abd82fd6901eb123ca/src/arc-runner.ts#L40-L44)
- [Fix Commit](https://github.com/step-security/harden-runner/commit/0080882f6c36860b6ba35c610c98ce87d4e2f26f)
- [step-security/harden-runner Repository](https://github.com/step-security/harden-runner)
- [NVD: CVE-2024-52587](https://nvd.nist.gov/vuln/detail/CVE-2024-52587)

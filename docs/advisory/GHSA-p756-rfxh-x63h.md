# GHSA-p756-rfxh-x63h

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2023-23939 |
| Affected Action | Azure/setup-kubectl |
| Severity | Low (CVSS 3.0) |
| Vulnerability Type | Incorrect Permission Assignment for Critical Resource (CWE-732) |
| Published | March 6, 2023 |

## Vulnerability Description

The `Azure/setup-kubectl` action (versions prior to v3) contains a privilege escalation vulnerability due to improper file permissions. The action executes `fs.chmodSync(kubectlPath, 777)`, setting world-writable permissions on the kubectl binary during installation.

**CVSS Vector:** CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:N
- Attack Vector: Adjacent (AV:A)
- Attack Complexity: High (AC:H)
- Privileges Required: Low (PR:L)
- User Interaction: None (UI:N)
- Scope: Changed (S:C)
- Confidentiality Impact: None (C:N)
- Integrity Impact: Low (I:L)
- Availability Impact: None (A:N)

**Affected Versions:** v2 and lower

**Patched Versions:** v3 and higher

**EPSS Score:** 0.335% (56th percentile) - Low probability of exploitation within 30 days

**Vulnerable Code Pattern:**
```javascript
// Vulnerable code inside the action
fs.chmodSync(kubectlPath, 0o777)
```

**The Problem:**
The action sets file permissions to 777 (read/write/execute for all users), making the binary modifiable by any local user on the system.

This makes the kubectl binary writable by any user on the system, including:
- Compromised processes running under different users
- Malicious actions executed in the same workflow
- Other workflows running on the same self-hosted runner

**Security Implications:**

The flaw enables:
- **Privilege Escalation:** Local actors on the GitHub Actions runner can replace the kubectl binary
- **Target User:** Escalation to the user executing kubectl, typically root
- **Attack Prerequisites:** Attacker must either:
  - Breach the GitHub Actions runner, or
  - Use a malicious Action in the workflow

An attacker could replace the kubectl binary with a malicious version, leading to privilege escalation in subsequent workflow runs or other users' workflows.

**Reported Impact:** No customers have reported being affected by this vulnerability.

## Vulnerable Pattern

```yaml
- name: Setup kubectl
  uses: Azure/setup-kubectl@v2
  with:
    version: 'v1.28.0'

- name: Use kubectl
  run: kubectl version --client
```

The workflow appears normal, but the action sets insecure file permissions internally.

## sisakulint Detection Result

```
(No vulnerability-specific warnings detected)
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| No | N/A | No |

sisakulint detected general security issues (permissions, timeout-minutes, commit-sha, etc.), but did not detect this specific vulnerability (improper file permissions 777 set on the kubectl binary).

## Reason for Non-Detection

This vulnerability **cannot be detected by static analysis** for the following reasons:

1. **Action internal implementation**: The vulnerability exists in the action's JavaScript code (`fs.chmodSync`), not in the workflow YAML
2. **No workflow-level indicators**: The workflow configuration is completely normal and follows best practices
3. **File system operations**: Static analysis cannot inspect runtime file system operations performed by actions
4. **Hidden security issue**: The permissions issue is not exposed in the action's input/output interface
5. **Binary-specific**: The vulnerability affects a binary file that is downloaded and configured at runtime

**Detection category**: Action internal implementation

## Mitigation

The vulnerability was fixed in version v3 by setting proper file permissions (755 instead of 777). Users should:

1. **Update to version v3 or later:**
   ```yaml
   - uses: Azure/setup-kubectl@v3
     with:
       version: 'v1.28.0'
   ```

2. **Pin the action to a specific commit SHA**

3. **For self-hosted runners, verify file permissions after setup:**
   ```bash
   ls -la $(which kubectl)
   # Should show: -rwxr-xr-x (755), not -rwxrwxrwx (777)
   ```

4. **Consider using isolated runners** for each workflow to prevent cross-workflow attacks

5. **Monitor file integrity** of critical binaries on self-hosted runners

## Workarounds

For users unable to upgrade to v3 or higher:
1. Carefully audit all GitHub Actions used in workflows
2. Ensure GitHub Actions runner environment security
3. Minimize use of third-party actions that could exploit this vulnerability

**Recommendation:** Upgrade to version v3 or later to eliminate this vulnerability. The low severity rating and lack of reported incidents suggest limited real-world exploitation risk, but upgrading remains the most secure approach.

## Impact

The impact is particularly severe for self-hosted runners where:
- Multiple workflows may run on the same runner
- Multiple users may have access to the same system
- Long-running runners can be persistently compromised

On GitHub-hosted runners, the impact is limited since each workflow runs in a fresh, isolated environment.

## Technical Fix Details

**Version v3 Changes:**

**Files Modified:**
- `src/run.ts` - Core functionality with permission fix
- `src/run.test.ts` - Updated tests

**The Fix:**
Changed the `chmod` permission mode from `'777'` to `'775'`:

**Before (Vulnerable):**
```javascript
fs.chmodSync(kubectlPath, 0o777)  // World-writable
```

**After (Fixed):**
```javascript
fs.chmodSync(kubectlPath, 0o775)  // Restricted write access
```

**Permission Explanation:**
- Permission `777` = read, write, execute for owner, group, and others (world-writable)
- Permission `775` = read, write, execute for owner and group; read and execute only for others

The change follows the principle of least privilege by restricting write permissions to only the owner and group, preventing unauthorized users from modifying the kubectl executable. This reduces the attack surface while maintaining necessary functionality.

## References
- [GitHub Advisory: GHSA-p756-rfxh-x63h](https://github.com/advisories/GHSA-p756-rfxh-x63h)
- [Azure/setup-kubectl Security Advisory](https://github.com/Azure/setup-kubectl/security/advisories/GHSA-p756-rfxh-x63h)
- [Fix Commit](https://github.com/Azure/setup-kubectl/commit/d449d75495d2b9d1463555bb00ca3dca77a42ab6)
- [Azure/setup-kubectl Repository](https://github.com/Azure/setup-kubectl)
- [NVD: CVE-2023-23939](https://nvd.nist.gov/vuln/detail/CVE-2023-23939)

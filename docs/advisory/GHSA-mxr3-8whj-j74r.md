# GHSA-mxr3-8whj-j74r

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2025-32955 |
| Affected Action | step-security/harden-runner |
| Severity | Moderate (CVSS 6.0) |
| Vulnerability Type | Privilege Escalation via Docker Group (CWE-250, CWE-268, CWE-272) |
| Published | January 2025 |

## Vulnerability Description

The `step-security/harden-runner` action's `disable-sudo` policy can be bypassed because "the runner user, being part of the docker group, can interact with the Docker daemon to launch privileged containers or access the host filesystem." This enables attackers to "regain root access or restore the sudoers file."

**CVSS Vector:** CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H
- Attack Vector: Local (AV:L)
- Attack Complexity: Low (AC:L)
- Privileges Required: High (PR:H) - Attacker must first achieve code execution
- User Interaction: None (UI:N)
- Confidentiality Impact: None (C:N)
- Integrity Impact: High (I:H)
- Availability Impact: High (A:H)

**Exploitation Prerequisites:**
An attacker must first achieve code execution on the runner through methods such as:
- Supply chain attack similar to tj-actions compromise
- Exploiting a Pwn Request vulnerability (code injection in pull_request_target)
- Other workflow-level vulnerabilities

**Affected Versions:** >= 0.12.0, < 2.12.0

**Patched Version:** 2.12.0

**Affected Configurations:**
- GitHub-hosted runners with `disable-sudo: true`
- Ephemeral self-hosted VM-based runners with `disable-sudo: true`
- **Not affected:** Kubernetes-based Actions Runner Controller (ARC)

An attacker could use commands like `docker run -v /:/host alpine chroot /host` to gain full root access to the host system, effectively bypassing the sudo restriction and accessing the entire host filesystem.

## Vulnerable Pattern

```yaml
- name: Harden Runner with disable-sudo
  uses: step-security/harden-runner@v2
  with:
    egress-policy: audit
    disable-sudo: true

- name: Execute privileged command via docker
  run: |
    # Bypasses disable-sudo policy
    docker run --rm -v /:/host alpine sh -c "echo 'Privileged access' > /host/tmp/pwned"
```

The workflow sets `disable-sudo: true` but doesn't prevent docker usage, allowing privilege escalation.

## sisakulint Detection Result

```
(No vulnerability-specific warnings detected)
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| No | N/A | No |

sisakulint detects common security issues (permissions, timeout-minutes, commit-sha, etc.), but it does not detect this specific vulnerability (bypass of `disable-sudo` policy via docker group).

## Reason for Non-Detection

This vulnerability **cannot be detected by static analysis** for the following reasons:

1. **Runtime behavior**: The vulnerability depends on the runtime environment configuration (docker group membership) rather than the workflow code itself
2. **Action internal implementation**: The issue is in how `harden-runner` implements the `disable-sudo` policy, not in the workflow's usage pattern
3. **Valid configuration**: Using `disable-sudo: true` is actually a security best practice; the issue is that it doesn't restrict docker access
4. **No workflow-level indicators**: There's no specific workflow pattern that indicates this vulnerability - any use of docker commands could potentially exploit it

**Detection category**: Action internal implementation + Runtime behavior

## Mitigation

The vulnerability was addressed in version 2.12.0 of `step-security/harden-runner` with the following improvements:

**Primary Solution: Migrate to `disable-sudo-and-containers` policy**

Version 2.12.0 introduces the new `disable-sudo-and-containers` option which:
- Disables sudo access (like the original `disable-sudo`)
- Removes access to dockerd and containerd sockets
- Uninstalls Docker entirely from the runner
- Provides comprehensive privilege escalation prevention

**Migration Steps:**

1. **Update to version 2.12.0 or later:**
   ```yaml
   - uses: step-security/harden-runner@v2.12.0
     with:
       disable-sudo-and-containers: true  # New comprehensive option
   ```

2. **Deprecation Notice:** The `disable-sudo` option will be deprecated as it "does not sufficiently restrict privilege escalation."

3. **Enhanced Detection:** Version 2.12.0 includes detection mechanisms that "alert on attempts to evade the `disable-sudo` policy."

**Additional Recommendations:**
- Avoid mixing security controls with docker operations in untrusted workflows
- For Kubernetes environments, use Actions Runner Controller (ARC) which is not affected
- Review workflow dependencies for supply chain attack risks

## Technical Fix Details

**Version 2.12.0 Changes:**

**Files Modified:**
- `README.md` - Documentation updates
- `action.yml` - Added `disable-sudo-and-containers` parameter
- `dist/post/index.js` and `dist/pre/index.js` - Compiled JavaScript bundles
- `src/checksum.ts` - Agent version updates
- `src/cleanup.ts` - Enhanced cleanup with new parameter checks
- `src/install-agent.ts` - Agent installation logic
- `src/interfaces.ts` - Type definitions for new parameter
- `src/policy-utils.ts` and `src/policy-utils.test.ts` - Policy handling logic

**Agent Version Updates:**
- TLS variant: v1.4.2 → v1.6.3
- Non-TLS variant: v0.13.7 → v0.14.0

**Implementation Details:**
The cleanup process now checks both `disable_sudo` and `disable_sudo_and_containers` flags before executing privileged operations. The new parameter propagates through the entire action lifecycle, including interfaces, policy utilities, and state management.

**Credits:**
Reported by [@loresuso](https://github.com/loresuso) and [@darryk10](https://github.com/darryk10)

## References
- [GitHub Advisory: GHSA-mxr3-8whj-j74r](https://github.com/advisories/GHSA-mxr3-8whj-j74r)
- [step-security/harden-runner Security Advisory](https://github.com/step-security/harden-runner/security/advisories/GHSA-mxr3-8whj-j74r)
- [Fix Commit](https://github.com/step-security/harden-runner/commit/0634a2670c59f64b4a01f0f96f84700a4088b9f0)
- [Release v2.12.0](https://github.com/step-security/harden-runner/releases/tag/v2.12.0)
- [step-security/harden-runner Repository](https://github.com/step-security/harden-runner)
- [NVD: CVE-2025-32955](https://nvd.nist.gov/vuln/detail/CVE-2025-32955)

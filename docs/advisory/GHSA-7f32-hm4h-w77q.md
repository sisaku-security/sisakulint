# GHSA-7f32-hm4h-w77q

## Summary
| Field | Value |
|-------|-------|
| CVE | N/A |
| Affected Action | rlespinasse/github-slug-action |
| Severity | Moderate |
| Vulnerability Type | Environment Variable Injection (Deprecated Command) |
| Published | 2022-10-19 |

## Vulnerability Description

The rlespinasse/github-slug-action used the deprecated `::set-env::` workflow command to set environment variables. This command was deprecated by GitHub in October 2020 due to security vulnerabilities that allow environment variable injection attacks.

The `::set-env` command is vulnerable because:
1. It doesn't properly handle newline characters in values
2. Attackers can inject additional environment variables by including newlines in their input
3. It can lead to code injection in subsequent steps that use the poisoned environment

GitHub deprecated this command in favor of writing to the `$GITHUB_ENV` file, which requires explicit newline handling and is more secure.

## Vulnerable Pattern

```yaml
on:
  pull_request_target:

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Set environment variable
        run: |
          echo "::set-env name=BRANCH_NAME::${{ github.event.pull_request.head.ref }}"
          echo "::set-env name=PR_TITLE::${{ github.event.pull_request.title }}"
```

**Attack Vector**: An attacker creates a PR with a branch name or title containing newlines:
```
feature-branch
MALICIOUS_VAR=injected_value
PATH=/tmp/evil:$PATH
```

This injects additional environment variables that will be available in subsequent workflow steps, potentially allowing code execution via PATH hijacking or other environment-based attacks.

## Safe Pattern

```yaml
on:
  pull_request_target:

jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      - name: Set environment variable
        env:
          BRANCH_REF: ${{ github.event.pull_request.head.ref }}
          PR_TITLE_VALUE: ${{ github.event.pull_request.title }}
        run: |
          # Sanitize by removing newlines
          SAFE_BRANCH=$(echo "$BRANCH_REF" | tr -d '\n')
          SAFE_TITLE=$(echo "$PR_TITLE_VALUE" | tr -d '\n')
          echo "BRANCH_NAME=$SAFE_BRANCH" >> $GITHUB_ENV
          echo "PR_TITLE=$SAFE_TITLE" >> $GITHUB_ENV
```

**Mitigation**:
1. Never use the deprecated `::set-env::` command
2. Use `$GITHUB_ENV` file for setting environment variables
3. Sanitize untrusted input by removing newlines with `tr -d '\n'`
4. Pass untrusted contexts through environment variables before processing

## sisakulint Detection Result

```
script/actions/advisory/GHSA-7f32-hm4h-w77q-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-7f32-hm4h-w77q-vulnerable.yaml:17:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 9). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
script/actions/advisory/GHSA-7f32-hm4h-w77q-vulnerable.yaml:22:14: workflow command "set-env" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_ENV` reference: https://sisaku-security.github.io/lint/docs/rules/deprecatedcommandsrule/ [deprecated-commands]
script/actions/advisory/GHSA-7f32-hm4h-w77q-vulnerable.yaml:22:14: workflow command "set-env" was deprecated. You should use `echo "{name}={value}" >> $GITHUB_ENV` reference: https://sisaku-security.github.io/lint/docs/rules/deprecatedcommandsrule/ [deprecated-commands]
script/actions/advisory/GHSA-7f32-hm4h-w77q-vulnerable.yaml:23:48: code injection (critical): "github.event.pull_request.head.ref" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-7f32-hm4h-w77q-vulnerable.yaml:24:45: code injection (critical): "github.event.pull_request.title" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | DeprecatedCommandsRule | Yes - Perfect match |
| Yes | CodeInjectionCriticalRule | Yes |
| Yes | UntrustedCheckoutRule | Yes |

**Detection Mechanism**:
- `DeprecatedCommandsRule` detects usage of deprecated `::set-env::` command (2 instances detected)
- `CodeInjectionCriticalRule` detects unsafe usage of untrusted inputs in the deprecated command
- `UntrustedCheckoutRule` detects unsafe checkout in privileged context
- Provides correct remediation: use `echo "{name}={value}" >> $GITHUB_ENV`

sisakulint detects deprecated GitHub Actions workflow commands including:
- `::set-env::` (detected in this workflow)
- `::add-path::`
- `::set-output::`

These commands were deprecated due to security vulnerabilities and should be replaced with their modern equivalents.

## Additional Context

This vulnerability is particularly dangerous because:
1. The deprecated command is still functional (not removed, just deprecated)
2. Many existing workflows and actions still use it
3. It's easily overlooked during security reviews
4. The attack surface is broad - any untrusted input can be exploited

The modern approach using `$GITHUB_ENV` requires explicit handling of multi-line values using heredoc syntax, making injection more difficult:
```bash
echo "VAR_NAME<<EOF" >> $GITHUB_ENV
echo "$VALUE" >> $GITHUB_ENV
echo "EOF" >> $GITHUB_ENV
```

## References
- [GitHub Advisory](https://github.com/advisories/GHSA-7f32-hm4h-w77q)
- [rlespinasse/github-slug-action Security Advisory](https://github.com/rlespinasse/github-slug-action/security/advisories/GHSA-7f32-hm4h-w77q)
- [Related Advisory GHSA-mfwh-5m23-j46w](https://github.com/advisories/GHSA-mfwh-5m23-j46w)
- [GitHub Blog: Deprecating set-env and add-path](https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/)
- [sisakulint: DeprecatedCommandsRule](../deprecatedcommands.md)

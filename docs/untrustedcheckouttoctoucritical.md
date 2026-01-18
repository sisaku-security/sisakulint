---
title: "Untrusted Checkout TOCTOU Critical Rule"
weight: 1
---

### Untrusted Checkout TOCTOU Critical Rule Overview

This rule detects **Time-of-Check to Time-of-Use (TOCTOU)** vulnerabilities in GitHub Actions workflows. It identifies scenarios where label-based approval mechanisms can be bypassed due to using mutable branch references instead of immutable commit SHAs.

**Security Severity: 9.3 (Critical)**

**Vulnerable Example:**

```yaml
name: CI
on:
  pull_request_target:
    types: [labeled]

jobs:
  test:
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}  # DANGEROUS: Mutable reference!
      - run: npm ci && npm test
```

**Detection Output:**

```bash
vulnerable.yaml:14:11: TOCTOU vulnerability detected: workflow uses 'labeled' event type with mutable ref '${{ github.event.pull_request.head.ref }}' in checkout. An attacker can push malicious code after the label is applied. Use '${{ github.event.pull_request.head.sha }}' instead. See CWE-367 [untrusted-checkout-toctou/critical]
     14 |          ref: ${{ github.event.pull_request.head.ref }}
```

### Security Background

#### What is TOCTOU?

TOCTOU (Time-of-Check to Time-of-Use) is a race condition vulnerability where the state of a resource changes between when it's checked and when it's used.

In the context of GitHub Actions:
1. **Time-of-Check**: A maintainer reviews the PR code and applies a "safe-to-test" label
2. **Time-of-Use**: The workflow checks out and runs the code
3. **Attack Window**: Between labeling and execution, an attacker can push malicious commits

#### Attack Scenario

```
1. Attacker opens PR with benign code
2. Maintainer reviews code, approves, adds "safe-to-test" label
3. Workflow triggers due to 'labeled' event
4. ATTACK WINDOW: Attacker force-pushes malicious code
5. Workflow checks out malicious code using mutable branch ref
6. Malicious code executes with repository secrets
```

#### Why is this Critical?

| Risk Factor | Impact |
|-------------|--------|
| **Secrets Access** | Malicious code runs with full access to repository secrets |
| **Write Permissions** | `pull_request_target` has write access to the repository |
| **Bypass Review** | Attack occurs after code review is complete |
| **Supply Chain** | Can inject malicious code into releases |

#### OWASP and CWE Mapping

- **CWE-367**: Time-of-check Time-of-use (TOCTOU) Race Condition
- **CWE-362**: Concurrent Execution using Shared Resource with Improper Synchronization
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Detection Logic

#### What Gets Detected

1. **Labeled event with mutable ref checkout**
   ```yaml
   on:
     pull_request_target:
       types: [labeled]
   # ...
   ref: ${{ github.event.pull_request.head.ref }}
   ```

2. **Branch name references**
   ```yaml
   ref: ${{ github.head_ref }}
   ```

#### Safe Patterns (NOT Detected)

Using immutable commit SHA:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}  # Immutable!
```

Using `github.sha` for merged commit:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.sha }}
```

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will replace mutable refs with immutable SHA references.

**Example:**

Before auto-fix:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.ref }}
```

After running `sisakulint -fix on`:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}
```

### Remediation Steps

1. **Use immutable commit SHA**
   ```yaml
   - uses: actions/checkout@v4
     with:
       ref: ${{ github.event.pull_request.head.sha }}
   ```

2. **Add approval requirement in job condition**
   ```yaml
   jobs:
     test:
       if: |
         contains(github.event.pull_request.labels.*.name, 'safe-to-test') &&
         github.event.action == 'labeled'
   ```

3. **Consider using environment protection rules**
   - Require approval before running in protected environments
   - Use deployment environments with required reviewers

### Best Practices

1. **Always use SHA for external PR code**
   ```yaml
   ref: ${{ github.event.pull_request.head.sha }}
   ```

2. **Minimize privileged workflow scope**
   - Only checkout what's necessary
   - Run untrusted code in isolated jobs

3. **Use workflow_run for separation**
   ```yaml
   # First workflow (unprivileged)
   on: pull_request
   # Runs tests without secrets

   # Second workflow (privileged)
   on: workflow_run
   # Only runs after first workflow succeeds
   ```

4. **Implement additional approval checks**
   - Require multiple labels or approvals
   - Use GitHub's deployment environments

### References

- [CodeQL: Untrusted Checkout TOCTOU](https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-toctou-critical/)
- [CWE-367: Time-of-check Time-of-use Race Condition](https://cwe.mitre.org/data/definitions/367.html)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

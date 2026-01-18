---
title: "Untrusted Checkout TOCTOU High Rule"
weight: 1
---

### Untrusted Checkout TOCTOU High Rule Overview

This rule detects **Time-of-Check to Time-of-Use (TOCTOU)** vulnerabilities in GitHub Actions workflows where deployment environment approval mechanisms can be bypassed due to using mutable branch references instead of immutable commit SHAs.

**Security Severity: 7.5 (High)**

**Vulnerable Example:**

```yaml
name: Deploy
on: pull_request_target

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # Requires manual approval
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}  # DANGEROUS: Mutable reference!
      - run: ./deploy.sh
```

**Detection Output:**

```bash
vulnerable.yaml:12:11: TOCTOU vulnerability detected: job uses deployment environment 'production' with mutable ref '${{ github.event.pull_request.head.ref }}' in checkout. An attacker can push malicious code after approval is granted. Use '${{ github.event.pull_request.head.sha }}' instead. See CWE-367 [untrusted-checkout-toctou/high]
     12 |          ref: ${{ github.event.pull_request.head.ref }}
```

### Security Background

#### What is Environment-based TOCTOU?

GitHub deployment environments can require manual approval before jobs run. However, if the checkout uses a mutable reference, an attacker can modify the code after approval but before execution.

#### Attack Scenario

```
1. Attacker opens PR with benign code
2. Approver reviews and approves the deployment
3. Workflow waits for approval, then starts
4. ATTACK WINDOW: Attacker force-pushes malicious code
5. Workflow checks out malicious code using mutable branch ref
6. Malicious code deploys to production with secrets
```

#### Why is this High Severity?

| Risk Factor | Impact |
|-------------|--------|
| **Deployment Access** | Malicious code can be deployed to production |
| **Secrets Access** | Environment secrets are exposed |
| **Bypass Approval** | Attack occurs after human approval |
| **Production Impact** | Direct impact on production systems |

#### OWASP and CWE Mapping

- **CWE-367**: Time-of-check Time-of-use (TOCTOU) Race Condition
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)
  - **CICD-SEC-8:** Ungoverned Usage of Third Party Services

### Detection Logic

#### What Gets Detected

1. **Environment with mutable ref checkout**
   ```yaml
   environment: production
   steps:
     - uses: actions/checkout@v4
       with:
         ref: ${{ github.event.pull_request.head.ref }}
   ```

2. **Named environment with branch reference**
   ```yaml
   environment:
     name: staging
   # ...
   ref: ${{ github.head_ref }}
   ```

#### Safe Patterns (NOT Detected)

Using immutable commit SHA:
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.event.pull_request.head.sha }}
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

2. **Consider two-workflow pattern**
   ```yaml
   # Workflow 1: Build artifacts (triggered by PR)
   # Workflow 2: Deploy artifacts (triggered by workflow_run)
   ```

3. **Use branch protection rules**
   - Require status checks before merging
   - Prevent force pushes to main branches

### Best Practices

1. **Always use SHA for PR code in deployment workflows**
2. **Separate build and deploy workflows**
3. **Use artifact-based deployments**
   - Build artifacts in one workflow
   - Deploy verified artifacts in another

### References

- [CodeQL: Untrusted Checkout TOCTOU High](https://codeql.github.com/codeql-query-help/actions/actions-untrusted-checkout-toctou-high/)
- [GitHub: Deployment Environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment)
- [CWE-367: TOCTOU Race Condition](https://cwe.mitre.org/data/definitions/367.html)

---
title: "Timeout Minutes Rule"
weight: 1
---

### Timeout Minutes Rule Overview

This rule enforces the `timeout-minutes` attribute for all jobs in GitHub Actions workflows. Without explicit timeouts, jobs can run indefinitely, consuming CI/CD resources and potentially being exploited for malicious purposes.

### Security Impact

**Severity: Low (3/10)**

Missing timeouts are primarily a best practice and resource management concern:

1. **Resource Exhaustion**: Long-running jobs consume CI/CD compute quotas
2. **Cost Overruns**: Billable minutes accumulate when jobs hang indefinitely
3. **C2 Potential**: Compromised workflows could use runners for extended operations
4. **Pipeline Blocking**: Stuck jobs delay releases and block other workflows

While not a direct security vulnerability, missing timeouts can enable or exacerbate security issues. This rule is classified as Low severity because it primarily addresses operational best practices rather than exploitable vulnerabilities.

**Invalid Example:**

```yaml
name: CI
on: [push, pull_request]

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    # Missing timeout-minutes
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint

  docker:
    name: Build Docker
    runs-on: ubuntu-latest
    # Missing timeout-minutes
    steps:
      - uses: actions/checkout@v4
      - run: docker build .
```

**Detection Output:**

```bash
CI.yaml:5:3: timeout-minutes is not set for job lint; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
      5 👈|  lint:

CI.yaml:13:3: timeout-minutes is not set for job docker; see https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes for more details. [missing-timeout-minutes]
      13 👈|  docker:
```

### Rule Background

#### Why Timeout Configuration Matters

Jobs without explicit timeouts pose several risks:

1. **Resource Exhaustion**: Long-running jobs consume compute minutes and can exhaust CI/CD quotas
2. **Denial of Service**: Malicious PRs could intentionally create infinite loops
3. **C2 Attack Vector**: Compromised workflows could be used as command-and-control infrastructure
4. **Cost Overruns**: Billable minutes accumulate when jobs hang indefinitely
5. **Developer Friction**: Stuck jobs block CI/CD pipelines and delay releases

#### Default Behavior

GitHub Actions has a default timeout of **360 minutes (6 hours)** per job. This is often excessive for most workflows and should be explicitly reduced.

#### Security Implications

Without timeouts, attackers can potentially:

- **Mine Cryptocurrency**: Use runner compute for resource-intensive operations
- **Exfiltrate Data Slowly**: Transfer data in small chunks over extended periods
- **Establish Persistence**: Maintain long-running processes for command-and-control
- **Consume Resources**: Create denial-of-service conditions through resource exhaustion

### Technical Detection Mechanism

The rule checks each job for the presence of `timeout-minutes`:

```go
func (rule *TimeoutMinutesRule) VisitJobPre(node *ast.Job) error {
    if node.TimeoutMinutes == nil {
        rule.Errorf(node.Pos,
            "timeout-minutes is not set for job %s; see %s for more details.",
            node.ID.Value, timeoutDocsURL)
        // Add auto-fixer
        rule.AddAutoFixer(NewJobFixer(node, rule))
    }
    return nil
}
```

### Detection Logic Explanation

#### What the Rule Checks

1. **Job-Level Timeouts**: Validates that each job has `timeout-minutes` defined
2. **Explicit Configuration**: Ensures timeouts are explicitly set, not relying on defaults
3. **All Jobs**: Applies to every job in the workflow

#### Why Not Step-Level Timeouts?

While GitHub Actions supports step-level `timeout-minutes`, the rule focuses on job-level timeouts because:

- Job-level timeouts provide overall protection for the entire job
- Step-level timeouts are optional refinements
- A single stuck step should not run indefinitely

### Valid Patterns

#### Pattern 1: Simple Timeout

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
```

#### Pattern 2: Different Timeouts per Job

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    timeout-minutes: 5  # Quick job
    steps:
      - uses: actions/checkout@v4
      - run: npm run lint

  test:
    runs-on: ubuntu-latest
    timeout-minutes: 30  # Longer job
    steps:
      - uses: actions/checkout@v4
      - run: npm test

  deploy:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
```

#### Pattern 3: Using Variables

```yaml
env:
  DEFAULT_TIMEOUT: 10

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: ${{ env.DEFAULT_TIMEOUT }}
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
```

### Auto-Fix Support

The timeout-minutes rule supports auto-fixing by adding a default timeout:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

**Before (Missing Timeout):**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
```

**After Auto-Fix:**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 5  # Added by sisakulint
    steps:
      - uses: actions/checkout@v4
      - run: npm run build
```

**Note:** The auto-fix adds a default timeout of 5 minutes. Review and adjust this value based on your job's actual requirements.

### Best Practices

#### 1. Set Realistic Timeouts

Choose timeouts based on typical job duration plus buffer:

```yaml
# Typical duration: 3 minutes → Set timeout: 5-10 minutes
timeout-minutes: 10
```

#### 2. Different Timeouts for Different Jobs

Match timeout to job complexity:

```yaml
jobs:
  lint:
    timeout-minutes: 5     # Fast checks

  unit-test:
    timeout-minutes: 15    # Moderate

  integration-test:
    timeout-minutes: 30    # Complex tests

  deploy:
    timeout-minutes: 20    # Deployment operations
```

#### 3. Consider Matrix Jobs

Matrix jobs may need longer timeouts:

```yaml
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        node: [16, 18, 20]
    timeout-minutes: 20  # Account for slower runners
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
```

#### 4. Self-Hosted Runners

Self-hosted runners may need adjusted timeouts:

```yaml
jobs:
  build:
    runs-on: self-hosted
    timeout-minutes: 60  # Self-hosted may have different performance
    steps:
      - run: ./long-build-process.sh
```

### Recommended Timeout Values

| Job Type | Recommended Timeout |
|----------|---------------------|
| Linting | 5-10 minutes |
| Unit Tests | 10-20 minutes |
| Integration Tests | 20-45 minutes |
| Build (Simple) | 10-15 minutes |
| Build (Complex) | 20-30 minutes |
| Docker Build | 15-30 minutes |
| Deployment | 10-20 minutes |

### Step-Level Timeouts (Optional)

For additional protection, you can also set step-level timeouts:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30  # Job-level timeout
    steps:
      - uses: actions/checkout@v4
        timeout-minutes: 2  # Step-level timeout

      - name: Install dependencies
        timeout-minutes: 5
        run: npm ci

      - name: Run tests
        timeout-minutes: 15
        run: npm test
```

### False Positives

This rule has no false positives because:

1. Explicit timeouts are always a best practice
2. The default 6-hour timeout is rarely appropriate
3. Setting timeouts has no negative side effects (when properly configured)

### Related Rules

- **[permissions]({{< ref "permissions.md" >}})**: Limits job permissions
- **[commit-sha]({{< ref "commitsharule.md" >}})**: Pins actions for security

### References

#### GitHub Documentation
- [GitHub Docs: timeout-minutes](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes)
- [GitHub Docs: Usage Limits](https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration)

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idtimeout-minutes" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration" >}}

### Testing

To test this rule:

```bash
# Detect missing timeouts
sisakulint .github/workflows/*.yml

# Apply auto-fix
sisakulint -fix on .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore missing-timeout-minutes
```

However, disabling this rule is **not recommended** as explicit timeouts are an important security and resource management practice.

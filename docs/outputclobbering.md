# Output Clobbering Rule

## Overview

The Output Clobbering rule detects vulnerabilities where untrusted input is written to `$GITHUB_OUTPUT` without proper sanitization. Attackers can inject newlines in user-controlled fields (like issue titles, PR bodies, or comments) to overwrite other output variables, potentially bypassing security controls.

## Vulnerability

When writing to `$GITHUB_OUTPUT` using the simple `name=value` format, newlines in the value can be used to inject additional output variables:

```yaml
# Vulnerable pattern
- run: |
    echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"
    echo "approved=false" >> "$GITHUB_OUTPUT"
```

An attacker can set their PR title to:
```
innocent title
approved=true
```

This would result in:
```
title=innocent title
approved=true
approved=false
```

GitHub Actions uses the **last** value for duplicate keys, so `approved` would be `false`. However, if the attacker places their injection **after** the legitimate write, they can overwrite it.

## Rule Variants

### output-clobbering-critical

Detects output clobbering in privileged workflow contexts:
- `pull_request_target`
- `workflow_run`
- `issue_comment`
- `issues`
- `discussion_comment`

These triggers have write access or access to secrets, making exploitation more severe.

### output-clobbering-medium

Detects output clobbering in normal workflow contexts:
- `pull_request`
- `push`
- `schedule`
- `workflow_dispatch`

These triggers have limited permissions but can still lead to issues like incorrect build outputs or workflow logic bypass.

## Detection

The rule detects patterns like:
- `echo "name=${{ untrusted }}" >> $GITHUB_OUTPUT`
- `echo "name=${{ untrusted }}" >> "$GITHUB_OUTPUT"`
- `echo "name=${{ untrusted }}" >> '$GITHUB_OUTPUT'`
- `echo "name=${{ untrusted }}" >> ${GITHUB_OUTPUT}`
- `printf "name=${{ untrusted }}\n" >> "$GITHUB_OUTPUT"`

## Safe Patterns

### 1. Heredoc Syntax (Recommended)

The heredoc syntax prevents newline injection because the delimiter must match exactly:

```yaml
- name: Safe output
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    {
      echo "title<<EOF"
      echo "$PR_TITLE"
      echo "EOF"
    } >> "$GITHUB_OUTPUT"
```

### 2. Heredoc with Unique Delimiter

For extra security, use a random delimiter:

```yaml
- name: Safe output with unique delimiter
  env:
    PR_BODY: ${{ github.event.pull_request.body }}
  run: |
    DELIMITER="EOF_$(openssl rand -hex 16)"
    {
      echo "body<<$DELIMITER"
      echo "$PR_BODY"
      echo "$DELIMITER"
    } >> "$GITHUB_OUTPUT"
```

### 3. Sanitizing Input

Remove newlines before writing:

```yaml
- name: Sanitized output
  env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    SANITIZED=$(echo "$PR_TITLE" | tr -d '\n\r')
    echo "title=$SANITIZED" >> "$GITHUB_OUTPUT"
```

### 4. Using Environment Variable Indirection

Pass untrusted data through environment variables first:

```yaml
- name: Safe with env var
  env:
    COMMENT: ${{ github.event.comment.body }}
  run: |
    {
      echo "comment<<EOF"
      echo "$COMMENT"
      echo "EOF"
    } >> "$GITHUB_OUTPUT"
```

## Auto-Fix

The rule provides auto-fix that:
1. Moves untrusted expressions to step-level environment variables
2. Transforms vulnerable `echo "name=value"` patterns to heredoc syntax

Before:
```yaml
- run: |
    echo "title=${{ github.event.pull_request.title }}" >> "$GITHUB_OUTPUT"
```

After:
```yaml
- env:
    PR_TITLE: ${{ github.event.pull_request.title }}
  run: |
    {
      echo "title<<EOF_SISAKULINT"
      echo "$PR_TITLE"
      echo "EOF_SISAKULINT"
    } >> "$GITHUB_OUTPUT"
```

## Real-World Impact

Output clobbering can lead to:

1. **Security bypass**: Overwriting `approved=true` to bypass review requirements
2. **Build manipulation**: Modifying version numbers or build flags
3. **Deployment targeting**: Changing deployment targets or environments
4. **Workflow logic bypass**: Skipping security checks or validation steps

## Related Rules

- `envvar-injection-critical` / `envvar-injection-medium`: Similar vulnerability for `$GITHUB_ENV`
- `code-injection-critical` / `code-injection-medium`: Direct code injection in run scripts
- `untrusted-checkout`: Checkout of untrusted PR code in privileged contexts

## References

- [GitHub Actions Security Best Practices](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [GitHub Actions Workflow Commands](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#setting-an-output-parameter)
- [OWASP CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

---
title: "AI Action Unsafe Sandbox Rule"
weight: 1
---

### AI Action Unsafe Sandbox Rule Overview

This rule detects **AI agent actions configured with unsafe sandbox or safety-strategy settings**, which disable sandbox protections and allow the AI agent to execute with unrestricted system access.

**Affected Actions:**
- `anthropics/claude-code-action`
- `github/copilot-swe-agent`
- `openai/openai-actions`
- `openai/codex-action`

### Security Impact

**Severity: High**

Disabling sandbox protections on AI agent actions creates severe risk:

1. **Unrestricted System Access**: The AI agent can modify any file, install packages, and run arbitrary system commands without restrictions
2. **Privilege Escalation**: With `unsafe` or `danger-full-access`, the agent runs with full user privileges
3. **Secret Exfiltration**: No sandbox boundary prevents the agent from accessing and transmitting sensitive data
4. **Supply Chain Compromise**: Unrestricted agents can modify build artifacts, dependencies, or CI/CD configuration

This vulnerability aligns with **CWE-250: Execution with Unnecessary Privileges** and **OWASP CI/CD Security Risk CICD-SEC-6: Insufficient Credential Hygiene**.

### Detected Patterns

#### 1. Unsafe safety-strategy (Codex)

```yaml
name: Vulnerable Agent
on:
  issues:
    types: [opened]

jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: unsafe   # DANGEROUS: disables all sandbox protections
```

#### 2. Full access mode (Codex)

```yaml
steps:
  - uses: openai/codex-action@v1
    with:
      safety-strategy: danger-full-access   # DANGEROUS: maximum privileges
```

#### 3. Skip permissions (Claude Code Action)

```yaml
steps:
  - uses: anthropics/claude-code-action@v1
    with:
      claude_args: --dangerouslySkipPermissions   # DANGEROUS: bypasses all permission checks
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Detection Logic

The rule checks each AI agent action step for:

1. `safety-strategy` or `safety_strategy` input with values `unsafe` or `danger-full-access`
2. `claude_args` input containing the `--dangerouslySkipPermissions` flag

### Remediation Steps

1. **Use a safe sandbox strategy** (recommended)

   ```yaml
   - uses: openai/codex-action@v1
     with:
       safety-strategy: drop-sudo   # Default, drops sudo privileges
   ```

2. **Use stricter sandbox modes for sensitive operations**

   ```yaml
   - uses: openai/codex-action@v1
     with:
       safety-strategy: read-only   # Most restrictive: read-only filesystem
   ```

3. **Remove --dangerouslySkipPermissions from Claude Code Action**

   ```yaml
   - uses: anthropics/claude-code-action@v1
     with:
       claude_args: --allowedTools "Read,Glob,Grep"   # Explicit tool list instead
       anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
   ```

### Available Safety Strategies

| Strategy | Description | Risk |
|----------|-------------|------|
| `drop-sudo` | Drops sudo privileges (default) | Low |
| `unprivileged-user` | Runs as unprivileged user | Low |
| `read-only` | Read-only filesystem access | Minimal |
| `unsafe` | No sandbox restrictions | **Critical** |
| `danger-full-access` | Full unrestricted access | **Critical** |

### Best Practices

1. **Default to `drop-sudo`**: Use the default sandbox strategy unless you have a specific reason to change it.

2. **Use `read-only` for analysis tasks**: If the agent only needs to read and analyze code, use the most restrictive sandbox.

3. **Never use `unsafe` or `danger-full-access` in production**: These modes should only be used in development environments with full awareness of the risks.

4. **Combine with tool restrictions**: Even with sandbox protections, limit the tools available to the agent (see [AI Action Excessive Tools]({{< ref "aiactionexcessivetools.md" >}})).

### Complementary Rules

- [AI Action Excessive Tools]({{< ref "aiactionexcessivetools.md" >}}): Detects dangerous tool grants (Bash/Write/Edit) with untrusted triggers
- [AI Action Unrestricted Trigger]({{< ref "aiactionunrestrictedtrigger.md" >}}): Detects open access (`allowed_non_write_users: "*"`)
- [AI Action Prompt Injection]({{< ref "aiactionpromptinjection.md" >}}): Detects untrusted input in AI prompts

### References

- [OpenAI Codex GitHub Action Security Checklist](https://developers.openai.com/codex/github-action#security-checklist)
- [Anthropic: claude-code-action security](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md)
- [OWASP: CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

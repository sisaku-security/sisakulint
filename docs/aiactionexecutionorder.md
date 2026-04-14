---
title: "AI Action Execution Order Rule"
weight: 1
---

## AI Action Execution Order Rule Overview

This rule detects **AI agent actions that are not the last step in a job**. The OpenAI Codex security checklist recommends running AI agent actions as the final step to prevent subsequent steps from inheriting potentially compromised state.

**Affected Actions:**
- `anthropics/claude-code-action`
- `github/copilot-swe-agent`
- `openai/openai-actions`
- `openai/codex-action`

### Security Impact

**Severity: Medium**

Running steps after an AI agent action creates risk because the agent may have modified:

1. **Source Code**: Files in the workspace may have been altered by the agent
2. **Environment Variables**: The agent may have set or modified environment variables
3. **Build Artifacts**: Generated files may contain malicious content
4. **Configuration Files**: CI/CD configuration or package manifests may have been tampered with

If subsequent steps rely on any of these (e.g., `npm publish`, `docker push`, `terraform apply`), they may execute against compromised state.

This vulnerability aligns with **CWE-829: Inclusion of Functionality from Untrusted Control Sphere** and **OWASP CI/CD Security Risk CICD-SEC-4: Poisoned Pipeline Execution**.

**Vulnerable Example:**

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: openai/codex-action@v1
        with:
          safety-strategy: drop-sudo
      - run: npm publish    # DANGEROUS: publishes potentially modified code
```

**Detection Output:**

```bash
vulnerable.yaml:8:9: action "openai/codex-action@v1" is not the last step in this job. The OpenAI/Anthropic security checklist recommends running AI agent actions as the last step to prevent subsequent steps from inheriting potentially compromised state. [ai-action-execution-order]
      8 |       - uses: openai/codex-action@v1
```

### Detection Logic

The rule operates at the job level:

1. Iterates through all steps in a job
2. Identifies steps using a known AI agent action (by prefix match)
3. If an AI action step is found and it is not the last step, emits a warning

### Attack Scenario

```text
1. A workflow checks out code and runs an AI agent
2. The AI agent, potentially manipulated via prompt injection, modifies source files
3. A subsequent step (npm publish, docker build, terraform apply) executes
4. The modified code/config is deployed to production
5. Attacker achieves supply chain compromise through the AI agent
```

### Remediation Steps

1. **Move AI actions to the last step** (recommended)

   ```yaml
   steps:
     - uses: actions/checkout@v4
     - run: npm test            # Run tests BEFORE the AI agent
     - run: npm run build       # Build BEFORE the AI agent
     - uses: openai/codex-action@v1
       with:
         safety-strategy: drop-sudo
   ```

2. **Separate AI and deployment into different jobs**

   ```yaml
   jobs:
     ai-review:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: openai/codex-action@v1
           with:
             safety-strategy: read-only

     deploy:
       needs: ai-review
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4   # Fresh checkout, not affected by AI
         - run: npm publish
   ```

3. **Use read-only sandbox when followed by other steps**

   If you must have steps after the AI action, at minimum use `read-only` sandbox to prevent file modifications:

   ```yaml
   steps:
     - uses: openai/codex-action@v1
       with:
         safety-strategy: read-only   # Cannot modify files
     - run: npm publish               # Less risky with read-only sandbox
   ```

### Best Practices

1. **AI agent as last step**: Always place AI agent actions at the end of the job step list.

2. **Separate concerns**: Use different jobs for AI analysis and deployment/publishing.

3. **Fresh checkout for deployment**: If deploying after AI analysis, do a fresh `actions/checkout` in a separate job.

4. **Combine with sandbox restrictions**: Use `read-only` or `unprivileged-user` sandbox strategies when the AI agent doesn't need write access (see [AI Action Unsafe Sandbox]({{< ref "aiactionunsafesandbox.md" >}})).

### Complementary Rules

- [AI Action Unsafe Sandbox]({{< ref "aiactionunsafesandbox.md" >}}): Detects unsafe sandbox/safety-strategy settings
- [AI Action Excessive Tools]({{< ref "aiactionexcessivetools.md" >}}): Detects dangerous tool grants in untrusted triggers
- [AI Action Prompt Injection]({{< ref "aiactionpromptinjection.md" >}}): Detects untrusted input in AI prompts

### References

- [OpenAI Codex GitHub Action Security Checklist](https://developers.openai.com/codex/github-action#security-checklist)
- [Anthropic: claude-code-action security](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md)
- [OWASP: CI/CD Security Risk CICD-SEC-4](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

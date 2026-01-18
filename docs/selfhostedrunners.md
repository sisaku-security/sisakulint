---
title: "Self-Hosted Runners Rule"
weight: 1
---

### Self-Hosted Runners Rule Overview

This rule detects **use of self-hosted runners** which pose significant security risks in public repositories. Self-hosted runners can persist state between workflow runs, allowing attackers to execute arbitrary code via pull requests.

**Vulnerable Example:**

```yaml
name: Build
on: pull_request

jobs:
  build:
    runs-on: self-hosted  # DANGEROUS in public repos!
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
```

**Detection Output:**

```bash
vulnerable.yaml:6:5: self-hosted runner detected via direct label specification. Self-hosted runners in public repositories allow any user to run arbitrary code on your infrastructure. See https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security [self-hosted-runner]
      6 |    runs-on: self-hosted
```

### Security Background

#### What are Self-Hosted Runners?

Self-hosted runners are machines you manage to run GitHub Actions workflows. Unlike GitHub-hosted runners, they:

- Persist between workflow runs
- Can access your internal network
- May contain sensitive data or credentials
- Are not automatically cleaned between runs

#### Why is this dangerous in public repos?

| Risk Factor | Impact |
|-------------|--------|
| **Arbitrary Code Execution** | Anyone can open a PR and run code |
| **State Persistence** | Malware persists between runs |
| **Network Access** | Attacker accesses internal resources |
| **Credential Theft** | Cached credentials exposed |
| **Lateral Movement** | Pivot point into infrastructure |

#### Attack Scenario

```
1. Public repo uses self-hosted runner
2. Attacker forks repo
3. Attacker modifies workflow to run malicious code
4. Attacker opens PR
5. Workflow triggers on self-hosted runner
6. Malicious code executes:
   - Installs backdoor
   - Steals credentials from environment
   - Accesses internal network
   - Persists for future workflows
```

#### OWASP and CWE Mapping

- **CWE-250**: Execution with Unnecessary Privileges
- **CWE-269**: Improper Privilege Management
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-1:** Insufficient Flow Control Mechanisms
  - **CICD-SEC-7:** Insecure System Configuration

### Detection Logic

#### What Gets Detected

1. **Direct self-hosted label**
   ```yaml
   runs-on: self-hosted
   runs-on: [self-hosted, linux]
   ```

2. **Runner group usage**
   ```yaml
   runs-on:
     group: my-runner-group
   ```

3. **Matrix with self-hosted**
   ```yaml
   strategy:
     matrix:
       runner: [self-hosted, ubuntu-latest]
   runs-on: ${{ matrix.runner }}
   ```

4. **Expression containing self-hosted**
   ```yaml
   runs-on: ${{ contains(inputs.runner, 'self-hosted') && 'self-hosted' || 'ubuntu-latest' }}
   ```

#### Safe Patterns (NOT Detected)

GitHub-hosted runners:
```yaml
runs-on: ubuntu-latest
runs-on: windows-latest
runs-on: macos-latest
```

### Remediation Steps

1. **Use GitHub-hosted runners for public repos**
   ```yaml
   runs-on: ubuntu-latest
   ```

2. **If self-hosted is required, make repo private**
   - Convert public repos to private
   - Use GitHub Enterprise with restricted access

3. **Implement runner isolation**
   - Use ephemeral runners that are destroyed after each job
   - Use container-based isolation
   - Implement network segmentation

4. **Restrict workflow triggers**
   ```yaml
   on:
     pull_request_target:  # Runs on base, not fork
       types: [labeled]
   ```

### Best Practices

1. **Never use self-hosted runners in public repos**
   - This is GitHub's official recommendation
   - Use GitHub-hosted runners instead

2. **For private repos with self-hosted runners**
   ```yaml
   # Use ephemeral runners
   runs-on: [self-hosted, ephemeral]

   # Or use containers
   container: node:18
   ```

3. **Implement runner security measures**
   - Enable runner auto-updates
   - Use dedicated runner accounts
   - Implement network isolation
   - Monitor runner activity

4. **Use larger GitHub-hosted runners**
   - For more resources, use larger runners
   - Available through GitHub Actions billing

### Alternative Approaches

1. **GitHub-hosted larger runners**
   ```yaml
   runs-on: ubuntu-latest-8-cores
   ```

2. **Self-hosted with strict controls**
   ```yaml
   # Only for internal workflows, not PRs
   on:
     push:
       branches: [main]

   jobs:
     build:
       if: github.repository_owner == 'your-org'
       runs-on: self-hosted
   ```

3. **Use pull_request_target with caution**
   ```yaml
   on:
     pull_request_target:
       types: [labeled]

   jobs:
     build:
       if: contains(github.event.pull_request.labels.*.name, 'safe-to-test')
       runs-on: self-hosted
   ```

### References

- [GitHub: Self-hosted runner security](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [GitHub: Using larger runners](https://docs.github.com/en/actions/using-github-hosted-runners/using-larger-runners)

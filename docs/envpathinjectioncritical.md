---
title: "PATH Injection Rule (Critical)"
weight: 10
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### PATH Injection Rule (Critical) Overview

This rule detects PATH injection vulnerabilities when untrusted input is written to `$GITHUB_PATH` within **privileged workflow contexts**. Privileged workflows have write permissions or access to secrets, making PATH injection particularly dangerous as attackers can hijack command execution by prepending malicious directories.

#### Key Features:

- **Privileged Context Detection**: Identifies dangerous patterns in `pull_request_target`, `workflow_run`, `issue_comment`, and other privileged triggers
- **GITHUB_PATH Write Detection**: Analyzes scripts that write to `$GITHUB_PATH` file
- **Auto-fix Support**: Automatically validates paths using `realpath` before writing to $GITHUB_PATH
- **Zero False Positives**: Does not flag already-safe patterns with proper path validation

### Security Impact

**Severity: Critical (9/10)**

PATH injection in privileged workflows represents a critical vulnerability in GitHub Actions:

1. **Command Hijacking**: Attackers can prepend malicious directories to PATH, causing legitimate commands to execute attacker-controlled binaries
2. **Build Process Compromise**: The `npm`, `pip`, `go`, or other build tools can be replaced with malicious versions
3. **Secret Exfiltration**: Replaced commands can capture secrets and credentials passed as arguments
4. **Supply Chain Attacks**: Compromised build tools can inject backdoors into artifacts
5. **Persistence Across Steps**: PATH modifications persist throughout the job, affecting all subsequent commands

This vulnerability is classified as **CWE-426: Untrusted Search Path** and **CWE-427: Uncontrolled Search Path Element**, and aligns with OWASP CI/CD Security Risk **CICD-SEC-04: Poisoned Pipeline Execution (PPE)**.

### Privileged Workflow Triggers

The following triggers are considered privileged because they run with write access or secrets:

- **`pull_request_target`**: Runs with write permissions and secrets, but triggered by untrusted PRs
- **`workflow_run`**: Executes with elevated privileges after another workflow completes
- **`issue_comment`**: Triggered by comments from any user, including external contributors
- **`issues`**: Triggered by issue events, potentially from untrusted sources
- **`discussion_comment`**: Triggered by discussion comments from any user

### Example Vulnerable Workflow

Consider this dangerous workflow that writes PR data to `$GITHUB_PATH` in a privileged context:

```yaml
name: Build PR Tools

on:
  pull_request_target:  # PRIVILEGED: Has write access and secrets
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # CRITICAL VULNERABILITY: Untrusted path written to GITHUB_PATH
      - name: Add PR tools to PATH
        run: |
          echo "${{ github.event.pull_request.head.ref }}/tools" >> "$GITHUB_PATH"

      - name: Build
        run: |
          npm install  # Could execute malicious 'npm' from attacker's path!
          npm run build
```

### Attack Scenario

**How PATH Injection Exploits Privileged Workflows:**

1. **Attacker Creates Malicious PR**: Opens a PR with a branch name crafted to inject a path:
   ```
   Branch: ../../tmp/evil
   ```
   Or uses a crafted directory structure containing malicious binaries.

2. **Workflow Triggers**: `pull_request_target` runs with write permissions and secrets

3. **PATH Hijacked**: The malicious path is prepended to $GITHUB_PATH:
   ```bash
   # Attacker's path gets added
   echo "../../tmp/evil/tools" >> "$GITHUB_PATH"
   # Now PATH becomes: /tmp/evil/tools:/usr/local/bin:/usr/bin:...
   ```

4. **Commands Hijacked**: Subsequent steps execute attacker-controlled binaries:
   ```yaml
   - name: Build and deploy
     run: |
       npm install  # Executes /tmp/evil/tools/npm instead of real npm
       python setup.py build  # Executes attacker's python
   ```

5. **Code Execution Achieved**: The attacker's fake `npm` or `python`:
   - Captures all arguments (including secrets)
   - Exfiltrates credentials via network calls
   - Injects backdoors into build artifacts
   - Modifies source code before compilation

### What Makes This Critical

**Privileged workflows with PATH injection are particularly dangerous because:**

1. **Write Access**: Workflows can modify repository content, create releases, and manage secrets
2. **Command Interception**: Unlike code injection, PATH hijacking intercepts ALL commands
3. **Stealth**: Fake commands can call real commands after exfiltration, hiding the attack
4. **Supply Chain Impact**: Compromised builds can poison production deployments

### Safe Pattern (Using Path Validation with realpath)

The recommended approach is to validate paths using `realpath`:

```yaml
name: Build PR Tools (Safe)

on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # SAFE: Validate path before adding to GITHUB_PATH
      - name: Add tools to PATH safely
        env:
          PR_REF_PATH: ${{ github.event.pull_request.head.ref }}
        run: |
          # realpath resolves the path and ensures it's absolute and canonical
          # This prevents path traversal attacks
          echo "$(realpath "$PR_REF_PATH")/tools" >> "$GITHUB_PATH"

      - name: Build
        run: |
          npm install  # Safe - PATH contains validated paths only
          npm run build
```

### Auto-Fix Example

sisakulint can automatically fix this vulnerability:

**Before (Vulnerable):**
```yaml
- name: Add tools to PATH
  run: |
    echo "${{ github.event.pull_request.head.ref }}/bin" >> "$GITHUB_PATH"
```

**After Auto-Fix (Safe):**
```yaml
- name: Add tools to PATH
  env:
    PR_HEAD_REF_PATH: ${{ github.event.pull_request.head.ref }}
  run: |
    echo "$(realpath "$PR_HEAD_REF_PATH")/bin" >> "$GITHUB_PATH"
```

### Detection Details

The rule detects:

1. **Direct writes to $GITHUB_PATH** using various formats:
   - `>> $GITHUB_PATH`
   - `>> "$GITHUB_PATH"`
   - `>> '${GITHUB_PATH}'`
   - `>>$GITHUB_PATH`

2. **Untrusted input sources** including:
   - `github.event.pull_request.head.ref`
   - `github.event.pull_request.head.sha`
   - `github.event.issue.title`
   - `github.event.comment.body`
   - And other user-controlled fields

3. **Privileged workflow triggers** where the impact is critical

### Why This Pattern is Dangerous

Writing untrusted input to `$GITHUB_PATH` without validation allows attackers to:

1. **Path Traversal**: Use `../` sequences to reference directories outside the workspace
2. **Command Hijacking**: Place malicious executables that shadow legitimate commands
3. **Build Tool Replacement**: Replace `npm`, `pip`, `go`, `cargo`, etc. with trojaned versions
4. **Persistent Compromise**: The modified PATH affects ALL subsequent steps

### Real-World Impact

PATH injection in privileged workflows can lead to:

- **Supply Chain Compromise**: Trojaned build tools inject backdoors into releases
- **Secret Theft**: Fake commands capture GITHUB_TOKEN and other secrets
- **Repository Takeover**: With write permissions, attackers can push malicious code
- **Artifact Poisoning**: Modified builds contain hidden malware

### Related Rules

- **[envpath-injection-medium]({{< ref "envpathinjectionmedium.md" >}})**: Detects the same pattern in normal (non-privileged) workflows
- **[envvar-injection-critical]({{< ref "envvarinjectioncritical.md" >}})**: Detects environment variable injection via $GITHUB_ENV
- **[code-injection-critical]({{< ref "codeinjectioncritical.md" >}})**: Detects direct code injection in privileged contexts
- **[untrustedcheckout]({{< ref "untrustedcheckout.md" >}})**: Detects unsafe checkout of PR code

### References

- [CodeQL: PATH Injection (Critical)](https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-critical/)
- [GitHub Security: Script Injection](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [OWASP: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

### Testing

To test this rule with example workflows:

```bash
# Detect vulnerable patterns
sisakulint script/actions/envpath-injection-critical.yaml

# Apply auto-fix
sisakulint -fix on script/actions/envpath-injection-critical.yaml
```

### Configuration

This rule is enabled by default. To disable it, use:

```bash
sisakulint -ignore envpath-injection-critical
```

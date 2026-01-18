---
title: "PATH Injection Rule (Medium)"
weight: 10
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### PATH Injection Rule (Medium) Overview

This rule detects PATH injection vulnerabilities when untrusted input is written to `$GITHUB_PATH` within **normal workflow contexts**. While these workflows have limited permissions compared to privileged triggers, PATH injection can still lead to command hijacking and build process compromise.

#### Key Features:

- **Normal Trigger Detection**: Identifies dangerous patterns in `pull_request`, `push`, `schedule`, and other normal triggers
- **GITHUB_PATH Write Detection**: Analyzes scripts that write to `$GITHUB_PATH` file
- **Auto-fix Support**: Automatically validates paths using `realpath` before writing to $GITHUB_PATH
- **Zero False Positives**: Does not flag already-safe patterns with proper path validation

### Security Impact

**Severity: Medium (6/10)**

PATH injection in normal workflows represents a moderate vulnerability in GitHub Actions:

1. **Command Hijacking**: Attackers can prepend malicious directories to PATH
2. **Build Process Compromise**: Build tools can be replaced with malicious versions
3. **Limited Blast Radius**: Normal triggers typically have read-only permissions
4. **Fork-Based Attacks**: External contributors can exploit this via fork PRs
5. **Persistence Across Steps**: PATH modifications persist throughout the job

This vulnerability is classified as **CWE-426: Untrusted Search Path** and **CWE-427: Uncontrolled Search Path Element**.

### Normal Workflow Triggers

The following triggers are considered normal (non-privileged):

- **`pull_request`**: Runs with read-only permissions on fork PRs
- **`push`**: Triggered by pushes to the repository
- **`schedule`**: Runs on a cron schedule
- **`workflow_dispatch`**: Manually triggered workflows
- **`release`**: Triggered by release events

### Example Vulnerable Workflow

Consider this workflow that writes user input to `$GITHUB_PATH`:

```yaml
name: Build with Custom Tools

on:
  pull_request:  # Normal trigger with limited permissions
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # MEDIUM VULNERABILITY: Untrusted path written to GITHUB_PATH
      - name: Add PR tools to PATH
        run: |
          echo "${{ github.head_ref }}/tools" >> "$GITHUB_PATH"

      - name: Build
        run: |
          make build  # Could execute malicious 'make' from attacker's path
```

### Attack Scenario

**How PATH Injection Can Be Exploited in Normal Workflows:**

1. **Attacker Forks Repository**: Creates a fork and opens a PR

2. **Malicious Branch Name**: Uses a crafted branch name:
   ```
   Branch: ../../../tmp/evil
   ```

3. **PATH Modified**: The workflow adds the attacker-controlled path:
   ```bash
   echo "../../../tmp/evil/tools" >> "$GITHUB_PATH"
   ```

4. **Commands Potentially Hijacked**: If the attacker can place binaries:
   ```yaml
   - name: Build
     run: |
       make build  # May execute attacker's 'make' if path resolves
   ```

5. **Limited Impact**: In normal workflows:
   - Read-only GITHUB_TOKEN limits damage
   - Cannot push to repository directly
   - But can still affect build artifacts and logs

### Why Medium Severity

**Normal workflows with PATH injection are less dangerous because:**

1. **Read-Only Access**: Fork PRs get read-only GITHUB_TOKEN
2. **No Secrets by Default**: Secrets aren't available in fork PR workflows
3. **Limited Repository Access**: Cannot modify repository content
4. **Contained Blast Radius**: Damage limited to the workflow run

**However, risks remain:**

- Build artifacts may be poisoned
- CI test results can be manipulated
- Workflow logs may leak information
- Self-hosted runners could be compromised

### Safe Pattern (Using Path Validation with realpath)

The recommended approach is to validate paths using `realpath`:

```yaml
name: Build with Custom Tools (Safe)

on:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # SAFE: Validate path before adding to GITHUB_PATH
      - name: Add tools to PATH safely
        env:
          HEAD_REF_PATH: ${{ github.head_ref }}
        run: |
          # realpath resolves the path and ensures it's absolute and canonical
          echo "$(realpath "$HEAD_REF_PATH")/tools" >> "$GITHUB_PATH"

      - name: Build
        run: |
          make build  # Safe - PATH contains validated paths only
```

### Auto-Fix Example

sisakulint can automatically fix this vulnerability:

**Before (Vulnerable):**
```yaml
- name: Add tools to PATH
  run: |
    echo "${{ github.head_ref }}/bin" >> "$GITHUB_PATH"
```

**After Auto-Fix (Safe):**
```yaml
- name: Add tools to PATH
  env:
    HEAD_REF_PATH: ${{ github.head_ref }}
  run: |
    echo "$(realpath "$HEAD_REF_PATH")/bin" >> "$GITHUB_PATH"
```

### Detection Details

The rule detects:

1. **Direct writes to $GITHUB_PATH** using various formats:
   - `>> $GITHUB_PATH`
   - `>> "$GITHUB_PATH"`
   - `>> '${GITHUB_PATH}'`
   - `>>$GITHUB_PATH`

2. **Untrusted input sources** including:
   - `github.head_ref`
   - `github.event.pull_request.head.ref`
   - `github.event.issue.title`
   - And other user-controlled fields

3. **Normal workflow triggers** where the impact is medium

### Comparison with Critical Severity

| Aspect | Medium (Normal Triggers) | Critical (Privileged Triggers) |
|--------|-------------------------|-------------------------------|
| Permissions | Read-only | Write access |
| Secrets | Not available (forks) | Available |
| Repository Access | Cannot modify | Can modify |
| Impact | Limited | Severe |
| Example Triggers | `pull_request`, `push` | `pull_request_target`, `workflow_run` |

### Related Rules

- **[envpath-injection-critical]({{< ref "envpathinjectioncritical.md" >}})**: Detects the same pattern in privileged workflows
- **[envvar-injection-medium]({{< ref "envvarinjectionmedium.md" >}})**: Detects environment variable injection via $GITHUB_ENV
- **[code-injection-medium]({{< ref "codeinjectionmedium.md" >}})**: Detects direct code injection in normal contexts

### References

- [CodeQL: PATH Injection (Medium)](https://codeql.github.com/codeql-query-help/actions/actions-envpath-injection-medium/)
- [GitHub Security: Script Injection](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections)
- [OWASP: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html)

### Testing

To test this rule with example workflows:

```bash
# Detect vulnerable patterns
sisakulint script/actions/envpath-injection-medium.yaml

# Apply auto-fix
sisakulint -fix on script/actions/envpath-injection-medium.yaml
```

### Configuration

This rule is enabled by default. To disable it, use:

```bash
sisakulint -ignore envpath-injection-medium
```

Note: Disabling this rule is generally not recommended, as PATH injection can still cause issues even in normal workflows.

---
title: "Obfuscation Rule"
weight: 1
---

### Obfuscation Rule Overview

This rule detects **obfuscated workflow patterns** that may be used to evade security scanners. Obfuscation techniques can hide malicious behavior from code review and automated security tools.

### Security Impact

**Severity: High (7/10)**

Obfuscated workflow patterns pose significant detection evasion risks:

1. **Security Scanner Bypass**: Malicious code hidden from automated analysis tools
2. **Code Review Evasion**: Obfuscated patterns difficult for humans to identify
3. **Payload Concealment**: Encoded commands hide actual malicious behavior
4. **Persistence**: Undetected malicious workflows remain active indefinitely

This vulnerability aligns with **CWE-116: Improper Encoding or Escaping of Output** and **OWASP CI/CD Security Risk CICD-SEC-4: Poisoned Pipeline Execution**.

**Vulnerable Example:**

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # SUSPICIOUS: Path contains obfuscation
      - uses: actions/checkout/./src/../@v4
      - name: Run script
        shell: cmd
        run: |
          set CMD=po
          set CMD=%CMD%wershell
          %CMD% -encodedcommand ZWNobyAiSGVsbG8i
```

**Detection Output:**

```bash
vulnerable.yaml:9:9: obfuscated action path detected: 'actions/checkout/./src/../@v4' contains '.' (current directory reference), '..' (parent directory traversal). This may indicate an attempt to evade security scanners. [obfuscation]
      9 |      - uses: actions/checkout/./src/../@v4

vulnerable.yaml:12:9: obfuscated shell command detected: 'cmd' shell with PowerShell invocation pattern. This may indicate an attempt to hide malicious commands. [obfuscation]
     12 |        run: |
```

### Security Background

#### What is Workflow Obfuscation?

Attackers may use various techniques to hide malicious code in workflows:

1. **Path Obfuscation**: Using `.`, `..`, or empty path segments
2. **Shell Obfuscation**: Using `cmd` shell to invoke PowerShell
3. **Variable Concatenation**: Building commands from parts
4. **Encoded Commands**: Base64 encoded PowerShell commands

#### Why is this dangerous?

| Technique | Risk |
|-----------|------|
| **Path Traversal** | May resolve to unexpected actions |
| **Shell Switching** | Hides actual command being run |
| **String Building** | Evades pattern-based detection |
| **Encoding** | Hides payload from review |

#### OWASP and CWE Mapping

- **CWE-116**: Improper Encoding or Escaping of Output
- **CWE-94**: Improper Control of Generation of Code
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Detection Logic

#### Path Obfuscation Detection

Detects suspicious path patterns in `uses`:

```yaml
# Detected patterns:
uses: owner/repo/./action@v1      # Current directory reference
uses: owner/repo/../other@v1      # Parent directory traversal
uses: owner/repo//action@v1       # Empty path component
```

#### Shell Obfuscation Detection

Detects suspicious shell usage:

```yaml
# Detected patterns:
shell: cmd
run: powershell ...               # PowerShell via cmd

shell: cmd
run: |
  set X=power
  %X%shell ...                    # Variable concatenation
```

#### What Is NOT Detected (Legitimate Patterns)

Normal action references:
```yaml
- uses: actions/checkout@v4
- uses: owner/repo/subdir/action@v1
```

Standard shell usage:
```yaml
- run: echo "Hello"
- shell: bash
  run: ./script.sh
```

### Auto-Fix

This rule supports automatic fixing for path obfuscation. When you run sisakulint with the `-fix on` flag, it will normalize obfuscated paths.

**Example:**

Before auto-fix:
```yaml
- uses: actions/checkout/./src/../@v4
```

After running `sisakulint -fix on`:
```yaml
- uses: actions/checkout@v4
```

### Remediation Steps

1. **Normalize action paths**
   ```yaml
   # Instead of: actions/checkout/./src/../@v4
   - uses: actions/checkout@v4
   ```

2. **Use explicit shell**
   ```yaml
   # Instead of cmd + powershell
   - shell: pwsh
     run: echo "Hello"
   ```

3. **Avoid variable concatenation for commands**
   ```yaml
   # Instead of building command names
   - run: npm install
   ```

4. **Review encoded commands**
   - Decode and inspect any base64 content
   - Prefer plain text commands

### Best Practices

1. **Use standard action references**
   ```yaml
   - uses: owner/repo@v1
   - uses: owner/repo/subdir@v1
   ```

2. **Use appropriate shells directly**
   ```yaml
   - shell: bash
     run: ./script.sh
   - shell: pwsh
     run: Get-Process
   ```

3. **Keep commands readable**
   - Avoid unnecessary encoding
   - Use comments for complex scripts
   - Store scripts in files when they're long

4. **Review third-party actions**
   - Check for obfuscation in action code
   - Prefer well-maintained official actions

### References

- [GitHub: Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)
- [zizmor: Obfuscation Detection](https://github.com/woodruffw/zizmor)
- [OWASP: Code Injection](https://owasp.org/www-community/attacks/Code_Injection)

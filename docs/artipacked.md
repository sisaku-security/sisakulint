---
title: "Artipacked Rule"
weight: 1
---

### Artipacked Rule Overview

This rule detects **credential leakage vulnerabilities** when `actions/checkout` credentials are persisted and the workspace is subsequently uploaded via `actions/upload-artifact`. This can expose the `GITHUB_TOKEN` stored in `.git/config`.

**Security Severity: High (checkout < v6) / Medium (checkout >= v6)**

**Vulnerable Example:**

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        # persist-credentials defaults to true, storing token in .git/config

      - run: npm ci && npm run build

      - uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: .  # DANGEROUS: Uploads entire workspace including .git/config!
```

**Detection Output:**

```bash
vulnerable.yaml:7:9: [High] actions/checkout without 'persist-credentials: false' followed by actions/upload-artifact with dangerous path '.'. The GITHUB_TOKEN stored in .git/config may be leaked. See https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/ [artipacked]
      7 |      - uses: actions/checkout@v4
```

### Security Background

#### What is Artipacked?

"Artipacked" refers to a vulnerability where authentication credentials from `actions/checkout` are inadvertently included in uploaded artifacts.

By default, `actions/checkout`:
- Stores the `GITHUB_TOKEN` in `.git/config` for subsequent git operations
- This behavior is controlled by `persist-credentials` (default: `true`)

When `actions/upload-artifact` uploads the workspace (`.`, `./`, or `${{ github.workspace }}`), the `.git/config` file containing the token is included.

#### Credential Storage Location

| Checkout Version | Credential Location |
|------------------|---------------------|
| v1 - v5 | `.git/config` |
| v6+ | `$RUNNER_TEMP` |

#### Attack Scenario

```
1. Workflow checks out code (credentials stored in .git/config)
2. Build process runs
3. Artifact upload includes entire workspace
4. Attacker downloads artifact from GitHub UI
5. Attacker extracts GITHUB_TOKEN from .git/config
6. Token used to access repository with workflow's permissions
```

#### Why is this dangerous?

| Risk Factor | Impact |
|-------------|--------|
| **Token Exposure** | GITHUB_TOKEN leaked in artifact |
| **Public Access** | Anyone with repo access can download artifacts |
| **Persistent** | Artifacts retained for 90 days by default |
| **Privilege Abuse** | Token has workflow's permissions |

#### OWASP and CWE Mapping

- **CWE-522**: Insufficiently Protected Credentials
- **CWE-312**: Cleartext Storage of Sensitive Information
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-6:** Insufficient Credential Hygiene

### Detection Logic

#### What Gets Detected

1. **Checkout without persist-credentials: false + dangerous upload**
   ```yaml
   - uses: actions/checkout@v4
   - uses: actions/upload-artifact@v4
     with:
       path: .
   ```

2. **Dangerous upload paths**
   ```yaml
   path: .           # Current directory
   path: ./          # Current directory
   path: ..          # Parent directory
   path: ${{ github.workspace }}
   ```

3. **Checkout without dangerous upload (warning)**
   ```yaml
   - uses: actions/checkout@v4
     # Warning: credentials persisted, consider adding persist-credentials: false
   ```

#### Safe Patterns (NOT Detected)

Explicit credential disable:
```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: false
```

Specific path upload:
```yaml
- uses: actions/upload-artifact@v4
  with:
    path: dist/  # Only uploads dist directory
```

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will add `persist-credentials: false` to checkout steps.

**Example:**

Before auto-fix:
```yaml
- uses: actions/checkout@v4
```

After running `sisakulint -fix on`:
```yaml
- uses: actions/checkout@v4
  with:
    persist-credentials: false
```

### Remediation Steps

1. **Disable credential persistence**
   ```yaml
   - uses: actions/checkout@v4
     with:
       persist-credentials: false
   ```

2. **Upload specific paths only**
   ```yaml
   - uses: actions/upload-artifact@v4
     with:
       path: |
         dist/
         build/
         !.git/
   ```

3. **Exclude .git from uploads**
   ```yaml
   - uses: actions/upload-artifact@v4
     with:
       path: .
       exclude: .git/**
   ```

4. **Use checkout v6+**
   - Credentials stored outside workspace
   - Still recommended to disable persistence

### Best Practices

1. **Always set persist-credentials: false**
   ```yaml
   - uses: actions/checkout@v4
     with:
       persist-credentials: false
   ```

2. **Be specific with artifact paths**
   ```yaml
   - uses: actions/upload-artifact@v4
     with:
       path: dist/  # Only what's needed
   ```

3. **Review artifact contents**
   - Download and inspect artifacts periodically
   - Check for sensitive files

4. **Use .gitignore patterns**
   - Ensure sensitive files are excluded
   - Consider using `.artifactignore`

### References

- [Unit42: GitHub Repo Artifacts Leak Tokens](https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/)
- [GitHub: actions/checkout persist-credentials](https://github.com/actions/checkout#persist-credentials)
- [zizmor: Artipacked Detection](https://github.com/woodruffw/zizmor)
- [GitHub: Storing workflow data as artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts)

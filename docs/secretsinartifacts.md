---
title: "Secrets in Artifacts Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Secrets in Artifacts Rule Overview

This rule detects when sensitive information may be included in GitHub Actions artifacts. It identifies patterns where artifacts could expose secrets like GITHUB_TOKEN, environment files, or entire repositories including the `.git` directory.

#### Key Features

- **Version Detection**: Identifies upload-artifact v3 and earlier (include hidden files by default)
- **Path Analysis**: Detects broad paths (`.`, `**`) that may include sensitive files
- **Sensitive File Detection**: Identifies explicit uploads of `.git`, `.env`, `.aws`, `.ssh`, etc.
- **Auto-Fix Support**: Adds `include-hidden-files: false` for v3 and earlier
- **CodeQL Compatible**: Based on CodeQL's actions-secrets-in-artifacts query

#### Security Severity: 7.5/10
**CWE-312**: Cleartext Storage of Sensitive Information

### Detection Patterns

The rule triggers when any of the following patterns are detected:

| Pattern | Version | Risk Level | Description |
|---------|---------|------------|-------------|
| `upload-artifact@v3` | v1-v3 | High | Includes hidden files by default, exposing `.git` directory |
| `upload-artifact@v2` | v1-v3 | High | Same as v3 |
| `upload-artifact@v1` | v1-v3 | High | Same as v3 |
| `path: .` + `include-hidden-files: true` | v4+ | High | Explicitly enables hidden files with broad path |
| `path: .env` | Any | High | Directly uploads environment files |
| `path: .git` | Any | High | Directly uploads git directory with tokens |
| `path: .aws` | Any | High | Uploads AWS credentials |
| `path: .ssh` | Any | High | Uploads SSH keys |

### Why This Is Dangerous

1. **GITHUB_TOKEN Exposure**: The `.git` directory contains GITHUB_TOKEN credentials
2. **Credential Leakage**: Environment files (`.env`) may contain API keys, passwords
3. **Configuration Exposure**: AWS/SSH configs contain access credentials
4. **Public Artifacts**: Artifacts may be accessible to unauthorized users

### Known Limitations

**Important**: This rule only detects semantic versions (`v1`, `v2`, `v3`, `v4`).

Actions using **SHA commits** or **branch names** are not analyzed:
- ❌ `actions/upload-artifact@6b208ae` (SHA commit - not detected)
- ❌ `actions/upload-artifact@main` (branch name - not detected)
- ✅ `actions/upload-artifact@v3` (semantic version - detected)

This limitation is by design for **simplicity** and **offline operation**.

**Future Enhancement**: GitHub API integration to resolve SHA/branch versions is tracked in [issue #297](https://github.com/sisaku-security/sisakulint/issues/297).

### Example Vulnerable Workflows

#### Example 1: upload-artifact v3 (Default Includes Hidden Files)

```yaml
name: Vulnerable Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ❌ VULNERABLE: v3 includes hidden files by default
      # This exposes .git directory containing GITHUB_TOKEN
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: build-output
          path: dist/
```

**Why it's vulnerable**: Even though `path: dist/`, v3 includes hidden files like `.git` by default.

#### Example 2: v4 with include-hidden-files: true

```yaml
name: Vulnerable Upload
on: push

jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ❌ VULNERABLE: Explicitly enabling hidden files with broad path
      - name: Upload entire repo
        uses: actions/upload-artifact@v4
        with:
          name: repo-snapshot
          path: .
          include-hidden-files: true  # Exposes .git, .env, etc.
```

#### Example 3: Direct Upload of Sensitive Files

```yaml
name: Config Upload
on: push

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ❌ VULNERABLE: Directly uploading environment file
      - name: Upload env file
        uses: actions/upload-artifact@v4
        with:
          name: config
          path: .env  # Contains API keys, passwords
```

### Secure Alternatives

#### Fix 1: Upgrade to v4 (Default is Safe)

```yaml
name: Secure Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ✅ SECURE: v4 excludes hidden files by default
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: build-output
          path: dist/
```

#### Fix 2: Add include-hidden-files: false for v3

```yaml
name: Secure Build (v3)
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # ✅ SECURE: Explicitly disable hidden files
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: build-output
          path: dist/
          include-hidden-files: false  # Prevents .git exposure
```

#### Fix 3: Use Specific Paths

```yaml
name: Secure Upload
on: push

jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm run build

      # ✅ SECURE: Only upload specific build output
      - name: Upload build
        uses: actions/upload-artifact@v4
        with:
          name: artifacts
          path: |
            dist/bundle.js
            dist/styles.css
            build/output/
```

### Auto-Fix Behavior

The rule provides automatic fixes for:

1. **v3 and earlier**: Adds `include-hidden-files: false`
   ```yaml
   # Before
   uses: actions/upload-artifact@v3

   # After (auto-fixed)
   uses: actions/upload-artifact@v3
   with:
     include-hidden-files: false
   ```

2. **v4+ with include-hidden-files: true**: Sets to `false`
   ```yaml
   # Before
   uses: actions/upload-artifact@v4
   with:
     include-hidden-files: true

   # After (auto-fixed)
   uses: actions/upload-artifact@v4
   with:
     include-hidden-files: false
   ```

**Note**: Direct uploads of sensitive files (`.env`, `.git`) are flagged but **not auto-fixed**, as the user may have intentional reasons.

### Testing

Run sisakulint with auto-fix dry-run to preview changes:

```bash
# Preview auto-fix changes
sisakulint -fix dry-run

# Apply auto-fix
sisakulint -fix on
```

### Additional Sensitive Patterns

The rule also detects uploads of:
- `.git` - Git directory with credentials
- `.env`, `.env.local` - Environment variable files
- `.npmrc` - NPM registry tokens
- `.pypirc` - PyPI credentials
- `.aws` - AWS credentials
- `.kube` - Kubernetes config
- `.ssh` - SSH private keys
- `credentials.json` - Generic credential files
- `secrets.*` - Secret configuration files

### Best Practices

1. **Always use v4+** for upload-artifact
2. **Use specific paths** instead of `.` or `**`
3. **Never upload configuration directories** (`.aws`, `.ssh`, `.kube`)
4. **Review artifact contents** before uploading
5. **Use artifact retention policies** to auto-delete old artifacts
6. **Limit artifact access** with appropriate permissions

### References

- [CodeQL Query: actions-secrets-in-artifacts](https://codeql.github.com/codeql-query-help/actions/actions-secrets-in-artifacts/)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [GitHub Actions: upload-artifact v4 Changes](https://github.blog/changelog/2024-02-12-deprecation-notice-v3-of-the-artifact-actions/)
- [Issue #297: Enhancement for SHA/branch version detection](https://github.com/sisaku-security/sisakulint/issues/297)

### Related Rules

- `commit-sha` - Enforces commit SHA pinning for actions
- `credential` - Detects hardcoded credentials
- `artifact-poisoning-critical` - Detects artifact poisoning attacks

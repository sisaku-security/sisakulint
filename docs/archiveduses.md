---
title: "Archived Uses Rule"
weight: 1
---

### Archived Uses Rule Overview

This rule detects **usage of actions or reusable workflows from archived repositories** that are no longer maintained. Using archived actions poses security risks as they no longer receive security updates or bug fixes.

### Security Impact

**Severity: Medium (5/10)**

Using archived actions poses maintenance and security risks:

1. **No Security Patches**: Known vulnerabilities remain unfixed indefinitely
2. **Dependency Rot**: Outdated dependencies accumulate CVEs over time
3. **No Support**: Issues and security reports are ignored
4. **Supply Chain Risk**: Unmaintained actions become targets for attackers

This vulnerability aligns with **CWE-1104: Use of Unmaintained Third Party Components** and **OWASP CI/CD Security Risk CICD-SEC-3: Dependency Chain Abuse**.

**Vulnerable Example:**

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rs/toolchain@v1  # ARCHIVED: No longer maintained!
        with:
          toolchain: stable
```

**Detection Output:**

```bash
vulnerable.yaml:9:9: archived action detected: 'actions-rs/toolchain' is from an archived repository that is no longer maintained. Archived actions may contain unfixed security vulnerabilities and should be replaced with actively maintained alternatives. [archived-uses]
      9 |      - uses: actions-rs/toolchain@v1
```

### Security Background

#### What are Archived Repositories?

Archived repositories are read-only and no longer receive:
- Security updates
- Bug fixes
- Feature improvements
- Dependency updates

#### Why is this dangerous?

| Risk Factor | Impact |
|-------------|--------|
| **No Security Patches** | Known vulnerabilities remain unfixed |
| **Dependency Rot** | Outdated dependencies with CVEs |
| **No Maintenance** | Issues and PRs ignored |
| **Potential Takeover** | Original maintainer may lose interest |
| **Supply Chain Risk** | Attackers may target unmaintained actions |

#### Common Archived Actions

| Archived Action | Recommended Alternative |
|-----------------|------------------------|
| `actions/create-release` | `softprops/action-gh-release` |
| `actions/upload-release-asset` | `softprops/action-gh-release` |
| `actions-rs/toolchain` | `dtolnay/rust-toolchain` |
| `actions-rs/cargo` | Native `cargo` commands |
| `actions/setup-ruby` | `ruby/setup-ruby` |

#### OWASP and CWE Mapping

- **CWE-1104**: Use of Unmaintained Third Party Components
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-3:** Dependency Chain Abuse

### Detection Logic

#### What Gets Detected

The rule maintains a list of known archived repositories including:

**Official GitHub Actions:**
- `actions/upload-release-asset`
- `actions/create-release`
- `actions/setup-ruby`
- `actions/setup-elixir`
- `actions/setup-haskell`

**Rust Actions (actions-rs):**
- `actions-rs/cargo`
- `actions-rs/toolchain`
- `actions-rs/clippy-check`
- `actions-rs/audit-check`
- `actions-rs/tarpaulin`
- `actions-rs/grcov`

**Azure Actions:**
- `Azure/container-scan`
- `Azure/get-keyvault-secrets`
- `Azure/k8s-actions`
- Various other Azure actions

**Community Actions:**
- Many community-maintained actions that have been archived

#### Safe Patterns (NOT Detected)

Actively maintained actions:
```yaml
- uses: actions/checkout@v4
- uses: dtolnay/rust-toolchain@stable
- uses: ruby/setup-ruby@v1
```

### Remediation Steps

1. **Replace with maintained alternatives**
   ```yaml
   # Instead of actions-rs/toolchain
   - uses: dtolnay/rust-toolchain@stable
     with:
       components: clippy, rustfmt

   # Instead of actions/create-release
   - uses: softprops/action-gh-release@v1
   ```

2. **Use native commands**
   ```yaml
   # Instead of actions-rs/cargo
   - run: cargo build --release
   - run: cargo test
   ```

3. **Fork and maintain** (if no alternative exists)
   - Fork the archived repository
   - Apply security updates
   - Consider publishing as new action

### Replacement Guide

#### Rust Actions (actions-rs/*)

```yaml
# Before: actions-rs/toolchain
- uses: actions-rs/toolchain@v1
  with:
    toolchain: stable
    components: clippy, rustfmt

# After: dtolnay/rust-toolchain
- uses: dtolnay/rust-toolchain@stable
  with:
    components: clippy, rustfmt

# Before: actions-rs/cargo
- uses: actions-rs/cargo@v1
  with:
    command: build
    args: --release

# After: Native cargo
- run: cargo build --release
```

#### Release Actions

```yaml
# Before: actions/create-release + actions/upload-release-asset
- uses: actions/create-release@v1
- uses: actions/upload-release-asset@v1

# After: softprops/action-gh-release
- uses: softprops/action-gh-release@v1
  with:
    files: |
      dist/*.tar.gz
      dist/*.zip
```

#### Ruby Setup

```yaml
# Before: actions/setup-ruby (archived)
- uses: actions/setup-ruby@v1

# After: ruby/setup-ruby (actively maintained)
- uses: ruby/setup-ruby@v1
  with:
    ruby-version: '3.2'
    bundler-cache: true
```

### Best Practices

1. **Regularly audit dependencies**
   - Check if actions are still maintained
   - Review repository activity
   - Subscribe to security advisories

2. **Use official alternatives when available**
   - Prefer actions from the organization that owns the technology
   - E.g., `ruby/setup-ruby` instead of `actions/setup-ruby`

3. **Pin to specific versions**
   ```yaml
   - uses: dtolnay/rust-toolchain@1.70.0
   ```

4. **Monitor for deprecation notices**
   - Watch for archive announcements
   - Check action README for migration guides

5. **Consider maintenance status before adoption**
   - Check last commit date
   - Review open issues and PRs
   - Check for security advisories

### References

- [GitHub: About archived repositories](https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories)
- [zizmor: Archived Actions List](https://github.com/woodruffw/zizmor)
- [GitHub: Third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)

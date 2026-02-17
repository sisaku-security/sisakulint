---
title: "Ref Confusion Rule"
weight: 1
---

### Ref Confusion Rule Overview

This rule detects **ref confusion vulnerabilities** where both a branch and tag with the same name exist in a repository. This ambiguity can lead to supply chain attacks where an attacker creates a malicious branch with the same name as an existing tag.

### Security Impact

**Severity: High (8/10)**

Ref confusion vulnerabilities pose significant supply chain risks:

1. **Ambiguous Resolution**: Git may resolve to unexpected code when both branch and tag exist
2. **Supply Chain Attack**: Attackers can create malicious branches matching tag names
3. **Silent Exploitation**: Users unaware they're running compromised code
4. **Widespread Impact**: Popular actions can affect thousands of repositories

This vulnerability aligns with **CWE-706: Use of Incorrectly-Resolved Name or Reference** and **OWASP CI/CD Security Risk CICD-SEC-3: Dependency Chain Abuse**.

**Vulnerable Example:**

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # DANGEROUS: 'v1' exists as both a branch and a tag!
      - uses: actions/checkout@v1
      - run: npm install
```

**Detection Output:**

```bash
vulnerable.yaml:9:9: ref confusion detected: ref 'v1' exists as both a branch and a tag in 'actions/checkout'. This ambiguity could be exploited for supply chain attacks. Pin to a specific commit SHA instead. [ref-confusion]
      9 |      - uses: actions/checkout@v1
```

### Security Background

#### What is Ref Confusion?

When you reference an action using a symbolic ref (like `v1`, `main`, or `release`), Git must resolve this to a specific commit. If both a branch and tag have the same name, the resolution becomes ambiguous:

- Git typically prefers tags over branches
- However, GitHub Actions may resolve differently in some cases
- An attacker can exploit this by creating a branch with a tag's name

#### Attack Scenario

```
1. Popular action has tag 'v2' pointing to safe commit
2. Attacker forks the repository
3. Attacker creates branch named 'v2' with malicious code
4. Attacker convinces maintainer to merge (or exploits permissions)
5. Now 'v2' exists as both branch and tag
6. Users referencing 'v2' might get malicious code
```

#### Why is this dangerous?

| Risk Factor | Impact |
|-------------|--------|
| **Ambiguous Resolution** | Unclear which ref will be used |
| **Supply Chain** | Affects all users of the action |
| **Silent Attack** | No obvious indication of compromise |
| **Trust Exploitation** | Leverages trust in popular actions |

#### OWASP and CWE Mapping

- **CWE-706**: Use of Incorrectly-Resolved Name or Reference
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-3:** Dependency Chain Abuse

### Detection Logic

#### What Gets Detected

1. **Symbolic refs that exist as both branch and tag**
   ```yaml
   uses: owner/repo@v1  # If v1 is both branch and tag
   ```

2. **Non-SHA references with ambiguity**
   ```yaml
   uses: owner/repo@main  # If 'main' exists as both
   ```

#### What Is NOT Detected (Safe Patterns)

Commit SHA (unambiguous):
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
```

Refs that only exist as one type:
```yaml
- uses: actions/checkout@v4  # If v4 is only a tag
```

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will replace the ambiguous ref with its commit SHA.

**Example:**

Before auto-fix:
```yaml
- uses: actions/checkout@v1
```

After running `sisakulint -fix on`:
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v1
```

### Remediation Steps

1. **Pin to commit SHA**
   ```yaml
   - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
   ```

2. **Use sisakulint's commit-sha rule**
   - The commit-sha rule will convert tags to SHAs automatically
   - This also provides protection against tag mutation

3. **Verify repository state**
   - Check if the action repo has branches matching tag names
   - Report suspicious patterns to maintainers

### Best Practices

1. **Always use commit SHAs for actions**
   ```yaml
   - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
   ```

2. **Add version comments**
   ```yaml
   - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
   ```

3. **Use Dependabot or Renovate**
   - These tools track official releases
   - They update to known-good commits

4. **Monitor action repositories**
   - Watch for suspicious branch creation
   - Subscribe to security advisories

### Technical Details

The rule uses GitHub API to check:

1. List all tags for the repository
2. List all branches for the repository
3. Check if the referenced ref exists in both lists
4. Report if ambiguity is detected

### References

- [Git: Ref Ambiguity](https://git-scm.com/book/en/v2/Git-Internals-Git-References)
- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [zizmor: Ref Confusion Detection](https://github.com/woodruffw/zizmor)

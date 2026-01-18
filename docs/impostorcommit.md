---
title: "Impostor Commit Rule"
weight: 1
---

### Impostor Commit Rule Overview

This rule detects **impostor commits** - commits that exist in the GitHub fork network but not in any branch or tag of the specified repository. This is a **supply chain attack vector** (CVSS 9.8) where attackers create malicious commits in forks and trick users into referencing them as if they were from the original repository.

**Vulnerable Example:**

```yaml
name: Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # DANGEROUS: This SHA might be from an attacker's fork!
      - uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
      - run: npm install  # Malicious code could be executed
```

**Detection Output:**

```bash
vulnerable.yaml:9:9: potential impostor commit detected: the commit 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' is not found in any branch or tag of 'actions/checkout'. This could be a supply chain attack where an attacker created a malicious commit in a fork. Verify the commit exists in the official repository or use a known tag instead. See: https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd for more details [impostor-commit]
      9 👈|      - uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

### Security Background

#### What is an Impostor Commit?

GitHub's fork network allows any commit from any fork to be referenced by its SHA hash through the parent repository. This means:

1. Attacker forks a popular action repository (e.g., `actions/checkout`)
2. Attacker adds malicious code in their fork and gets a commit SHA
3. Attacker convinces a victim to use that SHA (via PR, issue, or social engineering)
4. The victim thinks they're using `actions/checkout@<sha>` from the official repo
5. In reality, the malicious code from the attacker's fork gets executed

**The SHA looks legitimate** because it appears to come from `actions/checkout`, but the commit only exists in the attacker's fork, not in any official branch or tag.

#### Why is this dangerous?

| Aspect | Risk |
|--------|------|
| **Legitimacy Appearance** | The SHA reference looks like a secure, pinned version |
| **Bypasses Reviews** | PR reviewers may not notice the SHA is not from official releases |
| **Supply Chain Attack** | Compromises the build pipeline at a fundamental level |
| **Secrets Access** | Malicious code runs with full access to repository secrets |
| **Persistence** | Once merged, the attack persists in the repository |

#### Real-World Attack Scenario

```yaml
# Attacker sends a "helpful" PR to improve security by pinning to SHA
# The PR description says: "Pin actions to commit SHA for security"

name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # This SHA is from attacker's fork, not from actions/checkout!
      - uses: actions/checkout@abc123abc123abc123abc123abc123abc123abc1
      - run: npm ci
      - run: npm test
```

The attacker's modified `actions/checkout` could:
- Exfiltrate all repository secrets to an external server
- Modify source code before the build
- Inject backdoors into build artifacts
- Steal deployment credentials

#### OWASP and CWE Mapping

- **CWE-829:** Inclusion of Functionality from Untrusted Control Sphere
- **CWE-494:** Download of Code Without Integrity Check
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-3:** Dependency Chain Abuse
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Technical Detection Mechanism

The rule implements a multi-stage verification process:

**Stage 1: Fast Path - Tag/Branch Tips**

```go
// Check if SHA matches any tag or branch tip
tags := rule.getTags(ctx, client, owner, repo)
for _, tag := range tags {
    if tag.GetCommit().GetSHA() == sha {
        return &commitVerificationResult{isImpostor: false}
    }
}
```

**Stage 2: Medium Path - Branch Commits API**

```go
// Use GitHub's undocumented branches-where-head API
branchCommitsURL := fmt.Sprintf("repos/%s/%s/commits/%s/branches-where-head", owner, repo, sha)
```

**Stage 3: Slow Path - Compare API**

```go
// Check if commit is in the history of main branches
comparison, _, err := client.Repositories.CompareCommits(ctx, owner, repo, branchName, sha, nil)
if comparison.GetStatus() == "behind" || comparison.GetStatus() == "identical" {
    return &commitVerificationResult{isImpostor: false}
}
```

### Detection Logic Explanation

#### What Gets Detected

1. **Actions pinned to SHA that doesn't exist in any tag or branch**
   - `uses: actions/checkout@<unknown-sha>`
   - `uses: owner/repo@<unknown-sha>`

2. **SHA references that only exist in forks**
   - Commits that were created in a fork but never merged upstream

#### What Is NOT Detected (Safe Patterns)

✅ **Version tags** (checked by commit-sha rule instead):
```yaml
- uses: actions/checkout@v4
```

✅ **Valid commit SHA from official repository**:
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

✅ **Local actions**:
```yaml
- uses: ./.github/actions/my-action
```

✅ **Docker images**:
```yaml
- uses: docker://alpine:3.18
```

### False Positives

False positives can occur in these scenarios:

1. **New releases not yet indexed**
   - A very new commit might not be found immediately
   - Wait for GitHub API to update or verify manually

2. **Private repositories**
   - API authentication may be required to verify private repos
   - Set `GITHUB_TOKEN` environment variable for authentication

3. **Rate limiting**
   - GitHub API rate limits may prevent verification
   - Errors are logged but don't fail the lint

### References

#### Security Research
- [Chainguard: Impostor Commits in GitHub Actions](https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd)
- [zizmor: Impostor Commit Detection](https://github.com/woodruffw/zizmor)
- [Chainguard Clank](https://github.com/chainguard-dev/clank)

#### GitHub Documentation
- [Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [Using third-party actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)

#### OWASP Resources
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will replace the impostor commit SHA with the latest valid tag from the official repository.

**Auto-fix behavior:**
- Identifies the latest semver tag (e.g., `v4.1.1`)
- Fetches the commit SHA for that tag
- Replaces the action reference with the valid SHA and tag comment

**Example:**

Before auto-fix:
```yaml
- uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
```

After running `sisakulint -fix on`:
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
```

**Note:** Always verify the auto-fix result to ensure it uses the version you intend.

### Remediation Steps

When this rule triggers:

1. **Verify the commit origin**
   - Go to `https://github.com/owner/repo/commit/<sha>`
   - Check if the commit appears in any branch or tag

2. **Use known release tags**
   - Instead of arbitrary SHAs, use version tags
   - Let the `commit-sha` rule convert tags to verified SHAs

3. **Check PR sources carefully**
   - Be suspicious of PRs that add SHA-pinned actions
   - Verify the SHA exists in the official repository before merging

4. **Use auto-fix**
   - Run `sisakulint -fix on` to automatically replace with valid SHAs
   - Review the changes before committing

5. **Implement verification in CI**
   - Add sisakulint to your CI pipeline to catch impostor commits in PRs

### Best Practices

1. **Always use version tags initially**
   ```yaml
   - uses: actions/checkout@v4  # Clear, verifiable, easy to update
   ```

2. **Let tooling convert to SHA**
   ```yaml
   # After running sisakulint -fix on for commit-sha rule
   - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
   ```

3. **Verify SHA sources in code review**
   - Question any PR adding raw SHA references
   - Ask for the source tag/version

4. **Regular dependency updates**
   - Use Dependabot or Renovate to keep actions updated
   - These tools use official release information

### Additional Resources

For more information on securing your supply chain:
- [Sigstore](https://www.sigstore.dev/) - Cryptographic signing for software artifacts
- [SLSA Framework](https://slsa.dev/) - Supply chain Levels for Software Artifacts
- [GitHub Actions Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

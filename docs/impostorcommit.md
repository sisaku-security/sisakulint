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

The rule implements a 5-stage verification pipeline. Each stage is an independent check; if a stage confirms the commit is legitimate, verification stops immediately. All API failure paths **fail open** (i.e., assume legitimate) to avoid false positives.

**Stage 1: Fast Path — Tag Tips**

Fetches up to 500 tags (5 pages × 100) via `getTags()` and compares each tag's HEAD SHA against the target. Also records the latest semver tag for auto-fix suggestions.

```go
tags := rule.getTags(ctx, client, owner, repo)
for _, tag := range tags {
    if tag.GetCommit().GetSHA() == sha { return legitimate }
}
```

*Fail-open:* If the first page of the tags API fails (e.g., rate-limited), verification returns `isImpostor: false` immediately.

**Stage 2: Fast Path — Branch Tips**

Fetches up to 300 branches (3 pages × 100) via `getBranches()` and compares each branch HEAD SHA. This catches commits that are the current HEAD of any branch, including non-default branches (e.g., `stable`, `release/*`).

```go
branches := rule.getBranches(ctx, client, owner, repo)
for _, branch := range branches {
    if branch.GetCommit().GetSHA() == sha { return legitimate }
}
```

*Fail-open:* If the first page of the branches API fails, verification returns `isImpostor: false` immediately.

**Stage 3: Targeted Check — `branches-where-head` API**

Uses the typed `ListBranchesHeadCommit` API (`GET /repos/{owner}/{repo}/commits/{sha}/branches-where-head`) to check whether the SHA is the HEAD of any branch. This handles repositories with 300+ branches where Stage 2's pagination limit may miss the match.

```go
isBranchHead, err := rule.isBranchHead(ctx, client, owner, repo, sha)
if isBranchHead { return legitimate }
```

*Note on git alternates:* GitHub's `GET /commits/{sha}` endpoint may return `200 OK` for commits that only exist in the fork network (due to git alternates / shared object storage). This is why a simple "does the commit exist?" check is insufficient — the `branches-where-head` API is needed to verify the commit is actually referenced by a branch.

*Fail behavior:* Errors are logged but do **not** fail-open here, because subsequent stages provide the safety net.

**Stage 4: Fallback — Default Branch Reachability**

Fetches the repository's default branch name via `getDefaultBranch()` (falls back to `"main"` on API error), then uses `CompareCommits` to check if the SHA is an ancestor of that branch (status `"behind"` or `"identical"`).

```go
defaultBranch := rule.getDefaultBranch(ctx, client, owner, repo)
reachable := rule.isReachableFromBranch(ctx, client, owner, repo, defaultBranch, sha)
if reachable { return legitimate }
```

*Fail-open:* If `CompareCommits` fails, verification returns `isImpostor: false`.

**Stage 5: Extended — Per-Tag Reachability**

Compares the SHA against up to 10 recent tags using `CompareCommits`. If any tag can reach the SHA (`"behind"` or `"identical"`), it is legitimate.

```go
for _, tag := range tags[:maxTagCompareCommits] {
    comparison := client.Repositories.CompareCommits(ctx, owner, repo, tagSha, sha, nil)
    if comparison.GetStatus() == "behind" || "identical" { return legitimate }
}
```

*Fail-open:* If all tag comparisons fail (e.g., rate-limited), verification returns `isImpostor: false`.

**Final verdict:** If all 5 stages pass without confirming legitimacy, the commit is flagged as an impostor.

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
   - All API failure paths fail open — the rule will NOT flag a commit as impostor when the API is unavailable

4. ~~**Non-default branch HEAD commits**~~ *(Fixed)*
   - Previously, commits at the HEAD of non-default branches (e.g., `stable`, `release/v2`) could be falsely flagged
   - Now resolved by `getBranches()` (Stage 2) and the `branches-where-head` API (Stage 3)

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

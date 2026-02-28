---
title: "Commit SHA Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Commit SHA Rule Overview

This rule enforces the use of full-length commit SHAs (instead of tags or branches) when referencing GitHub Actions in workflows. This practice ensures immutability and protects against supply chain attacks where action versions could be modified maliciously.

### Security Impact

**Severity: High (7/10)**

Using mutable references (tags or branches) instead of commit SHAs poses significant supply chain risks:

1. **Tag Manipulation**: Attackers can move tags to point to compromised commits
2. **Imposter Commits**: Malicious commits in forks can be referenced via the parent repository
3. **Credential Theft**: Compromised actions may exfiltrate CI/CD secrets
4. **Code Injection**: Attackers can inject arbitrary code into build pipelines

This vulnerability aligns with **OWASP CI/CD Security Risk CICD-SEC-08: Ungoverned Usage of 3rd Party Services**.

#### Key Features:

- **SHA Enforcement**: Detects actions using tags (e.g., `@v4`) or branches (e.g., `@main`) instead of commit SHAs
- **Immutability Guarantee**: SHA references cannot be changed, preventing malicious updates to existing versions
- **Auto-fix Support**: Automatically converts tag/branch references to their corresponding commit SHAs
- **Supply Chain Protection**: Mitigates risks from compromised action repositories

### Example Workflow

Consider the following workflow file with tag-based action references:

```yaml
name: CI
on: [push, pull_request]

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.21.4"
      - name: Run GolangCI-Lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: latest
```

### Example Output

Running sisakulint will detect all actions using tags instead of commit SHAs:

```bash
$ sisakulint

.github/workflows/ci.yaml:9:9: the action ref in 'uses' for step '<unnamed>' should be a full length commit SHA for immutability and security. See documents: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [commit-sha]
      9 👈|      - uses: actions/checkout@v4

.github/workflows/ci.yaml:10:9: the action ref in 'uses' for step '<unnamed>' should be a full length commit SHA for immutability and security. See documents: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [commit-sha]
     10 👈|      - uses: actions/setup-go@v5

.github/workflows/ci.yaml:14:9: the action ref in 'uses' for step 'Run GolangCI-Lint' should be a full length commit SHA for immutability and security. See documents: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions [commit-sha]
     14 👈|      - name: Run GolangCI-Lint
```

### Auto-fix Support

The commit-sha rule supports auto-fixing by converting tag/branch references to their corresponding commit SHAs:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

After auto-fix, the workflow will use full commit SHAs:

```yaml
name: CI
on: [push, pull_request]

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
      - uses: actions/setup-go@0c52d547c9bc32b1aa3301fd7a9cb496313a4491  # v5.0.0
        with:
          go-version: "1.21.4"
      - name: Run GolangCI-Lint
        uses: golangci/golangci-lint-action@3a919529898de77ec3da873e3063ca4b10e7f5cc  # v6.0.0
        with:
          version: latest
```

### Feature Background

#### Real-World Supply Chain Attack: tj-actions Breach

This rule directly addresses one of the critical recommendations from the **Black Hat USA 2025 presentation** on the tj-actions supply chain breach, which demonstrated how tag-based references can be exploited:

**The Incident:**
- **tj-actions/changed-files**, a popular GitHub Action used in over 23,000 public repositories, was compromised
- Attackers used **"imposter commits"** living in a fork to inject malicious code
- The attack exploited the fact that Git tags are **mutable** and can be moved to point to different commits
- The malicious payload downloaded a Python script to dump and exfiltrate CI/CD secrets
- Traditional security tools failed to detect this sophisticated attack because the tag reference looked legitimate

**Attack Mechanism: Imposter Commits**

The attack leveraged a critical weakness in Git's tag system:
1. **Tags are mutable**: Unlike commit SHAs, Git tags can be deleted and recreated to point to different commits
2. **Fork-based injection**: Attackers created a fork with malicious code at the same tag name
3. **Repository confusion**: GitHub's action resolution could potentially pull from the wrong source
4. **Hidden malicious code**: The malicious commit was not visible in the main repository's history

**Recommendations**

The Black Hat presentation outlined four key security controls, with **"Pin Actions to Specific Commit SHAs"** as a critical recommendation:
1. Implement Security Monitoring for CI/CD Runners
2. Enforce an Action Allowlist
3. **Pin Actions to Specific Commit SHAs** - Commit SHAs are immutable and cryptographically secure, preventing tag manipulation attacks
4. Develop an Incident Response Plan

**Why Commit SHA Pinning Matters**

Git tags and branches are mutable references that can be changed to point to different commits. This creates several security vulnerabilities:

1. **Tag Manipulation**: Attackers can force-push tags to point to malicious commits
2. **Branch Updates**: Main/master branches are constantly updated, potentially introducing malicious code
3. **Imposter Commits**: As demonstrated in the tj-actions breach, malicious commits can be injected through tag manipulation
4. **No Cryptographic Guarantee**: Tags don't provide cryptographic verification of code integrity

In contrast, commit SHAs provide:
- **Immutability**: A commit SHA uniquely identifies a specific state of the repository
- **Cryptographic Verification**: SHA-1/SHA-256 hashes ensure the code hasn't been tampered with
- **Transparency**: The exact code version is always visible and auditable
- **Protection from Imposter Attacks**: Cannot be manipulated to point to different code

#### GitHub's Official Response: SHA Pinning Policy

In response to growing supply chain security concerns and incidents like the tj-actions breach, **GitHub officially introduced SHA pinning enforcement as a native platform feature in August 2025**:

**GitHub Actions Policy: Enforce SHA Pinning**

GitHub Enterprise Cloud and GitHub Enterprise Server now support organization-level policies to enforce SHA pinning for all workflows:

- **Policy Enforcement**: Organization administrators can require all actions to use full commit SHAs
- **Centralized Control**: Manage SHA pinning requirements across all repositories in an organization
- **Compliance Verification**: Automatically block workflows that don't comply with SHA pinning policies
- **Enterprise-Grade Security**: Built-in platform support for critical supply chain security practices

This official GitHub feature validates the importance of SHA pinning as a fundamental security control. Organizations using GitHub Enterprise can now enforce SHA pinning at the platform level, while sisakulint provides this capability for:
- GitHub Free and GitHub Pro users
- Pre-commit validation and CI/CD checks
- Auto-fixing capabilities to convert existing workflows
- Organizations wanting additional validation layers beyond GitHub's native enforcement

The introduction of this GitHub policy demonstrates that SHA pinning has become an industry-standard security practice, recognized by GitHub itself as essential for protecting CI/CD pipelines from supply chain attacks.

#### Automated Updates with SHA Pinning

In the past, one drawback of SHA-based versioning was the inability to automatically receive critical bug fixes or security updates for actions. However, this challenge has been effectively addressed by modern dependency management tools:

**Automated Update Solutions:**
- **Dependabot**: GitHub's native solution supports SHA-pinned actions and automatically creates PRs with updated commit SHAs when new versions are released
- **Renovate**: Advanced dependency management tool with sophisticated SHA pinning support and customizable update policies
- **GitHub Actions Update Tool**: Specialized tools for updating action references in workflows

**How It Works:**
1. Tools monitor action repositories for new releases/tags
2. When a new version is detected, they resolve the tag to its commit SHA
3. A pull request is automatically created updating the SHA reference
4. Comments in the workflow show which version the SHA corresponds to (e.g., `# v4.1.1`)
5. Teams can review and approve updates through normal PR processes

This approach preserves the security benefits of SHA-based versioning while ensuring workflows stay up-to-date with the latest secure versions, effectively balancing robust protection against supply chain attacks (including imposter commit attacks) with the convenience of automated updates.

#### Common Security Risks Addressed

As the complexity of CI/CD pipelines grows, several supply chain attack vectors emerge:

1. **Tag Manipulation**: Malicious actors can move tags to point to compromised code
2. **Imposter Commits**: As seen in tj-actions, attackers can inject malicious commits through fork-based attacks
3. **Credential Theft**: Compromised actions may exfiltrate secrets or credentials
4. **Code Injection**: Malicious actions can inject code into your build process
5. **Transitive Dependencies**: Action dependencies can be compromised without your knowledge

The commit-sha rule addresses these risks by enforcing immutable references:

- **Cryptographic Integrity**: Commit SHAs provide cryptographic verification
- **Audit Trail**: Exact versions are always traceable and auditable
- **Immutability**: Cannot be changed to point to different code
- **Transparency**: Team members can review exact code being executed
- **Protection from Fork Attacks**: Eliminates imposter commit vulnerabilities

This aligns with OWASP CI/CD Security Risk **CICD-SEC-8: Ungoverned Usage of 3rd Party Services**, specifically addressing the secure usage of third-party GitHub Actions. By enforcing SHA-based pinning, organizations maintain cryptographic verification of third-party code integrity and eliminate attack vectors that exploit mutable references.

### Configuration Best Practices

1. **Always use full commit SHAs**: Use 40-character SHAs, not shortened versions
2. **Add version comments**: Include the tag version in comments for readability
   ```yaml
   - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
   ```
3. **Enable automated updates**: Use Dependabot or Renovate to keep SHAs current
4. **Review updates carefully**: Treat SHA updates like any dependency update—review changes in PRs
5. **Combine with action allowlist**: Use both commit-sha and action-list rules for defense in depth
6. **Document exceptions**: If using tags for specific reasons, document why in comments

### Integration with Other Security Measures

The commit-sha rule works best when combined with other security controls:

**Defense in Depth Strategy:**
1. **Action Allowlist (action-list rule)**: Control which actions can be used
2. **Commit SHA Pinning (commit-sha rule)**: Ensure immutability of approved actions
3. **Permissions Control (permissions rule)**: Limit action capabilities
4. **Timeout Enforcement (timeout-minutes rule)**: Prevent resource exhaustion
5. **Expression Validation (expr/issue-injection rules)**: Prevent injection attacks

Together, these rules implement multiple layers of the OWASP CI/CD Security Top 10 recommendations, creating a comprehensive security posture for GitHub Actions workflows.

### See Also

**Industry References:**
- [Black Hat USA 2025: tj-actions Supply Chain Breach Analysis](https://www.stepsecurity.io/blog/when-changed-files-changed-everything-our-black-hat-2025-presentation-on-the-tj-actions-supply-chain-breach) - Real-world case study demonstrating the critical need for SHA pinning
- [Chainguard: What the Fork? Imposter Commits in GitHub Actions](https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd) - Deep dive into imposter commit attack mechanisms
- [GitHub Blog: GitHub Actions Policy Now Supports SHA Pinning (August 2025)](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/#enforce-sha-pinning) - Official GitHub Enterprise feature announcement
- [GitHub: Security Hardening for GitHub Actions - Using Third-Party Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions) - Official GitHub security guidance
- [GitHub: Finding and Customizing Actions - Using SHAs](https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas) - Technical details on SHA usage
- [OWASP Top 10 CI/CD Security Risks: CICD-SEC-08](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services) - Ungoverned Usage of 3rd Party Services

{{< popup_link2 href="https://www.stepsecurity.io/blog/when-changed-files-changed-everything-our-black-hat-2025-presentation-on-the-tj-actions-supply-chain-breach" >}}

{{< popup_link2 href="https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd" >}}

{{< popup_link2 href="https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/#enforce-sha-pinning" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/learn-github-actions/finding-and-customizing-actions#using-shas" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-08-Ungoverned-Usage-of-3rd-Party-Services" >}}
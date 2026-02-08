# GHSA-qmg3-hpqr-gqvc

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2025-30154 |
| Affected Action | reviewdog/action-setup |
| Severity | High |
| CVSS Score | 8.6/10 |
| Vulnerability Type | Embedded Malicious Code (CWE-506) |
| Published | March 11, 2025 |
| Compromise Window | March 11, 2025 18:42-20:31 UTC |

## Vulnerability Description

The `reviewdog/action-setup@v1` GitHub Action was compromised on March 11, 2025, between 18:42 and 20:31 UTC. Malicious code was added that dumps exposed secrets to GitHub Actions Workflow Logs.

Actions affected regardless of version or pinning method:
- reviewdog/action-shellcheck
- reviewdog/action-composite-template
- reviewdog/action-staticcheck
- reviewdog/action-ast-grep
- reviewdog/action-typos

The vulnerability is classified as CWE-506 (Embedded Malicious Code): "The product contains code that appears to be malicious in nature." This supply chain attack highlights the critical risk of using mutable tags (like `v1`, `v2`) instead of pinned commit SHAs. When an action's tag is compromised, all workflows using that tag automatically pull the malicious version on the next run.

**EPSS Score:** 15.395% (94th percentile) - indicating high probability of exploitation

**Note:** This vulnerability is listed in CISA's Known Exploited Vulnerabilities Catalog.

**Affected versions:** = 1 (version 1)
**Patched versions:** None listed (fix via commit 3f401fe retagging)

## Vulnerable Pattern

```yaml
name: Vulnerable Pattern
on:
  pull_request:

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Vulnerable: Using mutable tag v1
      # If tag is moved to malicious commit, workflow is compromised
      - uses: reviewdog/action-setup@v1

      - name: Run linter
        run: reviewdog -reporter=github-pr-review -runners=golint
```

**Why this is vulnerable:**
- Mutable tags can be force-pushed to point to malicious commits
- No integrity verification of action code
- Automatic updates to compromised versions
- Executes with full workflow permissions

## Safe Pattern

```yaml
name: Safe Pattern
on:
  pull_request:

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Safe: Pinned to specific commit SHA
      # Immutable - cannot be changed by attacker
      - uses: reviewdog/action-setup@3f401fe1b897d3dfd3a8fb7d8f404a7b0d7e6f5d # v1.0.0

      - name: Run linter
        run: reviewdog -reporter=github-pr-review -runners=golint
```

**Why this is safe:**
- Commit SHA is immutable and cryptographically verified
- Prevents automatic updates to compromised versions
- Explicit version control through comments
- Can be monitored by Dependabot for updates

## sisakulint Detection Result

```
script/actions/advisory/GHSA-qmg3-hpqr-gqvc-vulnerable.yaml:15:9: the action ref in 'uses' for step '<unnamed>' should be a full length commit SHA for immutability and security. See https://sisaku-security.github.io/lint/docs/rules/commitsharule/ [commit-sha]
script/actions/advisory/GHSA-qmg3-hpqr-gqvc-vulnerable.yaml:19:9: the action ref in 'uses' for step '<unnamed>' should be a full length commit SHA for immutability and security. See https://sisaku-security.github.io/lint/docs/rules/commitsharule/ [commit-sha]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | CommitShaRule | Yes |

**Detection Details:**
- `CommitShaRule` detects the use of mutable tags `@v4` and `@v1` instead of commit SHA at lines 15 and 19
- This is directly relevant to preventing the supply chain attack, as pinning to commit SHAs prevents malicious tag updates
- Auto-fix available: Converts tags to commit SHAs

sisakulint successfully identifies the supply chain risk by detecting the use of mutable tags, which is the root cause of this vulnerability class.

## Mitigation Recommendations

1. **Pin all actions to commit SHAs**: Use `uses: owner/action@<commit-sha> # version-comment` format
2. **Enable Dependabot**: Configure `dependabot.yml` to monitor GitHub Actions for updates
3. **Use KnownVulnerableActionsRule**: Keep sisakulint's vulnerability database updated
4. **Review action source code**: Before updating, review the diff of action changes
5. **Limit workflow permissions**: Use `permissions:` block to restrict GITHUB_TOKEN scope

## References
- [GitHub Advisory: GHSA-qmg3-hpqr-gqvc](https://github.com/advisories/GHSA-qmg3-hpqr-gqvc)
- [reviewdog Security Advisory](https://github.com/reviewdog/reviewdog/security/advisories/GHSA-qmg3-hpqr-gqvc)
- [Malicious Commit f0d342d](https://github.com/reviewdog/action-setup/commit/f0d342d)
- [Fix/Retag Commit](https://github.com/reviewdog/action-setup/commit/3f401fe1d58fe77e10d665ab713057375e39b887)
- [Issue #2079](https://github.com/reviewdog/reviewdog/issues/2079)
- [CVE-2025-30154](https://nvd.nist.gov/vuln/detail/CVE-2025-30154)
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [sisakulint: CommitShaRule](../commitsha.md)
- [sisakulint: KnownVulnerableActionsRule](../known_vulnerable_actions.md)
- [GitHub: Security hardening for Actions](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)

---
title: "Known Vulnerable Actions Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Known Vulnerable Actions Rule Overview

This rule detects GitHub Actions with known security vulnerabilities using the GitHub Security Advisories database. It helps identify actions that have been reported with CVEs or other security advisories and suggests upgrading to patched versions.

### Security Impact

**Severity: Varies (inherits from advisory CVSS score)**

The severity of each finding is determined by the GitHub Security Advisory:

| Advisory Severity | CVSS Score | sisakulint Severity |
|-------------------|------------|---------------------|
| Critical | 9.0-10.0 | Critical |
| High | 7.0-8.9 | High |
| Medium | 4.0-6.9 | Medium |
| Low | 0.1-3.9 | Low |

Using actions with known vulnerabilities poses significant risks:

1. **Known Exploits**: Attackers can leverage documented vulnerabilities
2. **Supply Chain Risk**: Vulnerable actions compromise your CI/CD pipeline
3. **Credential Theft**: Many action vulnerabilities enable secret exfiltration
4. **Code Injection**: Attackers can execute arbitrary code in your workflows

This vulnerability aligns with **OWASP CI/CD Security Risk CICD-SEC-3: Dependency Chain Abuse**.

#### Key Features

- **Real-time Advisory Lookup**: Queries GitHub Security Advisories API for up-to-date vulnerability information
- **Version Resolution**: Resolves symbolic refs (tags/branches) and commit SHAs to actual version numbers
- **Severity Reporting**: Reports vulnerability severity (Critical/High/Medium/Low) based on the advisory
- **Auto-fix Support**: Automatically upgrades vulnerable actions to their patched versions
- **Commit SHA Handling**: Properly handles actions pinned to commit SHAs
- **Caching**: Caches API responses to minimize rate limit impact

### Detection Logic

1. Parse action reference from `uses:` field (e.g., `owner/repo@ref`)
2. Resolve the ref to a version:
   - For symbolic refs (tags/branches): Resolve to commit SHA, then find the longest matching tag
   - For commit SHAs: Find the longest matching tag for that commit
3. Query GitHub Security Advisories API for vulnerabilities affecting that action and version
4. Report any matching vulnerabilities with severity, GHSA ID, and remediation advice

### Example: Vulnerable Workflow

```yaml
name: Vulnerable Actions Example
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # This version has known vulnerabilities
      - name: Check Changed Files
        uses: tj-actions/changed-files@v35
```

### Example Output

```
workflow.yaml:10:9: Action 'tj-actions/changed-files@v35' has a known high severity
vulnerability (GHSA-mcph-m25j-8j63): tj-actions/changed-files has Potential Actions
command injection in output filenames. Upgrade to version 41 or later.
See: https://github.com/advisories/GHSA-mcph-m25j-8j63 [known-vulnerable-actions]
```

### Auto-fix Behavior

When running with `-fix on` or `-fix dry-run`, the rule will:

1. **For symbolic refs** (e.g., `@v35`):
   - Update to the patched version tag (e.g., `@v41`)
   - Maintain the same ref style (with or without 'v' prefix)

2. **For commit SHAs** (e.g., `@a1b2c3d...`):
   - Resolve the patched version to its commit SHA
   - Update the SHA and add a comment with the version tag

### Before Auto-fix

```yaml
- uses: tj-actions/changed-files@v35
```

### After Auto-fix

```yaml
- uses: tj-actions/changed-files@v41
```

### Authentication

This rule requires GitHub API access to fetch security advisories. Authentication is obtained from (in order of priority):

1. `GITHUB_TOKEN` environment variable
2. `GH_TOKEN` environment variable
3. `gh auth token` command (GitHub CLI)
4. Git credential helper

Without authentication, the rule may be rate-limited and skip vulnerability checks.

### Skipped Actions

The following action types are not checked:

- Local actions (e.g., `./.github/actions/my-action`)
- Docker actions (e.g., `docker://alpine:latest`)
- Actions that cannot be resolved (private repos, network errors)

### Related Rules

- **commit-sha**: Ensures actions are pinned to full commit SHAs for immutability
- **action-list**: Allows/blocks specific actions based on a whitelist/blacklist

### References

- [GitHub Security Advisories](https://github.com/advisories)
- [GitHub Security Advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories)
- [OWASP CI/CD Security Risks - Poisoned Pipeline Execution](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [zizmor known-vulnerable-actions](https://github.com/woodruffw/zizmor/blob/main/crates/zizmor/src/audit/known_vulnerable_actions.rs)

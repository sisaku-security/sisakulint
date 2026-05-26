---
title: "Dependency Review Settings Rule"
weight: 1
---

### Dependency Review Settings Rule Overview

This rule detects `actions/dependency-review-action` configurations that weaken dependency review enforcement, omit recommended gate settings, or request pull request comment summaries without granting the permission needed to write those comments.

#### Key Features

- **Security Gate Checks**: Reports `warn-only: true`, `vulnerability-check: disable`, and `license-check: disable`
- **Recommended Setting Checks**: Reports missing `fail-on-severity`, missing `fail-on-scopes`, and missing license policy configuration
- **Allow-list Abuse Checks**: Reports large `allow-ghsas` and `allow-dependencies-licenses` exception lists
- **Permission Consistency Check**: Reports `comment-summary-in-pr: always` and `comment-summary-in-pr: on-failure` when the effective permissions do not include `pull-requests: write`
- **Job Override Awareness**: Follows GitHub Actions semantics where job-level `permissions:` override workflow-level `permissions:`
- **Focused Scope**: Checks scalar `with:` values on `actions/dependency-review-action` steps and ignores unrelated actions

### Security and Reliability Impact

**Severity: Medium**

`actions/dependency-review-action` is often used as a security gate for pull requests. Settings such as `warn-only: true` or `vulnerability-check: disable` can make the gate non-enforcing, while large exception lists can normalize broad bypasses.

The rule also checks reliability issues around PR comments. When comment summaries are enabled without `pull-requests: write`, the workflow configuration is internally inconsistent: the action is configured to write a PR comment, but the `GITHUB_TOKEN` permissions do not allow it.

### Example Vulnerable Workflow

```yaml
name: Dependency Review

on: pull_request

permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: true
          vulnerability-check: disable
          allow-ghsas: GHSA-1111-2222-3333, GHSA-2222-3333-4444, GHSA-3333-4444-5555, GHSA-4444-5555-6666, GHSA-5555-6666-7777
          comment-summary-in-pr: always
```

### Safe Configuration

Grant `pull-requests: write` at the job level when PR comments are needed:

```yaml
name: Dependency Review

on: pull_request

permissions:
  contents: read

jobs:
  review:
    permissions:
      contents: read
      pull-requests: write
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          warn-only: false
          vulnerability-check: true
          license-check: true
          fail-on-severity: high
          fail-on-scopes: runtime
          allow-licenses: MIT, Apache-2.0
          comment-summary-in-pr: always
```

Or disable PR comments:

```yaml
with:
  comment-summary-in-pr: never
```

### What the Rule Detects

#### `warn-only: true`

```yaml
steps:
  - uses: actions/dependency-review-action@v4
    with:
      warn-only: true
```

#### `vulnerability-check: disable`

```yaml
steps:
  - uses: actions/dependency-review-action@v4
    with:
      vulnerability-check: disable
```

#### `license-check: disable`

```yaml
steps:
  - uses: actions/dependency-review-action@v4
    with:
      license-check: disable
```

#### Missing gate settings

```yaml
steps:
  - uses: actions/dependency-review-action@v4
    with:
      warn-only: false
```

This reports missing `fail-on-severity`, missing `fail-on-scopes`, and missing license policy configuration when neither `allow-licenses` nor `deny-licenses` is set.

#### Large vulnerability allow-list

```yaml
steps:
  - uses: actions/dependency-review-action@v4
    with:
      allow-ghsas: GHSA-1111-2222-3333, GHSA-2222-3333-4444, GHSA-3333-4444-5555, GHSA-4444-5555-6666, GHSA-5555-6666-7777
```

#### Large dependency/license exception list

```yaml
steps:
  - uses: actions/dependency-review-action@v4
    with:
      allow-dependencies-licenses: pkg:npm/a@1.0.0, pkg:npm/b@1.0.0, pkg:npm/c@1.0.0, pkg:npm/d@1.0.0, pkg:npm/e@1.0.0
```

#### `comment-summary-in-pr: always`

```yaml
permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: always
```

#### `comment-summary-in-pr: on-failure`

```yaml
permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@v4
        with:
          comment-summary-in-pr: on-failure
```

### Limitations

- Dynamic expressions in `permissions:` are not evaluated.
- The rule checks scalar `with:` values only. Dynamic expressions such as `${{ ... }}` are treated conservatively for value-specific checks.
- Large allow-list detection currently uses a threshold of 5 or more entries.
- Repository default token permissions are not inferred; add explicit `pull-requests: write` when PR comments are required.

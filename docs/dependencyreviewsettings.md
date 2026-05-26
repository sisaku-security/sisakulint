---
title: "Dependency Review Settings Rule"
weight: 1
---

### Dependency Review Settings Rule Overview

This rule detects `actions/dependency-review-action` configurations that request pull request comment summaries without granting the permission needed to write those comments.

#### Key Features

- **Permission Consistency Check**: Reports `comment-summary-in-pr: always` and `comment-summary-in-pr: on-failure` when the effective permissions do not include `pull-requests: write`
- **Job Override Awareness**: Follows GitHub Actions semantics where job-level `permissions:` override workflow-level `permissions:`
- **Focused Scope**: Ignores `comment-summary-in-pr: never`, missing settings, and unrelated actions

### Security and Reliability Impact

**Severity: Medium**

`actions/dependency-review-action` can post a summary comment on pull requests. When comment summaries are enabled without `pull-requests: write`, the workflow configuration is internally inconsistent: the action is configured to write a PR comment, but the `GITHUB_TOKEN` permissions do not allow it.

This can cause dependency review feedback to be missing from the pull request even though the workflow appears to be configured for reviewer-facing summaries.

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
          comment-summary-in-pr: always
```

Or disable PR comments:

```yaml
with:
  comment-summary-in-pr: never
```

### What the Rule Detects

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
- The rule checks scalar `with.comment-summary-in-pr` values only.
- Repository default token permissions are not inferred; add explicit `pull-requests: write` when PR comments are required.

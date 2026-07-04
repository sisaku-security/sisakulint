---
title: "Deprecated Node Runtime Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

## Deprecated Node Runtime Rule Overview

The `deprecated-node-runtime` rule detects GitHub Actions that still run on the Node.js 20 action runtime. Node.js 20 reached end-of-life on 2026-04-30 and no longer receives security fixes, and GitHub removes node20 from the runner on 2026-09-16, after which affected actions stop working. node12 and node16 were already removed. The rule reports every workflow dependency on a deprecated runtime so a repository can migrate before the removal date.

### Rule ID

`deprecated-node-runtime`

### Severity

- **High**: an EOL runtime receives no security patches, and workflows depending on it break outright when the runtime is removed from the runner.

### Detection

| Class | What is reported | Auto-fix |
|-------|------------------|----------|
| Direct runtime | An action whose `action.yml` declares `runs.using: node12/node16/node20` | Yes, for known first-party actions |
| Composite transitive | A composite action whose direct internal steps use a deprecated runtime, depth 1 | No, the fix belongs to the action maintainer |
| Runner env flags | `ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION`, which stops working on 2026-09-16, and the removed `FORCE_JAVASCRIPT_ACTIONS_TO_NODE20` | No |
| EOL build target | `node-version: 20` or older in setup-node | No, changing a build target is a semantic change |

### Vulnerable Pattern

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4        # runs.using: node20
      - uses: actions/setup-node@v4
        with:
          node-version: 20               # EOL build target
```

sisakulint reports:

```
workflow.yaml:5:15: action 'actions/checkout@v4' runs on the deprecated Node.js runtime 'node20' (EOL since 2026-04-30 and scheduled for removal from the runner on 2026-09-16). Update to actions/checkout@v5 or later, which runs on node24. [deprecated-node-runtime]
```

### Safe Pattern

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5        # runs.using: node24
      - uses: actions/setup-node@v5
        with:
          node-version: 24
```

### Auto-fix

`sisakulint -fix on` bumps known first-party actions from their node20-generation major to the first node24-capable major, for example `actions/checkout@v4` to `@v5`, `actions/github-script@v7` to `@v8`, and `actions/upload-artifact@v4` to `@v6`. Subpaths such as `actions/cache/restore@v4` are preserved. SHA-pinned references are detected but left to the `commit-sha` rule to re-pin. The three diagnose-only classes in the table above are reported without a fix. Preview changes with `sisakulint -fix dry-run`.

### Resolver and Offline Fallback

The rule resolves each action's `action.yml` at the pinned ref through the GitHub API and treats its `runs.using` value as ground truth. SHA-pinned actions are therefore detected without needing a `# vX` ref comment, and a stale version comment can never cause a false positive. Set a token via `GITHUB_TOKEN` or `-github-token` to avoid the unauthenticated rate limit. When the API is unreachable the rule falls back to an embedded table of known actions plus tag and `# vX` comment heuristics, which is best-effort and may miss third-party actions.

### Known Limitations

- The embedded fallback table is a hand-maintained snapshot of first-party actions.
- Composite actions are inspected one level deep; runtimes nested deeper and reusable workflows are not tracked.

### References

- [GitHub Changelog: Deprecation of Node 20 on GitHub Actions runners](https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/)
- [Node.js Release Schedule](https://github.com/nodejs/Release)

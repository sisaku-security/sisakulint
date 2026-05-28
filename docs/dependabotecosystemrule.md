---
title: "Dependabot Ecosystem Rule"
weight: 1
---

### Dependabot Ecosystem Rule Overview

This rule detects package ecosystems that a repository depends on but does not configure in its
Dependabot configuration (`.github/dependabot.yaml` / `.github/dependabot.yml`). It infers the
required ecosystems from root-level lockfiles and from `setup-*` actions used in workflows, then
reports each ecosystem that is not covered by a `package-ecosystem` entry.

The `github-actions` ecosystem is intentionally out of scope here; it is handled by the
`DependabotGitHubActionsRule`.

#### Key Features

- **Lockfile Signals**: Infers ecosystems from lockfiles in the repository root.
- **Setup-action Signals**: Infers ecosystems from `setup-*` actions in workflow steps.
- **Local-scan Only**: Reads the local filesystem to locate lockfiles and the Dependabot config. The
  check is skipped in remote-scan mode.
- **Diagnose-only**: Reports findings only; it does not auto-fix the Dependabot configuration.
- **Renovate Aware**: Skips the check when a Renovate configuration manages dependencies (a broad
  preset such as `config:recommended`, or any `packageRules.matchManagers` entry).
- **Precise Anchoring**: Setup-action findings are anchored at the offending step; lockfile findings
  are reported at the top of the workflow file. When the same ecosystem is implied by both signals,
  the finding is deduplicated and keeps the precise step anchor.

### Security and Reliability Impact

**Severity: Warning**

Without a `package-ecosystem` entry, Dependabot will not open dependency-update pull requests for
that ecosystem. Outdated dependencies accumulate known vulnerabilities, and major-version updates are
not surfaced automatically. Configuring every ecosystem the repository actually uses keeps the supply
chain patched.

### Ecosystem Inference

#### Root-level lockfiles

| File | Ecosystem |
|------|-----------|
| `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` | `npm` |
| `go.sum` | `gomod` |
| `Cargo.lock` | `cargo` |
| `Gemfile.lock` | `bundler` |
| `composer.lock` | `composer` |
| `Pipfile.lock`, `poetry.lock`, `requirements.txt` | `pip` |
| `pom.xml` | `maven` |
| `build.gradle`, `build.gradle.kts`, `gradle.lockfile` | `gradle` |

Only the repository root is scanned; lockfiles in subdirectories are not inferred.

#### Setup actions

| Action | Ecosystem |
|--------|-----------|
| `actions/setup-node` | `npm` |
| `actions/setup-go` | `gomod` |
| `actions/setup-python` | `pip` |
| `actions/setup-java` | `maven`, `gradle`, or `sbt` |
| `ruby/setup-ruby` | `bundler` |

`actions/setup-java` is ambiguous: it is considered satisfied when the Dependabot config contains any
one of `maven`, `gradle`, or `sbt`.

### Example Finding

```yaml
name: ci
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4 # implies the npm ecosystem
        with:
          node-version: '20'
```

If `.github/dependabot.yaml` does not configure `npm`, the rule reports:

```
package ecosystem "npm" is used (detected from actions/setup-node) but not configured in dependabot.
```

### Safe Configuration

Add a matching `package-ecosystem` entry for every detected ecosystem:

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
```

### Limitations

- Local-scan only; remote-scan mode skips the check.
- Lockfiles are inferred from the repository root only (no recursive scan), so monorepo dependencies
  nested in subdirectories are not detected.
- Matching is based on the presence of a `package-ecosystem`; the Dependabot `directory` value is not
  cross-checked.
- The Renovate skip is best-effort: any `packageRules.matchManagers` entry or a recognized broad
  preset suppresses the check.
- The rule is diagnose-only and does not provide an auto-fix.

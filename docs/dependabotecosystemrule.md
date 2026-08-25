---
title: "Dependabot Ecosystem Rule"
weight: 1
---

## Dependabot Ecosystem Rule Overview

This rule detects package ecosystems that a repository depends on but does not configure in its
Dependabot configuration (`.github/dependabot.yaml` / `.github/dependabot.yml`). It infers the
required ecosystems from root-level lockfiles and from `setup-*` actions used in workflows, then
reports each ecosystem that is not covered by a `package-ecosystem` entry.

The `github-actions` ecosystem is intentionally out of scope here; it is handled by the
`DependabotGitHubActionsRule`.

### Key Features

- **Lockfile Signals**: Infers ecosystems from lockfiles in the repository root.
- **Setup-action Signals**: Infers ecosystems from `setup-*` actions in workflow steps, but only
  when the workflow actually manages dependencies for the ecosystem (see below). A `setup-*`
  action that merely bootstraps the runtime to run stdlib-only scripts does not imply a managed
  ecosystem.
- **Local-scan Only**: Reads the local filesystem to locate lockfiles and the Dependabot config. The
  check is skipped in legacy API-only remote-scan mode. Pull-request snapshot
  scans materialize repository context locally and therefore run this check.
- **Diagnose-only**: Reports findings only; it does not auto-fix the Dependabot configuration.
- **Renovate Aware**: When a Renovate configuration extends a broad preset (e.g.
  `config:recommended`), the check is skipped entirely. Otherwise only the ecosystems Renovate
  actually manages (via `packageRules.matchManagers` or `enabledManagers`) are treated as covered;
  warnings for other ecosystems still surface.
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

### Root-level lockfiles

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

### Setup actions

| Action | Ecosystem |
|--------|-----------|
| `actions/setup-node` | `npm` |
| `actions/setup-go` | `gomod` |
| `actions/setup-python` | `pip` |
| `actions/setup-java` | `maven`, `gradle`, or `sbt` |
| `ruby/setup-ruby` | `bundler` |

`actions/setup-java` is ambiguous: it is considered satisfied when the Dependabot config contains any
one of `maven`, `gradle`, or `sbt`.

A `setup-*` action alone is not treated as an ecosystem signal. The requirement is reported only when
it is corroborated by either a root-level manifest or lockfile for one of the accepted ecosystems
(for example `package.json`, `pyproject.toml`, `go.mod`, `requirements*.txt`, `Gemfile`, `pom.xml`)
or a `run` step invoking that ecosystem's package manager (for example `npm ci`, `pip install`,
`go mod tidy`, `bundle install`, `mvn package`). This avoids warning about workflows that use a
setup action purely to run stdlib-only scripts, which have no dependencies for Dependabot to update.

npm manifest corroboration is content-aware: a root `package.json` corroborates the npm ecosystem
only when it declares at least one dependency entry (`dependencies`, `devDependencies`,
`peerDependencies`, `optionalDependencies`, or `bundledDependencies` / `bundleDependencies`). A bare
`package.json` with only `scripts` (a zero-dependency project) is not treated as evidence that npm
dependencies are managed — Dependabot would have nothing to update, so the missing-entry warning
would only add configuration noise. Lockfile corroboration (`package-lock.json` / `pnpm-lock.yaml` /
`yarn.lock`) remains presence-based. An unparseable `package.json` is treated conservatively as
corroborating, so malformed manifests never drop a legitimate warning.

npm command corroboration is likewise restricted to dependency-managing invocations (`npm install` /
`npm ci` / `npm add` / `npm update` / `yarn install` / `pnpm install` / `bun install`, ...). Script
runners (`npm test`, `npm run`, `npm exec`) and `npx` do not manage project dependencies, so they do
not corroborate a setup-node requirement on their own.

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

```text
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

- Requires local repository context. Legacy API-only remote scans skip the
  check; pull-request snapshot scans provide that context and run it.
- Lockfiles are inferred from the repository root only (no recursive scan), so monorepo dependencies
  nested in subdirectories are not detected.
- Matching is based on the presence of a `package-ecosystem`; the Dependabot `directory` value is not
  cross-checked.
- The Renovate skip is best-effort: a recognized broad preset skips the check globally; otherwise
  only ecosystems Renovate actually manages (matched via `packageRules.matchManagers` or
  `enabledManagers`) are treated as covered, and warnings for the rest still surface.
- The rule is diagnose-only and does not provide an auto-fix.

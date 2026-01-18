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

This rule detects potential cache poisoning vulnerabilities in GitHub Actions workflows. It identifies two types of cache poisoning attacks:

1. **Indirect Cache Poisoning**: Dangerous combinations of untrusted triggers with unsafe checkout and cache operations
2. **Direct Cache Poisoning**: Untrusted input in cache configuration (key, restore-keys, path) that can be exploited regardless of trigger type

#### Key Features

- **Dual Detection Mode**: Detects both indirect (trigger-based) and direct (input-based) cache poisoning
- **Multiple Trigger Detection**: Identifies `issue_comment`, `pull_request_target`, and `workflow_run` triggers
- **Comprehensive Cache Detection**: Detects both `actions/cache` and setup-* actions with cache enabled
- **Direct Cache Input Validation**: Checks for untrusted expressions in `key`, `restore-keys`, and `path` inputs
- **Job Isolation**: Correctly scopes detection to individual jobs
- **Smart Checkout Tracking**: Resets unsafe state when a safe checkout follows an unsafe one
- **Conservative Pattern Matching**: Detects direct, indirect, and unknown expression patterns
- **CodeQL Compatible**: Based on CodeQL's query with enhanced detection capabilities
- **Auto-fix Support**: Removes unsafe `ref` input from checkout steps or replaces untrusted cache keys with `github.sha`

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

#### For Direct Cache Poisoning

1. **Use Immutable Identifiers**: Use `github.sha` instead of branch names or other mutable references
2. **Use Content Hashing**: Use `hashFiles()` for content-based cache keys
3. **Avoid User-Controllable Values**: Never use values from PR titles, bodies, comments, or labels in cache keys
4. **Use Static Paths**: Use fixed paths for cache storage, not user-provided values

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

### Detection Strategy and CodeQL Compatibility

This rule is based on [CodeQL's `actions-cache-poisoning-direct-cache` query](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/) but implements additional detection capabilities:

#### Conservative Detection Approach

sisakulint uses a **conservative detection strategy** for maximum security:

- **Direct patterns**: Detects explicit PR head references like `github.head_ref` and `github.event.pull_request.head.sha`
- **Indirect patterns**: Detects step outputs that may contain PR head references (e.g., `steps.*.outputs.head_sha`)
- **Unknown expressions**: Any unknown expression in `ref` with untrusted triggers is treated as potentially unsafe

This conservative approach may result in some false positives but ensures that subtle attack vectors are not missed.

#### Differences from CodeQL

| Aspect | CodeQL | sisakulint |
|--------|--------|-----------|
| Detection scope | Explicit patterns only | Explicit + indirect + unknown expressions |
| Label guards | Considers `if: contains(labels)` as safe | Reports warning (conservative) |
| Multiple checkouts | May not handle correctly | Resets state on safe checkout |
| Step outputs | Limited detection | Comprehensive pattern matching |

**Example difference**: CodeQL may consider workflows with label guards safe, but sisakulint still reports warnings because label-based protection depends on operational procedures that may fail.

### OWASP CI/CD Security Risks

This rule addresses CICD-SEC-9: Improper Artifact Integrity Validation and helps mitigate risks related to cache manipulation in CI/CD pipelines.

### See Also

- [CodeQL: Cache Poisoning via Caching of Untrusted Files](https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/)
- [GitHub Actions Security: Preventing Pwn Requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Top 10: CICD-SEC-9](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation)

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/" >}}

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation" >}}

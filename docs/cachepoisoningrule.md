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

This rule detects potential cache poisoning vulnerabilities in GitHub Actions workflows. It identifies dangerous combinations of untrusted triggers with cache operations that could allow attackers to inject malicious payloads into the cache.

The rule detects three types of cache poisoning attacks:
1. **Indirect Cache Poisoning**: Untrusted triggers + unsafe checkout + cache actions
2. **Cache Hierarchy Exploitation**: Workflows that can write to default branch cache via external triggers
3. **Cache Eviction Risk**: Multiple cache actions that could enable cache flooding attacks

#### Key Features

- **Precise Detection**: Only triggers when all three risk conditions are present
- **Multiple Trigger Detection**: Identifies `issue_comment`, `pull_request_target`, and `workflow_run` triggers
- **Comprehensive Cache Detection**: Detects both `actions/cache` and setup-* actions with cache enabled
- **Job Isolation**: Correctly scopes detection to individual jobs
- **Smart Checkout Tracking**: Resets unsafe state when a safe checkout follows an unsafe one
- **Conservative Pattern Matching**: Detects direct, indirect, and unknown expression patterns
- **CodeQL Compatible**: Based on CodeQL's query with enhanced detection capabilities
- **Auto-fix Support**: Removes unsafe `ref` input from checkout steps
- **Cache Hierarchy Exploitation Detection**: Identifies workflows with external triggers that can poison default branch cache
- **Cache Eviction Risk Detection**: Warns when workflows use excessive cache actions (5+)

### Detection Conditions

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

### Example Vulnerable Workflows

#### Example 1: Direct PR Head Reference

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

#### Example 2: Indirect Reference via Step Output (CodeQL Pattern)

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

### Example Output

```bash
$ sisakulint ./vulnerable-workflow.yaml

./vulnerable-workflow.yaml:15:9: cache poisoning risk: 'actions/setup-node@v4' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      15 👈|      - uses: actions/setup-node@v4

./vulnerable-workflow.yaml:20:9: cache poisoning risk: 'actions/cache@v3' used after checking out untrusted PR code (triggers: pull_request_target). Validate cached content or scope cache to PR level [cache-poisoning]
      20 👈|      - uses: actions/cache@v3
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

The cache-poisoning rule supports auto-fixing by removing the unsafe `ref` input from `actions/checkout`

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

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

### Mitigation Strategies

1. **Validate Cached Content**: Verify integrity of restored cache before use
2. **Scope Cache to PR**: Use PR-specific cache keys to isolate caches
3. **Isolate Workflows**: Separate untrusted code execution from privileged operations
4. **Use Safe Checkout**: Avoid checking out PR code in workflows with untrusted triggers and caching

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

#### Mitigation Strategies

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

#### Mitigation Strategies

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
- [The Monsters in Your Build Cache - GitHub Actions Cache Poisoning](https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/) - Detailed analysis of cache hierarchy exploitation

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-cache-poisoning-direct-cache/" >}}

{{< popup_link2 href="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-09-Improper-Artifact-Integrity-Validation" >}}

{{< popup_link2 href="https://adnanthekhan.com/2024/05/06/the-monsters-in-your-build-cache-github-actions-cache-poisoning/" >}}

# CacheBloatRule

## Overview

Detects potential cache bloat issues when using `actions/cache/restore` and `actions/cache/save` without proper conditions. This rule helps prevent the common problem of GitHub Actions cache growing indefinitely.

## Security Impact

**Severity: Low (3/10)**

Cache bloat is primarily a resource efficiency concern with limited security impact:

1. **Resource Consumption**: Bloated caches slow down CI/CD pipelines
2. **Cache Limit Issues**: May hit GitHub's 10GB cache limit per repository
3. **Cache Eviction Risk**: Important caches may be evicted due to size constraints
4. **Operational Impact**: Slower build times and increased costs

This rule is classified as Low severity because it addresses operational efficiency rather than exploitable vulnerabilities. However, improper cache management can indirectly enable cache poisoning attacks by creating unpredictable cache behavior.

## Problem

When using the cache/restore and cache/save action pair without proper conditions, the cache can accumulate over time:

1. Old cache is restored (including stale entries)
2. New build artifacts are added to the cache
3. Everything (old + new) is saved back

This cycle causes the cache to grow with each CI run, leading to:
- Slower cache restore/save times
- Increased storage usage
- Potential hitting of GitHub's 10GB cache limit per repository

## Solution

The recommended pattern is:

- **cache/restore**: Skip on push events (`github.event_name != 'push'`)
- **cache/save**: Only run on push events (`github.event_name == 'push'`)

This ensures:
- On push events: A clean build creates fresh cache (no accumulation from previous cache)
- On pull_request events: Cache is read-only, benefiting from push-created cache without contributing to bloat

Note: This rule checks only the event type (`github.event_name`), not the branch name. For most workflows where push events are configured only for main/master branches, this effectively limits cache writes to those branches. If your workflow triggers push events on feature branches, consider adding additional branch conditions.

## Detected Patterns

### Vulnerable Pattern

```yaml
jobs:
  build:
    steps:
      - uses: actions/cache/restore@v4
        with:
          path: ~/.cache
          key: cache-key
      - run: build
      - uses: actions/cache/save@v4
        with:
          path: ~/.cache
          key: cache-key
```

### Safe Pattern

```yaml
jobs:
  build:
    steps:
      - uses: actions/cache/restore@v4
        if: github.event_name != 'push'
        with:
          path: ~/.cache
          key: cache-key
      - run: build
      - uses: actions/cache/save@v4
        if: github.event_name == 'push'
        with:
          path: ~/.cache
          key: cache-key
```

## Detection Logic

The rule triggers when:
1. Both `actions/cache/restore` and `actions/cache/save` are present in the same job
2. AND one or both are missing the appropriate `if` condition

The rule does NOT trigger when:
- Only `actions/cache/restore` is used (read-only usage)
- Only `actions/cache/save` is used
- The unified `actions/cache` action is used
- Both have proper conditions

## Auto-Fix

The rule provides auto-fix that adds the appropriate `if` conditions:

- For restore: `if: github.event_name != 'push'`
- For save: `if: github.event_name == 'push'`

If an existing `if` condition is present, the new condition is appended with `&&`.

## Severity

Warning (recommendation level)

## Related Rules

- [cache-poisoning](./cachepoisoningrule.md) - Detects cache poisoning vulnerabilities

## References

- [GitHub Actions Caching](https://docs.github.com/en/actions/using-workflows/caching-dependencies-to-speed-up-workflows)
- [actions/cache](https://github.com/actions/cache)

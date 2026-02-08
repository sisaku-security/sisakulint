# GHSA-h3qr-39j9-4r5v

## Summary
| Field | Value |
|-------|-------|
| CVE | CVE-2023-30853 |
| Affected Action | gradle/gradle-build-action |
| Severity | High |
| CVSS Score | 7.6/10 |
| Vulnerability Type | Secrets Exposure (CWE-200, CWE-312) |
| Published | 2023 |

## Vulnerability Description

The Gradle Build Action vulnerability affects GitHub workflows that executed Gradle Build Tool with configuration cache enabled. Environment variables containing GitHub Actions secrets may be persisted into GitHub Actions cache entries. These cached secrets can be accessed by untrusted workflows, such as those running for pull requests from repository forks.

The vulnerability was discovered through internal code review with no evidence of exploitation. The issue stems from how Gradle Build Tool records environment variables when configuration cache is enabled, potentially storing sensitive data that should remain ephemeral.

This creates a vulnerability in untrusted contexts like `pull_request_target`:
1. Secrets are passed as environment variables to Gradle build
2. Configuration cache includes these secrets
3. Cache is uploaded to GitHub Actions cache storage
4. Untrusted pull requests can potentially access cached secrets
5. Attacker gains access to sensitive credentials

The risk is particularly high when:
- Using `pull_request_target` or other privileged triggers
- Setting `cache-read-only: false` (allowing cache writes)
- Passing secrets as environment variables to Gradle tasks

**EPSS Score:** 0.187% (41st percentile)

**Affected versions:** All versions < 2.4.2
**Patched versions:** Version 2.4.2 and newer

## Vulnerable Pattern

```yaml
name: Vulnerable Pattern
on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # Vulnerable: Secrets passed to Gradle with cache writes enabled
      # Configuration cache will include API_KEY and SIGNING_KEY
      - uses: gradle/gradle-build-action@v2
        env:
          API_KEY: ${{ secrets.API_KEY }}
          SIGNING_KEY: ${{ secrets.SIGNING_KEY }}
        with:
          arguments: build
          cache-read-only: false  # Allows writing cache with secrets

      - name: Run tests
        env:
          API_KEY: ${{ secrets.API_KEY }}
        run: ./gradlew test
```

**Why this is vulnerable:**
- Gradle configuration cache includes environment variables
- Secrets are cached and persisted to GitHub Actions cache
- `cache-read-only: false` allows untrusted PRs to write cache
- Cached secrets may be accessible to subsequent PR runs
- No encryption or isolation of secrets in cache

**Attack Scenario:**
1. Legitimate build runs with secrets in `pull_request_target` context
2. Gradle configuration cache includes `API_KEY` and `SIGNING_KEY`
3. Cache is uploaded to GitHub Actions cache storage
4. Attacker opens PR and triggers `pull_request_target` workflow
5. Attacker's workflow reads cache, extracting secrets
6. Attacker exfiltrates secrets or uses them for unauthorized access

## Safe Pattern

```yaml
name: Safe Pattern
on:
  pull_request_target:

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}

      # Safe: Use cache-read-only for untrusted contexts
      # Prevents secrets from being written to cache
      - uses: gradle/gradle-build-action@v2
        with:
          arguments: build
          cache-read-only: true  # Read-only for untrusted PRs

      # Alternative: Disable configuration cache when secrets are needed
      - name: Run tests with secrets (no cache)
        env:
          API_KEY: ${{ secrets.API_KEY }}
          # Disable configuration cache to prevent caching secrets
          ORG_GRADLE_PROJECT_disableConfigurationCache: true
        run: ./gradlew test
```

**Why this is safe:**
- `cache-read-only: true` prevents writing cache in untrusted contexts
- Secrets are not persisted to cache
- Configuration cache disabled when secrets are required
- Separation of build (cacheable) and secret-using tasks

**Better Approach:**
```yaml
jobs:
  build:
    # Separate job for untrusted code (no secrets)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: gradle/gradle-build-action@v2
        with:
          arguments: build test
          # No secrets exposed, safe to cache

  deploy:
    # Separate job for trusted operations (with secrets)
    needs: build
    if: github.event.pull_request.base.ref == 'main'
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@v4
      - uses: gradle/gradle-build-action@v2
        env:
          API_KEY: ${{ secrets.API_KEY }}
        with:
          arguments: publish
          cache-read-only: true
```

## sisakulint Detection Result

```
script/actions/advisory/GHSA-h3qr-39j9-4r5v-vulnerable.yaml:9:3: dangerous trigger (critical): workflow uses privileged trigger(s) [pull_request_target] without any security mitigations. These triggers grant write access and secrets access to potentially untrusted code. Add at least one mitigation: restrict permissions (permissions: read-all or permissions: {}), use environment protection, add label conditions, or check github.actor. See https://sisaku-security.github.io/lint/docs/rules/dangeroustriggersrulecritical/ [dangerous-triggers-critical]
script/actions/advisory/GHSA-h3qr-39j9-4r5v-vulnerable.yaml:17:16: checking out untrusted code from pull request in workflow with privileged trigger 'pull_request_target' (line 9). This allows potentially malicious code from external contributors to execute with access to repository secrets. Use 'pull_request' trigger instead, or avoid checking out PR code when using 'pull_request_target'. See https://sisaku-security.github.io/lint/docs/rules/untrustedcheckout/ for more details [untrusted-checkout]
script/actions/advisory/GHSA-h3qr-39j9-4r5v-vulnerable.yaml:21:15: action 'gradle/gradle-build-action' is from an archived repository and is no longer maintained. Archived actions may have unpatched security vulnerabilities and should be replaced with maintained alternatives. See: https://github.com/gradle/gradle-build-action [archived-uses]
script/actions/advisory/GHSA-h3qr-39j9-4r5v-vulnerable.yaml:30:9: cache poisoning risk via local script execution: 'Run tests' runs untrusted code after checking out PR head (triggers: pull_request_target). Attacker can steal cache tokens [cache-poisoning-poisonable-step]
```

### Analysis

| Detected | Rule | Category Match |
|----------|------|----------------|
| Yes | cache-poisoning-poisonable-step | Yes |
| Yes | untrusted-checkout | Yes |
| Yes | archived-uses | Yes |
| Yes | dangerous-triggers-critical | Yes |

**Detection Details:**
- `CachePoisoningPoisonableStepRule` successfully detects the risk of cache token theft when running untrusted code
- `UntrustedCheckoutRule` identifies the unsafe checkout of PR code in privileged context
- `ArchivedUsesRule` flags the use of an archived action
- `DangerousTriggersCriticalRule` flags the unsafe `pull_request_target` trigger without mitigations
- Does not specifically detect secrets in Gradle configuration cache environment variables

## Reason for Partial Detection

Static analysis limitations:
- Difficult to trace environment variables to Gradle configuration cache
- Requires understanding of action-specific caching behavior
- Need to correlate secrets, environment variables, and cache settings
- Complex data flow across multiple steps and actions

However, sisakulint does detect the cache poisoning risk through untrusted code execution, which is a related security concern.

**Improvement Opportunity:**
Implement `SecretsInCacheRule` to detect:
- Secrets passed as env vars to build tools with caching
- `cache-read-only: false` in untrusted contexts with secrets
- Gradle configuration cache with sensitive environment variables

## Mitigation Recommendations

1. **Use `cache-read-only: true`**: For all untrusted contexts (pull_request_target, workflow_run)
2. **Disable configuration cache with secrets**: Set `ORG_GRADLE_PROJECT_disableConfigurationCache: true`
3. **Separate jobs**: Build without secrets, deploy with secrets in protected job
4. **Use environment protection**: Require manual approval for jobs with secrets
5. **Rotate secrets**: If vulnerable pattern was used, rotate all secrets
6. **Review cache contents**: Check if secrets were cached in past runs
7. **Limit secret scope**: Only expose secrets to specific steps that need them
8. **Use GitHub Secrets encryption**: Rely on runtime secrets, not cached values

## Technical Details

**Gradle Configuration Cache:**
```groovy
// Configuration cache includes environment variables
tasks.register("deploy") {
    doLast {
        // API_KEY from environment is cached during configuration
        def apiKey = System.getenv("API_KEY")
        println "Deploying with API key: ${apiKey}"
    }
}
```

**Cache Key Example:**
```
gradle-configuration-cache-{hash-of-build-files}
```

If API_KEY is accessed during configuration, it's included in cached state.

## References
- [GitHub Advisory: GHSA-h3qr-39j9-4r5v](https://github.com/advisories/GHSA-h3qr-39j9-4r5v)
- [Gradle Build Action Security Advisory](https://github.com/gradle/gradle-build-action/security/advisories/GHSA-h3qr-39j9-4r5v)
- [Patch Release v2.4.2](https://github.com/gradle/gradle-build-action/releases/tag/v2.4.2)
- [CVE-2023-30853](https://nvd.nist.gov/vuln/detail/CVE-2023-30853)
- [sisakulint: CachePoisoningRule](../cachepoisoningrule.md)
- [sisakulint: CachePoisoningPoisonableStepRule](../cachepoisoningpoisonablestep.md)
- [Gradle Configuration Cache](https://docs.gradle.org/current/userguide/configuration_cache.html)
- [gradle-build-action Security](https://github.com/gradle/gradle-build-action#security-considerations)
- [GitHub Actions: Cache Security](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions)

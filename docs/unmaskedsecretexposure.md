---
title: "Unmasked Secret Exposure Rule"
weight: 1
---

### Unmasked Secret Exposure Rule Overview

This rule detects **unmasked secret exposure** patterns in GitHub Actions workflows. When secrets are derived from other secrets using operations like `fromJson()`, the derived values are **NOT automatically masked** by GitHub Actions. This can lead to accidental exposure of sensitive information in workflow logs.

**Vulnerable Example:**

```yaml
name: Deploy
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Parse secrets
        run: |
          # DANGEROUS: Derived secrets are NOT masked!
          TOKEN=${{ fromJson(secrets.CONFIG).api_token }}
          echo "Using token: $TOKEN"  # This will be visible in logs!
```

**Detection Output:**

```bash
vulnerable.yaml:10:11: unmasked secret exposure: secrets derived using fromJson() are not automatically masked and may be exposed in workflow logs. Use '::add-mask::' to mask derived values. See https://codeql.github.com/codeql-query-help/actions/actions-unmasked-secret-exposure/ [unmasked-secret-exposure]
     10 |          TOKEN=${{ fromJson(secrets.CONFIG).api_token }}
```

### Security Background

#### What is Unmasked Secret Exposure?

GitHub Actions automatically masks secrets stored in the repository settings when they appear in logs. However, this masking only applies to the **original secret values**. When you derive new values from secrets (e.g., parsing JSON, string manipulation), these derived values are **not masked**.

| Scenario | Masking Behavior |
|----------|------------------|
| `${{ secrets.API_TOKEN }}` | Automatically masked |
| `${{ fromJson(secrets.CONFIG).token }}` | **NOT masked** |
| `${{ secrets.PREFIX }}_suffix` | **NOT masked** |

#### Why is this dangerous?

1. **Log Exposure**: Derived secret values appear in plain text in workflow logs
2. **Public Visibility**: For public repositories, anyone can view the logs
3. **Downstream Access**: Forks and Actions artifacts may contain exposed secrets
4. **Audit Trail**: Exposed secrets persist in log history

#### OWASP and CWE Mapping

- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-6:** Insufficient Credential Hygiene

### Detection Logic

#### What Gets Detected

1. **fromJson() with secrets**
   ```yaml
   ${{ fromJson(secrets.JSON_CONFIG).api_key }}
   ```

2. **Nested secret access**
   ```yaml
   ${{ fromJson(secrets.CONFIG).nested.secret }}
   ```

3. **Secrets in env variables**
   ```yaml
   env:
     PARSED_TOKEN: ${{ fromJson(secrets.CONFIG).token }}
   ```

#### What Is NOT Detected (Safe Patterns)

Direct secret usage (automatically masked):
```yaml
- run: echo "token is ${{ secrets.API_TOKEN }}"
```

Properly masked derived secrets:
```yaml
- run: |
    TOKEN=${{ fromJson(secrets.CONFIG).api_token }}
    echo "::add-mask::$TOKEN"
    echo "Using token: $TOKEN"  # Now masked
```

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will add the `::add-mask::` command before using derived secrets.

**Example:**

Before auto-fix:
```yaml
- run: |
    TOKEN=${{ fromJson(secrets.CONFIG).api_token }}
    echo "Deploying with token"
```

After running `sisakulint -fix on`:
```yaml
- run: |
    TOKEN=${{ fromJson(secrets.CONFIG).api_token }}
    echo "::add-mask::$TOKEN"
    echo "Deploying with token"
```

### Remediation Steps

When this rule triggers:

1. **Add masking for derived secrets**
   ```yaml
   - run: |
       DERIVED_SECRET=${{ fromJson(secrets.CONFIG).token }}
       echo "::add-mask::$DERIVED_SECRET"
   ```

2. **Use environment variables with masking**
   ```yaml
   - name: Set up secrets
     run: echo "::add-mask::$DERIVED_SECRET"
     env:
       DERIVED_SECRET: ${{ fromJson(secrets.CONFIG).token }}
   ```

3. **Consider restructuring secrets**
   - Store individual secrets separately instead of JSON blobs
   - Use separate secret entries for each value

### Best Practices

1. **Always mask derived secrets immediately**
   ```yaml
   - run: |
       VALUE=${{ fromJson(secrets.CONFIG).value }}
       echo "::add-mask::$VALUE"
       # Now safe to use $VALUE
   ```

2. **Prefer direct secret references**
   ```yaml
   # Instead of: fromJson(secrets.CONFIG).api_key
   # Use: secrets.API_KEY
   ```

3. **Audit workflow logs**
   - Regularly check logs for exposed secrets
   - Enable secret scanning in repository settings

4. **Use structured secret management**
   - Consider HashiCorp Vault or AWS Secrets Manager
   - These provide better access control and audit trails

### References

- [CodeQL: Unmasked Secret Exposure](https://codeql.github.com/codeql-query-help/actions/actions-unmasked-secret-exposure/)
- [GitHub: Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [GitHub: Workflow Commands](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#masking-a-value-in-a-log)

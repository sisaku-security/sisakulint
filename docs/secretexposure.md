---
title: "Secret Exposure Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Secret Exposure Rule Overview

This rule detects excessive secrets exposure patterns in GitHub Actions workflows. It identifies dangerous patterns that expose more secrets than necessary, violating the principle of least privilege.

### Security Impact

**Severity: High (8/10)**

Excessive secrets exposure poses significant risks:

1. **Credential Leakage**: All secrets become accessible if workflow is compromised
2. **Blast Radius Expansion**: Single vulnerability exposes entire secrets inventory
3. **Audit Difficulty**: Dynamic access makes it impossible to determine actual secret usage
4. **Least Privilege Violation**: Workflows access more secrets than required

This vulnerability aligns with **OWASP CI/CD Security Risk CICD-SEC-2: Inadequate Identity and Access Management**.

#### Key Features

- **toJSON(secrets) Detection**: Identifies when all secrets are exposed at once
- **Dynamic Access Detection**: Detects dynamic secret name construction
- **Bracket Notation Warning**: Recommends dot notation over bracket notation
- **Multiple Pattern Support**: Detects various forms of dynamic secret access
- **CodeQL Compatible**: Based on CodeQL's actions-excessive-secrets-exposure query

### Detection Patterns

The rule triggers when any of the following patterns are detected:

| Pattern | Risk Level | Description |
|---------|------------|-------------|
| `toJSON(secrets)` | High | Exposes all repository and organization secrets at once |
| `secrets[format(...)]` | High | Dynamically constructs secret names at runtime |
| `secrets[variable]` | High | Uses variables to access secrets dynamically |
| `secrets[object.property]` | High | Uses object properties for dynamic secret selection |
| `secrets['literal']` | Medium | Uses bracket notation instead of dot notation |

### Why This Is Dangerous

1. **Excessive Exposure**: Using `toJSON(secrets)` or dynamic access patterns exposes more secrets than the workflow actually needs
2. **Attack Surface**: If the workflow is compromised, all secrets become accessible to attackers
3. **Audit Difficulty**: Dynamic secret access makes it difficult to audit which secrets are actually used
4. **Least Privilege Violation**: Workflows should only access the specific secrets they require

### Example Vulnerable Workflows

#### Example 1: toJSON(secrets) - Exposing All Secrets

```yaml
name: Vulnerable Build
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      # BAD: Exposes ALL repository and organization secrets
      ALL_SECRETS: ${{ toJSON(secrets) }}
    steps:
      - name: Build
        run: |
          echo "Building with secrets..."
          # All secrets are now accessible via $ALL_SECRETS
```

#### Example 2: Dynamic Secret Access with format()

```yaml
name: Multi-Environment Deploy
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        env: [dev, staging, prod]
    steps:
      - name: Deploy
        env:
          # BAD: Dynamically constructs secret name
          TOKEN: ${{ secrets[format('DEPLOY_TOKEN_%s', matrix.env)] }}
        run: |
          echo "Deploying to ${{ matrix.env }}"
```

#### Example 3: Dynamic Access with Variable

```yaml
name: Dynamic Secret Access
on: workflow_dispatch

jobs:
  access:
    runs-on: ubuntu-latest
    steps:
      - name: Get secret dynamically
        env:
          SECRET_NAME: API_KEY
          # BAD: Uses variable to access secret
          SECRET_VALUE: ${{ secrets[env.SECRET_NAME] }}
        run: |
          echo "Secret retrieved"
```

#### Example 4: Bracket Notation

```yaml
name: Bracket Notation
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Use secret
        env:
          # NOT RECOMMENDED: Use secrets.GITHUB_TOKEN instead
          TOKEN: ${{ secrets['GITHUB_TOKEN'] }}
        run: |
          echo "Using token"
```

### Example Output

```bash
$ sisakulint ./vulnerable-workflow.yaml

./vulnerable-workflow.yaml:8:20: excessive secrets exposure: toJSON(secrets) exposes all repository and organization secrets at once. Use specific secret references like secrets.MY_SECRET instead. See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/ [secret-exposure]
       8 👈|      ALL_SECRETS: ${{ toJSON(secrets) }}

./vulnerable-workflow.yaml:22:18: excessive secrets exposure: secrets[format(...)] dynamically constructs the secret name. This pattern exposes more secrets than necessary and makes security auditing difficult. Use conditional logic with explicit secret references instead. See https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/ [secret-exposure]
      22 👈|          TOKEN: ${{ secrets[format('DEPLOY_TOKEN_%s', matrix.env)] }}
```

### Safe Patterns

The following patterns are recommended and do NOT trigger warnings:

#### 1. Explicit Secret References (Recommended)

```yaml
on: push

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      # GOOD: Only access the specific secrets needed
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - name: Build
        run: npm publish
```

#### 2. Conditional Logic Instead of Dynamic Access

```yaml
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        env: [dev, staging, prod]
    steps:
      # GOOD: Use conditional logic to select specific secrets
      - name: Deploy to dev
        if: matrix.env == 'dev'
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN_DEV }}
        run: ./deploy.sh

      - name: Deploy to staging
        if: matrix.env == 'staging'
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN_STAGING }}
        run: ./deploy.sh

      - name: Deploy to prod
        if: matrix.env == 'prod'
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN_PROD }}
        run: ./deploy.sh
```

#### 3. toJSON with Non-Secret Variables

```yaml
on: push

jobs:
  debug:
    runs-on: ubuntu-latest
    steps:
      - name: Debug context
        env:
          # GOOD: toJSON with non-secret variables is safe
          MATRIX_JSON: ${{ toJSON(matrix) }}
          GITHUB_JSON: ${{ toJSON(github) }}
          NEEDS_JSON: ${{ toJSON(needs) }}
        run: |
          echo "Matrix: $MATRIX_JSON"
```

#### 4. Reusable Workflows with Explicit Secrets

```yaml
on: push

jobs:
  deploy:
    # GOOD: Pass only the specific secrets needed
    uses: ./.github/workflows/deploy.yml
    secrets:
      deploy_token: ${{ secrets.DEPLOY_TOKEN }}
      npm_token: ${{ secrets.NPM_TOKEN }}
```

### Mitigation Strategies

1. **Use Explicit References**: Always use `secrets.SECRET_NAME` instead of dynamic access
2. **Conditional Logic**: Replace dynamic access with if conditions and explicit secret references
3. **Minimize Scope**: Only pass secrets to the steps that actually need them
4. **Audit Usage**: Regularly review which secrets each workflow uses
5. **Use Reusable Workflows**: Pass only required secrets to reusable workflows

### Auto-fix Support

The secret-exposure rule supports auto-fixing for bracket notation patterns by converting them to dot notation:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

After auto-fix, bracket notation will be converted to dot notation:

```yaml
# Before
env:
  TOKEN: ${{ secrets['GITHUB_TOKEN'] }}
  API_KEY: ${{ secrets['MY_API_KEY'] }}

# After auto-fix
env:
  TOKEN: ${{ secrets.GITHUB_TOKEN }}
  API_KEY: ${{ secrets.MY_API_KEY }}
```

**Limitations:**
- Only fixes bracket notation with string literals that are valid identifiers (letters, numbers, underscores)
- Does not fix dynamic patterns like `secrets[format(...)]`, `secrets[variable]`, or `toJSON(secrets)`
- Secret names with hyphens or dots cannot be auto-fixed (they are reported but require manual intervention)

### Comparison: Dynamic vs Explicit Access

| Approach | Security | Auditability | Recommendation |
|----------|----------|--------------|----------------|
| `secrets.MY_SECRET` | High | Easy | Recommended |
| `secrets['MY_SECRET']` | Medium | Medium | Avoid |
| `secrets[variable]` | Low | Difficult | Do Not Use |
| `secrets[format(...)]` | Low | Difficult | Do Not Use |
| `toJSON(secrets)` | Very Low | Impossible | Never Use |

### OWASP CI/CD Security Risks

This rule addresses **CICD-SEC-2: Inadequate Identity and Access Management** by enforcing the principle of least privilege for secrets access in CI/CD pipelines.

### See Also

- [CodeQL: Excessive Secrets Exposure](https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/)
- [GitHub Actions: Using Secrets](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)
- [OWASP CI/CD Top 10: CICD-SEC-2](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management)

{{< popup_link2 href="https://codeql.github.com/codeql-query-help/actions/actions-excessive-secrets-exposure/" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management" >}}

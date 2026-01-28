---
title: "Secrets Inherit Rule"
weight: 1
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

### Secrets Inherit Rule Overview

This rule detects excessive secret inheritance using `secrets: inherit` in reusable workflow calls. Using `secrets: inherit` violates the Principle of Least Authority by passing all repository and organization secrets to the called workflow instead of explicitly specifying only the required ones.

#### Key Features

- **Excessive Inheritance Detection**: Identifies `secrets: inherit` usage in workflow calls
- **Auto-fix Support**: Automatically replaces with explicit secret mappings when metadata is available
- **Template-based Fix**: Provides a template when called workflow metadata is not accessible
- **Local and External Workflow Support**: Detects issues in both local (`./.github/workflows/`) and external workflow calls

### Detection Patterns

The rule triggers when the following pattern is detected:

| Pattern | Risk Level | Description |
|---------|------------|-------------|
| `secrets: inherit` | High | Passes all secrets to the called workflow without filtering |

### Why This Is Dangerous

1. **Principle of Least Authority Violation**: The called workflow receives access to all secrets, even those it doesn't need
2. **Audit Difficulty**: It becomes impossible to determine exactly which secrets are used by the reusable workflow
3. **Attack Surface Expansion**: If the called workflow is compromised, all secrets become accessible
4. **Supply Chain Risk**: External workflows with `secrets: inherit` gain access to all your repository's secrets
5. **Unintended Exposure**: Organization secrets and repository secrets are all passed, potentially including sensitive credentials

### Example Vulnerable Workflows

#### Example 1: Local Workflow with secrets: inherit

```yaml
name: CI Pipeline
on: push

jobs:
  # BAD: All secrets are passed to the called workflow
  call-workflow:
    uses: ./.github/workflows/deploy.yml
    secrets: inherit
```

#### Example 2: External Workflow with secrets: inherit

```yaml
name: External Workflow Call
on: push

jobs:
  # BAD: All your secrets are passed to an external workflow
  call-external:
    uses: owner/repo/.github/workflows/workflow.yml@v1
    secrets: inherit
```

### Example Output

```bash
$ sisakulint ./vulnerable-workflow.yaml

./vulnerable-workflow.yaml:8:11: using 'secrets: inherit' in workflow call "./.github/workflows/deploy.yml" violates the principle of least authority. Explicitly specify only the secrets that are required by the called workflow instead of inheriting all secrets [secrets-inherit]
       8 |    uses: ./.github/workflows/deploy.yml
```

### Safe Patterns

The following patterns are recommended and do NOT trigger warnings:

#### 1. Explicit Secret Mapping (Recommended)

```yaml
name: CI Pipeline
on: push

jobs:
  # GOOD: Only required secrets are explicitly passed
  call-workflow:
    uses: ./.github/workflows/deploy.yml
    secrets:
      DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

#### 2. No Secrets Needed

```yaml
name: Build Pipeline
on: push

jobs:
  # GOOD: Workflow doesn't need secrets
  call-build:
    uses: ./.github/workflows/build.yml
```

#### 3. External Workflow with Explicit Secrets

```yaml
name: External Deploy
on: push

jobs:
  # GOOD: Only specific secrets are passed to external workflow
  deploy:
    uses: owner/repo/.github/workflows/deploy.yml@v1
    secrets:
      API_KEY: ${{ secrets.EXTERNAL_API_KEY }}
```

### Auto-fix Support

The secrets-inherit rule supports auto-fixing with two strategies:

#### 1. Metadata-based Fix (Local Workflows)

When the called workflow is local and sisakulint can read its metadata, it generates explicit mappings based on the workflow's declared secrets:

```bash
# Preview changes without applying
sisakulint -fix dry-run

# Apply fixes
sisakulint -fix on
```

**Before:**
```yaml
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
    secrets: inherit
```

**After (when deploy.yml declares TOKEN and API_KEY secrets):**
```yaml
jobs:
  deploy:
    uses: ./.github/workflows/deploy.yml
    secrets:
      TOKEN: ${{ secrets.TOKEN }}
      API_KEY: ${{ secrets.API_KEY }}
```

#### 2. Template-based Fix (External Workflows)

When metadata is not available (external workflows or inaccessible files), a template is generated:

**After:**
```yaml
jobs:
  deploy:
    uses: owner/repo/.github/workflows/deploy.yml@v1
    secrets:
      SECRET_NAME: ${{ secrets.SECRET_NAME }}
```

**Note:** You should review and modify the template to include only the secrets actually required by the called workflow.

### Comparison: inherit vs Explicit

| Approach | Security | Auditability | Maintenance | Recommendation |
|----------|----------|--------------|-------------|----------------|
| `secrets: inherit` | Low | Poor | Easy but risky | Avoid |
| Explicit mapping | High | Excellent | Clear dependencies | Recommended |
| No secrets section | High | N/A | Simple | Use when no secrets needed |

### Mitigation Strategies

1. **Review Called Workflow**: Check which secrets the reusable workflow actually needs
2. **Explicit Mapping**: Replace `secrets: inherit` with explicit secret mappings
3. **Minimize Secrets**: Only pass secrets that are truly required
4. **Document Dependencies**: Keep track of which workflows need which secrets
5. **Regular Audit**: Periodically review workflow secret usage

### OWASP CI/CD Security Risks

This rule addresses **CICD-SEC-2: Inadequate Identity and Access Management** by enforcing the principle of least privilege for secrets in reusable workflow calls.

### See Also

- [zizmor: secrets-inherit audit](https://docs.zizmor.sh/audits/#secrets-inherit)
- [GitHub Docs: Passing secrets to nested workflows](https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-secrets-to-nested-workflows)
- [GitHub Docs: Using secrets in a workflow](https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions)
- [OWASP CI/CD Top 10: CICD-SEC-2](https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management)

{{< popup_link2 href="https://docs.zizmor.sh/audits/#secrets-inherit" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/reusing-workflows#passing-secrets-to-nested-workflows" >}}

{{< popup_link2 href="https://owasp.org/www-project-top-10-ci-cd-security-risks/CICD-SEC-02-Inadequate-Identity-And-Access-Management" >}}

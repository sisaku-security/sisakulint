---
title: "Unsound Contains Rule"
weight: 1
---

### Unsound Contains Rule Overview

This rule detects **bypassable `contains()` function usage** in GitHub Actions conditions. When `contains()` is used with a string literal as the first argument and user-controllable input as the second, attackers can bypass the condition by manipulating their input.

**Vulnerable Example:**

```yaml
name: Deploy
on: push

jobs:
  deploy:
    if: contains('refs/heads/main refs/heads/develop', github.ref)
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
```

**Detection Output:**

```bash
vulnerable.yaml:6:9: unsound contains() usage: string literal 'refs/heads/main refs/heads/develop' as first argument with user-controllable 'github.ref' as second argument. Attacker can create branch 'main refs/heads/develop' to bypass this check. Use fromJSON() array format instead. [unsound-contains]
      6 |    if: contains('refs/heads/main refs/heads/develop', github.ref)
```

### Security Background

#### What is Unsound Contains?

The `contains()` function in GitHub Actions expressions has different behavior based on argument types:

| First Argument | Behavior |
|----------------|----------|
| Array | Checks if array contains the value |
| String | Checks if string contains substring |

When the first argument is a string literal containing multiple values (space-separated), an attacker can create input that matches unexpectedly.

#### Attack Scenario

```
Condition: contains('refs/heads/main refs/heads/develop', github.ref)

1. Legitimate: refs/heads/main -> matches (OK)
2. Legitimate: refs/heads/develop -> matches (OK)
3. ATTACK: refs/heads/main refs/heads/develop -> matches! (BAD)
4. ATTACK: refs/heads/m -> matches 'main' substring! (BAD)
```

An attacker can create a branch named `main refs/heads/develop` or simply `m` to bypass the intended check.

#### Why is this dangerous?

| Risk Factor | Impact |
|-------------|--------|
| **Branch Bypass** | Attacker creates branch matching substring |
| **Deployment Access** | Unauthorized deployments to production |
| **Protection Bypass** | Branch protection rules circumvented |
| **Privilege Escalation** | Access to protected environments |

#### OWASP and CWE Mapping

- **CWE-185**: Incorrect Regular Expression
- **CWE-697**: Incorrect Comparison
- **OWASP Top 10 CI/CD Security Risks:**
  - **CICD-SEC-4:** Poisoned Pipeline Execution (PPE)

### Detection Logic

#### What Gets Detected

1. **String literal with user-controllable context**
   ```yaml
   if: contains('main develop', github.ref_name)
   if: contains('refs/heads/main refs/heads/develop', github.ref)
   ```

2. **User-controllable contexts**
   - `github.ref`, `github.ref_name`
   - `github.head_ref`, `github.base_ref`
   - `github.actor`
   - `github.event.*` values
   - `inputs.*` values
   - `env.*` values

#### Safe Patterns (NOT Detected)

Array format with `fromJSON()`:
```yaml
if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
```

Single value check:
```yaml
if: github.ref == 'refs/heads/main'
```

Exact match:
```yaml
if: github.ref_name == 'main' || github.ref_name == 'develop'
```

### Auto-Fix

This rule supports automatic fixing. When you run sisakulint with the `-fix on` flag, it will convert the string literal to a `fromJSON()` array format.

**Example:**

Before auto-fix:
```yaml
if: contains('refs/heads/main refs/heads/develop', github.ref)
```

After running `sisakulint -fix on`:
```yaml
if: contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref)
```

### Remediation Steps

1. **Use fromJSON() array format**
   ```yaml
   if: contains(fromJSON('["main", "develop"]'), github.ref_name)
   ```

2. **Use explicit equality checks**
   ```yaml
   if: github.ref_name == 'main' || github.ref_name == 'develop'
   ```

3. **Use startsWith() for prefix matching**
   ```yaml
   if: startsWith(github.ref, 'refs/heads/release/')
   ```

### Best Practices

1. **Always use array format for multiple values**
   ```yaml
   if: contains(fromJSON('["value1", "value2"]'), variable)
   ```

2. **Prefer exact matches when possible**
   ```yaml
   if: github.ref == 'refs/heads/main'
   ```

3. **Be explicit about matching behavior**
   ```yaml
   # Substring match (intentional)
   if: contains(github.event.comment.body, '/deploy')

   # Exact match (preferred)
   if: github.event.comment.body == '/deploy'
   ```

4. **Validate branch names**
   - Use branch naming conventions
   - Implement branch protection rules
   - Restrict who can create branches

### Technical Details

The `contains()` function behavior:

```javascript
// Array behavior (safe)
contains(['main', 'develop'], 'main') // true
contains(['main', 'develop'], 'm')    // false

// String behavior (potentially unsafe)
contains('main develop', 'main')      // true
contains('main develop', 'm')         // true (substring!)
contains('main develop', 'main dev')  // true (substring!)
```

### References

- [GitHub: Expressions](https://docs.github.com/en/actions/learn-github-actions/expressions)
- [zizmor: Unsound Contains](https://github.com/woodruffw/zizmor)
- [GitHub: Workflow Syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions)

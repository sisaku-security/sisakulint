---
title: "Conditional Rule"
weight: 1
---

### Conditional Rule Overview

This rule detects a common mistake in GitHub Actions where `if` conditions with multiple `${{ }}` expressions or extra characters always evaluate to `true`. This happens because GitHub Actions treats any non-empty string outside of `${{ }}` as truthy.

#### Key Features:

- **Always-True Detection**: Identifies conditions that will always evaluate to true
- **Multiple Expression Detection**: Catches conditions with multiple `${{ }}` blocks that behave unexpectedly
- **Extra Character Detection**: Warns about conditions with characters outside `${{ }}` brackets

### Security Impact

**Severity: Medium (5/10)**

Incorrect conditional logic can lead to:

1. **Security Bypass**: Critical security checks may be skipped when conditions always evaluate to true
2. **Unintended Deployments**: Deployment jobs might run when they shouldn't
3. **Resource Waste**: Jobs may run unnecessarily, wasting CI/CD resources
4. **Logic Errors**: Workflow behavior becomes unpredictable and hard to debug
5. **Access Control Bypass**: Permission-gated jobs may execute without proper validation

### Understanding GitHub Actions Conditionals

GitHub Actions evaluates `if` conditions in a specific way:

1. **Without `${{ }}`**: The entire string is parsed as an expression
2. **With `${{ }}`**: Only the content inside `${{ }}` is evaluated as an expression

The problem arises when:
- Multiple `${{ }}` blocks are used
- Extra characters exist outside `${{ }}`

In these cases, the string representation of the condition is evaluated, and any non-empty string is truthy.

### Example Vulnerable Workflow

Common conditional mistakes:

```yaml
name: CI Build

on: [push, pull_request]

jobs:
  deploy:
    runs-on: ubuntu-latest
    # ❌ PROBLEM: This ALWAYS evaluates to true!
    # The string "${{ github.ref == 'refs/heads/main' }} && ${{ github.event_name == 'push' }}"
    # is a non-empty string, so it's truthy regardless of the actual conditions
    if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.event_name == 'push' }}
    steps:
      - run: echo "Deploying..."

  test:
    runs-on: ubuntu-latest
    # ❌ PROBLEM: Extra space/text makes this always true
    if: true ${{ github.actor != 'dependabot[bot]' }}
    steps:
      - run: echo "Testing..."

  release:
    runs-on: ubuntu-latest
    # ❌ PROBLEM: Text before ${{ }} makes this always true
    if: Run if ${{ github.ref == 'refs/tags/*' }}
    steps:
      - run: echo "Releasing..."
```

### What the Rule Detects

#### 1. Multiple `${{ }}` Blocks in Conditions

When multiple expression blocks are combined with operators outside the blocks:

```yaml
# ❌ Always true - operators are outside ${{ }}
if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.event_name == 'push' }}

# ❌ Always true - multiple blocks
if: ${{ condition1 }} || ${{ condition2 }}
```

**Error Output:**

```bash
workflow.yml:10:9: The condition '${{ github.ref == 'refs/heads/main' }} && ${{ github.event_name == 'push' }}' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions. [cond]
```

#### 2. Extra Characters Outside `${{ }}`

Any text outside the expression block causes the condition to always be true:

```yaml
# ❌ Always true - "true" text outside brackets
if: true ${{ github.actor != 'bot' }}

# ❌ Always true - comment-like text
if: Run if ${{ condition }}

# ❌ Always true - trailing space/text
if: ${{ condition }} # this is a comment
```

**Error Output:**

```bash
workflow.yml:10:9: The condition 'true ${{ github.actor != 'bot' }}' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions. [cond]
```

### Safe Patterns

#### Pattern 1: Single Expression Block (Recommended)

Put all logic inside a single `${{ }}`:

```yaml
# ✅ Correct: All logic inside one block
if: ${{ github.ref == 'refs/heads/main' && github.event_name == 'push' }}

# ✅ Correct: Complex conditions in one block
if: ${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') || github.event_name == 'workflow_dispatch' }}
```

#### Pattern 2: No Expression Brackets

Omit `${{ }}` entirely - GitHub auto-evaluates:

```yaml
# ✅ Correct: No brackets needed for simple expressions
if: github.ref == 'refs/heads/main'

# ✅ Correct: Complex conditions without brackets
if: github.ref == 'refs/heads/main' && github.event_name == 'push'

# ✅ Correct: Functions work without brackets too
if: success() && github.actor != 'dependabot[bot]'
```

#### Pattern 3: Boolean Literals

For explicit true/false:

```yaml
# ✅ Correct: Literal true
if: ${{ true }}

# ✅ Correct: Literal false
if: ${{ false }}

# ✅ Correct: Without brackets
if: true
if: false
```

#### Pattern 4: Using Functions

```yaml
# ✅ Correct: Status check functions
if: success()
if: failure()
if: always()
if: cancelled()

# ✅ Correct: Combined with conditions
if: ${{ success() && github.ref == 'refs/heads/main' }}

# Without brackets
if: success() && github.ref == 'refs/heads/main'
```

#### Pattern 5: Complex Conditional Logic

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    # ✅ Correct: All logic in one expression
    if: |
      ${{
        github.event_name == 'push' &&
        github.ref == 'refs/heads/main' &&
        !contains(github.event.head_commit.message, '[skip deploy]')
      }}
    steps:
      - run: ./deploy.sh

  notify:
    runs-on: ubuntu-latest
    needs: [build, test]
    # ✅ Correct: Using needs context
    if: ${{ always() && (needs.build.result == 'failure' || needs.test.result == 'failure') }}
    steps:
      - run: ./notify-failure.sh
```

### Why This Happens

GitHub Actions processes `if` conditions as follows:

1. **String interpolation**: `${{ }}` blocks are replaced with their evaluated values
2. **String evaluation**: The resulting string is then evaluated as a boolean
3. **Truthiness**: Any non-empty string is truthy in GitHub Actions context

Example of the problem:

```yaml
# Original condition
if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.event_name == 'push' }}

# After interpolation (assuming both are true)
if: true && true
# This is the STRING "true && true", not boolean operators!
# Non-empty string → truthy → condition passes

# After interpolation (assuming both are false)
if: false && false
# This is the STRING "false && false"
# Non-empty string → truthy → condition STILL passes!
```

### Technical Detection Mechanism

The rule checks for conditions that contain `${{ }}` but have additional content:

```go
func (rule *ConditionalRule) checkcond(n *ast.String) {
    if n == nil {
        return
    }
    if !n.ContainsExpression() {
        return
    }
    // Check if it's a single ${{ }} expression
    if strings.HasPrefix(n.Value, "${{") &&
       strings.HasSuffix(n.Value, "}}") &&
       strings.Count(n.Value, "${{") == 1 {
        return  // Valid single expression
    }
    // Multiple expressions or extra content detected
    rule.Errorf(n.Pos,
        "The condition '%s' will always evaluate to true...",
        n.Value)
}
```

### Common Mistakes

#### Mistake 1: Combining Expressions with External Operators

```yaml
# ❌ Wrong: && is outside ${{ }}
if: ${{ condition1 }} && ${{ condition2 }}

# ✅ Correct: && is inside ${{ }}
if: ${{ condition1 && condition2 }}
```

#### Mistake 2: Adding Comments or Labels

```yaml
# ❌ Wrong: Text outside expression
if: Deploy if ${{ github.ref == 'refs/heads/main' }}

# ✅ Correct: Use name field for description
name: Deploy (only on main)
if: ${{ github.ref == 'refs/heads/main' }}
```

#### Mistake 3: Copy-Paste Errors

```yaml
# ❌ Wrong: Accidentally duplicated expression
if: ${{ condition }}${{ condition }}

# ✅ Correct: Single expression
if: ${{ condition }}
```

#### Mistake 4: Whitespace Issues

```yaml
# ❌ Wrong: Trailing content (might be invisible whitespace)
if: ${{ condition }}

# ✅ Correct: Clean expression
if: ${{ condition }}
```

### Best Practices

#### 1. Prefer No Brackets for Simple Conditions

```yaml
# Simple and clean
if: github.ref == 'refs/heads/main'
if: github.event_name == 'push'
if: success()
```

#### 2. Use Single Block for Complex Conditions

```yaml
# All logic in one place
if: ${{ github.ref == 'refs/heads/main' && github.event_name == 'push' && success() }}
```

#### 3. Use YAML Multiline for Readability

```yaml
if: >-
  ${{
    github.event_name == 'push' &&
    github.ref == 'refs/heads/main' &&
    github.actor != 'dependabot[bot]'
  }}
```

#### 4. Document Complex Conditions

```yaml
# Deploy only on main branch push, excluding bot commits
name: Deploy to production
if: ${{ github.ref == 'refs/heads/main' && github.event_name == 'push' && github.actor != 'dependabot[bot]' }}
```

### Auto-Fix Support

sisakulint can automatically fix conditional rule violations by removing unnecessary `${{ }}` wrappers from conditions.

#### Auto-Fix Example

**Before (Problematic):**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    if: ${{ github.event.repository.owner.id }} == ${{ github.event.sender.id }}
    steps:
      - name: Test
        if: ${{ steps.previous.outputs.status }} == 'success'
        run: echo test
```

**After Auto-Fix:**
```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    if: github.event.repository.owner.id  ==  github.event.sender.id
    steps:
      - name: Test
        if: steps.previous.outputs.status  == 'success'
        run: echo test
```

#### How to Apply Auto-Fix

```bash
# Preview changes without modifying files
sisakulint -fix dry-run .github/workflows/

# Apply fixes to files
sisakulint -fix on .github/workflows/
```

#### What the Auto-Fix Does

1. **Removes `${{ }}` wrappers**: Strips the expression brackets while preserving the content
2. **Fixes both job and step conditions**: Applies to `if:` at job level and step level
3. **Preserves operators**: Keeps `==`, `!=`, `&&`, `||` and other operators intact

#### Limitations

- The auto-fix removes all `${{ }}` wrappers, which may leave extra whitespace
- Manual review is recommended after applying fixes
- Complex multi-line conditions may need manual adjustment

### Relationship to Other Rules

- **[expression]({{< ref "expressionrule.md" >}})**: Validates expression syntax within `${{ }}`
- **[code-injection-critical]({{< ref "codeinjectioncritical.md" >}})**: Checks for untrusted input in conditions

### Detection Example

Running sisakulint on a workflow with conditional issues:

```bash
$ sisakulint .github/workflows/ci.yml

.github/workflows/ci.yml:10:9: The condition '${{ github.ref == 'refs/heads/main' }} && ${{ github.event_name == 'push' }}' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions. [cond]
    10 👈|    if: ${{ github.ref == 'refs/heads/main' }} && ${{ github.event_name == 'push' }}

.github/workflows/ci.yml:20:9: The condition 'true ${{ github.actor != 'dependabot[bot]' }}' will always evaluate to true. If you intended to use a literal value, please use ${{ true }}. Ensure there are no extra characters within the ${{ }} brackets in conditions. [cond]
    20 👈|    if: true ${{ github.actor != 'dependabot[bot]' }}
```

### References

- [GitHub Docs: Workflow Syntax - if conditions](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idif)
- [GitHub Docs: Expressions](https://docs.github.com/en/actions/learn-github-actions/expressions)
- [GitHub Docs: Contexts](https://docs.github.com/en/actions/learn-github-actions/contexts)

### Testing

To test this rule:

```bash
# Detect conditional issues
sisakulint .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore cond
```

Disabling this rule is **not recommended** as incorrect conditionals can lead to unexpected workflow behavior and potential security bypasses.

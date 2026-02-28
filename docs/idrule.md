---
title: "ID Rule"
weight: 1
---

### ID Rule Overview

This rule validates that job and step IDs in GitHub Actions workflows follow the required naming conventions. Invalid IDs can cause workflow parsing errors, reference failures, and unexpected behavior.

### Security Impact

**Severity: Low (2/10)**

Invalid IDs are primarily a syntax validation concern with minimal direct security impact:

1. **Workflow Parsing Failures**: Invalid IDs cause GitHub Actions to reject workflows
2. **Reference Errors**: Expressions referencing invalid IDs fail at runtime
3. **Debugging Difficulty**: Poor naming conventions complicate troubleshooting

This rule is classified as Low severity because it addresses syntactic correctness rather than security vulnerabilities. Invalid IDs will prevent workflows from running rather than creating exploitable conditions.

**Invalid Example:**

```yaml
on: push

jobs:
  foo-v1.2.3:           # Invalid: contains periods
    runs-on: ubuntu-latest
    steps:
      - run: echo 'job ID with version'
        id: echo for test  # Invalid: contains spaces
  -hello-world-:        # Invalid: starts with hyphen
    runs-on: ubuntu-latest
    steps:
      - run: echo 'oops'
  2d-game:              # Invalid: starts with number
    runs-on: ubuntu-latest
    steps:
      - run: echo 'oops'
```

**Detection Output:**

```bash
a.yaml:5:3: Invalid job ID "foo-v1.2.3". job IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
      5 👈|  foo-v1.2.3:

a.yaml:10:13: Invalid step ID "echo for test". step IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
       10 👈|        id: echo for test

a.yaml:12:3: Invalid job ID "-hello-world-". job IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
       12 👈|  -hello-world-:

a.yaml:17:3: Invalid job ID "2d-game". job IDs must start with a letter or '_', and may contain only alphanumeric characters, '-', or '_'. [id]
       17 👈|  2d-game:
```

### Rule Background

#### Why ID Validation Matters

Job and step IDs are used for:

1. **Cross-Job References**: Jobs use IDs to reference other jobs in `needs:` dependencies
2. **Output References**: Steps use IDs to share outputs via `${{ steps.step_id.outputs.* }}`
3. **Conditional Logic**: IDs are used in `if:` conditions to check job/step results
4. **Debugging**: Clear IDs help identify issues in workflow logs

Invalid IDs can cause:

- **Workflow Parsing Failures**: GitHub Actions will reject workflows with invalid IDs
- **Reference Errors**: Expressions referencing invalid IDs will fail
- **Confusing Errors**: Runtime errors may be difficult to diagnose

#### GitHub's Naming Convention

GitHub Actions enforces strict naming rules for identifiers:

| Rule | Valid | Invalid |
|------|-------|---------|
| Must start with letter or `_` | `build`, `_setup` | `1task`, `-task` |
| Only alphanumeric, `-`, `_` allowed | `build-test`, `setup_env` | `build.test`, `setup env` |
| Case-sensitive | `Build` != `build` | - |

### Technical Detection Mechanism

The rule uses regex-based validation:

```go
// ID validation pattern
var validID = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]*$`)

func (rule *IDRule) validateID(idType string, id *ast.String) {
    if !validID.MatchString(id.Value) {
        rule.Errorf(id.Pos,
            "Invalid %s ID %q. %s IDs must start with a letter or '_', "+
            "and may contain only alphanumeric characters, '-', or '_'.",
            idType, id.Value, idType)
    }
}
```

### Detection Logic Explanation

#### What the Rule Checks

1. **Job IDs**: Validates all job identifiers in the workflow
2. **Step IDs**: Validates all step identifiers within jobs
3. **First Character**: Must be a letter (a-z, A-Z) or underscore (`_`)
4. **Subsequent Characters**: May only contain letters, numbers, hyphens, or underscores

#### Common Invalid Patterns

| Pattern | Issue | Fix |
|---------|-------|-----|
| `build.test` | Contains period | `build-test` |
| `setup env` | Contains space | `setup-env` or `setup_env` |
| `1st-job` | Starts with number | `first-job` or `_1st-job` |
| `-deploy` | Starts with hyphen | `deploy` or `_deploy` |

### Valid Patterns

#### Pattern 1: Simple Alphabetic IDs

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Building"
        id: compile
```

#### Pattern 2: Using Hyphens

```yaml
jobs:
  build-and-test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
        id: run-tests
```

#### Pattern 3: Using Underscores

```yaml
jobs:
  _internal_setup:
    runs-on: ubuntu-latest
    steps:
      - run: ./setup.sh
        id: setup_environment
```

#### Pattern 4: Mixed Conventions

```yaml
jobs:
  Build_Stage_1:
    runs-on: ubuntu-latest
    steps:
      - run: make build
        id: compile-step-1
```

### Best Practices

#### 1. Use Descriptive IDs

Choose IDs that clearly describe the job or step's purpose:

```yaml
# Good: Descriptive
jobs:
  run-unit-tests:
    steps:
      - id: setup-node-environment
        uses: actions/setup-node@v4

# Bad: Vague
jobs:
  job1:
    steps:
      - id: step1
        uses: actions/setup-node@v4
```

#### 2. Use Consistent Naming Conventions

Pick a convention and stick with it:

```yaml
# Consistent: kebab-case
jobs:
  build-app:
    steps:
      - id: install-deps
      - id: run-tests
      - id: build-output

# Consistent: snake_case
jobs:
  build_app:
    steps:
      - id: install_deps
      - id: run_tests
      - id: build_output
```

#### 3. Avoid Version Numbers in IDs

Version numbers may contain invalid characters:

```yaml
# Bad: Contains period
jobs:
  deploy-v1.2.3:

# Good: Use hyphen instead
jobs:
  deploy-v1-2-3:
```

#### 4. Keep IDs Reasonably Short

Long IDs can make expressions unwieldy:

```yaml
# Good: Concise
id: setup-node

# Bad: Too verbose
id: setup-node-environment-for-building-application
```

### Cross-References with IDs

#### Job Dependencies

```yaml
jobs:
  build:  # Valid ID
    runs-on: ubuntu-latest
    steps:
      - run: make build

  test:
    needs: build  # References job ID
    runs-on: ubuntu-latest
    steps:
      - run: make test
```

#### Step Output References

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - id: get-version  # Valid step ID
        run: echo "version=1.0.0" >> "$GITHUB_OUTPUT"

      - name: Deploy
        run: |
          echo "Deploying version ${{ steps.get-version.outputs.version }}"
```

#### Conditional References

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - id: check-cache
        run: |
          if [ -d "node_modules" ]; then
            echo "cache-hit=true" >> "$GITHUB_OUTPUT"
          fi

      - name: Install dependencies
        if: steps.check-cache.outputs.cache-hit != 'true'
        run: npm install
```

### False Positives

This rule has virtually no false positives because:

1. GitHub's naming rules are well-documented and strict
2. The validation regex matches GitHub's actual requirements
3. Invalid IDs will cause workflow failures regardless

### Related Rules

- **[workflow-call]({{< ref "workflowcall.md" >}})**: Validates reusable workflow syntax
- **[permissions]({{< ref "permissions.md" >}})**: Validates permission configurations

### References

#### GitHub Documentation
- [GitHub Docs: Workflow Syntax - Jobs](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_id)
- [GitHub Docs: Workflow Syntax - Steps ID](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsid)

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_id" >}}

{{< popup_link2 href="https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#jobsjob_idstepsid" >}}

### Testing

To test this rule:

```bash
# Detect invalid IDs
sisakulint .github/workflows/*.yml
```

### Configuration

This rule is enabled by default. To disable it:

```bash
sisakulint -ignore id
```

However, disabling this rule is **not recommended** as invalid IDs will cause workflow failures on GitHub.

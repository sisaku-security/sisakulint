# Taint Propagation Design for Code Injection Detection

## Overview

This document describes the design for Phase 1 of taint propagation tracking in sisakulint, focusing on environment variable-based taint propagation to detect code injection vulnerabilities like GHSL-2024-325.

## Problem Statement

Current `code-injection` rules only check for direct usage of `${{ }}` expressions in `run:` scripts. They miss indirect taint propagation through:

1. Environment variables set from untrusted inputs
2. Step outputs derived from untrusted inputs

### Example: GHSL-2024-325 (Actual Budget)

```yaml
on: issue_comment

jobs:
  push-patch:
    steps:
      - uses: gotson/pull-request-comment-branch@v1
        id: comment-branch

      - env:
          BRANCH_NAME: ${{ steps.comment-branch.outputs.head_ref }}
        run: |
          git push origin HEAD:${BRANCH_NAME}  # NOT DETECTED!
```

The `BRANCH_NAME` variable contains attacker-controlled data, but sisakulint doesn't detect this because `steps.*.outputs.*` is not tracked as untrusted.

## Solution: TaintTracker

### Architecture

```
codeinjection.go
├── TaintTracker (NEW)
│   ├── AnalyzeStep()              # Collect taint from $GITHUB_OUTPUT writes
│   ├── IsTainted()                # Check if expression is tainted
│   └── taintedOutputs             # stepID -> outputName -> sources
├── extractEnvVarsWithUntrustedInput()  # Extended to use TaintTracker
└── checkShellMetacharacterInjection()  # Unchanged (uses shell.FindEnvVarUsages)
```

### Phase 1 Scope

Track taint propagation through:
1. `env:` section - variables set from untrusted expressions
2. `$GITHUB_OUTPUT` writes - outputs derived from untrusted inputs
3. `steps.*.outputs.*` references - propagate taint to consumers

### Detection Flow

```
1. VisitWorkflowPre: Initialize TaintTracker
2. VisitJobPre:
   a. First pass: Analyze all steps for $GITHUB_OUTPUT writes
   b. Record tainted outputs
3. VisitStep (second pass):
   a. Check env: expressions against BuiltinUntrustedInputs + taintedOutputs
   b. Check run: scripts for dangerous usage of tainted env vars
```

## Implementation Details

### TaintTracker Structure

```go
// pkg/core/taint.go

type TaintTracker struct {
    // stepID -> outputName -> taint sources (e.g., "github.head_ref")
    taintedOutputs map[string]map[string][]string
}

func NewTaintTracker() *TaintTracker

// Analyze step for $GITHUB_OUTPUT writes with tainted values
func (t *TaintTracker) AnalyzeStep(step *ast.Step)

// Check if expression references tainted step output
func (t *TaintTracker) IsTainted(expr expressions.ExprNode) (bool, []string)
```

### $GITHUB_OUTPUT Write Detection

```go
// pkg/core/taint_github_output.go

// Detect patterns like:
// - echo "name=value" >> $GITHUB_OUTPUT
// - echo "name=${{ untrusted }}" >> $GITHUB_OUTPUT
// - printf "name=%s" "$TAINTED_VAR" >> $GITHUB_OUTPUT

func (t *TaintTracker) analyzeGitHubOutputWrites(script string, stepID string)
```

### Detection Patterns

```bash
# Pattern 1: Direct echo with expression
echo "ref=${{ github.head_ref }}" >> $GITHUB_OUTPUT
# -> steps.<id>.outputs.ref is tainted

# Pattern 2: Variable propagation
REF="${{ github.head_ref }}"
echo "ref=$REF" >> $GITHUB_OUTPUT
# -> steps.<id>.outputs.ref is tainted

# Pattern 3: Heredoc
cat <<EOF >> $GITHUB_OUTPUT
ref=${{ github.head_ref }}
EOF
# -> steps.<id>.outputs.ref is tainted
```

### Integration with CodeInjectionRule

```go
// pkg/core/codeinjection.go

type CodeInjectionRule struct {
    BaseRule
    // ... existing fields
    taintTracker *TaintTracker  // NEW
}

func (rule *CodeInjectionRule) VisitWorkflowPre(node *ast.Workflow) error {
    rule.taintTracker = NewTaintTracker()
    rule.workflow = node
    return nil
}

func (rule *CodeInjectionRule) VisitJobPre(node *ast.Job) error {
    // First: collect taint information
    for _, step := range node.Steps {
        rule.taintTracker.AnalyzeStep(step)
    }

    // Then: run existing detection with taint awareness
    // ...
}

// Extended to check tainted step outputs
func (rule *CodeInjectionRule) checkUntrustedInputWithTaint(expr parsedExpression) []string {
    // 1. Check BuiltinUntrustedInputs (existing)
    paths := rule.checkUntrustedInput(expr)

    // 2. Check tainted step outputs (NEW)
    if tainted, sources := rule.taintTracker.IsTainted(expr.node); tainted {
        paths = append(paths, sources...)
    }

    return paths
}
```

## Limitations (Phase 1)

- Dynamic output names (`echo "$NAME=$VALUE"`) are not tracked
- Writes inside external script calls are not tracked
- All writes inside conditionals are tracked conservatively
- Complex shell variable transformations are not tracked

## Future Phases

### Phase 2: Step Output to Step Output Propagation
Track when a step reads tainted output and writes to its own output.

### Phase 3: Action Input/Output Inference
Infer that action outputs are tainted based on tainted inputs.

## Test Cases

### Vulnerable Pattern (should detect)

```yaml
# script/actions/taint-propagation-critical.yaml
name: Taint Propagation Test
on: issue_comment

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: get-ref
        run: echo "ref=${{ github.head_ref }}" >> $GITHUB_OUTPUT

      - env:
          BRANCH: ${{ steps.get-ref.outputs.ref }}
        run: |
          git push origin HEAD:${BRANCH}  # Should be detected
```

### Safe Pattern (should not detect)

```yaml
# script/actions/taint-propagation-safe.yaml
name: Safe Pattern
on: push

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - id: get-ref
        run: echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT  # github.sha is safe

      - env:
          REF: ${{ steps.get-ref.outputs.ref }}
        run: |
          git checkout $REF  # Safe
```

## File Structure

```
pkg/core/
├── taint.go                    # TaintTracker implementation
├── taint_github_output.go      # $GITHUB_OUTPUT analysis
├── taint_test.go               # Unit tests
├── codeinjection.go            # Integration (modified)
└── codeinjection_shell.go      # Existing (unchanged)

script/actions/
├── taint-propagation-critical.yaml  # Test vulnerable pattern
└── taint-propagation-safe.yaml      # Test safe pattern
```

## References

- GHSL-2024-325: https://securitylab.github.com/advisories/GHSL-2024-325_GHSL-2024-326_Actual/
- GitHub Actions Security: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- Existing shell parser: `pkg/shell/parser.go`

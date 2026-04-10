package core

import (
	"strings"
	"testing"
)

func TestAIActionUnsafeSandbox_DetectsUnsafeStrategy(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: unsafe
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) == 0 {
		t.Fatal("expected error for safety-strategy: unsafe, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "safety-strategy") {
		t.Errorf("expected error to mention safety-strategy, got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-unsafe-sandbox" {
		t.Errorf("expected error type ai-action-unsafe-sandbox, got: %s", ruleErrors[0].Type)
	}
}

func TestAIActionUnsafeSandbox_DetectsDangerFullAccess(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: danger-full-access
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) == 0 {
		t.Fatal("expected error for safety-strategy: danger-full-access, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "danger-full-access") {
		t.Errorf("expected error to mention danger-full-access, got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnsafeSandbox_DetectsDangerouslySkipPermissions(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --dangerouslySkipPermissions --allowedTools "Bash,Read"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) == 0 {
		t.Fatal("expected error for --dangerouslySkipPermissions, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "dangerouslySkipPermissions") {
		t.Errorf("expected error to mention dangerouslySkipPermissions, got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnsafeSandbox_AllowsSafeStrategies(t *testing.T) {
	t.Parallel()

	safeValues := []string{"drop-sudo", "unprivileged-user", "read-only"}
	for _, val := range safeValues {
		t.Run(val, func(t *testing.T) {
			t.Parallel()
			rule := NewAIActionUnsafeSandboxRule()

			workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          safety-strategy: ` + val + `
`
			parsed, errs := Parse([]byte(workflow))
			if len(errs) > 0 {
				t.Fatalf("failed to parse workflow: %v", errs)
			}

			v := NewSyntaxTreeVisitor()
			v.AddVisitor(rule)
			if err := v.VisitTree(parsed); err != nil {
				t.Fatalf("failed to visit tree: %v", err)
			}

			ruleErrors := rule.Errors()
			if len(ruleErrors) != 0 {
				t.Fatalf("expected no errors for safe strategy %q, got %d: %v", val, len(ruleErrors), ruleErrors)
			}
		})
	}
}

func TestAIActionUnsafeSandbox_IgnoresNonAIAction(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          safety-strategy: unsafe
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors for non-AI action, got %d", len(ruleErrors))
	}
}

func TestAIActionUnsafeSandbox_NoSandboxInputIsOK(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnsafeSandboxRule()

	workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with:
          model: o3-mini
`
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	ruleErrors := rule.Errors()
	if len(ruleErrors) != 0 {
		t.Fatalf("expected no errors when safety-strategy is not set, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

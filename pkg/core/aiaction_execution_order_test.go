package core

import (
	"strings"
	"testing"
)

func TestAIActionExecutionOrder_DetectsNotLastStep(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExecutionOrderRule()

	workflow := `
on:
  push:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: openai/codex-action@v1
        with:
          safety-strategy: drop-sudo
      - run: npm publish
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
		t.Fatal("expected error for AI action not being last step, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "not the last step") {
		t.Errorf("expected error to mention 'not the last step', got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-execution-order" {
		t.Errorf("expected error type ai-action-execution-order, got: %s", ruleErrors[0].Type)
	}
}

func TestAIActionExecutionOrder_AllowsLastStep(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExecutionOrderRule()

	workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: openai/codex-action@v1
        with:
          safety-strategy: drop-sudo
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
		t.Fatalf("expected no errors when AI action is last step, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIActionExecutionOrder_IgnoresNonAIAction(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExecutionOrderRule()

	workflow := `
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm test
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
		t.Fatalf("expected no errors for non-AI actions, got %d", len(ruleErrors))
	}
}

func TestAIActionExecutionOrder_DetectsMultipleAIActions(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExecutionOrderRule()

	workflow := `
on:
  push:
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: openai/codex-action@v1
        with:
          safety-strategy: drop-sudo
      - run: echo "done"
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
	if len(ruleErrors) < 2 {
		t.Fatalf("expected at least 2 errors for multiple AI actions not being last, got %d", len(ruleErrors))
	}
}

func TestAIActionExecutionOrder_ClaudeCodeAction(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExecutionOrderRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
      - run: echo "post-processing"
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
		t.Fatal("expected error for claude-code-action not being last step, got none")
	}
}

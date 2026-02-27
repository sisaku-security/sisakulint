package core

import (
	"strings"
	"testing"
)

func TestAIActionUnrestrictedTrigger_DetectsWildcard(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

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
          allowed_non_write_users: "*"
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
		t.Fatal("expected error for allowed_non_write_users: \"*\", got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "ai-action-unrestricted-trigger") {
		t.Errorf("expected error description to contain \"ai-action-unrestricted-trigger\", got: %s", ruleErrors[0].Description)
	}
}

func TestAIActionUnrestrictedTrigger_IgnoresSafeConfig(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

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
		t.Fatalf("expected no errors for safe config, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIActionUnrestrictedTrigger_IgnoresNonAIAction(t *testing.T) {
	t.Parallel()
	rule := NewAIActionUnrestrictedTriggerRule()

	workflow := `
on:
  issues:
    types: [opened]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          allowed_non_write_users: "*"
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

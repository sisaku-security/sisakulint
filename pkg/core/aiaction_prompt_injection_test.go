package core

import (
	"strings"
	"testing"
)

func TestAIPromptInjection_DetectsIssueTitleInPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIActionPromptInjectionRule()

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
          prompt: "Please triage this issue: ${{ github.event.issue.title }}"
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
		t.Fatal("expected error for untrusted input in prompt, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "prompt") {
		t.Errorf("expected error description to contain \"prompt\", got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-prompt-injection" {
		t.Errorf("expected error type to be \"ai-action-prompt-injection\", got: %s", ruleErrors[0].Type)
	}
}

func TestAIPromptInjection_DetectsIssueBodyInDirectPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIActionPromptInjectionRule()

	workflow := `
on:
  issue_comment:
    types: [created]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          direct_prompt: "Process this comment: ${{ github.event.comment.body }}"
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
		t.Fatal("expected error for untrusted input in direct_prompt, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "direct_prompt") {
		t.Errorf("expected error description to contain \"direct_prompt\", got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-prompt-injection" {
		t.Errorf("expected error type to be \"ai-action-prompt-injection\", got: %s", ruleErrors[0].Type)
	}
}

func TestAIPromptInjection_AllowsStaticPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIActionPromptInjectionRule()

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
          prompt: "Please triage the issue described in the environment variables ISSUE_TITLE and ISSUE_BODY."
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
		t.Fatalf("expected no errors for static prompt, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIPromptInjection_AllowsTrustedInputInPrompt(t *testing.T) {
	t.Parallel()
	rule := NewAIActionPromptInjectionRule()

	// github.event.issue.number と github.repository は BuiltinUntrustedInputs に含まれないため信頼できる値
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
          prompt: "Triage issue #${{ github.event.issue.number }} in repo ${{ github.repository }}"
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
		t.Fatalf("expected no errors for trusted inputs, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

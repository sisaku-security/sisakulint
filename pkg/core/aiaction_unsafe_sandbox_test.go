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

// The flag Claude Code accepts is --dangerously-skip-permissions. Until #647 the
// rule looked only for the camel-case spelling below and therefore reported
// nothing for a workflow that actually bypasses the permission checks.
func TestAIActionUnsafeSandbox_DetectsDangerouslySkipPermissionsFlag(t *testing.T) {
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
          claude_args: --dangerously-skip-permissions
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
		t.Fatal("expected error for --dangerously-skip-permissions, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "--dangerously-skip-permissions") {
		t.Errorf("expected error to mention --dangerously-skip-permissions, got: %s", ruleErrors[0].Description)
	}
	if strings.Contains(ruleErrors[0].Description, "dangerouslySkipPermissions") {
		t.Errorf("expected error not to mention the camel-case spelling, got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-unsafe-sandbox" {
		t.Errorf("expected error type ai-action-unsafe-sandbox, got: %s", ruleErrors[0].Type)
	}
}

// The camel-case spelling is not a Claude Code option (the CLI rejects it as
// "unknown option"), so it cannot bypass the permission checks. It is still
// reported because it is written as a bypass, but the message must not claim a
// bypass happened.
func TestAIActionUnsafeSandbox_CamelCaseSpellingIsReportedAsUnknownOption(t *testing.T) {
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
	if !strings.Contains(ruleErrors[0].Description, "--dangerouslySkipPermissions") {
		t.Errorf("expected error to mention the spelling that was written, got: %s", ruleErrors[0].Description)
	}
	if !strings.Contains(ruleErrors[0].Description, "unknown option") {
		t.Errorf("expected error to say that Claude Code rejects the spelling, got: %s", ruleErrors[0].Description)
	}
	if !strings.Contains(ruleErrors[0].Description, "--dangerously-skip-permissions") {
		t.Errorf("expected error to name the flag Claude Code accepts, got: %s", ruleErrors[0].Description)
	}
}

// A step carrying both spellings is one problem, not two.
func TestAIActionUnsafeSandbox_BothSpellingsReportOnce(t *testing.T) {
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
          claude_args: --dangerously-skip-permissions --dangerouslySkipPermissions
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
	if len(ruleErrors) != 1 {
		t.Fatalf("expected exactly one error when both spellings are present, got %d: %v", len(ruleErrors), ruleErrors)
	}
	if !strings.Contains(ruleErrors[0].Description, "--dangerously-skip-permissions") {
		t.Errorf("expected error to mention --dangerously-skip-permissions, got: %s", ruleErrors[0].Description)
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

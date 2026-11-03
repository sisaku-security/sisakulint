package core

import (
	"strings"
	"testing"
)

func TestAIActionExcessiveTools_DetectsBashWithIssuesTrigger(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

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
          claude_args: --allowedTools "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"
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
		t.Fatal("expected error for Bash tool with issues trigger, got none")
	}
	if !strings.Contains(ruleErrors[0].Description, "Bash") {
		t.Errorf("expected error description to contain \"Bash\", got: %s", ruleErrors[0].Description)
	}
	if ruleErrors[0].Type != "ai-action-excessive-tools" {
		t.Errorf("expected error type to be \"ai-action-excessive-tools\", got: %s", ruleErrors[0].Type)
	}
}

func TestAIActionExcessiveTools_AllowsReadOnlyTools(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

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
          claude_args: --allowedTools "Read,Glob,Grep"
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
		t.Fatalf("expected no errors for read-only tools with issues trigger, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

func TestAIActionExcessiveTools_AllowsBashWithPushTrigger(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

	workflow := `
on:
  push:
    branches: [main]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write"
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
		t.Fatalf("expected no errors for Bash tool with push trigger (trusted), got %d: %v", len(ruleErrors), ruleErrors)
	}
}

// A tool listed under --disallowedTools is denied, not granted. Until #646 the
// rule scanned the whole claude_args string, so naming Bash there made it report
// Bash as granted.
func TestAIActionExcessiveTools_IgnoresToolsDeniedByDisallowedTools(t *testing.T) {
	t.Parallel()
	rule := NewAIActionExcessiveToolsRule()

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
          claude_args: --allowedTools "Read,Glob,Grep" --disallowedTools "Bash,Write,Edit"
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
		t.Fatalf("expected no errors when the dangerous tools are disallowed, got %d: %v", len(ruleErrors), ruleErrors)
	}
}

// The grant has to keep being detected when --allowedTools is not the first
// flag and when it is repeated.
func TestAIActionExcessiveTools_ReadsOnlyAllowedToolsValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		claudeArgs   string
		wantTools    []string
		wantNoErrors bool
	}{
		{
			name:       "quoted list after another flag",
			claudeArgs: `--verbose --allowedTools "Read,Bash"`,
			wantTools:  []string{"Bash"},
		},
		{
			name:       "equals form",
			claudeArgs: `--allowedTools=Read,Write`,
			wantTools:  []string{"Write"},
		},
		{
			name:       "repeated flag",
			claudeArgs: `--allowedTools "Read" --allowedTools "NotebookEdit"`,
			wantTools:  []string{"NotebookEdit"},
		},
		{
			name:       "unquoted values",
			claudeArgs: `--allowedTools Read Edit`,
			wantTools:  []string{"Edit"},
		},
		{
			name:         "deny flag before the allow flag",
			claudeArgs:   `--disallowedTools "Bash" --allowedTools "Read"`,
			wantNoErrors: true,
		},
		{
			name:         "deny flag only",
			claudeArgs:   `--disallowedTools "Bash,Write,Edit"`,
			wantNoErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewAIActionExcessiveToolsRule()

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
          claude_args: ` + tt.claudeArgs + `
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
			if tt.wantNoErrors {
				if len(ruleErrors) != 0 {
					t.Fatalf("expected no errors, got %d: %v", len(ruleErrors), ruleErrors)
				}
				return
			}
			if len(ruleErrors) != 1 {
				t.Fatalf("expected one error, got %d: %v", len(ruleErrors), ruleErrors)
			}
			for _, tool := range tt.wantTools {
				if !strings.Contains(ruleErrors[0].Description, tool) {
					t.Errorf("expected error to mention %q, got: %s", tool, ruleErrors[0].Description)
				}
			}
		})
	}
}

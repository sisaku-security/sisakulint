package core

import (
	"strings"
	"testing"
)

func TestBotConditionsRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workflow    string
		expectError bool
		errContains string
	}{
		{
			name: "vulnerable: github.actor bot check in job if",
			workflow: `
on: pull_request_target
jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`,
			expectError: true,
			errContains: "spoofable bot condition",
		},
		{
			name: "vulnerable: github.triggering_actor bot check",
			workflow: `
on: workflow_run
jobs:
  deploy:
    if: github.triggering_actor == 'renovate[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: npm deploy
`,
			expectError: true,
			errContains: "github.triggering_actor",
		},
		{
			name: "vulnerable: github.event.pull_request.sender.login bot check",
			workflow: `
on: pull_request_target
jobs:
  approve:
    if: github.event.pull_request.sender.login == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: echo "approved"
`,
			expectError: true,
			errContains: "github.event.pull_request.sender.login",
		},
		{
			name: "vulnerable: github.actor_id with known bot ID",
			workflow: `
on: pull_request_target
jobs:
  auto-merge:
    if: github.actor_id == '49699333'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`,
			expectError: true,
			errContains: "github.actor_id",
		},
		{
			name: "vulnerable: step-level bot check",
			workflow: `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - if: github.actor == 'dependabot[bot]'
        run: gh pr merge --auto
`,
			expectError: true,
			errContains: "spoofable bot condition",
		},
		{
			name: "vulnerable: OR condition (dominant)",
			workflow: `
on: pull_request_target
jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`,
			expectError: true,
			errContains: "High confidence",
		},
		{
			name: "safe: github.event.pull_request.user.login",
			workflow: `
on: pull_request_target
jobs:
  auto-merge:
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`,
			expectError: false,
		},
		{
			name: "safe: no bot pattern in condition",
			workflow: `
on: pull_request_target
jobs:
  build:
    if: github.actor != ''
    runs-on: ubuntu-latest
    steps:
      - run: npm build
`,
			expectError: false,
		},
		{
			name: "safe: issue_comment with safe context",
			workflow: `
on: issue_comment
jobs:
  respond:
    if: github.event.comment.user.login == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: echo "bot comment"
`,
			expectError: false,
		},
		{
			name: "vulnerable: multiple bot checks with OR",
			workflow: `
on: pull_request_target
jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]' || github.actor == 'github-actions[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`,
			expectError: true,
			errContains: "spoofable bot condition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewBotConditionsRule()
			workflow, errs := Parse([]byte(tt.workflow))
			if len(errs) > 0 {
				t.Fatalf("failed to parse workflow: %v", errs)
			}

			v := NewSyntaxTreeVisitor()
			v.AddVisitor(rule)
			if err := v.VisitTree(workflow); err != nil {
				t.Fatalf("failed to visit tree: %v", err)
			}

			ruleErrors := rule.Errors()

			if tt.expectError {
				if len(ruleErrors) == 0 {
					t.Errorf("expected error containing %q but got none", tt.errContains)
				} else {
					found := false
					for _, err := range ruleErrors {
						if strings.Contains(err.Description, tt.errContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error containing %q but got: %v", tt.errContains, ruleErrors[0].Description)
					}
				}
			} else {
				if len(ruleErrors) > 0 {
					t.Errorf("expected no errors but got: %v", ruleErrors[0].Description)
				}
			}
		})
	}
}

func TestBotConditionsRuleSafeReplacements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		triggerEvent   string
		isIDContext    bool
		expectedResult string
	}{
		{
			name:           "pull_request_target login",
			triggerEvent:   "pull_request_target",
			isIDContext:    false,
			expectedResult: "github.event.pull_request.user.login",
		},
		{
			name:           "pull_request_target id",
			triggerEvent:   "pull_request_target",
			isIDContext:    true,
			expectedResult: "github.event.pull_request.user.id",
		},
		{
			name:           "issue_comment login",
			triggerEvent:   "issue_comment",
			isIDContext:    false,
			expectedResult: "github.event.comment.user.login",
		},
		{
			name:           "workflow_run login",
			triggerEvent:   "workflow_run",
			isIDContext:    false,
			expectedResult: "github.event.workflow_run.actor.login",
		},
		{
			name:           "unknown event login",
			triggerEvent:   "push",
			isIDContext:    false,
			expectedResult: "github.event.sender.login",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewBotConditionsRule()
			rule.currentTriggerEvent = tt.triggerEvent

			result := rule.getSafeReplacement(tt.isIDContext)
			if result != tt.expectedResult {
				t.Errorf("expected %q but got %q", tt.expectedResult, result)
			}
		})
	}
}

func TestBotConditionsRuleDominantCondition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		condition  string
		context    string
		isDominant bool
	}{
		{
			name:       "simple equality is dominant",
			condition:  "github.actor == 'dependabot[bot]'",
			context:    "github.actor",
			isDominant: true,
		},
		{
			name:       "OR chain is dominant",
			condition:  "github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'",
			context:    "github.actor",
			isDominant: true,
		},
		{
			name:       "AND chain is not dominant",
			condition:  "github.actor == 'dependabot[bot]' && github.event.pull_request.base.ref == 'main'",
			context:    "github.actor",
			isDominant: false,
		},
		{
			name:       "mixed OR/AND with OR first",
			condition:  "github.actor == 'dependabot[bot]' || (github.actor == 'renovate[bot]' && github.ref == 'main')",
			context:    "github.actor",
			isDominant: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewBotConditionsRule()
			result := rule.isDominantCondition(tt.condition, tt.context)
			if result != tt.isDominant {
				t.Errorf("expected isDominant=%v but got %v for condition %q", tt.isDominant, result, tt.condition)
			}
		})
	}
}

func TestBotConditionsRuleAutoFix(t *testing.T) {
	t.Parallel()

	workflow := `
on: pull_request_target
jobs:
  auto-merge:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`

	rule := NewBotConditionsRule()
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	// Get the auto-fixers
	fixers := rule.AutoFixers()
	if len(fixers) == 0 {
		t.Fatalf("expected at least one auto-fixer")
	}

	// Apply the fix
	for _, fixer := range fixers {
		if err := fixer.Fix(); err != nil {
			t.Fatalf("failed to apply fix: %v", err)
		}
	}

	// Check that the condition was fixed
	for _, job := range parsed.Jobs {
		if job.If != nil {
			if strings.Contains(job.If.Value, "github.actor") {
				t.Errorf("expected github.actor to be replaced, but got: %s", job.If.Value)
			}
			if !strings.Contains(job.If.Value, "github.event.pull_request.user.login") {
				t.Errorf("expected github.event.pull_request.user.login in condition, but got: %s", job.If.Value)
			}
		}
	}
}

func TestBotConditionsRuleAutoFixActorID(t *testing.T) {
	t.Parallel()

	workflow := `
on: pull_request_target
jobs:
  auto-merge:
    if: github.actor_id == '49699333'
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto
`

	rule := NewBotConditionsRule()
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	// Get the auto-fixers
	fixers := rule.AutoFixers()
	if len(fixers) == 0 {
		t.Fatalf("expected at least one auto-fixer")
	}

	// Apply the fix
	for _, fixer := range fixers {
		if err := fixer.Fix(); err != nil {
			t.Fatalf("failed to apply fix: %v", err)
		}
	}

	// Check that the condition was fixed
	for _, job := range parsed.Jobs {
		if job.If != nil {
			if strings.Contains(job.If.Value, "github.actor_id") {
				t.Errorf("expected github.actor_id to be replaced, but got: %s", job.If.Value)
			}
			if !strings.Contains(job.If.Value, "github.event.pull_request.user.id") {
				t.Errorf("expected github.event.pull_request.user.id in condition, but got: %s", job.If.Value)
			}
		}
	}
}

func TestBotConditionsRuleWorkflowRun(t *testing.T) {
	t.Parallel()

	workflow := `
on: workflow_run
jobs:
  deploy:
    if: github.triggering_actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: npm deploy
`

	rule := NewBotConditionsRule()
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	// Get the auto-fixers
	fixers := rule.AutoFixers()
	if len(fixers) == 0 {
		t.Fatalf("expected at least one auto-fixer")
	}

	// Apply the fix
	for _, fixer := range fixers {
		if err := fixer.Fix(); err != nil {
			t.Fatalf("failed to apply fix: %v", err)
		}
	}

	// Check that the condition was fixed to use workflow_run safe context
	for _, job := range parsed.Jobs {
		if job.If != nil {
			if strings.Contains(job.If.Value, "github.triggering_actor") {
				t.Errorf("expected github.triggering_actor to be replaced, but got: %s", job.If.Value)
			}
			if !strings.Contains(job.If.Value, "github.event.workflow_run.actor.login") {
				t.Errorf("expected github.event.workflow_run.actor.login in condition, but got: %s", job.If.Value)
			}
		}
	}
}

func TestBotConditionsRuleIssueComment(t *testing.T) {
	t.Parallel()

	workflow := `
on: issue_comment
jobs:
  respond:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: echo "bot"
`

	rule := NewBotConditionsRule()
	parsed, errs := Parse([]byte(workflow))
	if len(errs) > 0 {
		t.Fatalf("failed to parse workflow: %v", errs)
	}

	v := NewSyntaxTreeVisitor()
	v.AddVisitor(rule)
	if err := v.VisitTree(parsed); err != nil {
		t.Fatalf("failed to visit tree: %v", err)
	}

	// Get the auto-fixers
	fixers := rule.AutoFixers()
	if len(fixers) == 0 {
		t.Fatalf("expected at least one auto-fixer")
	}

	// Apply the fix
	for _, fixer := range fixers {
		if err := fixer.Fix(); err != nil {
			t.Fatalf("failed to apply fix: %v", err)
		}
	}

	// Check that the condition was fixed to use issue_comment safe context
	for _, job := range parsed.Jobs {
		if job.If != nil {
			if strings.Contains(job.If.Value, "github.actor") && !strings.Contains(job.If.Value, "github.event") {
				t.Errorf("expected github.actor to be replaced, but got: %s", job.If.Value)
			}
			if !strings.Contains(job.If.Value, "github.event.comment.user.login") {
				t.Errorf("expected github.event.comment.user.login in condition, but got: %s", job.If.Value)
			}
		}
	}
}

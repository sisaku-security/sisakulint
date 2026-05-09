package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// stubRule is a minimal Rule implementation used only by optin_test.go.
type stubRule struct {
	BaseRule
}

func newStubRule(name string, optIn bool) *stubRule {
	return &stubRule{BaseRule: BaseRule{RuleName: name, optIn: optIn}}
}

func (r *stubRule) VisitWorkflowPre(*ast.Workflow) error  { return nil }
func (r *stubRule) VisitWorkflowPost(*ast.Workflow) error { return nil }
func (r *stubRule) VisitJobPre(*ast.Job) error            { return nil }
func (r *stubRule) VisitJobPost(*ast.Job) error           { return nil }
func (r *stubRule) VisitStep(*ast.Step) error             { return nil }

func TestApplyOptInRules(t *testing.T) {
	tests := []struct {
		name        string
		rules       []Rule
		enabled     []string
		wantNames   []string
		wantErrSub  string
	}{
		{
			name:      "default excludes opt-in rule",
			rules:     []Rule{newStubRule("opt-a", true), newStubRule("normal-b", false)},
			enabled:   nil,
			wantNames: []string{"normal-b"},
		},
		{
			name:      "explicit enable keeps opt-in rule",
			rules:     []Rule{newStubRule("opt-a", true), newStubRule("normal-b", false)},
			enabled:   []string{"opt-a"},
			wantNames: []string{"opt-a", "normal-b"},
		},
		{
			name:       "unknown rule name returns error",
			rules:      []Rule{newStubRule("opt-a", true), newStubRule("normal-b", false)},
			enabled:    []string{"typo-name"},
			wantErrSub: `"typo-name"`,
		},
		{
			name:      "enabling a default-on rule is a no-op",
			rules:     []Rule{newStubRule("opt-a", true), newStubRule("normal-b", false)},
			enabled:   []string{"normal-b"},
			wantNames: []string{"normal-b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := applyOptInRules(tt.rules, tt.enabled)
			if tt.wantErrSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErrSub)
				}
				if !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotNames := make([]string, len(got))
			for i, r := range got {
				gotNames[i] = r.RuleNames()
			}
			if len(gotNames) != len(tt.wantNames) {
				t.Fatalf("got %v, want %v", gotNames, tt.wantNames)
			}
			for i := range gotNames {
				if gotNames[i] != tt.wantNames[i] {
					t.Fatalf("got %v, want %v", gotNames, tt.wantNames)
				}
			}
		})
	}
}

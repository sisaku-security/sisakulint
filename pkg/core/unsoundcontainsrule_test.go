package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestNewUnsoundContainsRule(t *testing.T) {
	rule := NewUnsoundContainsRule()
	if rule.RuleName != "unsound-contains" {
		t.Errorf("NewUnsoundContainsRule() RuleName = %v, want %v", rule.RuleName, "unsound-contains")
	}
	if rule.RuleDesc == "" {
		t.Error("NewUnsoundContainsRule() RuleDesc should not be empty")
	}
}

func TestUnsoundContainsRule_checkCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantError bool
		errorMsg  string
	}{
		// Vulnerable patterns - should produce error
		{
			name:      "basic vulnerable pattern with github.ref",
			condition: "${{ contains('refs/heads/main refs/heads/develop', github.ref) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern without ${{ }}",
			condition: "contains('refs/heads/main refs/heads/develop', github.ref)",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern with github.head_ref",
			condition: "${{ contains('feature release', github.head_ref) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern with github.base_ref",
			condition: "${{ contains('main develop', github.base_ref) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern with github.actor",
			condition: "${{ contains('admin user1 user2', github.actor) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern with github.ref_name",
			condition: "${{ contains('main develop feature', github.ref_name) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern with github.triggering_actor",
			condition: "${{ contains('admin bot', github.triggering_actor) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern with inputs",
			condition: "${{ contains('option1 option2', inputs.choice) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "vulnerable pattern with env",
			condition: "${{ contains('dev staging prod', env.ENVIRONMENT) }}",
			wantError: true,
			errorMsg:  "HIGH",
		},
		{
			name:      "informational pattern with other context",
			condition: "${{ contains('success failure', steps.build.outputs.status) }}",
			wantError: true,
			errorMsg:  "INFORMATIONAL",
		},
		// Safe patterns - should NOT produce error
		{
			name:      "safe pattern with fromJSON array",
			condition: "${{ contains(fromJSON('[\"refs/heads/main\", \"refs/heads/develop\"]'), github.ref) }}",
			wantError: false,
		},
		{
			name:      "safe pattern with array first argument",
			condition: "${{ contains(github.event.pull_request.labels.*.name, 'bug') }}",
			wantError: false,
		},
		{
			name:      "safe pattern with string search second arg literal",
			condition: "${{ contains(github.event.pull_request.title, 'WIP') }}",
			wantError: false,
		},
		{
			name:      "safe pattern - literal search in literal string",
			condition: "${{ contains('hello world', 'world') }}",
			wantError: false,
		},
		{
			name:      "safe pattern - variable first arg",
			condition: "${{ contains(matrix.os, 'ubuntu') }}",
			wantError: false,
		},
		{
			name:      "safe pattern - equality check (not contains)",
			condition: "${{ github.ref == 'refs/heads/main' }}",
			wantError: false,
		},
		{
			name:      "safe pattern - startsWith function",
			condition: "${{ startsWith(github.ref, 'refs/heads/') }}",
			wantError: false,
		},
		{
			name:      "nil condition",
			condition: "",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnsoundContainsRule()

			var cond *ast.String
			if tt.condition != "" {
				cond = &ast.String{
					Value: tt.condition,
					Pos:   &ast.Position{Line: 1, Col: 1},
				}
			}

			rule.checkCondition(cond, "test", nil, nil)

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				if tt.wantError {
					t.Errorf("checkCondition() expected error for condition %q but got none", tt.condition)
				} else {
					t.Errorf("checkCondition() unexpected error for condition %q: %v", tt.condition, rule.Errors())
				}
			}

			if tt.wantError && tt.errorMsg != "" && len(rule.Errors()) > 0 {
				if !strings.Contains(rule.Errors()[0].Description, tt.errorMsg) {
					t.Errorf("checkCondition() error should contain %q, got: %q", tt.errorMsg, rule.Errors()[0].Description)
				}
			}
		})
	}
}

func TestUnsoundContainsRule_isUserControllableContext(t *testing.T) {
	tests := []struct {
		name        string
		contextPath string
		want        bool
	}{
		// User-controllable contexts
		{"github.ref", "github.ref", true},
		{"github.ref_name", "github.ref_name", true},
		{"github.head_ref", "github.head_ref", true},
		{"github.base_ref", "github.base_ref", true},
		{"github.actor", "github.actor", true},
		{"github.triggering_actor", "github.triggering_actor", true},
		{"github.sha", "github.sha", true},
		{"env variable", "env.MY_VAR", true},
		{"inputs variable", "inputs.my_input", true},
		{"github.event property", "github.event.pull_request.title", true},
		// Not user-controllable contexts
		{"steps output", "steps.build.outputs.status", false},
		{"needs output", "needs.build.outputs.result", false},
		{"matrix value", "matrix.os", false},
		{"github.repository", "github.repository", false},
		{"github.workflow", "github.workflow", false},
		{"github.run_id", "github.run_id", false},
		{"secrets", "secrets.TOKEN", false},
	}

	rule := NewUnsoundContainsRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.isUserControllableContext(tt.contextPath)
			if got != tt.want {
				t.Errorf("isUserControllableContext(%q) = %v, want %v", tt.contextPath, got, tt.want)
			}
		})
	}
}

func TestUnsoundContainsRule_convertToJSONArray(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "space separated values",
			input: "refs/heads/main refs/heads/develop",
			want:  `["refs/heads/main", "refs/heads/develop"]`,
		},
		{
			name:  "comma separated values",
			input: "main,develop,feature",
			want:  `["main", "develop", "feature"]`,
		},
		{
			name:  "mixed separators",
			input: "main, develop feature",
			want:  `["main", "develop", "feature"]`,
		},
		{
			name:  "single value",
			input: "main",
			want:  `["main"]`,
		},
		{
			name:  "multiple spaces",
			input: "main    develop",
			want:  `["main", "develop"]`,
		},
	}

	rule := NewUnsoundContainsRule()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.convertToJSONArray(tt.input)
			if got != tt.want {
				t.Errorf("convertToJSONArray(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractExpressionContent(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple expression",
			input: "${{ github.ref }}",
			want:  "github.ref",
		},
		{
			name:  "expression with function",
			input: "${{ contains('main', github.ref) }}",
			want:  "contains('main', github.ref)",
		},
		{
			name:  "no expression",
			input: "github.ref",
			want:  "",
		},
		{
			name:  "expression with spaces",
			input: "${{   github.ref   }}",
			want:  "github.ref",
		},
		{
			name:  "empty expression",
			input: "${{ }}",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractExpressionContent(tt.input)
			if got != tt.want {
				t.Errorf("extractExpressionContent(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestUnsoundContainsRule_VisitStep(t *testing.T) {
	rule := NewUnsoundContainsRule()

	step := &ast.Step{
		If: &ast.String{
			Value: "${{ contains('main develop', github.ref) }}",
			Pos:   &ast.Position{Line: 5, Col: 10},
		},
	}

	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep() unexpected error: %v", err)
	}

	if len(rule.Errors()) == 0 {
		t.Error("VisitStep() should produce an error for vulnerable contains pattern")
	}
}

func TestUnsoundContainsRule_VisitJobPre(t *testing.T) {
	rule := NewUnsoundContainsRule()

	job := &ast.Job{
		If: &ast.String{
			Value: "${{ contains('admin user1', github.actor) }}",
			Pos:   &ast.Position{Line: 3, Col: 8},
		},
	}

	err := rule.VisitJobPre(job)
	if err != nil {
		t.Errorf("VisitJobPre() unexpected error: %v", err)
	}

	if len(rule.Errors()) == 0 {
		t.Error("VisitJobPre() should produce an error for vulnerable contains pattern")
	}
}

func TestUnsoundContainsRule_VisitJobPost(t *testing.T) {
	rule := NewUnsoundContainsRule()

	job := &ast.Job{}

	err := rule.VisitJobPost(job)
	if err != nil {
		t.Errorf("VisitJobPost() unexpected error: %v", err)
	}

	// VisitJobPost should reset currentJob
	if rule.currentJob != nil {
		t.Error("VisitJobPost() should reset currentJob to nil")
	}
}

func TestUnsoundContainsRule_AutoFixer(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "fix step condition with single quotes",
			input:    "${{ contains('refs/heads/main refs/heads/develop', github.ref) }}",
			expected: `${{ contains(fromJSON('["refs/heads/main", "refs/heads/develop"]'), github.ref) }}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnsoundContainsRule()
			baseNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: tt.input,
			}
			step := &ast.Step{
				If: &ast.String{
					BaseNode: baseNode,
					Value:    tt.input,
					Pos:      &ast.Position{Line: 1, Col: 1},
				},
			}

			// Visit to detect the issue and create fixer
			_ = rule.VisitStep(step)

			// Check that fixers were created
			fixers := rule.AutoFixers()
			if len(fixers) == 0 {
				t.Error("Expected auto-fixer to be created")
				return
			}

			// Apply the fix
			for _, fixer := range fixers {
				_ = fixer.Fix()
			}

			if step.If.Value != tt.expected {
				t.Errorf("AutoFix result = %q, want %q", step.If.Value, tt.expected)
			}
		})
	}
}

func TestUnsoundContainsRule_extractContextPath(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		want      string
	}{
		{
			name:      "simple variable",
			condition: "contains('test', github)",
			want:      "github",
		},
		{
			name:      "nested property",
			condition: "contains('test', github.ref)",
			want:      "github.ref",
		},
		{
			name:      "deeply nested property",
			condition: "contains('test', github.event.pull_request.title)",
			want:      "github.event.pull_request.title",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test is a bit indirect - we test through checkCondition
			// and verify the context path is correctly extracted from the error message
			rule := NewUnsoundContainsRule()
			cond := &ast.String{
				Value: tt.condition,
				Pos:   &ast.Position{Line: 1, Col: 1},
			}

			rule.checkCondition(cond, "test", nil, nil)

			if len(rule.Errors()) == 0 {
				// If no error, the context was not recognized as controllable
				// which is expected for some cases
				return
			}

			if !strings.Contains(rule.Errors()[0].Description, tt.want) {
				t.Errorf("Error message should contain context path %q, got: %q", tt.want, rule.Errors()[0].Description)
			}
		})
	}
}

func TestUnsoundContainsRule_ComplexConditions(t *testing.T) {
	tests := []struct {
		name       string
		condition  string
		wantErrors int
	}{
		{
			name:       "logical AND with vulnerable contains",
			condition:  "${{ github.event_name == 'push' && contains('main develop', github.ref) }}",
			wantErrors: 1,
		},
		{
			name:       "logical OR with vulnerable contains",
			condition:  "${{ github.event_name == 'schedule' || contains('admin bot', github.actor) }}",
			wantErrors: 1,
		},
		{
			name:       "negated vulnerable contains",
			condition:  "${{ !contains('main develop', github.ref) }}",
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnsoundContainsRule()
			cond := &ast.String{
				Value: tt.condition,
				Pos:   &ast.Position{Line: 1, Col: 1},
			}

			rule.checkCondition(cond, "test", nil, nil)

			if len(rule.Errors()) != tt.wantErrors {
				t.Errorf("checkCondition() got %d errors, want %d. Errors: %v", len(rule.Errors()), tt.wantErrors, rule.Errors())
			}
		})
	}
}

// TestUnsoundContainsRule_EdgeCase_CaseInsensitiveDetection tests that CONTAINS and Contains are detected
func TestUnsoundContainsRule_EdgeCase_CaseInsensitiveDetection(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		wantError bool
	}{
		{
			name:      "uppercase CONTAINS should be detected",
			condition: "${{ CONTAINS('main develop', github.ref) }}",
			wantError: true,
		},
		{
			name:      "mixed case Contains should be detected",
			condition: "${{ Contains('main develop', github.ref) }}",
			wantError: true,
		},
		{
			name:      "mixed case CoNtAiNs should be detected",
			condition: "${{ CoNtAiNs('main develop', github.ref) }}",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnsoundContainsRule()
			cond := &ast.String{
				Value: tt.condition,
				Pos:   &ast.Position{Line: 1, Col: 1},
			}

			rule.checkCondition(cond, "test", nil, nil)

			hasError := len(rule.Errors()) > 0
			if hasError != tt.wantError {
				if tt.wantError {
					t.Errorf("checkCondition() expected error for condition %q but got none", tt.condition)
				} else {
					t.Errorf("checkCondition() unexpected error for condition %q: %v", tt.condition, rule.Errors())
				}
			}
		})
	}
}

// TestUnsoundContainsRule_EdgeCase_CaseInsensitiveAutoFix tests that auto-fixer handles CONTAINS and Contains
func TestUnsoundContainsRule_EdgeCase_CaseInsensitiveAutoFix(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedFix string
	}{
		{
			name:        "uppercase CONTAINS should be auto-fixed",
			input:       "${{ CONTAINS('main develop', github.ref) }}",
			expectedFix: `${{ contains(fromJSON('["main", "develop"]'), github.ref) }}`,
		},
		{
			name:        "mixed case Contains should be auto-fixed",
			input:       "${{ Contains('main develop', github.ref) }}",
			expectedFix: `${{ contains(fromJSON('["main", "develop"]'), github.ref) }}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewUnsoundContainsRule()
			baseNode := &yaml.Node{
				Kind:  yaml.ScalarNode,
				Value: tt.input,
			}
			step := &ast.Step{
				If: &ast.String{
					BaseNode: baseNode,
					Value:    tt.input,
					Pos:      &ast.Position{Line: 1, Col: 1},
				},
			}

			// Visit to detect the issue and create fixer
			_ = rule.VisitStep(step)

			// Check that fixers were created
			fixers := rule.AutoFixers()
			if len(fixers) == 0 {
				t.Errorf("Expected auto-fixer to be created for %q", tt.input)
				return
			}

			// Apply the fix
			for _, fixer := range fixers {
				_ = fixer.Fix()
			}

			if step.If.Value != tt.expectedFix {
				t.Errorf("AutoFix result = %q, want %q", step.If.Value, tt.expectedFix)
			}
		})
	}
}

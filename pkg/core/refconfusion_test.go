package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestRefConfusionRule(t *testing.T) {
	t.Parallel()
	rule := NewRefConfusionRule()

	if rule.RuleName != "ref-confusion" {
		t.Errorf("Expected RuleName to be 'ref-confusion', got '%s'", rule.RuleName)
	}

	expectedDesc := "Detects actions using refs that exist as both a branch and tag, which can lead to supply chain attacks."
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}

	if rule.refCache == nil {
		t.Error("Expected refCache to be initialized")
	}
}

func TestIsSymbolicRef(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		ref      string
		expected bool
	}{
		{
			name:     "full length SHA is not symbolic",
			ref:      "a81bbbf8298c0fa03ea29cdc473d45769f953675",
			expected: false,
		},
		{
			name:     "semantic version is symbolic",
			ref:      "v3",
			expected: true,
		},
		{
			name:     "full semantic version is symbolic",
			ref:      "v3.5.2",
			expected: true,
		},
		{
			name:     "branch name is symbolic",
			ref:      "main",
			expected: true,
		},
		{
			name:     "short SHA is symbolic (7 chars)",
			ref:      "a81bbbf",
			expected: true,
		},
		{
			name:     "short SHA is symbolic (8 chars)",
			ref:      "a81bbbf8",
			expected: true,
		},
		{
			name:     "SHA with uppercase is symbolic (invalid hex)",
			ref:      "A81BBBF8298C0FA03EA29CDC473D45769F953675",
			expected: true,
		},
		{
			name:     "39 char hex is symbolic (too short)",
			ref:      "81bbbf8298c0fa03ea29cdc473d45769f95367",
			expected: true,
		},
		{
			name:     "41 char hex is symbolic (too long)",
			ref:      "a81bbbf8298c0fa03ea29cdc473d45769f953675a",
			expected: true,
		},
		{
			name:     "empty string is symbolic",
			ref:      "",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := isSymbolicRef(tt.ref)
			if result != tt.expected {
				t.Errorf("isSymbolicRef(%q) = %v, want %v", tt.ref, result, tt.expected)
			}
		})
	}
}

func TestParseActionRefForRefConfusion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		usesValue     string
		expectedOwner string
		expectedRepo  string
		expectedRef   string
		expectedOk    bool
	}{
		{
			name:          "standard action reference",
			usesValue:     "actions/checkout@v3",
			expectedOwner: "actions",
			expectedRepo:  "checkout",
			expectedRef:   "v3",
			expectedOk:    true,
		},
		{
			name:          "action with path",
			usesValue:     "actions/aws-for-github-actions/configure-aws-credentials@v1",
			expectedOwner: "actions",
			expectedRepo:  "aws-for-github-actions",
			expectedRef:   "v1",
			expectedOk:    true,
		},
		{
			name:          "action with full SHA",
			usesValue:     "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
			expectedOwner: "actions",
			expectedRepo:  "checkout",
			expectedRef:   "a81bbbf8298c0fa03ea29cdc473d45769f953675",
			expectedOk:    true,
		},
		{
			name:          "local action",
			usesValue:     "./local/action",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
			expectedOk:    false,
		},
		{
			name:          "local action with version",
			usesValue:     "./local/action@v1",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
			expectedOk:    false,
		},
		{
			name:          "missing @ symbol",
			usesValue:     "actions/checkout",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
			expectedOk:    false,
		},
		{
			name:          "missing repo",
			usesValue:     "actions@v3",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
			expectedOk:    false,
		},
		{
			name:          "empty string",
			usesValue:     "",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
			expectedOk:    false,
		},
		{
			name:          "docker reference",
			usesValue:     "docker://alpine:3.8",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
			expectedOk:    false,
		},
		{
			name:          "multiple @ symbols",
			usesValue:     "actions/checkout@v3@extra",
			expectedOwner: "",
			expectedRepo:  "",
			expectedRef:   "",
			expectedOk:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			owner, repo, ref, ok := parseActionRefForRefConfusion(tt.usesValue)
			if owner != tt.expectedOwner {
				t.Errorf("parseActionRefForRefConfusion(%q) owner = %q, want %q", tt.usesValue, owner, tt.expectedOwner)
			}
			if repo != tt.expectedRepo {
				t.Errorf("parseActionRefForRefConfusion(%q) repo = %q, want %q", tt.usesValue, repo, tt.expectedRepo)
			}
			if ref != tt.expectedRef {
				t.Errorf("parseActionRefForRefConfusion(%q) ref = %q, want %q", tt.usesValue, ref, tt.expectedRef)
			}
			if ok != tt.expectedOk {
				t.Errorf("parseActionRefForRefConfusion(%q) ok = %v, want %v", tt.usesValue, ok, tt.expectedOk)
			}
		})
	}
}

func TestRefConfusion_VisitStep_SkipCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		step *ast.Step
	}{
		{
			name: "run command (not ExecAction)",
			step: &ast.Step{
				ID: &ast.String{Value: "run-script"},
				Exec: &ast.ExecRun{
					Run: &ast.String{
						Value: "echo 'hello'",
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
		},
		{
			name: "local action",
			step: &ast.Step{
				ID: &ast.String{Value: "local"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "./local/action",
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
		},
		{
			name: "full commit SHA",
			step: &ast.Step{
				ID: &ast.String{Value: "checkout"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675",
					},
				},
				Pos: &ast.Position{Line: 20, Col: 5},
			},
		},
		{
			name: "missing @ symbol",
			step: &ast.Step{
				ID: &ast.String{Value: "invalid"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value: "actions/checkout",
					},
				},
				Pos: &ast.Position{Line: 25, Col: 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewRefConfusionRule()
			err := rule.VisitStep(tt.step)

			if err != nil {
				t.Errorf("VisitStep() returned unexpected error: %v", err)
			}

			if len(rule.Errors()) > 0 {
				t.Errorf("Expected no errors for skip case, got %d", len(rule.Errors()))
			}
		})
	}
}

func TestRefConfusion_VisitStep_NilChecks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		step *ast.Step
	}{
		{
			name: "step with nil Exec",
			step: &ast.Step{
				ID:   &ast.String{Value: "test"},
				Exec: nil,
				Pos:  &ast.Position{Line: 10, Col: 5},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewRefConfusionRule()
			err := rule.VisitStep(tt.step)
			if err != nil {
				t.Errorf("VisitStep() returned unexpected error: %v", err)
			}
		})
	}
}

func TestRefConfusion_FixStep_InvalidFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		step      *ast.Step
		wantError bool
	}{
		{
			name: "missing @ symbol",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value:    "actions/checkout",
						BaseNode: &yaml.Node{},
					},
				},
				Pos: &ast.Position{Line: 10, Col: 5},
			},
			wantError: true,
		},
		{
			name: "local action",
			step: &ast.Step{
				ID: &ast.String{Value: "test"},
				Exec: &ast.ExecAction{
					Uses: &ast.String{
						Value:    "./local/action@v1",
						BaseNode: &yaml.Node{},
					},
				},
				Pos: &ast.Position{Line: 15, Col: 5},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := NewRefConfusionRule()
			err := rule.FixStep(tt.step)

			if tt.wantError && err == nil {
				t.Error("Expected error but got nil")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestRefConfusion_RefCache(t *testing.T) {
	t.Parallel()
	rule := NewRefConfusionRule()

	rule.refCacheMu.Lock()
	rule.refCache["test/repo@v1"] = true
	rule.refCacheMu.Unlock()

	rule.refCacheMu.Lock()
	result, ok := rule.refCache["test/repo@v1"]
	rule.refCacheMu.Unlock()

	if !ok {
		t.Error("Expected cache entry to exist")
	}
	if !result {
		t.Error("Expected cache entry to be true")
	}
}

func TestRefConfusion_VisitorInterface(t *testing.T) {
	t.Parallel()
	rule := NewRefConfusionRule()

	if err := rule.VisitJobPre(&ast.Job{}); err != nil {
		t.Errorf("VisitJobPre() returned error: %v", err)
	}
	if err := rule.VisitJobPost(&ast.Job{}); err != nil {
		t.Errorf("VisitJobPost() returned error: %v", err)
	}
	if err := rule.VisitWorkflowPre(&ast.Workflow{}); err != nil {
		t.Errorf("VisitWorkflowPre() returned error: %v", err)
	}
	if err := rule.VisitWorkflowPost(&ast.Workflow{}); err != nil {
		t.Errorf("VisitWorkflowPost() returned error: %v", err)
	}
}

func TestRefConfusion_GetGitHubClient(t *testing.T) {
	t.Parallel()
	rule := NewRefConfusionRule()

	client := rule.getGitHubClient()
	if client == nil {
		t.Error("Expected GitHub client to be initialized")
	}

	client2 := rule.getGitHubClient()
	if client != client2 {
		t.Error("Expected same client instance (singleton)")
	}
}

func TestRefConfusion_DetectsConfusableRef(t *testing.T) {
	t.Parallel()
	rule := NewRefConfusionRule()

	rule.refCacheMu.Lock()
	rule.refCache["test/vulnerable-repo@v1.0.0"] = true
	rule.refCacheMu.Unlock()

	step := &ast.Step{
		ID: &ast.String{Value: "vulnerable-step"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{
				Value: "test/vulnerable-repo@v1.0.0",
			},
		},
		Pos: &ast.Position{Line: 10, Col: 5},
	}

	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep() returned unexpected error: %v", err)
	}

	if len(rule.Errors()) != 1 {
		t.Errorf("Expected 1 error for confusable ref, got %d", len(rule.Errors()))
	}

	if len(rule.Errors()) > 0 {
		errMsg := rule.Errors()[0].Error()
		if !strings.Contains(errMsg, "ref-confusion") {
			t.Error("Error message should contain rule name 'ref-confusion'")
		}
		if !strings.Contains(errMsg, "both a branch and a tag") {
			t.Error("Error message should mention 'both a branch and a tag'")
		}
		if !strings.Contains(errMsg, "supply chain attacks") {
			t.Error("Error message should mention 'supply chain attacks'")
		}
	}

	if len(rule.AutoFixers()) != 1 {
		t.Errorf("Expected 1 auto-fixer, got %d", len(rule.AutoFixers()))
	}
}

func TestRefConfusion_NotConfusableRef(t *testing.T) {
	t.Parallel()
	rule := NewRefConfusionRule()

	rule.refCacheMu.Lock()
	rule.refCache["test/safe-repo@v2.0.0"] = false
	rule.refCacheMu.Unlock()

	step := &ast.Step{
		ID: &ast.String{Value: "safe-step"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{
				Value: "test/safe-repo@v2.0.0",
			},
		},
		Pos: &ast.Position{Line: 15, Col: 5},
	}

	err := rule.VisitStep(step)
	if err != nil {
		t.Errorf("VisitStep() returned unexpected error: %v", err)
	}

	if len(rule.Errors()) != 0 {
		t.Errorf("Expected 0 errors for non-confusable ref, got %d", len(rule.Errors()))
	}

	if len(rule.AutoFixers()) != 0 {
		t.Errorf("Expected 0 auto-fixers, got %d", len(rule.AutoFixers()))
	}
}

func TestRefConfusion_MultipleSteps(t *testing.T) {
	t.Parallel()
	rule := NewRefConfusionRule()

	rule.refCacheMu.Lock()
	rule.refCache["org/confusable@v1"] = true
	rule.refCache["org/safe@v2"] = false
	rule.refCacheMu.Unlock()

	steps := []*ast.Step{
		{
			ID: &ast.String{Value: "step1"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{Value: "org/confusable@v1"},
			},
			Pos: &ast.Position{Line: 10, Col: 5},
		},
		{
			ID: &ast.String{Value: "step2"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{Value: "org/safe@v2"},
			},
			Pos: &ast.Position{Line: 15, Col: 5},
		},
		{
			ID: &ast.String{Value: "step3"},
			Exec: &ast.ExecRun{
				Run: &ast.String{Value: "echo test"},
			},
			Pos: &ast.Position{Line: 20, Col: 5},
		},
		{
			ID: &ast.String{Value: "step4"},
			Exec: &ast.ExecAction{
				Uses: &ast.String{Value: "actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675"},
			},
			Pos: &ast.Position{Line: 25, Col: 5},
		},
	}

	for _, step := range steps {
		_ = rule.VisitStep(step)
	}

	if len(rule.Errors()) != 1 {
		t.Errorf("Expected 1 error, got %d", len(rule.Errors()))
	}

	if len(rule.AutoFixers()) != 1 {
		t.Errorf("Expected 1 auto-fixer, got %d", len(rule.AutoFixers()))
	}
}

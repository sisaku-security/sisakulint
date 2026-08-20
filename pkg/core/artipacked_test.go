package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestNewArtipackedRule(t *testing.T) {
	rule := NewArtipackedRule()

	if rule.RuleName != "artipacked" {
		t.Errorf("Expected RuleName to be 'artipacked', got '%s'", rule.RuleName)
	}

	expectedDesc := "Detects credential leakage risk when actions/checkout credentials are persisted and workspace is uploaded via actions/upload-artifact"
	if rule.RuleDesc != expectedDesc {
		t.Errorf("Expected RuleDesc to be '%s', got '%s'", expectedDesc, rule.RuleDesc)
	}
}

func TestArtipackedRule_isCheckoutAction(t *testing.T) {
	rule := NewArtipackedRule()

	tests := []struct {
		name     string
		uses     string
		expected bool
	}{
		{"checkout v4", "actions/checkout@v4", true},
		{"checkout v6", "actions/checkout@v6", true},
		{"checkout with commit SHA", "actions/checkout@abc123def456", true},
		{"upload-artifact", "actions/upload-artifact@v4", false},
		{"other action", "actions/setup-node@v4", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.isCheckoutAction(tt.uses)
			if got != tt.expected {
				t.Errorf("isCheckoutAction(%q) = %v, want %v", tt.uses, got, tt.expected)
			}
		})
	}
}

func TestArtipackedRule_isUploadArtifactAction(t *testing.T) {
	rule := NewArtipackedRule()

	tests := []struct {
		name     string
		uses     string
		expected bool
	}{
		{"upload-artifact v4", "actions/upload-artifact@v4", true},
		{"upload-artifact v3", "actions/upload-artifact@v3", true},
		{"upload-artifact with commit SHA", "actions/upload-artifact@abc123", true},
		{"checkout", "actions/checkout@v4", false},
		{"download-artifact", "actions/download-artifact@v4", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.isUploadArtifactAction(tt.uses)
			if got != tt.expected {
				t.Errorf("isUploadArtifactAction(%q) = %v, want %v", tt.uses, got, tt.expected)
			}
		})
	}
}

func TestArtipackedRule_getCheckoutVersion(t *testing.T) {
	rule := NewArtipackedRule()

	tests := []struct {
		name     string
		uses     string
		comment  string
		expected int
	}{
		{"v1", "actions/checkout@v1", "", 1},
		{"v2", "actions/checkout@v2", "", 2},
		{"v3", "actions/checkout@v3", "", 3},
		{"v4", "actions/checkout@v4", "", 4},
		{"v5", "actions/checkout@v5", "", 5},
		{"v6", "actions/checkout@v6", "", 6},
		{"v6.0.0", "actions/checkout@v6.0.0", "", 6},
		{"commit SHA", "actions/checkout@abc123def456789012345678901234567890abcd", "", 0},
		// A full SHA whose first hex char is 6-9 must not be misread as a major
		// version (regression: "8ade..." previously returned 8 -> treated as v8).
		{"commit SHA leading 8", "actions/checkout@8ade1a2b3c4d5e6f70819a2b3c4d5e6f7081a2b3", "", 0},
		{"commit SHA leading 3", "actions/checkout@3f2a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2", "", 0},
		{"abbreviated SHA leading 7", "actions/checkout@7f8e9d0", "", 0},
		// SHA pins conventionally carry the resolved tag as a "# vX.Y.Z" line
		// comment (Dependabot / commit-sha autofix format). The comment must be
		// honored so a v6+ pin is not reported at a higher severity than the
		// equivalent tag pin.
		{"SHA with v7 comment", "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "# v7.0.0", 7},
		{"SHA with v7 comment no hash", "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "v7.0.0", 7},
		{"SHA with v6 comment", "actions/checkout@55cc8345863c7cc4c66a329aec7e433d2d1c52a9", "# v6.1.0", 6},
		{"SHA with bogus comment", "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "pin for security", 0},
		{"SHA with empty comment", "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", "#", 0},
		{"invalid format", "actions/checkout", "", 0},
		{"empty", "", "", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uses := &ast.String{Value: tt.uses}
			if tt.comment != "" {
				uses.BaseNode = &yaml.Node{LineComment: tt.comment}
			}
			got := rule.getCheckoutVersion(uses)
			if got != tt.expected {
				t.Errorf("getCheckoutVersion(%q, comment=%q) = %v, want %v", tt.uses, tt.comment, got, tt.expected)
			}
		})
	}
}

func TestArtipackedRule_isDangerousUploadPath(t *testing.T) {
	rule := NewArtipackedRule()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Dangerous paths
		{"current directory", ".", true},
		{"current directory with slash", "./", true},
		{"parent directory", "..", true},
		{"parent directory with path", "../something", true},
		{"github.workspace", "${{ github.workspace }}", true},
		{"github.workspace with subpath", "${{ github.workspace }}/build", true},
		{"GITHUB_WORKSPACE", "$GITHUB_WORKSPACE", true},
		{"GITHUB_WORKSPACE with subpath", "$GITHUB_WORKSPACE/build", true},
		// Glob patterns
		{"glob star", "*", true},
		{"glob double star", "**", true},
		{"glob double star slash star", "**/*", true},
		{"glob dot double star", "./**", true},
		{"glob dot double star slash star", "./**/*", true},

		// Safe paths
		{"empty path", "", false},
		{"specific directory", "build/output", false},
		{"dist folder", "dist", false},
		{"runner.temp", "${{ runner.temp }}/artifacts", false},
		{"specific glob pattern", "dist/**/*.js", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rule.isDangerousUploadPath(tt.path)
			if got != tt.expected {
				t.Errorf("isDangerousUploadPath(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestArtipackedRule_CheckoutWithPersistCredentialsFalse(t *testing.T) {
	rule := NewArtipackedRule()

	// Setup workflow
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/checkout@v4"},
							Inputs: map[string]*ast.Input{
								persistCredentialsKey: {
									Name:  &ast.String{Value: persistCredentialsKey},
									Value: &ast.String{Value: "false"},
								},
							},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
					{
						ID: &ast.String{Value: "upload"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/upload-artifact@v4"},
							Inputs: map[string]*ast.Input{
								"path": {
									Name:  &ast.String{Value: "path"},
									Value: &ast.String{Value: "."},
								},
							},
						},
						Pos: &ast.Position{Line: 15, Col: 5},
					},
				},
			},
		},
	}

	// Run the rule
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	// Should have no errors since persist-credentials is false
	errors := rule.Errors()
	if len(errors) != 0 {
		t.Errorf("Expected 0 errors when persist-credentials: false, got %d", len(errors))
		for _, e := range errors {
			t.Logf("Error: %s", e.Description)
		}
	}
}

func TestArtipackedRule_CheckoutWithDangerousUpload(t *testing.T) {
	rule := NewArtipackedRule()

	// Setup workflow with vulnerable pattern
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses:   &ast.String{Value: "actions/checkout@v4"},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
					{
						ID: &ast.String{Value: "upload"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/upload-artifact@v4"},
							Inputs: map[string]*ast.Input{
								"path": {
									Name:  &ast.String{Value: "path"},
									Value: &ast.String{Value: "."},
								},
							},
						},
						Pos: &ast.Position{Line: 15, Col: 5},
					},
				},
			},
		},
	}

	// Run the rule
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	// Should have 1 error for the dangerous checkout-upload pair
	errors := rule.Errors()
	if len(errors) != 1 {
		t.Errorf("Expected 1 error for dangerous checkout-upload pair, got %d", len(errors))
		for _, e := range errors {
			t.Logf("Error: %s", e.Description)
		}
		return
	}

	// Verify the error message contains key information
	errorMsg := errors[0].Description
	if !strings.Contains(errorMsg, "[High]") {
		t.Errorf("Expected High severity for checkout v4, got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, ".git/config") {
		t.Errorf("Expected mention of .git/config for checkout v4, got: %s", errorMsg)
	}
}

func TestArtipackedRule_CheckoutV6WithDangerousUpload(t *testing.T) {
	rule := NewArtipackedRule()

	// Setup workflow with checkout v6
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses:   &ast.String{Value: "actions/checkout@v6"},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
					{
						ID: &ast.String{Value: "upload"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/upload-artifact@v4"},
							Inputs: map[string]*ast.Input{
								"path": {
									Name:  &ast.String{Value: "path"},
									Value: &ast.String{Value: "."},
								},
							},
						},
						Pos: &ast.Position{Line: 15, Col: 5},
					},
				},
			},
		},
	}

	// Run the rule
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	// Should have 1 error with Medium severity
	errors := rule.Errors()
	if len(errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(errors))
		return
	}

	errorMsg := errors[0].Description
	if !strings.Contains(errorMsg, "[Medium]") {
		t.Errorf("Expected Medium severity for checkout v6, got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "$RUNNER_TEMP") {
		t.Errorf("Expected mention of $RUNNER_TEMP for checkout v6, got: %s", errorMsg)
	}
}

func TestArtipackedRule_CheckoutWithoutUpload(t *testing.T) {
	rule := NewArtipackedRule()

	// Setup workflow with checkout but no upload
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses:   &ast.String{Value: "actions/checkout@v4"},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
					{
						ID: &ast.String{Value: "build"},
						Exec: &ast.ExecRun{
							Run: &ast.String{Value: "npm run build"},
						},
						Pos: &ast.Position{Line: 12, Col: 5},
					},
				},
			},
		},
	}

	// Run the rule
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	// Should have 1 error for potential risk (checkout without explicit persist-credentials: false)
	errors := rule.Errors()
	if len(errors) != 1 {
		t.Errorf("Expected 1 error for checkout without persist-credentials: false, got %d", len(errors))
		for _, e := range errors {
			t.Logf("Error: %s", e.Description)
		}
		return
	}

	// Verify it mentions potential risk
	errorMsg := errors[0].Description
	if !strings.Contains(errorMsg, "[Medium]") && !strings.Contains(errorMsg, "[Low]") {
		t.Errorf("Expected Medium or Low severity for checkout without upload, got: %s", errorMsg)
	}
}

func TestArtipackedRule_CheckoutSHAWithVersionComment(t *testing.T) {
	rule := NewArtipackedRule()

	// SHA-pinned checkout whose trailing line comment carries the resolved
	// tag (the Dependabot / commit-sha autofix format). The rule must treat
	// it as v7 (>= 6) and report the low-severity branch, not the Medium
	// "unknown version" branch.
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{
								Value:    "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
								BaseNode: &yaml.Node{LineComment: "# v7.0.0"},
							},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
				},
			},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for checkout without persist-credentials: false, got %d", len(errors))
	}
	if !strings.Contains(errors[0].Description, "[Low]") {
		t.Errorf("Expected [Low] severity for SHA-pinned checkout v7 with version comment, got: %s", errors[0].Description)
	}
	if strings.Contains(errors[0].Description, "[Medium]") {
		t.Errorf("Expected no [Medium] severity for SHA-pinned checkout v7 with version comment, got: %s", errors[0].Description)
	}
}

func TestArtipackedRule_CheckoutSHAWithoutVersionComment(t *testing.T) {
	rule := NewArtipackedRule()

	// Same SHA but without the trailing version comment: version stays
	// unknown and the conservative Medium branch must still fire.
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{
								Value: "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
							},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
				},
			},
		},
	}

	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	errors := rule.Errors()
	if len(errors) != 1 {
		t.Fatalf("Expected 1 error for checkout without persist-credentials: false, got %d", len(errors))
	}
	if !strings.Contains(errors[0].Description, "[Medium]") {
		t.Errorf("Expected [Medium] severity for SHA-pinned checkout without version comment, got: %s", errors[0].Description)
	}
}

func TestArtipackedRule_SafeUploadPath(t *testing.T) {
	rule := NewArtipackedRule()

	// Setup workflow with safe upload path
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout"},
						Exec: &ast.ExecAction{
							Uses:   &ast.String{Value: "actions/checkout@v4"},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
					{
						ID: &ast.String{Value: "upload"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/upload-artifact@v4"},
							Inputs: map[string]*ast.Input{
								"path": {
									Name:  &ast.String{Value: "path"},
									Value: &ast.String{Value: "dist"},
								},
							},
						},
						Pos: &ast.Position{Line: 15, Col: 5},
					},
				},
			},
		},
	}

	// Run the rule
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	// Should have 1 error for checkout without persist-credentials: false (potential risk)
	// but not for dangerous upload since "dist" is a safe path
	errors := rule.Errors()
	if len(errors) != 1 {
		t.Errorf("Expected 1 error (checkout warning only), got %d", len(errors))
		for _, e := range errors {
			t.Logf("Error: %s", e.Description)
		}
	}
}

func TestArtipackedRule_AutoFix(t *testing.T) {
	// Create a YAML node for the step
	stepNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "uses"},
			{Kind: yaml.ScalarNode, Value: "actions/checkout@v4"},
		},
	}

	step := &ast.Step{
		ID: &ast.String{Value: "checkout"},
		Exec: &ast.ExecAction{
			Uses:   &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{},
		},
		Pos:      &ast.Position{Line: 10, Col: 5},
		BaseNode: stepNode,
	}

	rule := NewArtipackedRule()
	err := rule.FixStep(step)
	if err != nil {
		t.Errorf("FixStep() unexpected error: %v", err)
		return
	}

	// Verify the AST was updated
	action := step.Exec.(*ast.ExecAction)
	persistCreds, exists := action.Inputs[persistCredentialsKey]
	if !exists {
		t.Error("FixStep() did not add persist-credentials input")
		return
	}
	if persistCreds.Value.Value != "false" {
		t.Errorf("FixStep() persist-credentials = %s, want 'false'", persistCreds.Value.Value)
	}

	// Verify the YAML node was updated
	found := false
	for i := 0; i < len(stepNode.Content); i += 2 {
		if stepNode.Content[i].Value == "with" {
			withNode := stepNode.Content[i+1]
			for j := 0; j < len(withNode.Content); j += 2 {
				if withNode.Content[j].Value == persistCredentialsKey {
					if withNode.Content[j+1].Value == "false" {
						found = true
					}
				}
			}
		}
	}
	if !found {
		t.Error("FixStep() did not update YAML node with persist-credentials: false")
	}
}

func TestArtipackedRule_AutoFixWithExistingWith(t *testing.T) {
	// Create a YAML node for the step with existing 'with' section
	stepNode := &yaml.Node{
		Kind: yaml.MappingNode,
		Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Value: "uses"},
			{Kind: yaml.ScalarNode, Value: "actions/checkout@v4"},
			{Kind: yaml.ScalarNode, Value: "with"},
			{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "ref"},
					{Kind: yaml.ScalarNode, Value: "main"},
				},
			},
		},
	}

	step := &ast.Step{
		ID: &ast.String{Value: "checkout"},
		Exec: &ast.ExecAction{
			Uses: &ast.String{Value: "actions/checkout@v4"},
			Inputs: map[string]*ast.Input{
				"ref": {
					Name:  &ast.String{Value: "ref"},
					Value: &ast.String{Value: "main"},
				},
			},
		},
		Pos:      &ast.Position{Line: 10, Col: 5},
		BaseNode: stepNode,
	}

	rule := NewArtipackedRule()
	err := rule.FixStep(step)
	if err != nil {
		t.Errorf("FixStep() unexpected error: %v", err)
		return
	}

	// Verify the YAML node was updated with persist-credentials added to existing with
	withNode := stepNode.Content[3]
	found := false
	for i := 0; i < len(withNode.Content); i += 2 {
		if withNode.Content[i].Value == persistCredentialsKey {
			if withNode.Content[i+1].Value == "false" {
				found = true
			}
		}
	}
	if !found {
		t.Error("FixStep() did not add persist-credentials: false to existing with section")
	}
}

func TestArtipackedRule_MultipleCheckoutsAndUploads(t *testing.T) {
	rule := NewArtipackedRule()

	// Setup workflow with multiple checkouts and uploads
	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"build": {
				ID:  &ast.String{Value: "build"},
				Pos: &ast.Position{Line: 5, Col: 3},
				Steps: []*ast.Step{
					{
						ID: &ast.String{Value: "checkout1"},
						Exec: &ast.ExecAction{
							Uses:   &ast.String{Value: "actions/checkout@v4"},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 10, Col: 5},
					},
					{
						ID: &ast.String{Value: "checkout2"},
						Exec: &ast.ExecAction{
							Uses:   &ast.String{Value: "actions/checkout@v6"},
							Inputs: map[string]*ast.Input{},
						},
						Pos: &ast.Position{Line: 15, Col: 5},
					},
					{
						ID: &ast.String{Value: "upload"},
						Exec: &ast.ExecAction{
							Uses: &ast.String{Value: "actions/upload-artifact@v4"},
							Inputs: map[string]*ast.Input{
								"path": {
									Name:  &ast.String{Value: "path"},
									Value: &ast.String{Value: "."},
								},
							},
						},
						Pos: &ast.Position{Line: 20, Col: 5},
					},
				},
			},
		},
	}

	// Run the rule
	_ = rule.VisitWorkflowPre(workflow)
	_ = rule.VisitJobPre(workflow.Jobs["build"])
	for _, step := range workflow.Jobs["build"].Steps {
		_ = rule.VisitStep(step)
	}
	_ = rule.VisitJobPost(workflow.Jobs["build"])
	_ = rule.VisitWorkflowPost(workflow)

	// Should have 2 errors (one for each checkout-upload pair)
	errors := rule.Errors()
	if len(errors) != 2 {
		t.Errorf("Expected 2 errors for multiple checkouts with dangerous upload, got %d", len(errors))
		for _, e := range errors {
			t.Logf("Error: %s", e.Description)
		}
	}
}

func TestArtipackedRule_FixStep_ErrorCases(t *testing.T) {
	t.Parallel()

	rule := NewArtipackedRule()

	t.Run("step is not an action", func(t *testing.T) {
		t.Parallel()
		step := &ast.Step{
			ID:   &ast.String{Value: "run-step"},
			Exec: &ast.ExecRun{Run: &ast.String{Value: "echo test"}},
			Pos:  &ast.Position{Line: 10, Col: 5},
		}

		err := rule.FixStep(step)
		if err == nil {
			t.Error("FixStep() expected error for non-action step, got nil")
		}
	})

	t.Run("step is not a checkout action", func(t *testing.T) {
		t.Parallel()
		step := &ast.Step{
			ID: &ast.String{Value: "upload"},
			Exec: &ast.ExecAction{
				Uses:   &ast.String{Value: "actions/upload-artifact@v4"},
				Inputs: map[string]*ast.Input{},
			},
			Pos: &ast.Position{Line: 10, Col: 5},
		}

		err := rule.FixStep(step)
		if err == nil {
			t.Error("FixStep() expected error for non-checkout action, got nil")
		}
	})
}

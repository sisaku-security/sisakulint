package core

import (
	"io"
	"reflect"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

// TestWorkflowCall tests the WorkflowCall constructor function.
func TestWorkflowCall(t *testing.T) {
	cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
	workflowPath := "/test/workflow.yml"

	rule := WorkflowCall(workflowPath, cache)

	if rule.RuleName != "workflow-call" {
		t.Errorf("WorkflowCall() RuleName = %v, want %v", rule.RuleName, "workflow-call")
	}

	expectedDesc := "Checks for reusable workflow calls. Inputs and outputs of called reusable workflow are checked"
	if rule.RuleDesc != expectedDesc {
		t.Errorf("WorkflowCall() RuleDesc = %v, want %v", rule.RuleDesc, expectedDesc)
	}

	if rule.workflowPath != workflowPath {
		t.Errorf("WorkflowCall() workflowPath = %v, want %v", rule.workflowPath, workflowPath)
	}

	if rule.cache != cache {
		t.Errorf("WorkflowCall() cache = %v, want %v", rule.cache, cache)
	}

	if rule.workflowCallEventPos != nil {
		t.Errorf("WorkflowCall() workflowCallEventPos = %v, want nil", rule.workflowCallEventPos)
	}
}

// TestRuleWorkflowCall_VisitWorkflowPre tests the VisitWorkflowPre method.
func TestRuleWorkflowCall_VisitWorkflowPre(t *testing.T) {
	tests := []struct {
		name         string
		workflow     *ast.Workflow
		wantEventPos bool
		wantErr      bool
	}{
		{
			name: "workflow with workflow_call event",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WorkflowCallEvent{
						Pos: &ast.Position{Line: 5, Col: 3},
					},
				},
			},
			wantEventPos: true,
			wantErr:      false,
		},
		{
			name: "workflow without workflow_call event",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "push"},
					},
				},
			},
			wantEventPos: false,
			wantErr:      false,
		},
		{
			name: "workflow with multiple events including workflow_call",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "push"},
					},
					&ast.WorkflowCallEvent{
						Pos: &ast.Position{Line: 10, Col: 5},
					},
				},
			},
			wantEventPos: true,
			wantErr:      false,
		},
		{
			name: "workflow with no events",
			workflow: &ast.Workflow{
				On: []ast.Event{},
			},
			wantEventPos: false,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := WorkflowCall("/test/workflow.yml", cache)

			err := rule.VisitWorkflowPre(tt.workflow)
			if (err != nil) != tt.wantErr {
				t.Errorf("VisitWorkflowPre() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantEventPos && rule.workflowCallEventPos == nil {
				t.Errorf("VisitWorkflowPre() workflowCallEventPos is nil, want non-nil")
			}

			if !tt.wantEventPos && rule.workflowCallEventPos != nil {
				t.Errorf("VisitWorkflowPre() workflowCallEventPos = %v, want nil", rule.workflowCallEventPos)
			}
		})
	}
}

// TestRuleWorkflowCall_VisitJobPre tests the VisitJobPre method.
func TestRuleWorkflowCall_VisitJobPre(t *testing.T) {
	tests := []struct {
		name    string
		job     *ast.Job
		wantErr bool
	}{
		{
			name: "job without workflow call",
			job: &ast.Job{
				ID:           &ast.String{Value: "test-job"},
				WorkflowCall: nil,
			},
			wantErr: false,
		},
		{
			name: "job with workflow call but nil uses",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: nil,
				},
			},
			wantErr: false,
		},
		{
			name: "job with workflow call with empty uses value",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{Value: ""},
				},
			},
			wantErr: false,
		},
		{
			name: "job with workflow call containing expression",
			job: &ast.Job{
				ID: &ast.String{Value: "test-job"},
				WorkflowCall: &ast.WorkflowCall{
					Uses: &ast.String{
						Value: "${{ vars.WORKFLOW_PATH }}",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := WorkflowCall("/test/workflow.yml", cache)

			err := rule.VisitJobPre(tt.job)
			if (err != nil) != tt.wantErr {
				t.Errorf("VisitJobPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestIsWorkflowCallUsesLocalFormat tests the isWorkflowCallUsesLocalFormat function.
func TestIsWorkflowCallUsesLocalFormat(t *testing.T) {
	tests := []struct {
		name string
		uses string
		want bool
	}{
		{
			name: "valid local format",
			uses: "./.github/workflows/reusable.yml",
			want: true,
		},
		{
			name: "valid local format with subdirectory",
			uses: "./workflows/test.yml",
			want: true,
		},
		{
			name: "invalid - does not start with ./",
			uses: "workflows/test.yml",
			want: false,
		},
		{
			name: "invalid - contains @ref",
			uses: "./.github/workflows/reusable.yml@main",
			want: false,
		},
		{
			name: "invalid - empty after ./",
			uses: "./",
			want: false,
		},
		{
			name: "invalid - only ./",
			uses: ".",
			want: false,
		},
		{
			name: "invalid - remote reference",
			uses: "owner/repo/path/to/workflow.yml@v1",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWorkflowCallUsesLocalFormat(tt.uses)
			if got != tt.want {
				t.Errorf("isWorkflowCallUsesLocalFormat(%q) = %v, want %v", tt.uses, got, tt.want)
			}
		})
	}
}

// TestIsWorkflowCallUsesRepoFormat tests the isWorkflowCallUsesRepoFormat function.
func TestIsWorkflowCallUsesRepoFormat(t *testing.T) {
	tests := []struct {
		name string
		uses string
		want bool
	}{
		{
			name: "valid repo format",
			uses: "owner/repo/path/to/workflow.yml@v1",
			want: true,
		},
		{
			name: "valid repo format with tag",
			uses: "owner/repo/.github/workflows/test.yml@main",
			want: true,
		},
		{
			name: "valid repo format with commit sha",
			uses: "owner/repo/workflow.yml@abc123def456",
			want: true,
		},
		{
			name: "invalid - starts with dot",
			uses: "./workflows/test.yml",
			want: false,
		},
		{
			name: "invalid - no owner",
			uses: "repo/workflow.yml@v1",
			want: false,
		},
		{
			name: "invalid - no repo",
			uses: "owner/@v1",
			want: false,
		},
		{
			name: "invalid - no path",
			uses: "owner/repo/@v1",
			want: false,
		},
		{
			name: "invalid - no ref",
			uses: "owner/repo/workflow.yml",
			want: false,
		},
		{
			name: "invalid - empty ref",
			uses: "owner/repo/workflow.yml@",
			want: false,
		},
		{
			name: "invalid - only owner",
			uses: "owner",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isWorkflowCallUsesRepoFormat(tt.uses)
			if got != tt.want {
				t.Errorf("isWorkflowCallUsesRepoFormat(%q) = %v, want %v", tt.uses, got, tt.want)
			}
		})
	}
}

// TestRuleWorkflowCall_checkWorkflowCallUsesLocal tests the checkWorkflowCallUsesLocal method.
func TestRuleWorkflowCall_checkWorkflowCallUsesLocal(t *testing.T) {
	tests := []struct {
		name       string
		call       *ast.WorkflowCall
		metadata   *ReusableWorkflowMetadata
		setupCache func(*LocalReusableWorkflowCache, string, *ReusableWorkflowMetadata)
		wantErrors int
	}{
		{
			name: "valid workflow call with no inputs or secrets",
			call: &ast.WorkflowCall{
				Uses:    &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs:  map[string]*ast.WorkflowCallInput{},
				Secrets: map[string]*ast.WorkflowCallSecret{},
			},
			metadata: &ReusableWorkflowMetadata{
				Inputs:  ReusableWorkflowMetadataInputs{},
				Secrets: ReusableWorkflowMetadataSecrets{},
			},
			setupCache: func(cache *LocalReusableWorkflowCache, key string, meta *ReusableWorkflowMetadata) {
				cache.writeCache(key, meta)
			},
			wantErrors: 0,
		},
		{
			name: "workflow call with required input missing",
			call: &ast.WorkflowCall{
				Uses:    &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs:  map[string]*ast.WorkflowCallInput{},
				Secrets: map[string]*ast.WorkflowCallSecret{},
			},
			metadata: &ReusableWorkflowMetadata{
				Inputs: ReusableWorkflowMetadataInputs{
					"required_input": &ReusableWorkflowMetadataInput{
						Name:     "required_input",
						Required: true,
					},
				},
				Secrets: ReusableWorkflowMetadataSecrets{},
			},
			setupCache: func(cache *LocalReusableWorkflowCache, key string, meta *ReusableWorkflowMetadata) {
				cache.writeCache(key, meta)
			},
			wantErrors: 1,
		},
		{
			name: "workflow call with undefined input",
			call: &ast.WorkflowCall{
				Uses: &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs: map[string]*ast.WorkflowCallInput{
					"undefined_input": {
						Name: &ast.String{Value: "undefined_input", Pos: &ast.Position{Line: 2, Col: 1}},
					},
				},
				Secrets: map[string]*ast.WorkflowCallSecret{},
			},
			metadata: &ReusableWorkflowMetadata{
				Inputs:  ReusableWorkflowMetadataInputs{},
				Secrets: ReusableWorkflowMetadataSecrets{},
			},
			setupCache: func(cache *LocalReusableWorkflowCache, key string, meta *ReusableWorkflowMetadata) {
				cache.writeCache(key, meta)
			},
			wantErrors: 1,
		},
		{
			name: "workflow call with required secret missing",
			call: &ast.WorkflowCall{
				Uses:           &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs:         map[string]*ast.WorkflowCallInput{},
				Secrets:        map[string]*ast.WorkflowCallSecret{},
				InheritSecrets: false,
			},
			metadata: &ReusableWorkflowMetadata{
				Inputs: ReusableWorkflowMetadataInputs{},
				Secrets: ReusableWorkflowMetadataSecrets{
					"required_secret": &ReusableWorkflowMetadataSecret{
						Name:     "required_secret",
						Required: true,
					},
				},
			},
			setupCache: func(cache *LocalReusableWorkflowCache, key string, meta *ReusableWorkflowMetadata) {
				cache.writeCache(key, meta)
			},
			wantErrors: 1,
		},
		{
			name: "workflow call with inherit secrets - should not check secrets",
			call: &ast.WorkflowCall{
				Uses:           &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs:         map[string]*ast.WorkflowCallInput{},
				Secrets:        map[string]*ast.WorkflowCallSecret{},
				InheritSecrets: true,
			},
			metadata: &ReusableWorkflowMetadata{
				Inputs: ReusableWorkflowMetadataInputs{},
				Secrets: ReusableWorkflowMetadataSecrets{
					"required_secret": &ReusableWorkflowMetadataSecret{
						Name:     "required_secret",
						Required: true,
					},
				},
			},
			setupCache: func(cache *LocalReusableWorkflowCache, key string, meta *ReusableWorkflowMetadata) {
				cache.writeCache(key, meta)
			},
			wantErrors: 0,
		},
		{
			name: "workflow call with undefined secret",
			call: &ast.WorkflowCall{
				Uses:   &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs: map[string]*ast.WorkflowCallInput{},
				Secrets: map[string]*ast.WorkflowCallSecret{
					"undefined_secret": {
						Name: &ast.String{Value: "undefined_secret", Pos: &ast.Position{Line: 3, Col: 1}},
					},
				},
				InheritSecrets: false,
			},
			metadata: &ReusableWorkflowMetadata{
				Inputs:  ReusableWorkflowMetadataInputs{},
				Secrets: ReusableWorkflowMetadataSecrets{},
			},
			setupCache: func(cache *LocalReusableWorkflowCache, key string, meta *ReusableWorkflowMetadata) {
				cache.writeCache(key, meta)
			},
			wantErrors: 1,
		},
		{
			name: "workflow call with all valid inputs and secrets",
			call: &ast.WorkflowCall{
				Uses: &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs: map[string]*ast.WorkflowCallInput{
					"valid_input": {
						Name: &ast.String{Value: "valid_input", Pos: &ast.Position{Line: 2, Col: 1}},
					},
				},
				Secrets: map[string]*ast.WorkflowCallSecret{
					"valid_secret": {
						Name: &ast.String{Value: "valid_secret", Pos: &ast.Position{Line: 3, Col: 1}},
					},
				},
				InheritSecrets: false,
			},
			metadata: &ReusableWorkflowMetadata{
				Inputs: ReusableWorkflowMetadataInputs{
					"valid_input": &ReusableWorkflowMetadataInput{
						Name:     "valid_input",
						Required: false,
					},
				},
				Secrets: ReusableWorkflowMetadataSecrets{
					"valid_secret": &ReusableWorkflowMetadataSecret{
						Name:     "valid_secret",
						Required: false,
					},
				},
			},
			setupCache: func(cache *LocalReusableWorkflowCache, key string, meta *ReusableWorkflowMetadata) {
				cache.writeCache(key, meta)
			},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			if tt.setupCache != nil {
				tt.setupCache(cache, tt.call.Uses.Value, tt.metadata)
			}

			rule := WorkflowCall("/test/workflow.yml", cache)
			// Enable debug output to avoid nil pointer dereference in Debug method
			// Note: There's a bug in BaseRule.Debug (line 41-42 should be == nil, not != nil)
			rule.EnableDebugOutput(io.Discard)
			rule.checkWorkflowCallUsesLocal(tt.call)

			errors := rule.Errors()
			errorCount := len(errors)
			if errorCount != tt.wantErrors {
				t.Errorf("checkWorkflowCallUsesLocal() error count = %v, want %v", errorCount, tt.wantErrors)
				for i, err := range errors {
					t.Logf("Error %d: %s", i+1, err.Description)
				}
			}
		})
	}
}

// TestRuleWorkflowCall_Integration tests the complete workflow call validation flow.
func TestRuleWorkflowCall_Integration(t *testing.T) {
	tests := []struct {
		name       string
		workflow   *ast.Workflow
		setupCache func(*LocalReusableWorkflowCache)
		wantErrors int
	}{
		{
			name: "valid local workflow call",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"call-workflow": {
						ID: &ast.String{Value: "call-workflow"},
						WorkflowCall: &ast.WorkflowCall{
							Uses: &ast.String{Value: "./reusable.yml", Pos: &ast.Position{Line: 5, Col: 10}},
							Inputs: map[string]*ast.WorkflowCallInput{
								"input1": {
									Name: &ast.String{Value: "input1", Pos: &ast.Position{Line: 6, Col: 10}},
								},
							},
							Secrets:        map[string]*ast.WorkflowCallSecret{},
							InheritSecrets: false,
						},
					},
				},
			},
			setupCache: func(cache *LocalReusableWorkflowCache) {
				cache.writeCache("./reusable.yml", &ReusableWorkflowMetadata{
					Inputs: ReusableWorkflowMetadataInputs{
						"input1": {Name: "input1", Required: false},
					},
					Secrets: ReusableWorkflowMetadataSecrets{},
				})
			},
			wantErrors: 0,
		},
		{
			name: "invalid workflow call format",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"call-workflow": {
						ID: &ast.String{Value: "call-workflow"},
						WorkflowCall: &ast.WorkflowCall{
							Uses:    &ast.String{Value: "invalid-format", Pos: &ast.Position{Line: 5, Col: 10}},
							Inputs:  map[string]*ast.WorkflowCallInput{},
							Secrets: map[string]*ast.WorkflowCallSecret{},
						},
					},
				},
			},
			setupCache: func(cache *LocalReusableWorkflowCache) {},
			wantErrors: 1,
		},
		{
			name: "valid remote workflow call",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"call-workflow": {
						ID: &ast.String{Value: "call-workflow"},
						WorkflowCall: &ast.WorkflowCall{
							Uses:    &ast.String{Value: "owner/repo/.github/workflows/test.yml@v1", Pos: &ast.Position{Line: 5, Col: 10}},
							Inputs:  map[string]*ast.WorkflowCallInput{},
							Secrets: map[string]*ast.WorkflowCallSecret{},
						},
					},
				},
			},
			setupCache: func(cache *LocalReusableWorkflowCache) {},
			wantErrors: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			if tt.setupCache != nil {
				tt.setupCache(cache)
			}

			rule := WorkflowCall("/test/workflow.yml", cache)
			rule.EnableDebugOutput(io.Discard)

			// Visit workflow pre
			if err := rule.VisitWorkflowPre(tt.workflow); err != nil {
				t.Fatalf("VisitWorkflowPre() error = %v", err)
			}

			// Visit jobs
			for _, job := range tt.workflow.Jobs {
				if err := rule.VisitJobPre(job); err != nil {
					t.Fatalf("VisitJobPre() error = %v", err)
				}
			}

			errors := rule.Errors()
			errorCount := len(errors)
			if errorCount != tt.wantErrors {
				t.Errorf("Integration test error count = %v, want %v", errorCount, tt.wantErrors)
				for i, err := range errors {
					t.Logf("Error %d: %s", i+1, err.Description)
				}
			}
		})
	}
}

// TestRuleWorkflowCall_EdgeCases tests edge cases for workflow call validation.
func TestRuleWorkflowCall_EdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		call       *ast.WorkflowCall
		wantErrors int
	}{
		{
			name: "workflow call with expression in uses",
			call: &ast.WorkflowCall{
				Uses: &ast.String{
					Value: "${{ inputs.workflow-path }}",
					Pos:   &ast.Position{Line: 1, Col: 1},
				},
				Inputs:  map[string]*ast.WorkflowCallInput{},
				Secrets: map[string]*ast.WorkflowCallSecret{},
			},
			wantErrors: 0,
		},
		{
			name: "workflow call starting with ./ but invalid",
			call: &ast.WorkflowCall{
				Uses: &ast.String{
					Value: "./",
					Pos:   &ast.Position{Line: 1, Col: 1},
				},
				Inputs:  map[string]*ast.WorkflowCallInput{},
				Secrets: map[string]*ast.WorkflowCallSecret{},
			},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
			rule := WorkflowCall("/test/workflow.yml", cache)
			rule.EnableDebugOutput(io.Discard)

			job := &ast.Job{
				ID:           &ast.String{Value: "test-job"},
				WorkflowCall: tt.call,
			}

			if err := rule.VisitJobPre(job); err != nil {
				t.Fatalf("VisitJobPre() error = %v", err)
			}

			errors := rule.Errors()
			errorCount := len(errors)
			if errorCount != tt.wantErrors {
				t.Errorf("Edge case error count = %v, want %v", errorCount, tt.wantErrors)
				for i, err := range errors {
					t.Logf("Error %d: %s", i+1, err.Description)
				}
			}
		})
	}
}

// TestRuleWorkflowCall_MultipleInputsAndSecrets tests scenarios with multiple inputs and secrets.
func TestRuleWorkflowCall_MultipleInputsAndSecrets(t *testing.T) {
	cache := NewLocalReusableWorkflowCache(nil, "/test/path", nil)
	cache.writeCache("./test.yml", &ReusableWorkflowMetadata{
		Inputs: ReusableWorkflowMetadataInputs{
			"input1": {Name: "input1", Required: true},
			"input2": {Name: "input2", Required: false},
			"input3": {Name: "input3", Required: true},
		},
		Secrets: ReusableWorkflowMetadataSecrets{
			"secret1": {Name: "secret1", Required: true},
			"secret2": {Name: "secret2", Required: false},
		},
	})

	tests := []struct {
		name       string
		call       *ast.WorkflowCall
		wantErrors int
	}{
		{
			name: "missing required input and secret",
			call: &ast.WorkflowCall{
				Uses: &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs: map[string]*ast.WorkflowCallInput{
					"input1": {Name: &ast.String{Value: "input1", Pos: &ast.Position{Line: 2, Col: 1}}},
					// missing input3 (required)
				},
				Secrets: map[string]*ast.WorkflowCallSecret{
					// missing secret1 (required)
				},
				InheritSecrets: false,
			},
			wantErrors: 2, // missing input3 and secret1
		},
		{
			name: "all required inputs and secrets provided",
			call: &ast.WorkflowCall{
				Uses: &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs: map[string]*ast.WorkflowCallInput{
					"input1": {Name: &ast.String{Value: "input1", Pos: &ast.Position{Line: 2, Col: 1}}},
					"input3": {Name: &ast.String{Value: "input3", Pos: &ast.Position{Line: 3, Col: 1}}},
				},
				Secrets: map[string]*ast.WorkflowCallSecret{
					"secret1": {Name: &ast.String{Value: "secret1", Pos: &ast.Position{Line: 4, Col: 1}}},
				},
				InheritSecrets: false,
			},
			wantErrors: 0,
		},
		{
			name: "extra undefined inputs and secrets",
			call: &ast.WorkflowCall{
				Uses: &ast.String{Value: "./test.yml", Pos: &ast.Position{Line: 1, Col: 1}},
				Inputs: map[string]*ast.WorkflowCallInput{
					"input1":     {Name: &ast.String{Value: "input1", Pos: &ast.Position{Line: 2, Col: 1}}},
					"input3":     {Name: &ast.String{Value: "input3", Pos: &ast.Position{Line: 3, Col: 1}}},
					"undefined1": {Name: &ast.String{Value: "undefined1", Pos: &ast.Position{Line: 4, Col: 1}}},
				},
				Secrets: map[string]*ast.WorkflowCallSecret{
					"secret1":    {Name: &ast.String{Value: "secret1", Pos: &ast.Position{Line: 5, Col: 1}}},
					"undefined2": {Name: &ast.String{Value: "undefined2", Pos: &ast.Position{Line: 6, Col: 1}}},
				},
				InheritSecrets: false,
			},
			wantErrors: 2, // undefined1 and undefined2
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := WorkflowCall("/test/workflow.yml", cache)
			rule.EnableDebugOutput(io.Discard)
			rule.checkWorkflowCallUsesLocal(tt.call)

			errors := rule.Errors()
			errorCount := len(errors)
			if errorCount != tt.wantErrors {
				t.Errorf("error count = %v, want %v", errorCount, tt.wantErrors)
				for i, err := range errors {
					t.Logf("Error %d: %s", i+1, err.Description)
				}
			}
		})
	}
}

// TestLocalReusableWorkflowCache tests the LocalReusableWorkflowCache functionality.
func TestLocalReusableWorkflowCache(t *testing.T) {
	t.Run("NewLocalReusableWorkflowCache", func(t *testing.T) {
		cache := NewLocalReusableWorkflowCache(nil, "/test/cwd", nil)
		if cache == nil {
			t.Fatal("NewLocalReusableWorkflowCache() returned nil")
		}
		if cache.cwd != "/test/cwd" {
			t.Errorf("cache.cwd = %v, want /test/cwd", cache.cwd)
		}
	})

	t.Run("writeCache and readCache", func(t *testing.T) {
		cache := NewLocalReusableWorkflowCache(nil, "/test/cwd", nil)
		metadata := &ReusableWorkflowMetadata{
			Inputs:  ReusableWorkflowMetadataInputs{},
			Secrets: ReusableWorkflowMetadataSecrets{},
		}

		cache.writeCache("./test.yml", metadata)

		retrieved, ok := cache.readCache("./test.yml")
		if !ok {
			t.Error("readCache() returned false, want true")
		}
		if !reflect.DeepEqual(retrieved, metadata) {
			t.Errorf("readCache() = %v, want %v", retrieved, metadata)
		}
	})

	t.Run("readCache non-existent key", func(t *testing.T) {
		cache := NewLocalReusableWorkflowCache(nil, "/test/cwd", nil)

		_, ok := cache.readCache("./nonexistent.yml")
		if ok {
			t.Error("readCache() returned true for non-existent key, want false")
		}
	})

	t.Run("writeCache nil metadata", func(t *testing.T) {
		cache := NewLocalReusableWorkflowCache(nil, "/test/cwd", nil)

		cache.writeCache("./invalid.yml", nil)

		retrieved, ok := cache.readCache("./invalid.yml")
		if !ok {
			t.Error("readCache() returned false, want true")
		}
		if retrieved != nil {
			t.Errorf("readCache() = %v, want nil", retrieved)
		}
	})
}

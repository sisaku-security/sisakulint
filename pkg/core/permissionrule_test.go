package core

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"gopkg.in/yaml.v3"
)

func TestPermissionsRule(t *testing.T) {
	tests := []struct {
		name string
		want *PermissionRule
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PermissionsRule(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PermissionsRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermissionRule_VisitJobPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Job
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		//todo:
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &PermissionRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitJobPre(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("PermissionRule.VisitJobPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPermissionRule_VisitWorkflowPre(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		n *ast.Workflow
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		//todo:
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &PermissionRule{
				BaseRule: tt.fields.BaseRule,
			}
			if err := rule.VisitWorkflowPre(tt.args.n); (err != nil) != tt.wantErr {
				t.Errorf("PermissionRule.VisitWorkflowPre() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPermissionRule_checkPermissions(t *testing.T) {
	type fields struct {
		BaseRule BaseRule
	}
	type args struct {
		p *ast.Permissions
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := &PermissionRule{
				BaseRule: tt.fields.BaseRule,
			}
			rule.checkPermissions(tt.args.p)
		})
	}
}

func TestPermissionRule_ValidScopes(t *testing.T) {
	// Test that all valid permission scopes are recognized
	validScopes := []string{
		"actions",
		"attestations",
		"checks",
		"contents",
		"deployments",
		"discussions",
		"id-token",
		"issues",
		"models",
		"packages",
		"pages",
		"pull-requests",
		"repository-projects",
		"security-events",
		"statuses",
	}

	for _, scope := range validScopes {
		t.Run(scope, func(t *testing.T) {
			rule := PermissionsRule()
			permissions := &ast.Permissions{
				Scopes: map[string]*ast.PermissionScope{
					scope: {
						Name:  &ast.String{Value: scope, Pos: &ast.Position{Line: 1, Col: 1}},
						Value: &ast.String{Value: "read", Pos: &ast.Position{Line: 1, Col: 10}},
					},
				},
			}
			rule.checkPermissions(permissions)
			if len(rule.Errors()) > 0 {
				t.Errorf("scope %q should be valid, but got error: %v", scope, rule.Errors()[0])
			}
		})
	}
}

func TestPermissionRule_InvalidScope(t *testing.T) {
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		Scopes: map[string]*ast.PermissionScope{
			"invalid-scope": {
				Name:  &ast.String{Value: "invalid-scope", Pos: &ast.Position{Line: 1, Col: 1}},
				Value: &ast.String{Value: "read", Pos: &ast.Position{Line: 1, Col: 20}},
			},
		},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) == 0 {
		t.Error("expected error for invalid scope, but got none")
	}
}

func TestPermissionRule_ReadAllPermission(t *testing.T) {
	// Test that read-all is accepted as valid
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		All: &ast.String{Value: "read-all", Pos: &ast.Position{Line: 1, Col: 1}},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) > 0 {
		t.Errorf("read-all should be valid, but got error: %v", rule.Errors()[0])
	}
}

func TestPermissionRule_WriteAllPermission(t *testing.T) {
	// Test that write-all generates a warning
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		All: &ast.String{Value: "write-all", Pos: &ast.Position{Line: 1, Col: 1}},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) == 0 {
		t.Error("write-all should generate a warning, but got none")
	}
}

func TestPermissionRule_InvalidAllPermission(t *testing.T) {
	// Test that invalid all-scope permission generates an error
	rule := PermissionsRule()
	permissions := &ast.Permissions{
		All: &ast.String{Value: "invalid-all", Pos: &ast.Position{Line: 1, Col: 1}},
	}
	rule.checkPermissions(permissions)
	if len(rule.Errors()) == 0 {
		t.Error("invalid-all should generate an error, but got none")
	}
}

func TestPermissionRule_MissingPermissions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workflow    *ast.Workflow
		wantErr     bool
		errContains string
	}{
		{
			name: "missing permissions - should error",
			workflow: &ast.Workflow{
				Name: &ast.String{Value: "test", Pos: &ast.Position{Line: 1, Col: 1}},
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 2, Col: 1}}},
				},
				Permissions: nil,
			},
			wantErr:     true,
			errContains: "does not have explicit 'permissions' block",
		},
		{
			name: "has permissions - no error",
			workflow: &ast.Workflow{
				Name: &ast.String{Value: "test", Pos: &ast.Position{Line: 1, Col: 1}},
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 2, Col: 1}}},
				},
				Permissions: &ast.Permissions{
					All: &ast.String{Value: "read-all", Pos: &ast.Position{Line: 3, Col: 1}},
				},
			},
			wantErr: false,
		},
		{
			name: "reusable workflow without permissions - no error",
			workflow: &ast.Workflow{
				Name: &ast.String{Value: "reusable", Pos: &ast.Position{Line: 1, Col: 1}},
				On: []ast.Event{
					&ast.WorkflowCallEvent{Pos: &ast.Position{Line: 2, Col: 1}},
				},
				Permissions: nil,
			},
			wantErr: false,
		},
		{
			// When workflow_call is present with other triggers, it's treated as reusable.
			// This is because the workflow can be called with inherited permissions,
			// even if it also responds to other events.
			name: "reusable workflow with other triggers - no error for workflow_call",
			workflow: &ast.Workflow{
				Name: &ast.String{Value: "reusable", Pos: &ast.Position{Line: 1, Col: 1}},
				On: []ast.Event{
					&ast.WorkflowCallEvent{Pos: &ast.Position{Line: 2, Col: 1}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 3, Col: 1}}},
				},
				Permissions: nil,
			},
			wantErr: false,
		},
		{
			name: "all jobs have permissions - no error",
			workflow: &ast.Workflow{
				Name: &ast.String{Value: "test", Pos: &ast.Position{Line: 1, Col: 1}},
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 2, Col: 1}}},
				},
				Permissions: nil,
				Jobs: map[string]*ast.Job{
					"job1": {
						Permissions: &ast.Permissions{
							Scopes: map[string]*ast.PermissionScope{
								"issues": {
									Name:  &ast.String{Value: "issues", Pos: &ast.Position{Line: 5, Col: 1}},
									Value: &ast.String{Value: "write", Pos: &ast.Position{Line: 5, Col: 10}},
								},
							},
						},
					},
					"job2": {
						Permissions: &ast.Permissions{
							Scopes: map[string]*ast.PermissionScope{
								"contents": {
									Name:  &ast.String{Value: "contents", Pos: &ast.Position{Line: 10, Col: 1}},
									Value: &ast.String{Value: "read", Pos: &ast.Position{Line: 10, Col: 10}},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "some jobs missing permissions - should error",
			workflow: &ast.Workflow{
				Name: &ast.String{Value: "test", Pos: &ast.Position{Line: 1, Col: 1}},
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 2, Col: 1}}},
				},
				Permissions: nil,
				Jobs: map[string]*ast.Job{
					"job1": {
						Permissions: &ast.Permissions{
							Scopes: map[string]*ast.PermissionScope{
								"issues": {
									Name:  &ast.String{Value: "issues", Pos: &ast.Position{Line: 5, Col: 1}},
									Value: &ast.String{Value: "write", Pos: &ast.Position{Line: 5, Col: 10}},
								},
							},
						},
					},
					"job2": {
						Permissions: nil, // Missing permissions
					},
				},
			},
			wantErr:     true,
			errContains: "does not have explicit 'permissions' block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rule := PermissionsRule()
			err := rule.VisitWorkflowPre(tt.workflow)
			if err != nil {
				t.Errorf("VisitWorkflowPre() returned error: %v", err)
			}

			errors := rule.Errors()
			if tt.wantErr {
				if len(errors) == 0 {
					t.Error("expected error but got none")
				} else if tt.errContains != "" {
					found := false
					for _, e := range errors {
						if strings.Contains(e.Description, tt.errContains) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected error containing %q, got %v", tt.errContains, errors)
					}
				}
			} else {
				// Filter out any errors that are not about missing permissions
				for _, e := range errors {
					if strings.Contains(e.Description, "does not have explicit 'permissions' block") {
						t.Errorf("expected no missing permissions error, but got: %v", e.Description)
					}
				}
			}
		})
	}
}

func TestPermissionRule_AutoFix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		wantPermission bool
	}{
		{
			name: "adds permissions after on block",
			input: `name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`,
			wantPermission: true,
		},
		{
			name: "adds permissions after name when no on block found first",
			input: `name: Test
jobs:
  test:
    runs-on: ubuntu-latest
`,
			wantPermission: true,
		},
		{
			name: "adds permissions after on block when no name field",
			input: `on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`,
			wantPermission: true,
		},
		{
			name: "adds permissions after on block with run-name instead of name",
			input: `run-name: Deploy by @${{ github.actor }}
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`,
			wantPermission: true,
		},
		{
			name: "adds permissions at beginning when only jobs field exists",
			input: `jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
`,
			wantPermission: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Parse the workflow
			var node yaml.Node
			if err := yaml.Unmarshal([]byte(tt.input), &node); err != nil {
				t.Fatalf("failed to parse yaml: %v", err)
			}

			workflow := &ast.Workflow{
				BaseNode:    node.Content[0],
				Permissions: nil,
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 2, Col: 1}}},
				},
			}

			rule := PermissionsRule()
			_ = rule.VisitWorkflowPre(workflow)

			// Check that auto-fixer was added
			fixers := rule.AutoFixers()
			if len(fixers) == 0 {
				t.Fatal("expected auto-fixer to be added")
			}

			// Apply the fix
			if err := fixers[0].Fix(); err != nil {
				t.Fatalf("fix failed: %v", err)
			}

			// Check that permissions was added
			if tt.wantPermission {
				// BaseNode is MappingNode in test (not DocumentNode)
				mappingNode := workflow.BaseNode
				found := false
				for i := 0; i < len(mappingNode.Content); i += 2 {
					if mappingNode.Content[i].Value == "permissions" {
						found = true
						// Check that it's an empty mapping (permissions: {})
						if mappingNode.Content[i+1].Kind != yaml.MappingNode {
							t.Errorf("expected permissions to be a mapping node, got kind %d", mappingNode.Content[i+1].Kind)
						}
						if len(mappingNode.Content[i+1].Content) != 0 {
							t.Errorf("expected empty permissions mapping, got %d items", len(mappingNode.Content[i+1].Content))
						}
						// Check that TODO comment is present
						if !strings.Contains(mappingNode.Content[i].HeadComment, "TODO") {
							t.Errorf("expected TODO comment on permissions key, got %q", mappingNode.Content[i].HeadComment)
						}
						break
					}
				}
				if !found {
					t.Error("permissions block was not added")
				}
			}
		})
	}
}

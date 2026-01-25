package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestMitigationStatusScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status MitigationStatus
		want   int
	}{
		{
			name:   "no mitigations",
			status: MitigationStatus{},
			want:   0,
		},
		{
			name: "permissions only",
			status: MitigationStatus{
				HasPermissionsRestriction: true,
			},
			want: 3,
		},
		{
			name: "environment only",
			status: MitigationStatus{
				HasEnvironmentProtection: true,
			},
			want: 2,
		},
		{
			name: "label only",
			status: MitigationStatus{
				HasLabelCondition: true,
			},
			want: 1,
		},
		{
			name: "actor only",
			status: MitigationStatus{
				HasActorRestriction: true,
			},
			want: 1,
		},
		{
			name: "fork only",
			status: MitigationStatus{
				HasForkCheck: true,
			},
			want: 1,
		},
		{
			name: "all mitigations",
			status: MitigationStatus{
				HasPermissionsRestriction: true,
				HasEnvironmentProtection:  true,
				HasLabelCondition:         true,
				HasActorRestriction:       true,
				HasForkCheck:              true,
			},
			want: 8,
		},
		{
			name: "label and actor (score 2)",
			status: MitigationStatus{
				HasLabelCondition:   true,
				HasActorRestriction: true,
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.status.Score()
			if got != tt.want {
				t.Errorf("Score() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMitigationStatusSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status MitigationStatus
		want   string
	}{
		{
			name:   "no mitigations = critical",
			status: MitigationStatus{},
			want:   SeverityCritical,
		},
		{
			name: "score 1 = medium",
			status: MitigationStatus{
				HasLabelCondition: true,
			},
			want: SeverityMedium,
		},
		{
			name: "score 2 = medium",
			status: MitigationStatus{
				HasLabelCondition:   true,
				HasActorRestriction: true,
			},
			want: SeverityMedium,
		},
		{
			name: "score 3 = no warning",
			status: MitigationStatus{
				HasPermissionsRestriction: true,
			},
			want: "",
		},
		{
			name: "score 5 = no warning",
			status: MitigationStatus{
				HasPermissionsRestriction: true,
				HasEnvironmentProtection:  true,
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.status.Severity()
			if got != tt.want {
				t.Errorf("Severity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMitigationStatusFoundMitigations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status MitigationStatus
		want   []string
	}{
		{
			name:   "no mitigations",
			status: MitigationStatus{},
			want:   nil,
		},
		{
			name: "all mitigations",
			status: MitigationStatus{
				HasPermissionsRestriction: true,
				HasEnvironmentProtection:  true,
				HasLabelCondition:         true,
				HasActorRestriction:       true,
				HasForkCheck:              true,
			},
			want: []string{
				"permissions restriction",
				"environment protection",
				"label condition",
				"actor restriction",
				"fork check",
			},
		},
		{
			name: "partial mitigations",
			status: MitigationStatus{
				HasLabelCondition:   true,
				HasActorRestriction: true,
			},
			want: []string{
				"label condition",
				"actor restriction",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.status.FoundMitigations()

			if len(got) != len(tt.want) {
				t.Errorf("FoundMitigations() returned %d items, want %d", len(got), len(tt.want))
				return
			}

			for i, name := range got {
				if name != tt.want[i] {
					t.Errorf("FoundMitigations()[%d] = %v, want %v", i, name, tt.want[i])
				}
			}
		})
	}
}

func TestCheckMitigations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		workflow *ast.Workflow
		want     MitigationStatus
	}{
		{
			name:     "nil workflow",
			workflow: nil,
			want:     MitigationStatus{},
		},
		{
			name: "workflow with read-all permissions",
			workflow: &ast.Workflow{
				Permissions: &ast.Permissions{
					All: &ast.String{Value: "read-all"},
				},
			},
			want: MitigationStatus{
				HasPermissionsRestriction: true,
			},
		},
		{
			name: "workflow with empty permissions",
			workflow: &ast.Workflow{
				Permissions: &ast.Permissions{
					All: &ast.String{Value: "{}"},
				},
			},
			want: MitigationStatus{
				HasPermissionsRestriction: true,
			},
		},
		{
			name: "workflow with scoped permissions",
			workflow: &ast.Workflow{
				Permissions: &ast.Permissions{
					Scopes: map[string]*ast.PermissionScope{
						"contents": {Name: &ast.String{Value: "contents"}, Value: &ast.String{Value: "read"}},
					},
				},
			},
			want: MitigationStatus{
				HasPermissionsRestriction: true,
			},
		},
		{
			name: "workflow with write-all permissions (not a restriction)",
			workflow: &ast.Workflow{
				Permissions: &ast.Permissions{
					All: &ast.String{Value: "write-all"},
				},
			},
			want: MitigationStatus{},
		},
		{
			name: "job with environment protection",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"deploy": {
						Environment: &ast.Environment{
							Name: &ast.String{Value: "production"},
						},
					},
				},
			},
			want: MitigationStatus{
				HasEnvironmentProtection: true,
			},
		},
		{
			name: "job with label condition",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"build": {
						If: &ast.String{Value: "contains(github.event.pull_request.labels.*.name, 'safe-to-run')"},
					},
				},
			},
			want: MitigationStatus{
				HasLabelCondition: true,
			},
		},
		{
			name: "job with actor restriction",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"build": {
						If: &ast.String{Value: "github.actor == 'dependabot[bot]'"},
					},
				},
			},
			want: MitigationStatus{
				HasActorRestriction: true,
			},
		},
		{
			name: "job with fork check",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"build": {
						If: &ast.String{Value: "github.event.pull_request.head.repo.fork == false"},
					},
				},
			},
			want: MitigationStatus{
				HasForkCheck: true,
			},
		},
		{
			name: "step with label condition",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"build": {
						Steps: []*ast.Step{
							{
								If: &ast.String{Value: "contains(github.event.pull_request.labels.*.name, 'approved')"},
							},
						},
					},
				},
			},
			want: MitigationStatus{
				HasLabelCondition: true,
			},
		},
		{
			name: "job-level permissions (not workflow-level)",
			workflow: &ast.Workflow{
				Jobs: map[string]*ast.Job{
					"build": {
						Permissions: &ast.Permissions{
							All: &ast.String{Value: "read-all"},
						},
					},
				},
			},
			want: MitigationStatus{
				HasPermissionsRestriction: true,
			},
		},
		{
			name: "multiple mitigations",
			workflow: &ast.Workflow{
				Permissions: &ast.Permissions{
					All: &ast.String{Value: "read-all"},
				},
				Jobs: map[string]*ast.Job{
					"deploy": {
						Environment: &ast.Environment{
							Name: &ast.String{Value: "production"},
						},
						If: &ast.String{Value: "contains(github.event.pull_request.labels.*.name, 'approved')"},
					},
				},
			},
			want: MitigationStatus{
				HasPermissionsRestriction: true,
				HasEnvironmentProtection:  true,
				HasLabelCondition:         true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CheckMitigations(tt.workflow)

			if got.HasPermissionsRestriction != tt.want.HasPermissionsRestriction {
				t.Errorf("HasPermissionsRestriction = %v, want %v", got.HasPermissionsRestriction, tt.want.HasPermissionsRestriction)
			}
			if got.HasEnvironmentProtection != tt.want.HasEnvironmentProtection {
				t.Errorf("HasEnvironmentProtection = %v, want %v", got.HasEnvironmentProtection, tt.want.HasEnvironmentProtection)
			}
			if got.HasLabelCondition != tt.want.HasLabelCondition {
				t.Errorf("HasLabelCondition = %v, want %v", got.HasLabelCondition, tt.want.HasLabelCondition)
			}
			if got.HasActorRestriction != tt.want.HasActorRestriction {
				t.Errorf("HasActorRestriction = %v, want %v", got.HasActorRestriction, tt.want.HasActorRestriction)
			}
			if got.HasForkCheck != tt.want.HasForkCheck {
				t.Errorf("HasForkCheck = %v, want %v", got.HasForkCheck, tt.want.HasForkCheck)
			}
		})
	}
}

func TestDangerousTriggersCriticalRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		workflow *ast.Workflow
		wantErr  bool
		errMsg   string
	}{
		{
			name: "critical: pull_request_target without mitigations",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "dangerous trigger (critical)",
		},
		{
			name: "critical: workflow_run without mitigations",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "workflow_run", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "dangerous trigger (critical)",
		},
		{
			name: "safe: pull_request_target with permissions restriction",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Permissions: &ast.Permissions{
					All: &ast.String{Value: "read-all", Pos: &ast.Position{Line: 3, Col: 1}},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "safe: normal trigger (pull_request)",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "medium (not critical): pull_request_target with label condition",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						If: &ast.String{Value: "contains(github.event.pull_request.labels.*.name, 'safe')"},
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: false, // This is medium, not critical
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewDangerousTriggersCriticalRule()
			err := rule.VisitWorkflowPre(tt.workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre returned error: %v", err)
			}

			errs := rule.Errors()
			if tt.wantErr {
				if len(errs) == 0 {
					t.Error("expected error but got none")
					return
				}
				if !strings.Contains(errs[0].Description, tt.errMsg) {
					t.Errorf("error message = %q, want to contain %q", errs[0].Description, tt.errMsg)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("expected no error but got: %v", errs[0].Description)
				}
			}
		})
	}
}

func TestDangerousTriggersMediumRule(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		workflow *ast.Workflow
		wantErr  bool
		errMsg   string
	}{
		{
			name: "medium: pull_request_target with label condition only",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						If: &ast.String{Value: "contains(github.event.pull_request.labels.*.name, 'safe')"},
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "dangerous trigger (medium)",
		},
		{
			name: "medium: workflow_run with actor restriction only",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "workflow_run", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						If: &ast.String{Value: "github.actor == 'dependabot[bot]'"},
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "dangerous trigger (medium)",
		},
		{
			name: "safe: pull_request_target with permissions restriction",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Permissions: &ast.Permissions{
					All: &ast.String{Value: "read-all", Pos: &ast.Position{Line: 3, Col: 1}},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: false, // score >= 3, no warning
		},
		{
			name: "critical (not medium): no mitigations",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "pull_request_target", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: false, // This is critical, not medium
		},
		{
			name: "safe: normal trigger (push)",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{
						Hook: &ast.String{Value: "push", Pos: &ast.Position{Line: 2, Col: 1}},
						Pos:  &ast.Position{Line: 2, Col: 1},
					},
				},
				Jobs: map[string]*ast.Job{
					"test": {
						Steps: []*ast.Step{
							{
								Exec: &ast.ExecRun{
									Run: &ast.String{Value: "echo test"},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rule := NewDangerousTriggersMediumRule()
			err := rule.VisitWorkflowPre(tt.workflow)
			if err != nil {
				t.Fatalf("VisitWorkflowPre returned error: %v", err)
			}

			errs := rule.Errors()
			if tt.wantErr {
				if len(errs) == 0 {
					t.Error("expected error but got none")
					return
				}
				if !strings.Contains(errs[0].Description, tt.errMsg) {
					t.Errorf("error message = %q, want to contain %q", errs[0].Description, tt.errMsg)
				}
			} else {
				if len(errs) > 0 {
					t.Errorf("expected no error but got: %v", errs[0].Description)
				}
			}
		})
	}
}

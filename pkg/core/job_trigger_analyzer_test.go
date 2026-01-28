package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestJobTriggerAnalyzer_AnalyzeJobTriggers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		workflowTriggers []string
		jobIf            string
		want             []string
	}{
		{
			name:             "no if condition returns all workflow triggers",
			workflowTriggers: []string{"pull_request", "pull_request_target", "push"},
			jobIf:            "",
			want:             []string{"pull_request", "pull_request_target", "push"},
		},
		{
			name:             "github.event_name == 'pull_request' filters to pull_request only",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "github.event_name == 'pull_request'",
			want:             []string{"pull_request"},
		},
		{
			name:             "github.event_name != 'pull_request_target' excludes pull_request_target",
			workflowTriggers: []string{"pull_request", "pull_request_target", "push"},
			jobIf:            "github.event_name != 'pull_request_target'",
			want:             []string{"pull_request", "push"},
		},
		{
			name:             "contains with fromJson filters to specified triggers",
			workflowTriggers: []string{"pull_request", "pull_request_target", "push", "schedule"},
			jobIf:            "contains(fromJson('[\"push\", \"pull_request\"]'), github.event_name)",
			want:             []string{"pull_request", "push"},
		},
		{
			name:             "AND condition with event_name check",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "github.event_name == 'pull_request' && github.event.action == 'opened'",
			want:             []string{"pull_request"},
		},
		{
			name:             "OR condition combines triggers",
			workflowTriggers: []string{"pull_request", "pull_request_target", "push"},
			jobIf:            "github.event_name == 'push' || github.event_name == 'pull_request'",
			want:             []string{"pull_request", "push"},
		},
		{
			name:             "NOT condition excludes trigger",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "!(github.event_name == 'pull_request_target')",
			want:             []string{"pull_request"},
		},
		{
			name:             "unrelated condition returns all triggers (conservative)",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "github.actor != 'dependabot[bot]'",
			want:             []string{"pull_request", "pull_request_target"},
		},
		{
			name:             "complex nested condition",
			workflowTriggers: []string{"pull_request", "pull_request_target", "push"},
			jobIf:            "(github.event_name == 'pull_request' || github.event_name == 'push') && github.ref == 'refs/heads/main'",
			want:             []string{"pull_request", "push"},
		},
		{
			name:             "single quoted string comparison",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            `github.event_name == 'pull_request'`,
			want:             []string{"pull_request"},
		},
		{
			name:             "expression with ${{ }} wrapper",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "${{ github.event_name == 'pull_request' }}",
			want:             []string{"pull_request"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			analyzer := NewJobTriggerAnalyzer(tt.workflowTriggers)

			var jobIf *ast.String
			if tt.jobIf != "" {
				jobIf = &ast.String{Value: tt.jobIf}
			}

			job := &ast.Job{
				If: jobIf,
			}

			got := analyzer.AnalyzeJobTriggers(job)

			// Convert to set for comparison
			gotSet := make(map[string]bool)
			for _, trigger := range got {
				gotSet[trigger] = true
			}

			wantSet := make(map[string]bool)
			for _, trigger := range tt.want {
				wantSet[trigger] = true
			}

			if len(gotSet) != len(wantSet) {
				t.Errorf("AnalyzeJobTriggers() got %v, want %v", got, tt.want)
				return
			}

			for trigger := range wantSet {
				if !gotSet[trigger] {
					t.Errorf("AnalyzeJobTriggers() missing trigger %q, got %v, want %v", trigger, got, tt.want)
				}
			}
		})
	}
}

func TestJobTriggerAnalyzer_HasPrivilegedTrigger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		workflowTriggers []string
		jobIf            string
		want             bool
	}{
		{
			name:             "workflow with pull_request_target and no job if",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "",
			want:             true,
		},
		{
			name:             "workflow with pull_request_target but job filters to pull_request only",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "github.event_name == 'pull_request'",
			want:             false,
		},
		{
			name:             "workflow with workflow_run and no job if",
			workflowTriggers: []string{"workflow_run"},
			jobIf:            "",
			want:             true,
		},
		{
			name:             "workflow with issue_comment and no job if",
			workflowTriggers: []string{"issue_comment", "push"},
			jobIf:            "",
			want:             true,
		},
		{
			name:             "workflow with only safe triggers",
			workflowTriggers: []string{"pull_request", "push"},
			jobIf:            "",
			want:             false,
		},
		{
			name:             "workflow_call trigger",
			workflowTriggers: []string{"workflow_call"},
			jobIf:            "",
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			analyzer := NewJobTriggerAnalyzer(tt.workflowTriggers)

			var jobIf *ast.String
			if tt.jobIf != "" {
				jobIf = &ast.String{Value: tt.jobIf}
			}

			job := &ast.Job{
				If: jobIf,
			}

			got := analyzer.HasPrivilegedTrigger(job)

			if got != tt.want {
				t.Errorf("HasPrivilegedTrigger() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJobTriggerAnalyzer_HasUnsafeTrigger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		workflowTriggers []string
		jobIf            string
		want             bool
	}{
		{
			name:             "workflow with pull_request_target and no job if",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "",
			want:             true,
		},
		{
			name:             "workflow with pull_request_target but job filters to pull_request only",
			workflowTriggers: []string{"pull_request", "pull_request_target"},
			jobIf:            "github.event_name == 'pull_request'",
			want:             false,
		},
		{
			name:             "workflow with workflow_run",
			workflowTriggers: []string{"workflow_run"},
			jobIf:            "",
			want:             true,
		},
		{
			name:             "workflow with issue_comment",
			workflowTriggers: []string{"issue_comment", "push"},
			jobIf:            "",
			want:             true,
		},
		{
			name:             "safe triggers only",
			workflowTriggers: []string{"pull_request", "push"},
			jobIf:            "",
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			analyzer := NewJobTriggerAnalyzer(tt.workflowTriggers)

			var jobIf *ast.String
			if tt.jobIf != "" {
				jobIf = &ast.String{Value: tt.jobIf}
			}

			job := &ast.Job{
				If: jobIf,
			}

			got := analyzer.HasUnsafeTrigger(job)

			if got != tt.want {
				t.Errorf("HasUnsafeTrigger() = %v, want %v", got, tt.want)
			}
		})
	}
}

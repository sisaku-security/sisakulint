package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestHasPrivilegedTriggers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		workflow *ast.Workflow
		want     bool
	}{
		{
			name:     "nil workflow",
			workflow: nil,
			want:     false,
		},
		{
			name: "nil On",
			workflow: &ast.Workflow{
				On: nil,
			},
			want: false,
		},
		{
			name: "empty On",
			workflow: &ast.Workflow{
				On: []ast.Event{},
			},
			want: false,
		},
		{
			name: "pull_request_target is privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
				},
			},
			want: true,
		},
		{
			name: "workflow_run is privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "workflow_run"}},
				},
			},
			want: true,
		},
		{
			name: "issue_comment is privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "issue_comment"}},
				},
			},
			want: true,
		},
		{
			name: "issues is privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "issues"}},
				},
			},
			want: true,
		},
		{
			name: "discussion_comment is privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "discussion_comment"}},
				},
			},
			want: true,
		},
		{
			name: "pull_request is not privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
				},
			},
			want: false,
		},
		{
			name: "push is not privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
				},
			},
			want: false,
		},
		{
			name: "schedule is not privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.ScheduledEvent{},
				},
			},
			want: false,
		},
		{
			name: "mixed triggers with one privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
				},
			},
			want: true,
		},
		{
			name: "mixed triggers all non-privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
				},
			},
			want: false,
		},
		{
			name: "case insensitive - uppercase",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "PULL_REQUEST_TARGET"}},
				},
			},
			want: true,
		},
		{
			name: "case insensitive - mixed case",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "Pull_Request_Target"}},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := HasPrivilegedTriggers(tt.workflow)
			if got != tt.want {
				t.Errorf("HasPrivilegedTriggers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPrivilegedTriggerNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		workflow *ast.Workflow
		want     []string
	}{
		{
			name:     "nil workflow",
			workflow: nil,
			want:     nil,
		},
		{
			name: "no privileged triggers",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
				},
			},
			want: nil,
		},
		{
			name: "single privileged trigger",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
				},
			},
			want: []string{"pull_request_target"},
		},
		{
			name: "multiple privileged triggers",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "workflow_run"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "issue_comment"}},
				},
			},
			want: []string{"pull_request_target", "workflow_run", "issue_comment"},
		},
		{
			name: "mixed privileged and non-privileged",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "push"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
				},
			},
			want: []string{"pull_request_target"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetPrivilegedTriggerNames(tt.workflow)

			if len(got) != len(tt.want) {
				t.Errorf("GetPrivilegedTriggerNames() returned %d items, want %d", len(got), len(tt.want))
				return
			}

			for i, name := range got {
				if name != tt.want[i] {
					t.Errorf("GetPrivilegedTriggerNames()[%d] = %v, want %v", i, name, tt.want[i])
				}
			}
		})
	}
}

func TestGetPrivilegedTriggerEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		workflow  *ast.Workflow
		wantCount int
	}{
		{
			name:      "nil workflow",
			workflow:  nil,
			wantCount: 0,
		},
		{
			name: "no privileged triggers",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request"}},
				},
			},
			wantCount: 0,
		},
		{
			name: "single privileged trigger",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
				},
			},
			wantCount: 1,
		},
		{
			name: "multiple privileged triggers",
			workflow: &ast.Workflow{
				On: []ast.Event{
					&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}},
					&ast.WebhookEvent{Hook: &ast.String{Value: "workflow_run"}},
				},
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetPrivilegedTriggerEvents(tt.workflow)

			if len(got) != tt.wantCount {
				t.Errorf("GetPrivilegedTriggerEvents() returned %d events, want %d", len(got), tt.wantCount)
			}

			// Verify all returned events are privileged
			for _, event := range got {
				if !PrivilegedTriggers[event.EventName()] {
					t.Errorf("GetPrivilegedTriggerEvents() returned non-privileged event: %s", event.EventName())
				}
			}
		})
	}
}

func TestPrivilegedTriggersMap(t *testing.T) {
	t.Parallel()

	// Ensure all expected privileged triggers are in the map
	expectedTriggers := []string{
		"pull_request_target",
		"workflow_run",
		"issue_comment",
		"issues",
		"discussion_comment",
	}

	for _, trigger := range expectedTriggers {
		if !PrivilegedTriggers[trigger] {
			t.Errorf("Expected %s to be in PrivilegedTriggers map", trigger)
		}
	}

	// Ensure common non-privileged triggers are NOT in the map
	nonPrivilegedTriggers := []string{
		"pull_request",
		"push",
		"workflow_dispatch",
		"schedule",
		"release",
		"create",
		"delete",
	}

	for _, trigger := range nonPrivilegedTriggers {
		if PrivilegedTriggers[trigger] {
			t.Errorf("Expected %s to NOT be in PrivilegedTriggers map", trigger)
		}
	}
}

package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestOrderedWorkflowJobsPreservesSourceOrderWithoutNeeds(t *testing.T) {
	t.Parallel()

	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"second": {
				ID:  &ast.String{Value: "second"},
				Pos: &ast.Position{Line: 20, Col: 3},
			},
			"first": {
				ID:  &ast.String{Value: "first"},
				Pos: &ast.Position{Line: 10, Col: 3},
			},
		},
	}

	got := orderedWorkflowJobs(workflow)
	assertJobOrder(t, got, []string{"first", "second"})
}

func TestOrderedWorkflowJobsVisitsNeedsBeforeDependents(t *testing.T) {
	t.Parallel()

	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"job-a": {
				ID:  &ast.String{Value: "job-a"},
				Pos: &ast.Position{Line: 40, Col: 3},
			},
			"independent": {
				ID:  &ast.String{Value: "independent"},
				Pos: &ast.Position{Line: 10, Col: 3},
			},
			"job-c": {
				ID: &ast.String{Value: "job-c"},
				Needs: []*ast.String{
					{Value: "job-b"},
				},
				Pos: &ast.Position{Line: 30, Col: 3},
			},
			"job-b": {
				ID: &ast.String{Value: "job-b"},
				Needs: []*ast.String{
					{Value: "job-a"},
				},
				Pos: &ast.Position{Line: 20, Col: 3},
			},
		},
	}

	got := orderedWorkflowJobs(workflow)
	assertJobOrder(t, got, []string{"independent", "job-a", "job-b", "job-c"})
}

func TestOrderedWorkflowJobsUsesSourceOrderForReadyJobs(t *testing.T) {
	t.Parallel()

	workflow := &ast.Workflow{
		Jobs: map[string]*ast.Job{
			"dependent": {
				ID: &ast.String{Value: "dependent"},
				Needs: []*ast.String{
					{Value: "dependency"},
				},
				Pos: &ast.Position{Line: 10, Col: 3},
			},
			"independent": {
				ID:  &ast.String{Value: "independent"},
				Pos: &ast.Position{Line: 20, Col: 3},
			},
			"dependency": {
				ID:  &ast.String{Value: "dependency"},
				Pos: &ast.Position{Line: 30, Col: 3},
			},
		},
	}

	got := orderedWorkflowJobs(workflow)
	assertJobOrder(t, got, []string{"independent", "dependency", "dependent"})
}

func assertJobOrder(t *testing.T, jobs []*ast.Job, want []string) {
	t.Helper()

	if len(jobs) != len(want) {
		t.Fatalf("got %d jobs, want %d", len(jobs), len(want))
	}

	for i, job := range jobs {
		if job == nil || job.ID == nil {
			t.Fatalf("job %d missing ID: %#v", i, job)
		}
		if job.ID.Value != want[i] {
			t.Fatalf("job %d = %q, want %q", i, job.ID.Value, want[i])
		}
	}
}

package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestWorkflowTaintMap_NewAndRegister(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()
	if m == nil {
		t.Fatal("NewWorkflowTaintMap() returned nil")
	}

	// 未登録ジョブは registered=false
	sources, registered := m.IsTaintedNeedsOutput("extract", "pr_title")
	if registered {
		t.Errorf("unregistered job should return registered=false")
	}
	if len(sources) > 0 {
		t.Errorf("unregistered job should return no sources")
	}
}

func TestWorkflowTaintMap_RegisterAndResolve(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()
	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})

	sources, registered := m.IsTaintedNeedsOutput("extract", "pr_title")
	if !registered {
		t.Errorf("registered job should return registered=true")
	}
	if len(sources) == 0 {
		t.Errorf("tainted output should return sources")
	}
	if sources[0] != "github.event.pull_request.title" {
		t.Errorf("got source %q, want %q", sources[0], "github.event.pull_request.title")
	}
}

func TestWorkflowTaintMap_RegisterCleanOutput(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()
	m.markJobAsRegistered("safe-job")

	sources, registered := m.IsTaintedNeedsOutput("safe-job", "sha")
	if !registered {
		t.Errorf("registered job should return registered=true even for clean output")
	}
	if len(sources) > 0 {
		t.Errorf("clean output should return no sources, got: %v", sources)
	}
}

func TestWorkflowTaintMap_IdempotentRegister(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()
	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})
	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})

	sources, _ := m.IsTaintedNeedsOutput("extract", "pr_title")
	if len(sources) != 1 {
		t.Errorf("idempotent register should not duplicate sources, got: %v", sources)
	}
}

func TestWorkflowTaintMap_RegisterJobOutputs_StepsRef(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	tracker.taintedOutputs["meta"] = map[string][]string{
		"title": {"github.event.pull_request.title"},
	}

	m := NewWorkflowTaintMap()
	outputs := map[string]*ast.Output{
		"pr_title": {
			Name:  &ast.String{Value: "pr_title"},
			Value: &ast.String{Value: "${{ steps.meta.outputs.title }}"},
		},
	}
	m.RegisterJobOutputs("extract", tracker, outputs)

	sources, registered := m.IsTaintedNeedsOutput("extract", "pr_title")
	if !registered {
		t.Fatal("job should be registered after RegisterJobOutputs")
	}
	if len(sources) == 0 {
		t.Fatal("output should be tainted")
	}
	if sources[0] != "github.event.pull_request.title" {
		t.Errorf("got %q, want %q", sources[0], "github.event.pull_request.title")
	}
}

func TestWorkflowTaintMap_RegisterJobOutputs_CleanOutput(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	m := NewWorkflowTaintMap()
	outputs := map[string]*ast.Output{
		"sha": {
			Name:  &ast.String{Value: "sha"},
			Value: &ast.String{Value: "${{ steps.get-sha.outputs.sha }}"},
		},
	}
	m.RegisterJobOutputs("safe-job", tracker, outputs)

	sources, registered := m.IsTaintedNeedsOutput("safe-job", "sha")
	if !registered {
		t.Fatal("job should be registered even for clean outputs")
	}
	if len(sources) > 0 {
		t.Errorf("clean output should have no taint sources, got: %v", sources)
	}
}

func TestWorkflowTaintMap_RegisterJobOutputs_NilOutput(t *testing.T) {
	t.Parallel()

	tracker := NewTaintTracker()
	m := NewWorkflowTaintMap()
	m.RegisterJobOutputs("empty-job", tracker, nil)

	_, registered := m.IsTaintedNeedsOutput("empty-job", "anything")
	if !registered {
		t.Error("job should be registered even with nil outputs")
	}
}

func TestWorkflowTaintMap_MultiHopChain(t *testing.T) {
	t.Parallel()

	// job-A: untrusted → steps output
	trackerA := NewTaintTracker()
	trackerA.taintedOutputs["meta"] = map[string][]string{
		"title": {"github.event.pull_request.title"},
	}

	trackerB := NewTaintTracker()

	m := NewWorkflowTaintMap()

	outputsA := map[string]*ast.Output{
		"pr_title": {
			Name:  &ast.String{Value: "pr_title"},
			Value: &ast.String{Value: "${{ steps.meta.outputs.title }}"},
		},
	}
	m.RegisterJobOutputs("job-a", trackerA, outputsA)

	// job-B references job-A's output
	outputsB := map[string]*ast.Output{
		"processed": {
			Name:  &ast.String{Value: "processed"},
			Value: &ast.String{Value: "${{ needs.job-a.outputs.pr_title }}"},
		},
	}
	m.RegisterJobOutputs("job-b", trackerB, outputsB)

	sources, registered := m.IsTaintedNeedsOutput("job-b", "processed")
	if !registered {
		t.Fatal("job-b should be registered")
	}
	if len(sources) == 0 {
		t.Fatal("multi-hop: job-b.processed should be tainted via job-a")
	}
	if sources[0] != "github.event.pull_request.title" {
		t.Errorf("got source %q, want original source %q", sources[0], "github.event.pull_request.title")
	}
}

func TestWorkflowTaintMap_ResolveFromExprStr_NeedsPattern(t *testing.T) {
	t.Parallel()

	m := NewWorkflowTaintMap()
	m.setJobOutputTaint("extract", "pr_title", []string{"github.event.pull_request.title"})

	tests := []struct {
		name        string
		expr        string
		wantTaint   bool
		wantPending bool
	}{
		{
			name:      "tainted needs reference",
			expr:      "needs.extract.outputs.pr_title",
			wantTaint: true,
		},
		{
			name:      "clean needs reference (registered job, clean output)",
			expr:      "needs.extract.outputs.sha",
			wantTaint: false,
		},
		{
			name:        "unregistered job → pending",
			expr:        "needs.unknown-job.outputs.x",
			wantPending: true,
		},
		{
			name:      "not a needs expression",
			expr:      "steps.foo.outputs.bar",
			wantTaint: false,
		},
		{
			name:      "github context → not needs",
			expr:      "github.event.pull_request.title",
			wantTaint: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sources, pending := m.resolveFromExprStr(tt.expr)
			if tt.wantTaint && len(sources) == 0 {
				t.Errorf("expected taint sources for %q, got none", tt.expr)
			}
			if !tt.wantTaint && len(sources) > 0 {
				t.Errorf("expected no taint sources for %q, got: %v", tt.expr, sources)
			}
			if tt.wantPending != pending {
				t.Errorf("pending=%v, want %v for %q", pending, tt.wantPending, tt.expr)
			}
		})
	}
}

package core

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
	"github.com/sisaku-security/sisakulint/pkg/core/chain"
)

func TestValidateResultHasChainRecords(t *testing.T) {
	var r ValidateResult
	r.ChainRecords = []chain.SinkRecord{{JobID: "build"}}
	if len(r.ChainRecords) != 1 {
		t.Fatal("ChainRecords field missing or wrong type")
	}
}

func TestBuildAssemblerInputTriggersAndPermissions(t *testing.T) {
	wf := &ast.Workflow{
		Name: &ast.String{Value: "CI"},
		On: []ast.Event{
			&ast.WebhookEvent{Hook: &ast.String{Value: "pull_request_target"}, Pos: &ast.Position{Line: 2, Col: 3}},
		},
		Permissions: &ast.Permissions{All: &ast.String{Value: "write-all"}, Pos: &ast.Position{Line: 3, Col: 3}},
		Jobs: map[string]*ast.Job{
			"build": {ID: &ast.String{Value: "build"}, Pos: &ast.Position{Line: 5, Col: 3}},
		},
	}
	records := []chain.SinkRecord{{JobID: "build", StepPos: &ast.Position{Line: 10, Col: 9},
		SourceKind: chain.SourceSecret, SourceName: "secrets.TOKEN", SinkKind: chain.SinkLog, RuleName: "secret-in-log"}}

	in := buildAssemblerInput(".github/workflows/ci.yml", wf, records)

	if in.WorkflowName != "CI" {
		t.Errorf("WorkflowName = %q", in.WorkflowName)
	}
	if len(in.JobContexts) != 1 {
		t.Fatalf("JobContexts len = %d, want 1", len(in.JobContexts))
	}
	jc := in.JobContexts[0]
	if jc.JobID != "build" {
		t.Errorf("JobID = %q", jc.JobID)
	}
	if len(jc.Triggers) != 1 || !jc.Triggers[0].Untrusted {
		t.Errorf("expected 1 untrusted trigger, got %+v", jc.Triggers)
	}
}

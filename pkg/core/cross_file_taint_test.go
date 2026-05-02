package core

import (
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestWorkspaceAdapterAppendError(t *testing.T) {
	res := &ValidateResult{FilePath: "./a.yml"}
	w := &workspaceAdapter{path: "./a.yml", result: res}
	w.AppendError(&LintingError{Description: "x", LineNumber: 1, ColNumber: 2, Type: "test"})
	if len(res.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(res.Errors))
	}
	if res.Errors[0].FilePath != "./a.yml" {
		t.Errorf("FilePath should be set to workspace path, got %q", res.Errors[0].FilePath)
	}
}

func TestWorkspaceAdapterAppendAutoFixer(t *testing.T) {
	res := &ValidateResult{}
	w := &workspaceAdapter{path: "./a.yml", result: res}
	fx := NewFuncFixer("test", func() error { return nil })
	w.AppendAutoFixer(fx)
	if len(res.AutoFixers) != 1 {
		t.Fatalf("expected 1 fixer, got %d", len(res.AutoFixers))
	}
}

func TestFindWorkspace(t *testing.T) {
	ws := []workspaceLike{
		&workspaceAdapter{path: "./a.yml", result: &ValidateResult{}},
		&workspaceAdapter{path: "./b.yml", result: &ValidateResult{}},
	}
	if findWorkspace(ws, "./a.yml") == nil {
		t.Error("expected to find ./a.yml")
	}
	if findWorkspace(ws, "./missing.yml") != nil {
		t.Error("expected nil for missing path")
	}
}

func newProjectStub(t *testing.T) *Project {
	t.Helper()
	// Project's zero-value with a non-nil pointer is enough for
	// IsChainResolutionEnabled. Real Project construction lives in
	// pkg/core/project.go; the chain logic only checks for non-nil.
	return &Project{}
}

func newTestCache(t *testing.T) *LocalReusableWorkflowCache {
	c := NewLocalReusableWorkflowCache(newProjectStub(t), "/cwd", nil)
	return c
}

func TestResolveChainMatch(t *testing.T) {
	c := newTestCache(t)
	c.RecordCallerTaint("./.github/workflows/build.yml", &CallerTaint{
		CallerWorkflowPath:   "./.github/workflows/ci.yml",
		InputName:            "branch",
		UntrustedSources:     []string{"github.event.pull_request.head.ref"},
		Pos:                  &ast.Position{Line: 5, Col: 7},
		HasPrivilegedTrigger: true,
	})
	c.RecordCalleeSink("./.github/workflows/build.yml", &CalleeSink{
		CalleeWorkflowPath: "./.github/workflows/build.yml",
		InputName:          "branch",
		InputPath:          "inputs.branch",
		SinkType:           SinkRun,
		Pos:                &ast.Position{Line: 12, Col: 9},
		Step:               &ast.Step{},
	})
	caller := &workspaceAdapter{path: "./.github/workflows/ci.yml", result: &ValidateResult{}}
	callee := &workspaceAdapter{path: "./.github/workflows/build.yml", result: &ValidateResult{}}
	c.ResolvePendingChains([]workspaceLike{caller, callee})

	if len(caller.result.Errors) != 1 {
		t.Fatalf("caller should have 1 chain error, got %d", len(caller.result.Errors))
	}
	if !strings.Contains(caller.result.Errors[0].Description, "critical") {
		t.Errorf("expected critical severity, got %q", caller.result.Errors[0].Description)
	}
	if len(callee.result.AutoFixers) != 1 {
		t.Errorf("callee should have 1 fixer, got %d", len(callee.result.AutoFixers))
	}
}

func TestResolveCalleeSolo(t *testing.T) {
	c := newTestCache(t)
	c.RecordCalleeSink("./.github/workflows/build.yml", &CalleeSink{
		CalleeWorkflowPath: "./.github/workflows/build.yml",
		InputName:          "branch",
		SinkType:           SinkRun,
		Pos:                &ast.Position{Line: 12, Col: 9},
		Step:               &ast.Step{},
	})
	callee := &workspaceAdapter{path: "./.github/workflows/build.yml", result: &ValidateResult{}}
	c.ResolvePendingChains([]workspaceLike{callee})

	if len(callee.result.Errors) != 1 {
		t.Fatalf("callee solo should produce 1 error, got %d", len(callee.result.Errors))
	}
	if !strings.Contains(callee.result.Errors[0].Description, "medium") {
		t.Errorf("expected medium severity, got %q", callee.result.Errors[0].Description)
	}
}

func TestResolveCallerWithoutSinkProducesNothing(t *testing.T) {
	c := newTestCache(t)
	c.RecordCallerTaint("./.github/workflows/build.yml", &CallerTaint{
		InputName: "branch", Pos: &ast.Position{Line: 1, Col: 1},
	})
	caller := &workspaceAdapter{path: "./.github/workflows/ci.yml", result: &ValidateResult{}}
	c.ResolvePendingChains([]workspaceLike{caller})
	if len(caller.result.Errors) != 0 {
		t.Errorf("expected no errors, got %d", len(caller.result.Errors))
	}
}

func TestResolveDedupChainKey(t *testing.T) {
	c := newTestCache(t)
	for i := 0; i < 3; i++ {
		c.RecordCallerTaint("./b.yml", &CallerTaint{
			InputName: "x", Pos: &ast.Position{Line: 1, Col: 1},
			CallerWorkflowPath: "./a.yml",
		})
	}
	for i := 0; i < 3; i++ {
		c.RecordCalleeSink("./b.yml", &CalleeSink{
			InputName: "x", Pos: &ast.Position{Line: 5, Col: 5},
			CalleeWorkflowPath: "./b.yml", Step: &ast.Step{},
		})
	}
	caller := &workspaceAdapter{path: "./a.yml", result: &ValidateResult{}}
	callee := &workspaceAdapter{path: "./b.yml", result: &ValidateResult{}}
	c.ResolvePendingChains([]workspaceLike{caller, callee})
	if len(caller.result.Errors) != 1 {
		t.Errorf("expected 1 deduped error, got %d", len(caller.result.Errors))
	}
}

func TestResolveTwoCallerFilesAtSamePosNotDeduped(t *testing.T) {
	c := newTestCache(t)
	for _, callerPath := range []string{"./a.yml", "./b.yml"} {
		c.RecordCallerTaint("./shared.yml", &CallerTaint{
			CallerWorkflowPath:   callerPath,
			InputName:            "x",
			Pos:                  &ast.Position{Line: 5, Col: 7},
			HasPrivilegedTrigger: true,
		})
	}
	c.RecordCalleeSink("./shared.yml", &CalleeSink{
		CalleeWorkflowPath: "./shared.yml",
		InputName:          "x",
		SinkType:           SinkRun,
		Pos:                &ast.Position{Line: 12, Col: 9},
		Step:               &ast.Step{},
	})
	a := &workspaceAdapter{path: "./a.yml", result: &ValidateResult{}}
	b := &workspaceAdapter{path: "./b.yml", result: &ValidateResult{}}
	callee := &workspaceAdapter{path: "./shared.yml", result: &ValidateResult{}}
	c.ResolvePendingChains([]workspaceLike{a, b, callee})

	if len(a.result.Errors) != 1 {
		t.Errorf("caller a should have 1 error, got %d", len(a.result.Errors))
	}
	if len(b.result.Errors) != 1 {
		t.Errorf("caller b should have 1 error, got %d", len(b.result.Errors))
	}
}

func TestResolveSkipsEntriesWithNilPos(t *testing.T) {
	c := newTestCache(t)
	c.RecordCallerTaint("./b.yml", &CallerTaint{
		CallerWorkflowPath: "./a.yml",
		InputName:          "x",
		Pos:                nil, // would panic without guard
	})
	c.RecordCalleeSink("./b.yml", &CalleeSink{
		CalleeWorkflowPath: "./b.yml",
		InputName:          "x",
		Pos:                nil,
		Step:               &ast.Step{},
	})
	a := &workspaceAdapter{path: "./a.yml", result: &ValidateResult{}}
	callee := &workspaceAdapter{path: "./b.yml", result: &ValidateResult{}}
	// Must not panic; should produce zero warnings (nothing valid to emit).
	c.ResolvePendingChains([]workspaceLike{a, callee})
	if len(a.result.Errors)+len(callee.result.Errors) != 0 {
		t.Errorf("expected no errors when Pos missing, got a=%d callee=%d",
			len(a.result.Errors), len(callee.result.Errors))
	}
}

func TestEnvVarNameFor(t *testing.T) {
	cases := map[string]string{
		"":            "UNTRUSTED_INPUT",
		"branch":      "INPUT_BRANCH",
		"branch-name": "INPUT_BRANCH_NAME",
		"cfg.path":    "INPUT_CFG_PATH",
	}
	for in, want := range cases {
		if got := envVarNameFor(in); got != want {
			t.Errorf("envVarNameFor(%q) = %q, want %q", in, got, want)
		}
	}
}

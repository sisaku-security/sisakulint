package core

import "testing"

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

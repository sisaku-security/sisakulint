package core

// workspaceLike is the minimal contract ResolvePendingChains needs to
// inject post-Wait errors and fixers into per-file results.
type workspaceLike interface {
	Path() string
	AppendError(err *LintingError)
	AppendAutoFixer(fx AutoFixer)
}

// workspaceAdapter wraps the linter's anonymous workspace struct.
type workspaceAdapter struct {
	path   string
	result *ValidateResult
}

func (w *workspaceAdapter) Path() string { return w.path }

func (w *workspaceAdapter) AppendError(err *LintingError) {
	if w.result == nil || err == nil {
		return
	}
	if err.FilePath == "" {
		err.FilePath = w.path
	}
	w.result.Errors = append(w.result.Errors, err)
}

func (w *workspaceAdapter) AppendAutoFixer(fx AutoFixer) {
	if w.result == nil || fx == nil {
		return
	}
	w.result.AutoFixers = append(w.result.AutoFixers, fx)
}

// findWorkspace returns the adapter whose path matches normPath, or nil.
// Comparison uses exact string match — callers must normalize paths
// upstream (e.g. via PathToWorkflowSpecification or filepath.Clean).
func findWorkspace(ws []workspaceLike, normPath string) workspaceLike {
	for _, w := range ws {
		if w.Path() == normPath {
			return w
		}
	}
	return nil
}

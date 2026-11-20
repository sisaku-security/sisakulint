package job

import (
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// Ancestors are the jobs of w that j depends on through needs, directly or
// through other jobs, each once by its ID, whatever their ifs; not j.
func Ancestors(w *workflow.Workflow, j *workflow.Job) []workflow.Job {
	return workflow.NeedClosure(w, j, func(*workflow.Job) bool { return true })[1:]
}

// ByName are the jobs of w by expr.FoldName of their IDs, the first of
// each name, as workflow.Map.Lookup finds them; none with no w.
func ByName(w *workflow.Workflow) map[string]workflow.Job {
	out := map[string]workflow.Job{}
	if w == nil || w.Jobs.Status != workflow.Present {
		return out
	}
	for _, e := range w.Jobs.Value.Entries {
		k := expr.FoldName(e.Key.AsString())
		if _, ok := out[k]; !ok && e.Value.Status == workflow.Present {
			out[k] = e.Value.Value
		}
	}
	return out
}

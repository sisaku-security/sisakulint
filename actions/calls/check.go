package calls

import (
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// Diagnostics are what GitHub's reader rejects of the jobs among files
// that call a workflow among them (workflow.CheckCall), by the caller.
// Only a job's ./… and $/… are read, which name the caller's commit: a
// call of another repository's workflow, or of a file that is not among
// files or is not a workflow, is not checked. Unlike Graph, a call of a
// workflow without workflow_call is kept, since that is one of the
// checks.
func Diagnostics(files []File) map[facts.InputPath][]workflow.Diagnostic {
	byName := map[facts.InputPath]*workflow.Workflow{}
	for _, f := range files {
		if f.Workflow != nil {
			byName[f.Name] = f.Workflow
		}
	}
	out := map[facts.InputPath][]workflow.Diagnostic{}
	for _, f := range files {
		w := f.Workflow
		if w == nil || w.Jobs.Status != workflow.Present {
			continue
		}
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present || je.Value.Value.Kind != workflow.JobCall {
				continue
			}
			j := je.Value.Value
			target, ok := localTarget(j.Uses)
			if !ok {
				continue
			}
			n, err := facts.CleanInputPath(target)
			if err != nil {
				continue
			}
			called, ok := byName[n]
			if !ok {
				continue
			}
			if ds := workflow.CheckCall(j, called); len(ds) > 0 {
				out[f.Name] = append(out[f.Name], ds...)
			}
		}
	}
	return out
}

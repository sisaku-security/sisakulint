package job

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// CalledOnly is whether w has no event of its own but workflow_call: only
// a caller runs it, whose token it gets no more than
// (https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations),
// or nothing does (on: {} or no on, which GitHub refuses to run).
func CalledOnly(w *workflow.Workflow) bool {
	switch w.On.Status {
	case workflow.Absent:
		return true // GitHub runs nothing without on; the model reports it
	case workflow.Present:
	default:
		return false
	}
	for _, e := range w.On.Value.Events {
		if n, err := workflow.ParseEventName(e.Name.AsString()); err != nil || n != workflow.EventNameWorkflowCall {
			return false
		}
	}
	return true
}

// calledOf is where the reusable workflow the job j calls is, and
// owner/name for one named by it. A uses the model rejects is none: GitHub
// does not run the workflow.
func calledOf(j workflow.Job) (analysis.CalledWorkflowKind, facts.Repo) {
	if j.Uses.Status != workflow.Present {
		return analysis.CalledWorkflowKindNone, facts.Repo{}
	}
	u := j.Uses.Value
	k := u.Kind
	if k == workflow.UsesFolded {
		k = u.Folded // GitHub folds a literal ${{ }} and calls what it is
	}
	switch k {
	case workflow.UsesLocal, workflow.UsesSelf:
		return analysis.CalledWorkflowKindLocal, facts.Repo{}
	case workflow.UsesRemote:
		r, _ := facts.ParseRepo(u.Owner.Text + "/" + u.Repo.Text)
		return analysis.CalledWorkflowKindRemote, r
	}
	return analysis.CalledWorkflowKindNone, facts.Repo{}
}

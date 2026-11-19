package attacker

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// PlacedIf is an if with the place it stands in: the if of a step, or the
// if of a job with the jobs that the job depends on directly through needs
// (Need, as JobCodeTruth reads them in JobStateUnknown). The if of a job
// reads the needs context; the if of a step does not. StepIf, JobIf and
// JobIfs make it.
type PlacedIf struct {
	c   workflow.Field[workflow.If]
	job *jobIf // nil for the if of a step
}

// StepIf is the if c of a step.
func StepIf(c workflow.Field[workflow.If]) PlacedIf { return PlacedIf{c: c} }

// JobIf is the if of the job j of w, with the jobs of w that j depends on
// directly. A need that names no job is left out: GitHub does not accept
// the workflow. With no w, the jobs that j depends on are not known, and
// the if of j is read as the if of a step: an empty needs.*.result would
// read contains(needs.*.result, 'success') as false.
func JobIf(w *workflow.Workflow, j *workflow.Job) PlacedIf {
	if w == nil {
		return StepIf(j.If)
	}
	out := PlacedIf{c: j.If, job: &jobIf{}}
	if j.Needs.Status != workflow.Present || w.Jobs.Status != workflow.Present {
		return out
	}
	for _, n := range j.Needs.Value.Items {
		if e, ok := w.Jobs.Value.Lookup(n.AsString()); ok && e.Value.Status == workflow.Present {
			out.job.needs = append(out.job.needs, Need{Job: e.Value.Value})
		}
	}
	return out
}

// NeedJobs are the jobs of w whose ifs a run of the job j goes through: j,
// and, while the if of a job is true only when success() is true
// (TrueOnlyOnSuccess), the jobs it depends on through needs, as GitHub
// skips such a job when a job it depends on is skipped or fails
// (https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/data/reusables/actions/jobs/section-using-jobs-in-a-workflow-needs.md).
// Each job once by its ID, j first; j alone with no w.
func NeedJobs(w *workflow.Workflow, j *workflow.Job) []workflow.Job {
	return workflow.NeedClosure(w, j, func(j *workflow.Job) bool { return TrueOnlyOnSuccess(j.If) })
}

// JobIfs are the ifs of the jobs NeedJobs, each a JobIf.
func JobIfs(w *workflow.Workflow, j *workflow.Job) []PlacedIf {
	jobs := NeedJobs(w, j)
	out := make([]PlacedIf, len(jobs))
	for i := range jobs {
		out[i] = JobIf(w, &jobs[i])
	}
	return out
}

// truth is what p is in a run of e with the values of lookup and of
// override (truthWith); the if of a job also reads needs.<id>.result and
// needs.*.result of the jobs it depends on directly, as JobCodeTruth reads
// them in JobStateUnknown.
func (p PlacedIf) truth(e analysis.EventActivity, lookup func([]expr.PathElem) (expr.Value, bool), override func(expr.Node) (expr.Value, bool)) expr.Truth {
	if p.job != nil {
		lookup = withNeeds(lookup, p.c, p.job, JobStateUnknown)
		override = overrides(override, p.job.starOverride(p.c))
	}
	return truthWith(p.c, e, lookup, override)
}

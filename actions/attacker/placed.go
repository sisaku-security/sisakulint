package attacker

import (
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// PlacedIf is an if with the place it stands in: the if of a step, with
// the jobs that the job of the step depends on directly through needs when
// every one of them succeeded in each run of the step (StepIf), or the if
// of a job with the jobs that the job depends on directly (Need, as
// JobCodeTruth reads them in JobStateUnknown). The if of a job of a
// workflow (JobIf) is also false in a run in which every job that the job
// depends on through needs is skipped and the if is false there
// (afterSkipped). StepIf, JobIf and JobIfs make it.
type PlacedIf struct {
	c   workflow.Field[workflow.If]
	job *jobIf // nil for an if that does not read the needs context
}

// StepIf is the if c of a step of the job j of w. GitHub runs a job whose
// if is true only when success() is true (TrueOnlyOnSuccess) only after
// every job that the job depends on directly succeeded
// (https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/data/reusables/actions/jobs/section-using-jobs-in-a-workflow-needs.md),
// and those jobs have completed before the job starts, so in the if of each
// step of such a job needs.<id>.result of each of those jobs is success,
// and needs.*.result is an array of success, one for each of those jobs,
// whatever the JobState of the step. The if of a step of any other job
// does not read needs, nor does the if of a step of an action (no j: an
// action does not read the needs context of the job) or of a job whose
// workflow is not known (no w).
func StepIf(w *workflow.Workflow, j *workflow.Job, c workflow.Field[workflow.If]) PlacedIf {
	if w == nil || j == nil || !TrueOnlyOnSuccess(j.If) {
		return PlacedIf{c: c}
	}
	return PlacedIf{c: c, job: &jobIf{needs: JobIf(w, j).job.needs, succeeded: true}}
}

// JobIf is the if of the job j of w, with the jobs of w that j depends on
// directly, and w and j, for the jobs that j depends on through needs
// (afterSkipped). A need that names no job is left out: GitHub does not
// accept the workflow. With no w, the jobs that j depends on are not known,
// and the if of j does not read the needs context (as StepIf with no w): an
// empty needs.*.result would read contains(needs.*.result, 'success') as
// false.
func JobIf(w *workflow.Workflow, j *workflow.Job) PlacedIf {
	if w == nil {
		return PlacedIf{c: j.If}
	}
	out := PlacedIf{c: j.If, job: &jobIf{w: w, self: j}}
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

// truth is what p is in a run of the run event r with the values of lookup
// and of override (truthWith), reading the needs context as needsIn reads
// it in JobStateUnknown; the if of a job also reads the jobs that the job
// depends on as far as r is known (afterSkipped).
func (p PlacedIf) truth(r runEvent, lookup func([]expr.PathElem) (expr.Value, bool), override func(expr.Node) (expr.Value, bool)) expr.Truth {
	if p.job.afterSkipped(p.c, r, lookup, override) {
		return expr.TruthFalse
	}
	return p.plainTruth(lookup, override)
}

// plainTruth is truth without afterSkipped.
func (p PlacedIf) plainTruth(lookup func([]expr.PathElem) (expr.Value, bool), override func(expr.Node) (expr.Value, bool)) expr.Truth {
	lookup, extra := p.needsIn(lookup, JobStateUnknown)
	return truthWith(p.c, lookup, overrides(override, extra))
}

// needsIn is lookup that also knows needs.<id>.result of the jobs that p
// reads, and the value of needs.*.result, in a job of the state s: in the
// if of a step that reads them (StepIf), every one of those jobs succeeded,
// whatever s is; in the if of a job, as JobCodeTruth reads them.
func (p PlacedIf) needsIn(lookup func([]expr.PathElem) (expr.Value, bool), s JobState) (func([]expr.PathElem) (expr.Value, bool), func(expr.Node) (expr.Value, bool)) {
	if p.job == nil {
		return lookup, nil
	}
	succeeded := p.job.succeeded || TrueOnlyOnSuccess(p.c)
	return withNeeds(lookup, succeeded, p.job, s), p.job.starOverride(succeeded)
}

// truthIn is truthIn of p in a job of the state s, with the values of
// lookup and the needs context as needsIn reads it.
func (p PlacedIf) truthIn(lookup func([]expr.PathElem) (expr.Value, bool), s JobState) expr.Truth {
	lookup, extra := p.needsIn(lookup, s)
	return truthIn(p.c, lookup, s, extra)
}

package attacker

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// JobState is what is known of the job when the if of a step of the job is
// read: the status functions read GitHub's job.status
// (https://github.com/actions/runner/blob/v2.337.0/src/Runner.Worker/Expressions/FailureFunction.cs
// and its siblings). In a step of a composite action they read
// github.action_status, which JobState does not tell. The if of a job is
// read only in JobStateSucceeded and JobStateFailed, where the status
// functions of the if of the job read the jobs that the job depends on
// through needs: no JobState tells a job that the job depends on and that
// was skipped while none failed. The truth of the if of a job of a workflow
// (JobIf) reads such a run when it is in every run of the event: every job
// that the job depends on is skipped (afterSkipped).
type JobState uint8

const (
	// JobStateUnknown is that the state is not known: no status function
	// is known, as Table reads every if.
	JobStateUnknown JobState = iota
	// JobStateFailed is that a step before failed without
	// continue-on-error, and the run is not cancelled: job.status is
	// failure, so success() and cancelled() are false, and failure() and
	// always() true. For the if of a job, JobStateFailed is that a job that
	// the job depends on through needs, directly or through other jobs,
	// failed, and the run is not cancelled.
	JobStateFailed
	// JobStateCancelled is that the run is cancelled: job.status is
	// cancelled, so success() and failure() are false, and cancelled()
	// and always() true.
	JobStateCancelled
	// JobStateSucceeded is that no step before failed without
	// continue-on-error, and the run is not cancelled: job.status is
	// success, so success() and always() are true, and failure() and
	// cancelled() false. For the if of a job, JobStateSucceeded is that
	// every job that the job depends on through needs, directly or through
	// other jobs, succeeded, and the run is not cancelled; a job whose
	// continue-on-error is true and that failed counts as one that
	// succeeded (observed on 2026-11-16: its needs.<id>.result is success,
	// and a job that needs it with no status function in its if runs).
	JobStateSucceeded
)

var jobStateNames = [...]string{"unknown", "failed", "cancelled", "succeeded"}

func (s JobState) String() string { return jobStateNames[s] }

// status is whether the status function f is true in a job of the state
// s, which is not JobStateUnknown.
func (s JobState) status(f analysis.StatusFunction) bool {
	switch f {
	case analysis.StatusFunctionAlways:
		return true
	case analysis.StatusFunctionFailure:
		return s == JobStateFailed
	case analysis.StatusFunctionCancelled:
		return s == JobStateCancelled
	}
	return s == JobStateSucceeded // success()
}

// jobStatus is the value of job.status in a job of the state s: the
// status that the status functions read
// (https://github.com/actions/runner/blob/v2.337.0/src/Runner.Worker/JobContext.cs);
// none when s is JobStateUnknown.
func (s JobState) jobStatus() (string, bool) {
	switch s {
	case JobStateSucceeded:
		return "success", true
	case JobStateFailed:
		return "failure", true
	case JobStateCancelled:
		return "cancelled", true
	}
	return "", false
}

// CodeTruth is what the if p is in the runs of e that bring the
// attacker's code (the runs of KeptCode), in a job of the state s: true
// or false when p is so in every run, else not known; false when e has
// no such run (a review, whose pull request is from a branch of the
// repository). It reads p in its IfTree; the if of a job reads needs as
// JobCodeTruth reads them, with no job of needs that SurelyRuns or Fails.
func (t Table) CodeTruth(p PlacedIf, e analysis.EventActivity, s JobState) expr.Truth {
	return t.codeTruth(p, e, s)
}

func (t Table) codeTruth(p PlacedIf, e analysis.EventActivity, s JobState) expr.Truth {
	if objects[e.Name()].branchHead {
		return expr.TruthFalse
	}
	if len(Runs(e)) == 0 {
		return p.truthIn(eventLookup(e), s)
	}
	runs := slices.DeleteFunc(t.runs(e), func(k RunKind) bool { return k == RunBaseBranch })
	return truthOverRuns(runs, func(k RunKind) expr.Truth {
		return p.truthIn(t.lookupFor(e, k), s)
	})
}

// RunTruth is CodeTruth in every run of e that the attacker starts (the
// runs of Kept).
func (t Table) RunTruth(p PlacedIf, e analysis.EventActivity, s JobState) expr.Truth {
	if len(Runs(e)) == 0 {
		return p.truthIn(eventLookup(e), s)
	}
	return truthOverRuns(t.runs(e), func(k RunKind) expr.Truth {
		return p.truthIn(t.lookupFor(e, k), s)
	})
}

// ActorTruth is CodeTruth in the runs of e that the attacker triggers as
// their actor (the runs of KeptActor).
func (t Table) ActorTruth(p PlacedIf, e analysis.EventActivity, s JobState) expr.Truth {
	return truthOverRuns(t.actorRuns(e), func(k RunKind) expr.Truth {
		return p.truthIn(lookupRows(e, t.rowsOf(e, k, true)), s)
	})
}

// Need is a job that a job depends on directly through needs, as the if
// of the job reads it: SurelyRuns is that the job runs in the run, so the
// job is not skipped; Fails is that the job fails in the run, on the pull
// request of the attacker or as the attacker makes it fail.
type Need struct {
	Job        workflow.Job
	Fails      bool
	SurelyRuns bool
}

// JobCodeTruth is CodeTruth for the if c of a job whose direct needs are
// needs (none when the job has no needs). The needs context has the jobs
// that the job depends on directly
// (https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/content/actions/reference/workflows-and-actions/contexts.md,
// needs context).
//
// An if that calls no status function is read only when every job that its
// job depends on directly succeeded, as GitHub skips the job otherwise
// (https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/content/actions/reference/workflows-and-actions/expressions.md,
// status check functions); an if that is true only when success() is true
// (TrueOnlyOnSuccess, success() && X for one) is false otherwise. In such an
// if, needs.<id>.result of each job of needs is success, and needs.*.result
// is success for each job of needs, whether the job surely runs or not; a
// job whose continue-on-error is true and that failed has the result success
// too (observed on 2026-11-16).
//
// Any other if may be true after a job of needs is skipped, which no
// JobState tells: in JobStateSucceeded, which for the if
// of a job is that every job it depends on succeeded, needs.<id>.result is
// success for a job of needs that SurelyRuns; in JobStateFailed, it is
// failure for a job of needs that Fails; needs.*.result is not known.
// JobCodeTruth is given no workflow, so it does not read a run in which
// every job that the job depends on is skipped; the truth of the if that
// JobIf makes reads that run (afterSkipped).
//
// The if of a step (StepIf) is read by CodeTruth, which reads needs for it
// from the if of its job, not from its JobState: in a job whose if is
// always(), a step reads JobStateSucceeded after a job it depends on
// failed; in a job whose if is true only when success() is true, every job
// that the job depends on directly succeeded, in each JobState of the step.
func (t Table) JobCodeTruth(c workflow.Field[workflow.If], needs []Need, e analysis.EventActivity, s JobState) expr.Truth {
	return t.codeTruth(PlacedIf{c: c, job: &jobIf{needs: needs}}, e, s)
}

// JobActorTruth is ActorTruth for the if c of a job whose direct needs are
// needs, read as JobCodeTruth reads them.
func (t Table) JobActorTruth(c workflow.Field[workflow.If], needs []Need, e analysis.EventActivity, s JobState) expr.Truth {
	return t.ActorTruth(PlacedIf{c: c, job: &jobIf{needs: needs}}, e, s)
}

// jobIf is the needs context of an if: the jobs that the job of the if
// depends on directly, as JobCodeTruth reads them. succeeded is that every
// one of those jobs succeeded in each run in which the if is read: StepIf
// sets it for the if of a step of a job whose if is true only when
// success() is true. JobIf also sets w and self, the workflow and the job,
// for the jobs that the job depends on through needs (afterSkipped);
// JobCodeTruth, JobActorTruth and StepIf leave them nil, so afterSkipped
// does not read their ifs. A nil *jobIf is an if that does not read needs.
type jobIf struct {
	needs     []Need
	succeeded bool
	w         *workflow.Workflow
	self      *workflow.Job
}

// withNeeds is lookup that also knows needs.<id>.result of the jobs that
// the job of j depends on, in the state s, as JobCodeTruth reads them:
// success for each when succeeded (every one of them succeeded in each run
// in which the if is read).
func withNeeds(lookup func([]expr.PathElem) (expr.Value, bool), succeeded bool, j *jobIf, s JobState) func([]expr.PathElem) (expr.Value, bool) {
	if j == nil || len(j.needs) == 0 {
		return lookup
	}
	return func(p []expr.PathElem) (expr.Value, bool) {
		if len(p) == 3 && expr.HasPrefix(p, "needs") && p[1].Name != "" && expr.EqualName(p[2].Name, "result") {
			for _, n := range j.needs {
				if !expr.EqualName(n.Job.ID.AsString(), p[1].Name) {
					continue
				}
				switch {
				case succeeded, s == JobStateSucceeded && n.SurelyRuns:
					return expr.String("success"), true
				case s == JobStateFailed && n.Fails:
					return expr.String("failure"), true
				}
			}
		}
		return lookup(p)
	}
}

// starOverride reads needs.*.result in an if with the needs context j as
// JobCodeTruth reads it: when succeeded (every job that the job depends on
// directly succeeded in each run in which the if is read), an array of
// success, one for each of those jobs; else none.
func (j *jobIf) starOverride(succeeded bool) func(expr.Node) (expr.Value, bool) {
	if j == nil || !succeeded {
		return nil
	}
	return func(n expr.Node) (expr.Value, bool) {
		if _, ok := n.(*expr.Property); !ok {
			return expr.Value{}, false
		}
		p, ok := expr.AccessPath(n)
		if !ok || len(p) != 3 || !expr.HasPrefix(p, "needs") || !p[1].Star || p[2].Name == "" || !expr.EqualName(p[2].Name, "result") {
			return expr.Value{}, false
		}
		results := make([]expr.Value, len(j.needs))
		for i := range results {
			results[i] = expr.String("success")
		}
		return expr.Array(results...), true
	}
}

// overrides is the value of a node that a gives, else the one that b
// gives.
func overrides(a, b func(expr.Node) (expr.Value, bool)) func(expr.Node) (expr.Value, bool) {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	return func(n expr.Node) (expr.Value, bool) {
		if v, ok := a(n); ok {
			return v, true
		}
		return b(n)
	}
}

// truthOverRuns is true or false when truth is so for every run of runs, else
// not known; false for no run.
func truthOverRuns(runs []RunKind, truth func(RunKind) expr.Truth) expr.Truth {
	if len(runs) == 0 {
		return expr.TruthFalse
	}
	out := truth(runs[0])
	for _, k := range runs[1:] {
		if truth(k) != out {
			return expr.TruthUnknown
		}
	}
	return out
}

// truthIn is what the if c is with the values of lookup, in a job of the
// state s. After a failure or a cancel, an if that calls no status function
// is false, as success() && is added, and no if is false too. Otherwise, no
// if is true, and a mixed if is true, as a mixed if is a string that is not
// empty; an empty if is success(), true in a job that succeeded. In a job
// whose state is known, job.status is the status of the state. extra gives
// the values of other nodes (needs.*.result in the if of a job).
func truthIn(c workflow.Field[workflow.If], lookup func([]expr.PathElem) (expr.Value, bool), s JobState, extra func(expr.Node) (expr.Value, bool)) expr.Truth {
	if status, ok := s.jobStatus(); ok {
		lookup = withJobStatus(lookup, status)
	}
	if (s == JobStateFailed || s == JobStateCancelled) && !HasStatusFunction(c) {
		return expr.TruthFalse
	}
	switch {
	case c.Status != workflow.Present:
		return expr.TruthTrue
	case c.Value.Form == workflow.IfMixed:
		return expr.TruthTrue
	case c.Value.Form == workflow.IfEmpty && s == JobStateSucceeded:
		return expr.TruthTrue
	}
	tree, ok := IfTree(c)
	if !ok {
		return expr.TruthUnknown // empty (success()), or the string of ${{ 'x' }} that does not parse
	}
	var override func(expr.Node) (expr.Value, bool)
	if s != JobStateUnknown {
		values := map[analysis.StatusFunction]bool{}
		for _, f := range []analysis.StatusFunction{analysis.StatusFunctionAlways, analysis.StatusFunctionFailure, analysis.StatusFunctionCancelled, analysis.StatusFunctionSuccess} {
			values[f] = s.status(f)
		}
		override = statusValues(values)
	}
	return expr.PartialWith(tree, lookup, overrides(override, extra)).Truthy()
}

// withJobStatus is lookup that also knows job.status, as status.
func withJobStatus(lookup func([]expr.PathElem) (expr.Value, bool), status string) func([]expr.PathElem) (expr.Value, bool) {
	return func(p []expr.PathElem) (expr.Value, bool) {
		if len(p) == 2 && expr.HasPrefix(p, "job", "status") {
			return expr.String(status), true
		}
		return lookup(p)
	}
}

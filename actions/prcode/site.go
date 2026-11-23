package prcode

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// CodeRunStep is a step after a checkout that runs what it brings.
type CodeRunStep struct {
	Step workflow.Step
	Name string     // the step's name, else steps[<n>]
	Text string     // the command or the uses, as written
	Span shell.Span // of the command in the run; zero for a uses
	Cite Cite       // why the row of the table runs code of the tree
	// Asynchronous is that the script runs the command in a list ended by
	// & (shell.ExecutionEnvironmentAsynchronous): the command runs, and the
	// exit code of the step depends on the exit code of the command only
	// when the script waits for the command (wait). shell.Walk reads the
	// body of a function where the function is defined, so the command of
	// a function that the script calls with & is not marked, and neither is
	// the command of a coproc or of a script that is not a shell script.
	Asynchronous bool
}

// Cite is the https URL of what a row of a table rests on.
type Cite struct{ url string }

func (c Cite) String() string { return c.url }

// CheckoutSite is a step that uses actions/checkout, and what the rules read of it.
type CheckoutSite struct {
	Step workflow.Step
	Job  *workflow.Job // nil in an action.yml
	Path facts.StepPath
	Uses workflow.Uses

	CheckoutCode analysis.CheckoutCode
	// Refs are the references that make CheckoutCode CodePR, the repository's
	// first; Fork is whether the repository is the fork, and NoRef whether
	// no ref is given (then the fork's default branch is brought).
	Refs  []CheckoutRef
	Fork  bool
	NoRef bool
	// InconclusiveValues are the values the tables cannot tell (the whole with, a ref
	// or a repository); Dynamic is whether with is a whole ${{ }}.
	InconclusiveValues []workflow.String
	Dynamic            bool

	PRCodeOn []analysis.EventActivity // the privileged events the step can run on
	// DispatchOn is the runs of workflow_dispatch the step can run on, and
	// DispatchInput whether its ref or repository refers to an input of
	// workflow_dispatch; CallFromPR is whether the input is also the
	// caller's on a call from an event of PRCodeOn.
	DispatchOn    []analysis.EventActivity
	DispatchInput bool
	CallFromPR    bool
	Guard         analysis.Guard
	SHA           facts.SHA // when GuardSHA

	Approval    analysis.Approval
	Environment facts.EnvironmentName // when ApprovalEnvironment
	// Placement is where it puts the tree, and Placed whether it puts it:
	// false when the checkout fails on its path (CheckoutPlacement), and
	// then it brings nothing to run or to save.
	Placement    Placement
	Placed       bool
	CodeRunSteps []CodeRunStep   // the steps after it that run what it brings
	CacheSaves   []CacheSaveStep // the steps that save what it brings to the cache
	// Unanswered are the uses of the steps that may save what it brings to
	// the cache, as CacheSaves reads them, that --online could not answer
	Unanswered []UnansweredCall
}

// Mutable is whether what s brings can move after the event: a ref GitHub
// or the author moves, or the fork's default branch.
func (s CheckoutSite) Mutable() bool {
	commit := false
	for _, r := range s.Refs {
		if r.Mutable {
			return true
		}
		commit = commit || r.Input == analysis.CheckoutInputRef
	}
	return s.Fork && !commit // a fork's branch, whatever the ref names but a commit
}

// Split is s.Events split into those the guard of actions/checkout covers
// (pull_request_target, workflow_run) and the rest.
func (s CheckoutSite) Split() (guarded, open []analysis.EventActivity) {
	for _, e := range s.PRCodeOn {
		if analysis.Guarded(e) {
			guarded = append(guarded, e)
		} else {
			open = append(open, e)
		}
	}
	return guarded, open
}

// Analyze is the checkout steps of w, or of the composite steps of a, each
// with the privileged events it can run on and the code it brings.
func Analyze(w *workflow.Workflow, a *workflow.ActionMetadata) []CheckoutSite {
	return AnalyzeWith(w, a, nil)
}

// AnalyzeWith is Analyze, which reads each script of a run with m, once for
// every analysis that reads it (a nil m reads each time).
func AnalyzeWith(w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo) []CheckoutSite {
	return AnalyzeIn(nil, calls.Node{}, w, a, m)
}

// AnalyzeIn is AnalyzeWith, with the events of the input name, when it is
// called, read from its callers c (a nil c reads none).
func AnalyzeIn(c *taint.Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo) []CheckoutSite {
	return AnalyzeComposite(c, name, w, a, m, nil)
}

// AnalyzeComposite is AnalyzeIn, which also reads the steps of the
// composite actions the steps run with inner (CacheSaveStep.Via) and the
// uses on the way with no answer (CheckoutSite.Unanswered).
func AnalyzeComposite(c *taint.Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo, inner Inner) []CheckoutSite {
	var out []CheckoutSite
	if w != nil {
		evs := c.EventsOr(name, prCodeEvents, true, func() []analysis.EventActivity { return taint.EventsOf(w, prCodeEvents) })
		for _, je := range w.Jobs.Value.Entries {
			j := je.Value.Value
			jobIfs := attacker.JobIfs(w, &j)
			jobEvs := taint.FilterCode(c.Table(), evs, jobIfs...)
			steps := j.Steps.Value.Items
			order, caches := workflow.OrderOf(steps), cacheSteps(steps, inner)
			for _, s := range steps {
				if s.Uses.Status != workflow.Present || !calls.IsCheckout(s.Uses.Value) {
					continue
				}
				path, err := stepPath(&j, s)
				if err != nil {
					continue // a job id the model reports as invalid
				}
				site := CheckoutSite{Step: s, Job: &j, Path: path, Uses: s.Uses.Value, PRCodeOn: taint.FilterCode(c.Table(), jobEvs, attacker.StepIf(w, &j, s.If))}
				site.DispatchOn, site.DispatchInput = dispatchOn(c.Table(), name, w, append(slices.Clone(jobIfs), attacker.StepIf(w, &j, s.If))...), checkoutDispatchInput(w, s.With)
				if _, remote := name.Remote(); remote {
					site.DispatchInput = false // its own workflow_dispatch starts runs in its repository
				}
				site.CallFromPR = callFromPR(w, site.DispatchInput, site.PRCodeOn)
				site.read()
				site.approval()
				site.evidence(w, steps, order, caches, m)
				out = append(out, site)
			}
		}
	}
	if a != nil && a.Runs.Status == workflow.Present && a.Runs.Value.Kind == workflow.RunsComposite {
		evs := c.EventsOr(name, prCodeEvents, true, func() []analysis.EventActivity { return taint.EventsAll(prCodeEvents) })
		steps := a.Runs.Value.Steps.Value.Items
		order, caches := workflow.OrderOf(steps), cacheSteps(steps, inner)
		for _, s := range steps {
			if s.Uses.Status != workflow.Present || !calls.IsCheckout(s.Uses.Value) {
				continue
			}
			path, _ := stepPath(nil, s)
			site := CheckoutSite{Step: s, Path: path, Uses: s.Uses.Value, PRCodeOn: taint.FilterCode(c.Table(), evs, attacker.StepIf(nil, nil, s.If))}
			site.read()
			site.approval()
			site.evidence(nil, steps, order, caches, m)
			out = append(out, site)
		}
	}
	return out
}

// stepPath is where s is, as a file of facts names it: a step of job, or
// of the runs of an action when job is nil.
func stepPath(job *workflow.Job, s workflow.Step) (facts.StepPath, error) {
	if job == nil {
		return facts.ActionStep(s.Place.Steps)
	}
	if k, ok := s.Place.Parallel(); ok {
		return facts.WorkflowGroupStep(job.ID.AsString(), s.Place.Steps, k)
	}
	return facts.WorkflowStep(job.ID.AsString(), s.Place.Steps)
}

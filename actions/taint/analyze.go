package taint

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// Analysis is the sinks of a workflow or an action.yml.
type Analysis struct {
	Sinks []Sink
}

// Sink is a value read as code, and the references in its ${{ }}.
type Sink struct {
	Step        workflow.Step
	Job         *workflow.Job // nil in an action.yml
	Kind        analysis.SinkKind
	Value       workflow.String
	ReachableOn []analysis.EventActivity // the attacker's events the step can run on
	Refs        []ExprRef
	// CollectionParts are the indexes of the parts of Value whose value may
	// be an object or an array: env takes such a value as a mapping or a
	// sequence and fails the step, so it is not moved there.
	CollectionParts []int
	// Envs are the env the step sees, nearest first: its own, and in a
	// workflow the job's and the workflow's.
	Envs []workflow.Field[workflow.Map[workflow.String]]
	// Shell is the shell of a run, and XTrace whether the shell starts with
	// xtrace on (a shell: with -x). EnvironmentFileWrites and InconclusiveWrites are, for a run of
	// bash or sh, the references written to $GITHUB_ENV and $GITHUB_OUTPUT
	// that an attacker may control, and the places of those writes not
	// examined (filecmd.go).
	Shell                 Shell
	XTrace                bool
	EnvironmentFileWrites []EnvironmentFileWrite
	InconclusiveWrites    []InconclusiveWrite
	// Arguments are, for a run of bash or sh, the words of its simple
	// commands with a value an attacker may control in them (arguments.go).
	Arguments []CommandArgument
	// Requests are, for a run of bash or sh, the requests its simple
	// commands send (request.go).
	Requests []RequestSite
	// SecretLeaks are, for a run of bash or sh, where it prints a value it
	// made from a secret (secretlog.go).
	SecretLeaks []SecretLeak
	// HasStepID is whether the step has an id: the runner keeps the outputs
	// of a step only when the step has an id. HasStepAfter is whether a
	// step of the job (or the action) starts after the step is done; a step
	// of the same parallel group does not.
	HasStepID    bool
	HasStepAfter bool
	// UnsecureFlag and LogWrites are, for a run of bash or sh,
	// ACTIONS_ALLOW_UNSECURE_COMMANDS in the env context of its step, and
	// the references an attacker may control that it prints to its log,
	// read where the flag may be on with a step after it, or where the step
	// has an id (logwrite.go).
	UnsecureFlag UnsecureFlag
	LogWrites    []LogWrite
	// VariableCodes are, for a run of bash, the variables of env whose
	// value an attacker may control and that the run reads as code
	// (varcode.go).
	VariableCodes []VariableCode
	// AuthoredCommands are, for a run of bash or sh, the workflow commands
	// set-output, save-state, set-env and add-path whose names are in its
	// text and that it prints to its log (authored.go).
	AuthoredCommands []AuthoredCommand
	// CallsNotRead is, for a run of bash or sh, the first call of a function
	// whose body a reading of the run did not read past its limit of calls
	// (shell.NameVisibility, shell.Writes, and the trace of secretlog.go):
	// what the analyses above give after it is not decided.
	CallsNotRead shell.CallsNotRead
	// secretFlow reads, for a run of bash or sh, the secrets its words
	// carry and where the hosts of its requests come from (secretflow.go).
	secretFlow *secretFlow
	// nested is, for the script another shell runs from the code after -c
	// of a command of the run (nested.go), the run's text with only that
	// code in it; "" for the run itself.
	nested string
}

// ExprRef is a reference in a sink.
type ExprRef struct {
	Part              int       // of Value.Parts
	Span              expr.Span // in the value
	Path              []expr.PathElem
	Verdict           analysis.Verdict
	ControlledOn      []analysis.EventActivity     // when Controlled: those on which an attacker controls it
	Lines             []analysis.EventActivity     // when Controlled: those on which an attacker writes it with line breaks (Arbitrary)
	LeadingDash       []analysis.EventActivity     // when Controlled: those on which an attacker can make it begin with - (LeadingDash)
	DashUndecided     []analysis.EventActivity     // when Controlled: those, not of LeadingDash, on which whether an attacker can is not known
	DashRepoName      []analysis.EventActivity     // when Controlled: those of LeadingDash on which every value that may begin with - is the name of a repository (RepoName)
	Commands          []analysis.EventActivity     // when Controlled: those on which an attacker writes a workflow command in it (WorkflowCommand)
	CommandsUndecided []analysis.EventActivity     // when Controlled: those on which whether an attacker writes one is not known
	PathCommands      []analysis.EventActivity     // when Controlled: those on which an attacker writes an add-path command in it, of a value that holds no command that takes a property (PathCommand); a value that holds any command puts its events in Commands instead
	EveryRunOn        []analysis.EventActivity     // when Controlled: those of ControlledOn on which the attacker chooses the value in every run, whoever starts the run: a reference of vars or secrets in a run of an attacker who writes them (analysis.BarrierVariableValue, analysis.BarrierSecretValue)
	Source            []expr.PathElem              // the reference the value comes from: Path, or for env.<name> the first in the env's value an attacker may control
	Env               []workflow.String            // env.X: the values of env it went through, the first first
	InconclusiveKind  analysis.InconclusiveRefKind // when Inconclusive
	With              []Via                        // inputs.x: the with (or the default) it came through, the outermost caller's first
	OtherCallers      []Via                        // inputs.x: the with of each other caller that gives it what an attacker controls
}

// Via is a value of with, or the default of an input, that an input of a
// called workflow or action gets, in the input it is written in.
type Via struct {
	Node  calls.Node
	Value workflow.String
}

// Analyze finds the sinks of w, or of the composite steps of a.
func Analyze(w *workflow.Workflow, a *workflow.ActionMetadata) Analysis {
	return AnalyzeWith(w, a, nil)
}

// AnalyzeWith is AnalyzeIn without callers: each called workflow or
// action is read in the worst case.
func AnalyzeWith(w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo) Analysis {
	return AnalyzeIn(nil, calls.Node{}, w, a, m)
}

// AnalyzeIn is Analyze, with the events and the inputs of the input name,
// when it is called, read from its callers cl (a nil cl reads none), and
// each script of a run read with m once for every analysis that reads it
// (a nil m reads each time).
func AnalyzeIn(cl *Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo) Analysis {
	var out Analysis
	walk(cl, name, w, a, m, func(c scope, s workflow.Step) {
		out.Sinks = append(out.Sinks, c.sinks(s)...)
	})
	return out
}

// walk calls f with each step of w, or of the composite steps of a, and
// the scope it is read in.
func walk(cl *Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo, f func(scope, workflow.Step)) {
	cross := crossMemo{}
	if w != nil {
		evs := cl.EventsOr(name, TableEvents(), false, func() []analysis.EventActivity { return attackerEvents(w) })
		anyEvs := valueEventsOf(cl, name, func() []analysis.EventActivity { return EventsOf(w, valueEventNames()) })
		c := workflowScope(cl, name, w, m)
		c.cross = &cross
		for _, je := range w.Jobs.Value.Entries {
			j := je.Value.Value
			jobIfs := attacker.JobIfs(w, &j)
			jobEvs := Filter(cl.Table(), evs, jobIfs...)
			c.jobAnyEvents = FilterEventOnly(anyEvs, jobIfs...)
			c.jobNarrowings = jobNarrowingsOf(cl.Table(), w, &j)
			steps := j.Steps.Value.Items
			order := workflow.OrderOf(steps)
			for i, s := range steps {
				f(c.step(&j, jobEvs, steps, order, i), s)
			}
		}
	}
	if a != nil && a.Runs.Status == workflow.Present && a.Runs.Value.Kind == workflow.RunsComposite {
		evs := cl.EventsOr(name, TableEvents(), false, allActivityTypes)
		anyEvs := valueEventsOf(cl, name, func() []analysis.EventActivity { return EventsAll(valueEventNames()) })
		steps := a.Runs.Value.Steps.Value.Items
		order := workflow.OrderOf(steps)
		for i, s := range steps {
			c := actionScope(cl, name, evs, steps, order, i, m)
			c.anyEvents = FilterEventOnly(anyEvs, attacker.StepIf(nil, nil, s.If))
			c.cross = &cross
			f(c, s)
		}
	}
}

// Pick is a value of a step that StepValues reads.
type Pick struct {
	Value workflow.String
	InEnv bool // an env of the step's own: its env.<name> are read from the job's on
}

// StepValue is a value of a step other than a sink, such as an input of
// its with, and the references in its ${{ }}, read as those of a sink.
type StepValue struct {
	Step        workflow.Step
	Job         *workflow.Job // nil in an action.yml
	StepIndex   int           // of the steps of its job, or of the action
	Index       int           // of the step's picks
	Value       workflow.String
	InEnv       bool
	ReachableOn []analysis.EventActivity // the attacker's events the step can run on
	// WrittenValueOn are the events of the step on which a value that the
	// attacker writes for every workflow run, a variable or a secret, may
	// reach the step: in a run of an attacker who writes vars or secrets,
	// the events of the step whoever starts the run (the events of vars and
	// secrets of the scope); none otherwise. A step of a composite action
	// has no vars and no secrets, but the with of its callers may give the
	// action a variable or a secret, so a step of an action has the events
	// of the scope too.
	WrittenValueOn []analysis.EventActivity
	Refs           []ExprRef
}

// StepValues are the values pick chooses of each step of w, or of the
// composite steps of a, with what AnalyzeIn reads (cl, name).
func StepValues(cl *Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata, pick func(workflow.Step) []Pick) []StepValue {
	var out []StepValue
	walk(cl, name, w, a, nil, func(c scope, s workflow.Step) {
		for i, p := range pick(s) {
			from := 0
			if p.InEnv {
				from = 1
			}
			out = append(out, StepValue{Step: s, Job: c.job, StepIndex: len(c.before), Index: i, Value: p.Value, InEnv: p.InEnv, ReachableOn: c.events, WrittenValueOn: c.anyEvents, Refs: c.refs(p.Value, from, writtenText)})
		}
	})
	return out
}

// workflowScope is the scope of w before a job and a step are known.
func workflowScope(cl *Callers, name calls.Node, w *workflow.Workflow, m *shell.Memo) scope {
	c := scope{wf: w, scripts: m, name: name, callers: cl, jobs: map[string]workflow.Job{}}
	if _, remote := name.Remote(); remote || len(EventsOn(w, valueEventNames())) == 0 {
		// runs here only when called: past its callers' ifs too
		c.callerNarrowings = cl.callerNarrowings(name)
	}
	if w.On.Status == workflow.Present {
		_, call := w.On.Value.Event(workflow.EventNameWorkflowCall)
		_, dispatch := w.On.Value.Event(workflow.EventNameWorkflowDispatch)
		c.inputs, c.dispatch = call || dispatch, dispatch
	}
	if _, remote := name.Remote(); remote {
		// its own workflow_dispatch starts runs in its repository
		c.dispatch = false
	}
	for _, je := range w.Jobs.Value.Entries {
		c.jobs[expr.FoldName(je.Value.Value.ID.AsString())] = je.Value.Value
	}
	return c
}

// step is c for the step i of steps of the job j, on jobEvs: the events
// the job's if lets through. order is workflow.OrderOf(steps).
func (c scope) step(j *workflow.Job, jobEvs []analysis.EventActivity, steps []workflow.Step, order workflow.StepOrder, i int) scope {
	s := steps[i]
	p := attacker.StepIf(c.wf, j, s.If)
	c.events, c.job, c.memo = Filter(c.callers.Table(), jobEvs, p), j, map[envKey]ExprRef{}
	c.anyEvents = FilterEventOnly(c.jobAnyEvents, p)
	c.stepNarrowing = runNarrowing(c.callers.Table(), s, p) // the job's, jobNarrowings, are set once for the job
	c.before, c.order, c.all = steps[:i], order, steps
	c.envs = []workflow.Field[workflow.Map[workflow.String]]{s.Env, j.Env, c.wf.Env}
	return c
}

// actionScope is the scope of the step i of the steps of a composite
// action, on evs. order is workflow.OrderOf(steps).
func actionScope(cl *Callers, name calls.Node, evs []analysis.EventActivity, steps []workflow.Step, order workflow.StepOrder, i int, m *shell.Memo) scope {
	s := steps[i]
	p := attacker.StepIf(nil, nil, s.If)
	return scope{events: Filter(cl.Table(), evs, p), inputs: true, action: true, before: steps[:i], all: steps, order: order, envs: []workflow.Field[workflow.Map[workflow.String]]{s.Env}, memo: map[envKey]ExprRef{}, scripts: m, name: name, callers: cl,
		stepNarrowing: runNarrowing(cl.Table(), s, p), callerNarrowings: cl.callerNarrowings(name)}
}

// runNarrowing is the Narrowing of the if p of s when s runs a script: the
// runner runs the pre step of an action of another repository whatever the
// if of its step (the InitCondition of the pre step), and the pre step
// evaluates the step's with and env, so the if of a step that uses an action
// does not narrow them
// (https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Runner.Worker/ActionManager.cs#L375-L387).
func runNarrowing(t attacker.Table, s workflow.Step, p attacker.PlacedIf) attacker.Narrowing {
	if s.Run.Status != workflow.Present {
		return attacker.Narrowing{}
	}
	return t.NarrowingOf(p)
}

// scope is what a reference of a step is read in.
type scope struct {
	events   []analysis.EventActivity
	job      *workflow.Job
	envs     []workflow.Field[workflow.Map[workflow.String]] // the step's, the job's, the workflow's
	inputs   bool                                            // there are inputs: a reusable workflow, a dispatch or an action
	dispatch bool                                            // github.event.inputs are a dispatch's inputs
	memo     map[envKey]ExprRef                              // what env.<name> is, read from a level
	wf       *workflow.Workflow                              // nil in an action.yml
	action   bool                                            // a scope of an action, a step of a composite action or the default of an input of an action, which has no vars and no secrets
	before   []workflow.Step                                 // the steps before the step, which steps.<id> can name
	all      []workflow.Step                                 // the steps of the job (or the action), the step's among them
	order    workflow.StepOrder                              // of before and the step: whose outputs it sees
	jobs     map[string]workflow.Job                         // the jobs of the workflow by folded id; nil in an action.yml
	scripts  *shell.Memo                                     // reads each script once (AnalyzeIn)
	name     calls.Node                                      // the input the scope is of
	callers  *Callers                                        // what decides inputs and the events when it is called; nil: none
	st       *resolving                                      // when callers are reading it: their question, which it is part of
	cross    *crossMemo                                      // what each step writes to $GITHUB_ENV and $GITHUB_OUTPUT (secretfile.go)
	// jobNarrowings and stepNarrowing are what the ifs that a run of the
	// job goes through (jobNarrowingsOf), and the if of the step when the
	// step runs a script (runNarrowing), let a reference be: a reference
	// one of them narrows is no attacker's
	jobNarrowings []attacker.Narrowing
	stepNarrowing attacker.Narrowing
	// callerNarrowings are those of the ifs of each chain of calls of the
	// scope's input (Callers.callerNarrowings): the same for each of its
	// steps.
	callerNarrowings [][]attacker.Narrowing
	// anyEvents are the events of on that a run of the step may be of,
	// whoever starts it, by github.event_name and github.event.action
	// alone (attacker.EventOnly), and jobAnyEvents those of the job: where
	// the attacker of the run writes vars or secrets (variable-value,
	// secret-value), every such run reads them. None in a run whose
	// attacker writes neither
	anyEvents, jobAnyEvents []analysis.EventActivity
}

// envKey is env.<name> read from a level: what it is does not depend on
// where it is written, so it is found once: env that refers to env many
// times at each level would take time that multiplies by the level.
type envKey struct {
	from int
	name string
}

func (c scope) sinks(s workflow.Step) []Sink {
	var out []Sink
	add := func(k analysis.SinkKind, v workflow.String) {
		refs := c.refs(v, 0, writtenText)
		x := Sink{Step: s, Job: c.job, Kind: k, Value: v, ReachableOn: c.reachableOn(refs), Refs: refs, CollectionParts: c.collectionParts(v), Envs: c.envs,
			HasStepID: s.ID.Status == workflow.Present, HasStepAfter: c.laterStep()}
		if k == analysis.SinkRun {
			x.setShell(c.wf)
			if x.Shell == ShellBash || x.Shell == ShellSh {
				c.fileCommands(&x)
				c.arguments(&x)
				x.secretFlow = c.secretFlowOf(&x)
				c.requests(&x, x.secretFlow)
				c.secretLeaks(&x, x.secretFlow)
				c.unsecureCommands(&x, x.secretFlow)
				x.AuthoredCommands = authoredCommands(x.secretFlow)
				if x.Shell == ShellBash {
					c.variableCodes(&x, x.secretFlow)
				}
				c.nestedScripts(&x)
			}
		}
		out = append(out, x)
	}
	if s.Run.Status == workflow.Present {
		add(analysis.SinkRun, s.Run.Value)
	}
	if isGitHubScript(s.Uses) && s.With.Status == workflow.Present {
		if e, ok := s.With.Value.Lookup("script"); ok && e.Value.Status == workflow.Present {
			add(analysis.SinkScript, e.Value.Value)
		}
	}
	return out
}

func isGitHubScript(f workflow.Field[workflow.Uses]) bool {
	if f.Status != workflow.Present {
		return false
	}
	return slices.ContainsFunc(f.Value.Actions(), func(a workflow.UsesAction) bool { return a.Is("actions", "github-script", workflow.RootActionPath) })
}

// refs are the references of the ${{ }} of v whose values are written
// out, each ${{ }} written in the form root (walkWritten); env is read from
// the level env on (0: the step's).
func (c scope) refs(v workflow.String, env int, root writtenForm) []ExprRef {
	var out []ExprRef
	for i, p := range v.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		walkWritten(p.Tree, root, nil, func(n expr.Node, written []expr.PathElem, form writtenForm) {
			path, _ := expr.AccessPath(n)
			r := c.classify(written, env, form)
			r.Part, r.Span, r.Path = i, p.InValue(n.Span()), path
			if r.Source == nil {
				r.Source = path
			}
			out = append(out, r)
		})
	}
	return out
}

// WrittenRefs calls f with each reference of n whose value may become part
// of what n makes as text (walkWritten): not those compared, negated, given
// to a function that makes a bool or a hash of them, written only when
// falsy or not at all, nor those whose value is written only as Object or
// Array whatever the event (through a star as text, all of a context).
func WrittenRefs(n expr.Node, f func(expr.Node)) {
	walkWritten(n, writtenText, nil, func(ref expr.Node, path []expr.PathElem, form writtenForm) {
		if !unwritten(path, form) {
			f(ref)
		}
	})
}

// classify is what an attacker controls of what a reference writes of the
// path in form, read from the level env on.
func (c scope) classify(path []expr.PathElem, env int, form writtenForm) ExprRef {
	if unwritten(path, form) {
		return ExprRef{} // Object or Array
	}
	if c.narrowed(path, env) {
		return ExprRef{} // one of the strings an if compares it with
	}
	name := func(i int) string {
		if i < len(path) {
			return expr.FoldName(path[i].Name)
		}
		return ""
	}
	gap := func(g analysis.InconclusiveRefKind) ExprRef {
		return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: g}
	}
	switch name(0) {
	case "github":
		if c.dispatch && name(1) == "event" && name(2) == "inputs" {
			return gap(analysis.InconclusiveRefInputDispatch)
		}
		var on, lines, dash, dashUndecided, repo, cmds, undecided, paths []analysis.EventActivity
		for _, e := range c.events {
			var w writing
			for _, at := range writtenPaths(e, path, form) {
				if !c.narrowedOn(e, at.path) {
					w = w.or(writingOf(e, at.path, at.text))
				}
			}
			if !w.on {
				continue
			}
			on = append(on, e)
			if w.lines {
				lines = append(lines, e)
			}
			if w.dash {
				dash = append(dash, e)
				if w.repoName {
					repo = append(repo, e)
				}
			} else if w.dashUndecided {
				dashUndecided = append(dashUndecided, e)
			}
			switch w.cmd {
			case CommandWritingWritten:
				cmds = append(cmds, e)
			case CommandWritingUndecided:
				undecided = append(undecided, e)
			}
			if w.path && w.cmd != CommandWritingWritten {
				paths = append(paths, e)
			}
		}
		if on != nil {
			return ExprRef{Verdict: analysis.Controlled, ControlledOn: on, Lines: lines, LeadingDash: dash, DashUndecided: dashUndecided, DashRepoName: repo, Commands: cmds, CommandsUndecided: undecided, PathCommands: paths}
		}
	// vars and secrets are of a workflow: a step of a composite action and
	// the default of an input of an action have neither (the contexts of
	// step-with, step-env, string-steps-context and input-default-context in
	// https://github.com/actions/languageservices/blob/4043eda158e16579cc5fb1b0b07a4bce2a76f0b5/workflow-parser/src/action-v1.0.json)
	case "vars":
		if name(1) != "" && !c.action && c.callers.Table().Barriers().Passes(analysis.BarrierVariableValue) {
			return writtenValue(c.anyEvents)
		}
	case "secrets":
		if n := name(1); n != "" && n != "github_token" && !c.action && c.callers.Table().Barriers().Passes(analysis.BarrierSecretValue) {
			return writtenValue(c.anyEvents)
		}
	case "env":
		return c.env(path, env)
	// the outputs, all of steps or of a step (or of needs, or of a job
	// needed), or what of a step or a job a star or an index not known
	// picks: each may be the outputs
	case "steps":
		if n := name(2); n == "outputs" || n == "" {
			return c.stepOutput(name(1))
		}
	case "needs":
		if n := name(2); n == "outputs" || n == "" {
			return c.jobOutput(name(1))
		}
	case "inputs":
		if c.inputs {
			r, cov := c.input(name(1))
			if r.Verdict == analysis.Controlled {
				return r
			}
			// a dispatch's inputs are whoever dispatches, with a
			// workflow_call or not
			if c.dispatch {
				return gap(analysis.InconclusiveRefInputDispatch)
			}
			if cov == analysis.CallerCoverageAll {
				return r
			}
			return gap(analysis.InconclusiveRefInputCall)
		}
	case "matrix":
		if c.job != nil {
			switch m := c.job.Matrix; {
			case m.Status == workflow.Dynamic, m.Status == workflow.Present && hasExpr(m.Value):
				return gap(analysis.InconclusiveRefMatrix)
			}
		}
	}
	return ExprRef{}
}

// jobNarrowingsOf are the narrowings of the ifs that a run of the job j
// of w goes through (attacker.NeedJobs): j runs only when the if of each
// of those jobs is true. An if of a job reads github, needs, vars and
// inputs, whose values are the same in every job of a run but github.job,
// which no attacker writes, so the value that the if of a job that j needs
// narrows is narrowed in j too.
func jobNarrowingsOf(t attacker.Table, w *workflow.Workflow, j *workflow.Job) []attacker.Narrowing {
	jobs := attacker.NeedJobs(w, j)
	out := make([]attacker.Narrowing, len(jobs))
	for i := range jobs {
		out[i] = t.NarrowingOf(attacker.JobIf(w, &jobs[i]))
	}
	return out
}

// narrowed is whether an if of the scope lets path be only strings it
// compares path with, whatever the event: env.<name> by the if of the step
// alone, read from the step's level (the runner evaluates the step's env
// before its if, and no if of a job may read env), the others by either.
func (c scope) narrowed(path []expr.PathElem, env int) bool {
	if len(path) > 0 && expr.EqualName(path[0].Name, "env") {
		return env == 0 && c.stepNarrowing.NarrowsAnyEvent(path)
	}
	return c.narrowedBy(path, func(n attacker.Narrowing) bool { return n.NarrowsAnyEvent(path) })
}

// narrowedOn is narrowed of a reference below github on the event e.
func (c scope) narrowedOn(e analysis.EventActivity, path []expr.PathElem) bool {
	return c.narrowedBy(path, func(n attacker.Narrowing) bool { return n.Narrows(e, path) })
}

// narrowedBy is whether f holds of a narrowing of the job or of the step,
// or, for path below github, of one of every chain of calls of the
// scope's input: github is the same in the callers and the called, while
// inputs, needs, env and the rest are values of their own in each.
func (c scope) narrowedBy(path []expr.PathElem, f func(attacker.Narrowing) bool) bool {
	if slices.ContainsFunc(c.jobNarrowings, f) || f(c.stepNarrowing) {
		return true
	}
	if len(path) == 0 || !expr.EqualName(path[0].Name, "github") {
		return false
	}
	return len(c.callerNarrowings) > 0 && !slices.ContainsFunc(c.callerNarrowings, func(ch []attacker.Narrowing) bool { return !slices.ContainsFunc(ch, f) })
}

// input is what the callers give inputs.<id> of the scope's input on its
// events, and in a run whose attacker writes vars or secrets what of a
// variable or a secret a caller gives on the events any run may be of
// (anyEvents): a question of its own, or part of the callers' question
// that reads the scope.
func (c scope) input(id string) (ExprRef, analysis.CallerCoverage) {
	if c.callers == nil {
		return ExprRef{}, analysis.CallerCoverageNone
	}
	if c.st != nil {
		return c.callers.inputIn(c.st, c.name, id, c.events, c.anyEvents)
	}
	return c.callers.Input(c.name, id, c.events, c.anyEvents)
}

// env reads env.<name> from the level from on: the value's own references
// are read from the level after the one it is set at, so a chain ends.
func (c scope) env(path []expr.PathElem, from int) ExprRef {
	if len(path) < 2 || path[1].Name == "" {
		return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: analysis.InconclusiveRefEnvWhole} // all of env, or an index not known
	}
	k := envKey{from, expr.FoldName(path[1].Name)}
	if r, ok := c.memo[k]; ok {
		return r
	}
	r := c.envFrom(path[1].Name, from)
	if c.memo != nil {
		c.memo[k] = r
	}
	return r
}

func (c scope) envFrom(name string, from int) ExprRef {
	for lvl := from; lvl < len(c.envs); lvl++ {
		f := c.envs[lvl]
		if f.Status == workflow.Dynamic {
			return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: analysis.InconclusiveRefEnvDynamic}
		}
		if f.Status != workflow.Present {
			continue
		}
		e, ok := f.Value.Lookup(name)
		if !ok {
			continue
		}
		if e.Value.Status != workflow.Present {
			return ExprRef{}
		}
		out := ExprRef{}
		for _, r := range c.refs(e.Value.Value, lvl+1, writtenText) {
			switch {
			case r.Verdict == analysis.Controlled:
				out.Verdict = analysis.Controlled
				out.DashRepoName = joinRepoName(out, r) // before out takes the events of r
				out.ControlledOn = sortEvents(append(out.ControlledOn, r.ControlledOn...))
				if len(r.Lines) > 0 {
					out.Lines = sortEvents(append(out.Lines, r.Lines...))
				}
				if len(r.LeadingDash) > 0 {
					out.LeadingDash = sortEvents(append(out.LeadingDash, r.LeadingDash...))
				}
				if len(r.DashUndecided) > 0 {
					out.DashUndecided = sortEvents(append(out.DashUndecided, r.DashUndecided...))
				}
				if len(r.Commands) > 0 {
					out.Commands = sortEvents(append(out.Commands, r.Commands...))
				}
				if len(r.CommandsUndecided) > 0 {
					out.CommandsUndecided = sortEvents(append(out.CommandsUndecided, r.CommandsUndecided...))
				}
				if len(r.PathCommands) > 0 {
					out.PathCommands = sortEvents(append(out.PathCommands, r.PathCommands...))
				}
				if len(r.EveryRunOn) > 0 {
					out.EveryRunOn = sortEvents(append(out.EveryRunOn, r.EveryRunOn...))
				}
				if len(out.Env) == 0 {
					out.Source = r.Source
					out.Env = append([]workflow.String{e.Value.Value}, r.Env...)
					out.With, out.OtherCallers = r.With, r.OtherCallers
				}
			case r.Verdict == analysis.Inconclusive && out.Verdict == analysis.NotControlled:
				out.Verdict, out.InconclusiveKind = analysis.Inconclusive, r.InconclusiveKind
			}
		}
		if out.Verdict != analysis.Controlled {
			out.Env, out.With, out.OtherCallers, out.Source = nil, nil, nil, nil
		}
		return out
	}
	return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: analysis.InconclusiveRefEnvUnset}
}

// stepOutput is what steps.<id>.outputs is: inconclusive, of the kind of
// the form of the step before this one that has the id; nothing when no
// step before has it, as the runner gives it empty. An id
// not written out (id "": steps[x], steps.*) is the least decided of the
// steps before that have an id.
func (c scope) stepOutput(id string) ExprRef {
	g := analysis.InconclusiveRefUnset
	for _, s := range c.before {
		// the outputs of a step that runs alongside are not there yet
		if !c.order.DoneBefore(s.Order, len(c.before)) || s.ID.Status != workflow.Present || id != "" && expr.FoldName(s.ID.Value.AsString()) != id {
			continue
		}
		g = max(g, stepGap(s))
	}
	if g == analysis.InconclusiveRefUnset {
		return ExprRef{}
	}
	return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: g}
}

// stepGap is the kind of the outputs of s, or InconclusiveRefUnset for a step whose
// form is not known, which GitHub does not run.
func stepGap(s workflow.Step) analysis.InconclusiveRefKind {
	if s.Run.Status == workflow.Present {
		return analysis.InconclusiveRefStepRun
	}
	if s.Uses.Status != workflow.Present {
		return analysis.InconclusiveRefUnset
	}
	switch usesKind(s.Uses.Value) {
	case workflow.UsesLocal, workflow.UsesSelf:
		return analysis.InconclusiveRefStepLocalAction
	case workflow.UsesRemote:
		return analysis.InconclusiveRefStepRemoteAction
	case workflow.UsesDocker:
		return analysis.InconclusiveRefStepDocker
	}
	return analysis.InconclusiveRefUnset
}

// jobOutput is what needs.<id>.outputs is: inconclusive, of the kind of
// the job needed; nothing for a job not in needs and in an
// action.yml, which has no needs. An id not written out is
// the least decided of the jobs needed.
func (c scope) jobOutput(id string) ExprRef {
	if c.job == nil || c.job.Needs.Status != workflow.Present {
		return ExprRef{}
	}
	g := analysis.InconclusiveRefUnset
	for _, n := range c.job.Needs.Value.Items {
		nid := expr.FoldName(n.AsString())
		if id != "" && nid != id {
			continue
		}
		if j, ok := c.jobs[nid]; ok {
			g = max(g, jobGap(j))
		}
	}
	if g == analysis.InconclusiveRefUnset {
		return ExprRef{}
	}
	return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: g}
}

// jobGap is the kind of the outputs of j, or InconclusiveRefUnset for a job whose form
// is not known.
func jobGap(j workflow.Job) analysis.InconclusiveRefKind {
	switch j.Kind {
	case workflow.JobRunner:
		return analysis.InconclusiveRefJob
	case workflow.JobCall:
		if j.Uses.Status != workflow.Present {
			return analysis.InconclusiveRefUnset
		}
		switch usesKind(j.Uses.Value) {
		case workflow.UsesLocal, workflow.UsesSelf:
			return analysis.InconclusiveRefJobLocalCall
		case workflow.UsesRemote:
			return analysis.InconclusiveRefJobRemoteCall
		}
	}
	return analysis.InconclusiveRefUnset
}

// usesKind is the kind of u, or of what it folds to.
func usesKind(u workflow.Uses) workflow.UsesKind {
	if u.Kind == workflow.UsesFolded {
		return u.Folded
	}
	return u.Kind
}

// hasExpr is whether a scalar under n has a ${{.
func hasExpr(n cst.Node) bool {
	if n.Kind() == cst.NodeScalar {
		return strings.Contains(string(n.Bytes()), "${{")
	}
	for e := range n.Children() {
		if c, ok := e.Node(); ok && hasExpr(c) {
			return true
		}
	}
	return false
}

// text is the script of s as the shell sees it (Masked), or the nested
// script s reads.
func (s *Sink) text() string {
	if s.nested != "" {
		return s.nested
	}
	return Masked(s.Value)
}

// readSink is the script of s (text), read once for c.
func (c scope) readSink(s *Sink) shell.Read {
	if s.nested == "" {
		return ReadScript(c.scripts, s.Value)
	}
	var at []int
	for _, p := range s.Value.Parts {
		if p.Expr && s.nested[p.Span.Start] != ' ' { // those in the code
			at = append(at, p.Span.Start)
		}
	}
	return c.scripts.Read(s.nested, at)
}

// ReadScript is the script of v as the shell sees it (Masked), read once
// for m with the places of its ${{ }}.
func ReadScript(m *shell.Memo, v workflow.String) shell.Read {
	var at []int
	for _, p := range v.Parts {
		if p.Expr {
			at = append(at, p.Span.Start)
		}
	}
	return m.Read(Masked(v), at)
}

// writtenValue is a value the attacker writes as they choose, on evs: lines, a
// leading dash and workflow commands (a variable or a secret they write),
// in every run on evs, whoever starts the run (EveryRunOn).
func writtenValue(evs []analysis.EventActivity) ExprRef {
	if len(evs) == 0 {
		return ExprRef{Verdict: analysis.NotControlled}
	}
	return ExprRef{Verdict: analysis.Controlled, ControlledOn: evs, Lines: evs, LeadingDash: evs, Commands: evs, EveryRunOn: evs}
}

// reachableOn are the events a sink with refs is reached on: the
// attacker's events of the step, and, in a run whose attacker writes vars
// or secrets, the events on which a reference of refs is theirs.
func (c scope) reachableOn(refs []ExprRef) []analysis.EventActivity {
	t := c.callers.Table().Barriers()
	if !t.Passes(analysis.BarrierVariableValue) && !t.Passes(analysis.BarrierSecretValue) {
		return c.events
	}
	out := slices.Clone(c.events)
	for _, r := range refs {
		for _, e := range r.ControlledOn {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// valueEventsOf are the events of on of the input name that any run may
// be of, for the references of vars and secrets: none in a run whose
// attacker writes neither. own are those of the input itself when no
// caller decides them.
func valueEventsOf(cl *Callers, name calls.Node, own func() []analysis.EventActivity) []analysis.EventActivity {
	t := cl.Table().Barriers()
	if !t.Passes(analysis.BarrierVariableValue) && !t.Passes(analysis.BarrierSecretValue) {
		return nil
	}
	return cl.EventsOr(name, valueEventNames(), false, own)
}

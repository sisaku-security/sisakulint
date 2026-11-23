package taint

import (
	"slices"
	"strings"
	"sync"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Callers reads the events and the inputs of a called workflow or a
// composite action from its callers among the inputs of a run. It is safe
// to use at once from goroutines: one question is answered at a time. A
// nil *Callers reads no caller: each called one is read in the worst
// case.
type Callers struct {
	g      *calls.Graph
	table  attacker.Table // the attacker run table of the run
	mu     sync.Mutex
	events map[eventsKey][]analysis.EventActivity
	inputs map[inputKey][]given // what each caller gives, in the order of CallsOf
}

type eventsKey struct {
	name  calls.Node
	names string // the event names asked, sorted and joined
	code  bool
}

type inputKey struct {
	called calls.Node
	id     string // folded; "" for each input (inputs, inputs[x])
}

// given is what one caller gives an input, and the events its run of the
// called one may be on.
type given struct {
	ref    ExprRef
	events []analysis.EventActivity
	// in a run whose attacker writes vars or secrets: what of the value
	// such an attacker may choose (valuePart), on the events of vars and
	// secrets of the call (valueEventNames), read on the events any run of
	// the step may be of
	valueRef    ExprRef
	valueEvents []analysis.EventActivity
}

// resolving is what one question to Callers is reading: a question that
// comes back to one of them is a cycle, which GitHub refuses. An answer
// read through a cut cycle depends on where the question
// started, so it is not kept.
type resolving struct {
	events map[eventsKey]bool
	inputs map[inputKey]bool
	cut    bool
}

func newResolving() *resolving {
	return &resolving{events: map[eventsKey]bool{}, inputs: map[inputKey]bool{}}
}

// NewCallers reads the callers of g, in the attacker run table of a run
// that adds no attacker (attacker.Outsider).
func NewCallers(g *calls.Graph) *Callers { return NewCallersIn(g, attacker.Outsider) }

// NewCallersIn reads the callers of g, in the attacker run table t of the
// run.
func NewCallersIn(g *calls.Graph, t attacker.Table) *Callers {
	return &Callers{g: g, table: t, events: map[eventsKey][]analysis.EventActivity{}, inputs: map[inputKey][]given{}}
}

// Table is the attacker run table c reads ifs in: attacker.Outsider for a
// nil c.
func (c *Callers) Table() attacker.Table {
	if c == nil {
		return attacker.Outsider
	}
	return c.table
}

// Graph is the calls c reads; nil for a nil c.
func (c *Callers) Graph() *calls.Graph {
	if c == nil {
		return nil
	}
	return c.g
}

// Coverage is how much of the callers of name the inputs have;
// CallerCoverageNone for a nil c.
func (c *Callers) Coverage(name calls.Node) analysis.CallerCoverage {
	if c == nil {
		return analysis.CallerCoverageNone
	}
	return c.g.Coverage(name)
}

// Events are the events of names the input name runs on: a workflow's
// own, and when it can be called those its callers run it on; an action's,
// its callers'. The callers decide the called part when the coverage is
// CallerCoverageAll; else it is every event of names (the worst case).
// code keeps the events the callers' ifs let through as FilterCode does,
// else as Filter. A call that comes back to name while it is read adds
// nothing. A nil c, or a name not among the inputs, gives none and
// CallerCoverageNone.
func (c *Callers) Events(name calls.Node, names []workflow.EventName, code bool) ([]analysis.EventActivity, analysis.CallerCoverage) {
	if c == nil {
		return nil, analysis.CallerCoverageNone
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.eventsIn(newResolving(), name, names, code)
}

func (c *Callers) eventsIn(st *resolving, name calls.Node, names []workflow.EventName, code bool) ([]analysis.EventActivity, analysis.CallerCoverage) {
	f, ok := c.g.File(name)
	if !ok {
		return nil, analysis.CallerCoverageNone
	}
	cov := c.g.Coverage(name)
	k := eventsKey{name, joinNames(names), code}
	if evs, ok := c.events[k]; ok {
		return evs, cov
	}
	if st.events[k] {
		st.cut = true
		return nil, cov
	}
	st.events[k] = true
	outer := st.cut
	st.cut = false

	var out []analysis.EventActivity
	called := f.Action != nil
	if _, remote := name.Remote(); remote {
		// a remote called workflow runs here only when called: its own on
		// starts runs in its repository
		called = true
	} else if w := f.Workflow; w != nil {
		out = EventsOn(w, names)
		if w.On.Status == workflow.Present {
			_, called = w.On.Value.Event(workflow.EventNameWorkflowCall)
		}
	}
	if called {
		if cov == analysis.CallerCoverageAll {
			for _, call := range c.g.CallsOf(name) {
				out = append(out, c.callerEvents(st, call, names, code)...)
			}
		} else {
			out = append(out, EventsAll(names)...)
		}
	}
	out = sortEvents(out)

	delete(st.events, k)
	if !st.cut {
		c.events[k] = out
	}
	st.cut = st.cut || outer
	return out, cov
}

// EventsOr are the events of name from c, or or's when c is nil or has no
// input named name.
func (c *Callers) EventsOr(name calls.Node, names []workflow.EventName, code bool, or func() []analysis.EventActivity) []analysis.EventActivity {
	if c == nil {
		return or()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.eventsOrIn(newResolving(), name, names, code, or)
}

func (c *Callers) eventsOrIn(st *resolving, name calls.Node, names []workflow.EventName, code bool, or func() []analysis.EventActivity) []analysis.EventActivity {
	if _, ok := c.g.File(name); !ok {
		return or()
	}
	evs, _ := c.eventsIn(st, name, names, code)
	return evs
}

// callerEvents are the events call runs its called one on: its caller's,
// those the job's if and the step's let through; for the events of vars
// and secrets (valueEventNames), by github.event_name and
// github.event.action alone.
func (c *Callers) callerEvents(st *resolving, call calls.Call, names []workflow.EventName, code bool) []analysis.EventActivity {
	evs, _ := c.eventsIn(st, call.Caller, names, code)
	filter := Filter
	switch {
	case joinNames(names) == joinNames(valueEventNames()):
		// the events of vars and secrets: any run, whoever starts it
		filter = func(_ attacker.Table, evs []analysis.EventActivity, ifs ...attacker.PlacedIf) []analysis.EventActivity {
			return FilterEventOnly(evs, ifs...)
		}
	case code:
		filter = FilterCode
	}
	var ifs []attacker.PlacedIf
	if call.Job != nil {
		ifs = append(ifs, c.callerJobIfs(call)...)
	}
	if call.Step != nil {
		ifs = append(ifs, c.callerStepIf(call))
	}
	return filter(c.Table(), evs, ifs...)
}

// callerStepIf is the if of the step of call, of the job of call in the
// workflow of its caller; of a step of a composite action when call has no
// job (attacker.StepIf).
func (c *Callers) callerStepIf(call calls.Call) attacker.PlacedIf {
	f, ok := c.g.File(call.Caller)
	if !ok || call.Job == nil {
		return attacker.StepIf(nil, nil, call.Step.If)
	}
	return attacker.StepIf(f.Workflow, call.Job, call.Step.If)
}

// callerJobIfs are the ifs that a run of the job of call goes through, in
// the workflow of its caller (attacker.JobIfs); the if of the job alone,
// which does not read the needs context, when the caller is not a workflow
// of the graph.
func (c *Callers) callerJobIfs(call calls.Call) []attacker.PlacedIf {
	f, ok := c.g.File(call.Caller)
	if !ok || f.Workflow == nil {
		return []attacker.PlacedIf{attacker.JobIf(nil, call.Job)}
	}
	return attacker.JobIfs(f.Workflow, call.Job)
}

func joinNames(names []workflow.EventName) string {
	s := make([]string, len(names))
	for i, n := range names {
		s[i] = n.String()
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

// Input is what an attacker controls of inputs.<id> of the input called,
// read on evs (the events of the step that reads it), and the coverage of
// its callers. What each caller gives it, its with or else the input's
// default read in the caller's scope, is kept to evs first: a caller whose
// run does not reach the step gives nothing. Then Controlled wins, then
// the first Inconclusive, then not controlled. id "" is each input
// (inputs, inputs[x]). An input of type boolean or number holds nothing an
// attacker writes: a value that is not one fails the caller's run. A call
// that comes back to (called, id) while it is read is Inconclusive of
// input-call. A nil c, or called without callers, gives nothing.
//
// In a run whose attacker writes vars or secrets, a caller also gives, on
// the events of vars and secrets, what of its value the attacker chooses
// in every run (ExprRef.EveryRunOn), kept to anyEvs: the events any run of
// the step may be of. A value the attacker does not write, such as an
// input of workflow_dispatch, is not read on those events.
func (c *Callers) Input(called calls.Node, id string, evs, anyEvs []analysis.EventActivity) (ExprRef, analysis.CallerCoverage) {
	if c == nil {
		return ExprRef{}, analysis.CallerCoverageNone
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inputIn(newResolving(), called, id, evs, anyEvs)
}

func (c *Callers) inputIn(st *resolving, called calls.Node, id string, evs, anyEvs []analysis.EventActivity) (ExprRef, analysis.CallerCoverage) {
	cov := c.g.Coverage(called)
	if cov == analysis.CallerCoverageNone {
		return ExprRef{}, cov
	}
	k := inputKey{called, id}
	gs, ok := c.inputs[k]
	if !ok {
		if st.inputs[k] {
			st.cut = true
			return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: analysis.InconclusiveRefInputCall}, cov
		}
		st.inputs[k] = true
		outer := st.cut
		st.cut = false
		if !c.typed(called, id) {
			t := c.Table().Barriers()
			values := t.Passes(analysis.BarrierVariableValue) || t.Passes(analysis.BarrierSecretValue)
			for _, call := range c.g.CallsOf(called) {
				r := c.givenBy(st, call, called, id)
				g := given{ref: r, events: c.callerEvents(st, call, TableEvents(), false)}
				if values {
					f, _ := c.g.File(call.Caller)
					g.valueRef, g.valueEvents = valuePartOn(r, c.callerEvents(st, call, valueEventNames(), false), f.Workflow)
				}
				gs = append(gs, g)
			}
		}
		delete(st.inputs, k)
		if !st.cut {
			c.inputs[k] = gs
		}
		st.cut = st.cut || outer
	}
	var out ExprRef
	for _, g := range gs {
		// one caller's value: on the step's events, and of vars and
		// secrets on the events any run of the step may be of
		out = mergeCaller(out, merge([]ExprRef{g.on(evs), given{ref: g.valueRef, events: g.valueEvents}.on(anyEvs)}))
	}
	return out, cov
}

// valuePart is what of r an attacker who writes vars or secrets may
// choose in any run: r kept to its EveryRunOn when the attacker chooses it
// in every run, r when it is not analyzed (a variable or a secret may
// reach the output of a job or a step, or a matrix), and nothing for an
// input of workflow_dispatch, which the one who dispatches chooses, or for
// a value the attacker controls only in their own runs.
func valuePart(r ExprRef) ExprRef {
	switch {
	case r.Verdict == analysis.Controlled && len(r.EveryRunOn) > 0:
		return r.on(r.EveryRunOn)
	case r.Verdict == analysis.Inconclusive && r.InconclusiveKind != analysis.InconclusiveRefInputDispatch:
		return r
	}
	return ExprRef{}
}

// valuePartOn is valuePart of r, read in a step of the workflow w (nil in
// an action) on evs, the events of vars and secrets of the step, and the
// events of evs on which it holds. A workflow that can be dispatched reads
// each input that is not Controlled as an input of workflow_dispatch
// (InconclusiveRefInputDispatch), also on the events of its callers; when
// w can also be called, the input on the events other than workflow_dispatch
// is the value a caller gives, which is not analyzed and which a variable
// or a secret may reach: on those events it is kept, as an input of a call
// (InconclusiveRefInputCall).
func valuePartOn(r ExprRef, evs []analysis.EventActivity, w *workflow.Workflow) (ExprRef, []analysis.EventActivity) {
	if r.Verdict == analysis.Inconclusive && r.InconclusiveKind == analysis.InconclusiveRefInputDispatch && callable(w) {
		r.InconclusiveKind = analysis.InconclusiveRefInputCall
		return r, slices.DeleteFunc(slices.Clone(evs), func(e analysis.EventActivity) bool { return e.Name() == workflow.EventNameWorkflowDispatch })
	}
	return valuePart(r), evs
}

// callable is whether the on of w has workflow_call; false for a nil w.
func callable(w *workflow.Workflow) bool {
	if w == nil || w.On.Status != workflow.Present {
		return false
	}
	_, call := w.On.Value.Event(workflow.EventNameWorkflowCall)
	return call
}

// ValuePartOn are the events on which r, read in a step of the workflow w
// (nil in an action) on evs in a run whose attacker writes vars or secrets,
// may hold what such an attacker chooses (valuePartOn): the EveryRunOn of r
// when the attacker chooses r in every run, those of evs on which r is not
// analyzed but for an input of workflow_dispatch, and none otherwise. A step
// that gives r in its with to a composite action of another repository,
// whose steps are read without callers, gives the action such a value on
// those events.
func ValuePartOn(r ExprRef, evs []analysis.EventActivity, w *workflow.Workflow) []analysis.EventActivity {
	switch p, on := valuePartOn(r, evs, w); p.Verdict {
	case analysis.Controlled:
		return p.EveryRunOn
	case analysis.Inconclusive:
		return on
	}
	return nil
}

// on is what g gives a step that runs on evs: Controlled kept to evs,
// and nothing from a caller whose run does not reach it.
func (g given) on(evs []analysis.EventActivity) ExprRef {
	if !slices.ContainsFunc(g.events, func(e analysis.EventActivity) bool { return slices.Contains(evs, e) }) {
		return ExprRef{}
	}
	return g.ref.on(evs)
}

// mergeCaller adds r, what one caller gives, to out, what the callers
// before it give.
func mergeCaller(out, r ExprRef) ExprRef {
	switch {
	case r.Verdict == analysis.Controlled && out.Verdict == analysis.Controlled:
		out.DashRepoName = joinRepoName(out, r) // before out takes the events of r
		out.ControlledOn = sortEvents(append(slices.Clone(out.ControlledOn), r.ControlledOn...))
		out.Lines = sortEvents(append(slices.Clone(out.Lines), r.Lines...))
		out.LeadingDash = sortEvents(append(slices.Clone(out.LeadingDash), r.LeadingDash...))
		out.DashUndecided = sortEvents(append(slices.Clone(out.DashUndecided), r.DashUndecided...))
		out.Commands = sortEvents(append(slices.Clone(out.Commands), r.Commands...))
		out.CommandsUndecided = sortEvents(append(slices.Clone(out.CommandsUndecided), r.CommandsUndecided...))
		out.PathCommands = sortEvents(append(slices.Clone(out.PathCommands), r.PathCommands...))
		out.EveryRunOn = sortEvents(append(slices.Clone(out.EveryRunOn), r.EveryRunOn...))
		if len(r.With) > 0 {
			out.OtherCallers = append(slices.Clone(out.OtherCallers), r.With[0])
		}
		return out
	case r.Verdict == analysis.Controlled:
		return r
	case r.Verdict == analysis.Inconclusive && out.Verdict == analysis.NotControlled:
		return r
	}
	return out
}

// on is r with ControlledOn, Lines, LeadingDash, DashUndecided, DashRepoName, Commands, CommandsUndecided, PathCommands and EveryRunOn kept to evs: the events the step
// that reads it runs on, which its own ifs narrow.
func (r ExprRef) on(evs []analysis.EventActivity) ExprRef {
	if r.Verdict != analysis.Controlled {
		return r
	}
	keep := func(xs []analysis.EventActivity) []analysis.EventActivity {
		return slices.DeleteFunc(slices.Clone(xs), func(e analysis.EventActivity) bool { return !slices.Contains(evs, e) })
	}
	r.ControlledOn, r.Lines, r.LeadingDash, r.DashUndecided, r.DashRepoName = keep(r.ControlledOn), keep(r.Lines), keep(r.LeadingDash), keep(r.DashUndecided), keep(r.DashRepoName)
	r.Commands, r.CommandsUndecided, r.PathCommands, r.EveryRunOn = keep(r.Commands), keep(r.CommandsUndecided), keep(r.PathCommands), keep(r.EveryRunOn)
	if len(r.Commands) == 0 {
		r.Commands = nil
	}
	if len(r.CommandsUndecided) == 0 {
		r.CommandsUndecided = nil
	}
	if len(r.PathCommands) == 0 {
		r.PathCommands = nil
	}
	if len(r.EveryRunOn) == 0 {
		r.EveryRunOn = nil
	}
	if len(r.ControlledOn) == 0 {
		return ExprRef{}
	}
	if len(r.Lines) == 0 {
		r.Lines = nil
	}
	if len(r.LeadingDash) == 0 {
		r.LeadingDash = nil
	}
	if len(r.DashUndecided) == 0 {
		r.DashUndecided = nil
	}
	if len(r.DashRepoName) == 0 {
		r.DashRepoName = nil
	}
	return r
}

// joinRepoName is DashRepoName of a and b joined, as the parts of one
// value or as the values it may be: the events of the LeadingDash of
// either on which each of them that an attacker controls on the event has
// the event in its DashRepoName too. Any other value an attacker controls
// (a branch's name, a label) may hold = and blanks, and wins.
func joinRepoName(a, b ExprRef) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range sortEvents(append(slices.Clone(a.LeadingDash), b.LeadingDash...)) {
		if slices.Contains(out, e) {
			continue
		}
		if (!slices.Contains(a.ControlledOn, e) || slices.Contains(a.DashRepoName, e)) && (!slices.Contains(b.ControlledOn, e) || slices.Contains(b.DashRepoName, e)) {
			out = append(out, e)
		}
	}
	return out
}

// givenBy is what call gives inputs.<id> of called: its with's value, or
// else the input's default read as called's on the caller's events. id ""
// is each input the call gives or called declares.
func (c *Callers) givenBy(st *resolving, call calls.Call, called calls.Node, id string) ExprRef {
	if id == "" {
		var out ExprRef
		for _, x := range c.inputIDs(call, called) {
			out = mergeCaller(out, c.givenBy(st, call, called, x))
		}
		out.OtherCallers = nil // the inputs of one caller, not other callers
		return out
	}
	sc, ok := c.callerScope(st, call)
	if !ok {
		return ExprRef{Verdict: analysis.Inconclusive, InconclusiveKind: analysis.InconclusiveRefInputCall}
	}
	if v, ok := withValue(call.With, id); ok {
		return via(merge(sc.refs(v, 0, writtenText)), Via{Node: call.Caller, Value: v})
	}
	d, ok := c.defaultOf(called, id)
	if !ok {
		return ExprRef{}
	}
	dsc := scope{events: sc.events, name: called, callers: c, st: st, inputs: true}
	if f, _ := c.g.File(called); f.Action != nil {
		dsc.action = true
		dsc.job = sc.job // an action's default reads the matrix of the job that runs it
		// and no inputs: the if of the job that runs it narrows what it reads.
		// A called workflow's default reads its own inputs, which the
		// caller's if, of the caller's inputs, does not narrow
		dsc.jobNarrowings = sc.jobNarrowings
	} else {
		// a called workflow's default may read vars (the contexts of
		// on.workflow_call.inputs.<inputs_id>.default), whose value is the
		// attacker's on the events any run of the caller may be of
		dsc.anyEvents = sc.anyEvents
	}
	return via(merge(dsc.refs(d, 0, writtenJSON)), Via{Node: called, Value: d}) // a default, whose type is not checked: all of it
}

// inputIDs are the inputs call gives called and those called declares,
// folded, each once, but those of type boolean or number.
func (c *Callers) inputIDs(call calls.Call, called calls.Node) []string {
	var out []string
	add := func(k string) {
		if k = expr.FoldName(k); !slices.Contains(out, k) && !c.typed(called, k) {
			out = append(out, k)
		}
	}
	if call.With.Status == workflow.Present {
		for _, e := range call.With.Value.Entries {
			add(e.Key.AsString())
		}
	}
	for _, k := range c.declared(called) {
		add(k)
	}
	return out
}

// via puts v after the with r came through: those are of the callers
// further out, v is the one that gives the input.
func via(r ExprRef, v Via) ExprRef {
	if r.Verdict == analysis.Controlled {
		r.With = append(slices.Clone(r.With), v)
	}
	return r
}

// merge is the references of one value as one: Controlled if any is, else
// the first Inconclusive, else not controlled.
func merge(refs []ExprRef) ExprRef {
	var out ExprRef
	for _, r := range refs {
		switch {
		case r.Verdict == analysis.Controlled && out.Verdict == analysis.Controlled:
			out.DashRepoName = joinRepoName(out, r) // before out takes the events of r
			out.ControlledOn = sortEvents(append(slices.Clone(out.ControlledOn), r.ControlledOn...))
			out.Lines = sortEvents(append(slices.Clone(out.Lines), r.Lines...))
			out.LeadingDash = sortEvents(append(slices.Clone(out.LeadingDash), r.LeadingDash...))
			out.DashUndecided = sortEvents(append(slices.Clone(out.DashUndecided), r.DashUndecided...))
			out.Commands = sortEvents(append(slices.Clone(out.Commands), r.Commands...))
			out.CommandsUndecided = sortEvents(append(slices.Clone(out.CommandsUndecided), r.CommandsUndecided...))
			out.PathCommands = sortEvents(append(slices.Clone(out.PathCommands), r.PathCommands...))
			out.EveryRunOn = sortEvents(append(slices.Clone(out.EveryRunOn), r.EveryRunOn...))
		case r.Verdict == analysis.Controlled:
			out = r
		case r.Verdict == analysis.Inconclusive && out.Verdict == analysis.NotControlled:
			out = r
		}
	}
	return out
}

// withValue is the value with gives the input id, its key compared
// ignoring the case as GitHub does.
func withValue(with workflow.Field[workflow.Map[workflow.String]], id string) (workflow.String, bool) {
	if with.Status != workflow.Present {
		return workflow.String{}, false
	}
	for _, e := range with.Value.Entries {
		if expr.FoldName(e.Key.AsString()) == id && e.Value.Status == workflow.Present {
			return e.Value.Value, true
		}
	}
	return workflow.String{}, false
}

// declared are the names of the inputs of called, folded: of
// on.workflow_call in a workflow, of inputs in an action.
func (c *Callers) declared(called calls.Node) []string {
	var out []string
	f, _ := c.g.File(called)
	if w := f.Workflow; w != nil && w.On.Status == workflow.Present {
		if ev, ok := w.On.Value.Event(workflow.EventNameWorkflowCall); ok && ev.Inputs.Status == workflow.Present {
			for _, e := range ev.Inputs.Value.Entries {
				out = append(out, expr.FoldName(e.Key.AsString()))
			}
		}
	}
	if a := f.Action; a != nil && a.Inputs.Status == workflow.Present {
		for _, e := range a.Inputs.Value.Entries {
			out = append(out, expr.FoldName(e.Key.AsString()))
		}
	}
	return out
}

// callInput is the input id of on.workflow_call of called, a workflow.
func (c *Callers) callInput(called calls.Node, id string) (workflow.Input, bool) {
	f, _ := c.g.File(called)
	if w := f.Workflow; w != nil && w.On.Status == workflow.Present {
		if ev, ok := w.On.Value.Event(workflow.EventNameWorkflowCall); ok && ev.Inputs.Status == workflow.Present {
			for _, e := range ev.Inputs.Value.Entries {
				if expr.FoldName(e.Key.AsString()) == id && e.Value.Status == workflow.Present {
					return e.Value.Value, true
				}
			}
		}
	}
	return workflow.Input{}, false
}

// typed is whether the input id of called is of type boolean or number.
func (c *Callers) typed(called calls.Node, id string) bool {
	in, ok := c.callInput(called, id)
	if !ok || in.Type.Status != workflow.Present {
		return false
	}
	t := in.Type.Value.AsString()
	return t == "boolean" || t == "number"
}

// defaultOf is the default of the input id of called: of on.workflow_call
// in a workflow, of inputs in an action.
func (c *Callers) defaultOf(called calls.Node, id string) (workflow.String, bool) {
	if in, ok := c.callInput(called, id); ok {
		if in.Default.Status == workflow.Present {
			return in.Default.Value, true
		}
		return workflow.String{}, false
	}
	f, _ := c.g.File(called)
	if a := f.Action; a != nil && a.Inputs.Status == workflow.Present {
		for _, e := range a.Inputs.Value.Entries {
			if expr.FoldName(e.Key.AsString()) == id && e.Value.Status == workflow.Present && e.Value.Value.Default.Status == workflow.Present {
				return e.Value.Value.Default.Value, true
			}
		}
	}
	return workflow.String{}, false
}

// callerScope is the scope call's with is read in: the job's (a job that
// calls a workflow reads no env), or the step's.
func (c *Callers) callerScope(st *resolving, call calls.Call) (scope, bool) {
	f, ok := c.g.File(call.Caller)
	if !ok {
		return scope{}, false
	}
	if w := f.Workflow; w != nil && call.Job != nil {
		evs := c.eventsOrIn(st, call.Caller, TableEvents(), false, func() []analysis.EventActivity { return attackerEvents(w) })
		sc := workflowScope(c, call.Caller, w, nil)
		sc.st = st
		jobIfs := attacker.JobIfs(w, call.Job)
		jobEvs := Filter(c.Table(), evs, jobIfs...)
		sc.jobAnyEvents = FilterEventOnly(c.valueEventsIn(st, call.Caller, func() []analysis.EventActivity { return EventsOf(w, valueEventNames()) }), jobIfs...)
		if call.StepIndex < 0 {
			sc.events, sc.job, sc.jobNarrowings, sc.anyEvents = jobEvs, call.Job, jobNarrowingsOf(c.Table(), w, call.Job), sc.jobAnyEvents
			return sc, true
		}
		steps := call.Job.Steps.Value.Items
		sc.jobNarrowings = jobNarrowingsOf(c.Table(), w, call.Job)
		return sc.step(call.Job, jobEvs, steps, workflow.OrderOf(steps), call.StepIndex), true
	}
	if a := f.Action; a != nil && call.Step != nil {
		evs := c.eventsOrIn(st, call.Caller, TableEvents(), false, allActivityTypes)
		steps := a.Runs.Value.Steps.Value.Items
		sc := actionScope(c, call.Caller, evs, steps, workflow.OrderOf(steps), call.StepIndex, nil)
		sc.st = st
		sc.anyEvents = FilterEventOnly(c.valueEventsIn(st, call.Caller, func() []analysis.EventActivity { return EventsAll(valueEventNames()) }), attacker.StepIf(nil, nil, steps[call.StepIndex].If))
		return sc, true
	}
	return scope{}, false
}

// valueEventsIn is valueEventsOf for a question of the callers st is
// part of: none in a run whose attacker writes neither vars nor secrets.
func (c *Callers) valueEventsIn(st *resolving, name calls.Node, own func() []analysis.EventActivity) []analysis.EventActivity {
	t := c.Table().Barriers()
	if !t.Passes(analysis.BarrierVariableValue) && !t.Passes(analysis.BarrierSecretValue) {
		return nil
	}
	return c.eventsOrIn(st, name, valueEventNames(), false, own)
}

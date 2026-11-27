package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/taint"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/labeler"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// Rule is a rule: its description in the registry of rules, and the check
// that reports findings. Check does no I/O of its own; what it needs to
// know from outside the input it asks c.Resolver. Check may run at once on
// several RuleContexts (the engine checks fixes at once), so a rule keeps no
// state of its own between calls.
type Rule interface {
	Meta() Meta
	Check(ctx context.Context, c *RuleContext) error
}

// ExampledRule is a rule whose Meta has no examples: ExampledMeta is that
// Meta with the examples of its declarations. Reading the examples is
// most of the time a registry would take to make, and running the rules
// does not need them, so the registry asks ExampledMeta only when it
// shows the examples (MarshalJSON, Explain, CheckExamples). ExampledMeta
// without its examples is Meta: a type that embeds an ExampledRule and
// changes its Meta gets its ExampledMeta too, which the registry refuses.
type ExampledRule interface {
	Rule
	ExampledMeta() Meta
}

// RuleContext is what a rule sees of one input.
type RuleContext struct {
	Resolver facts.Resolver

	// what the engine reads; a rule reads the IR, through its reader
	// (WithView), and where a handle is (At), not the model or the tree
	input    Input
	tree     *cst.Tree
	workflow *workflow.Workflow       // when the input is a workflow
	action   *workflow.ActionMetadata // when the input is an action.yml
	inputs   InputSet
	repo     facts.Repo     // Inputs.Repo
	access   *ir.RuleAccess // what the rule reads of the IR of the input
	run      *runState
	rule     RuleID
	// the kinds whose findings get repo.pull-request-target-allowed in
	// their condition (pullRequestTargetKinds)
	pullRequestTarget []FindingKindID
	// the kinds of fact of the runs of status, check_suite and check_run
	// that the findings of each kind get in their condition (appChecksKinds)
	appChecks   map[FindingKindID][]facts.Kind
	found       []FindingDraft
	gaps        []InconclusiveDraft
	done        bool
	remoteQuery facts.Query // the fact whose value is the file, when it is a remote called workflow (RemoteCalled)
}

// Barriers are the barriers the attacker of the run gets past: none in a
// run that adds no attacker (AddedAttacker).
func (c *RuleContext) Barriers() analysis.BarrierPasses { return c.access.Barriers() }

// InconclusiveDraft is a place a rule finds and examines where it cannot
// decide whether the workflow departs from Meta.Expected, or whether the
// consequence of one of its finding kinds can occur there: the value or
// the content that decides it is outside what the rule reads (a value an
// attacker may write, a setting, a file the rule does not read). KindID is of the rule's Meta.InconclusiveKinds.
// The engine makes of it a Finding whose certainty is CertaintyInconclusive.
// Related are the places that would take part in the consequence if the
// consequence occurred there, each with what the place would do, in no
// order that means anything; as Related of a FindingDraft, a place may be in
// the file of the value of a fact.
type InconclusiveDraft struct {
	KindID   InconclusiveKindID
	Location Location
	Note     string
	Related  []Related

	// anchor is what the engine tells the finding apart by, before the
	// count of the places with the same one (inconclusiveOf); relocateGap
	// sets it from where the place was, and empty is from Location
	anchor string
}

// Inconclusive hands an inconclusive place to the engine. Like Report, it is
// an internal error after Check has returned.
func (c *RuleContext) Inconclusive(d InconclusiveDraft) {
	if c.done {
		if c.run != nil && !c.run.finished {
			c.run.fail(c.rule, c.input.Name, "an inconclusive place was reported after Check returned")
		}
		return
	}
	d.Location.Via = slices.Clone(d.Location.Via)
	d.Location.vias = slices.Clone(d.Location.vias)
	d.Related = slices.Clone(d.Related)
	for i := range d.Related {
		d.Related[i].Location.Via = slices.Clone(d.Related[i].Location.Via)
	}
	c.gaps = append(c.gaps, d)
}

// Report hands a finding to the engine. It is copied, so the rule may
// change d afterwards. A report after Check has returned is an internal
// error.
func (c *RuleContext) Report(d FindingDraft) {
	if c.done {
		if c.run != nil && !c.run.finished {
			c.run.fail(c.rule, c.input.Name, "a finding was reported after Check returned")
		}
		return
	}
	f := copyFinding(d)
	f.Condition = withPullRequestTarget(c, c.pullRequestTarget, f)
	f.Condition = withAppChecks(c, c.appChecks, f)
	c.found = append(c.found, f)
}

func copyFinding(f FindingDraft) FindingDraft {
	f.Related = slices.Clone(f.Related)
	f.Evidence = slices.Clone(f.Evidence)
	for i := range f.Related {
		f.Related[i].Location.Via = slices.Clone(f.Related[i].Location.Via)
	}
	for i := range f.Evidence {
		f.Evidence[i].Location.Via = slices.Clone(f.Evidence[i].Location.Via)
	}
	f.Location.Via = slices.Clone(f.Location.Via)
	f.Location.vias = slices.Clone(f.Location.vias)
	if f.Fix != nil {
		x := *f.Fix
		x.SideEffects = slices.Clone(x.SideEffects)
		x.Edits = slices.Clone(x.Edits)
		for j := range x.Edits {
			e := &x.Edits[j]
			e.Old, e.New = bytes.Clone(e.Old), bytes.Clone(e.New)
		}
		f.Fix = &x
	}
	if f.NoFix != nil {
		n := *f.NoFix
		n.Queries = slices.Clone(n.Queries)
		f.NoFix = &n
	}
	if f.Condition != nil {
		c := f.Condition.clone()
		f.Condition = &c
	}
	return f
}

type runState struct {
	errors   []RunError
	finished bool
}

func (s *runState) fail(rule RuleID, input facts.InputPath, format string, a ...any) {
	s.errors = append(s.errors, RunError{Rule: rule, Input: input, Message: fmt.Sprintf(format, a...)})
}

// pass is one rule checked on one input: what the engine keeps the same
// while it finishes the rule's findings and checks their fixes.
type pass struct {
	st      *runState
	rule    Rule
	m       Meta // rule.Meta()
	input   Input
	inputs  Inputs // every input of the run, input among them
	rec     *facts.Recorder
	callers func() *taint.Callers // the callers among inputs
	quality bool                  // rule is a quality rule: no severity, fix or inconclusive place
	// barriers are what the attacker of the run gets past: the check of a
	// fix runs the rule again in the same attacker run table
	barriers analysis.BarrierPasses
}

// with is p reporting its errors to st: a check that runs at once with
// others has a runState of its own.
func (p pass) with(st *runState) pass {
	p.st = st
	return p
}

func (p pass) fail(format string, a ...any) {
	p.st.fail(p.m.ID, p.input.Name, format, a...)
}

// Run checks in with the rules of reg, one input and one rule at a time,
// in the order of their names, and writes the report. What the rules ask
// of r is asked once for each fact, and put in the report. A rule that
// returns an error or panics loses every finding it reported on that
// input, since those would look complete; the error is in the report. A
// rule is not stopped while it runs: when ctx is done, the rules not run
// yet are an internal error.
func Run(ctx context.Context, in Inputs, reg *Registry, r facts.Resolver) Report {
	return RunWithBarriers(ctx, in, reg, r, analysis.BarrierPasses{})
}

// RunWithBarriers is Run in which the attacker gets past g: a run that adds
// an attacker (AddedAttacker). Each rule reads g (RuleContext.Barriers),
// and the analyses read the ifs in the attacker run table of g.
func RunWithBarriers(ctx context.Context, in Inputs, reg *Registry, r facts.Resolver, g analysis.BarrierPasses) Report {
	in = withCallDiagnostics(in)
	st := &runState{}
	rec := facts.NewRecorder(r)
	rep := Report{Inputs: in.List, Complete: in.Complete, Excluded: in.Excluded, Reported: in.Reported, SkippedRules: reg.Skipped(), unreadCalls: unreadCallsOf(in)}
	for _, rule := range reg.rules {
		m := rule.Meta()
		if reg.IsQuality(m.ID) {
			rep.QualityRules = append(rep.QualityRules, m.ID)
			continue
		}
		rep.Rules = append(rep.Rules, RuleRef{ID: m.ID, Severity: m.Severity()})
	}
	composites := compositeReader(in, rec)
	callers, labelers := lazyCallersIn(ctx, in, composites, attacker.TableOf(g)), lazyLabelersIn(in, attacker.TableOf(g))
	k := &checker{reg: reg, in: in, rec: rec, st: st, callers: callers, rep: &rep, fps: map[Fingerprint]bool{}, reader: composites, barriers: g}
	for _, input := range in.List {
		if input.Tree == nil {
			continue
		}
		x := newIR(input.Name.String(), input.Tree, input.Workflow, input.ActionMetadata).WithCallers(callers).WithLabelers(labelers).WithComposite(ctx, composites).WithBarriers(g)
		k.checkFile(ctx, x, input, nil)
	}
	for _, r := range callers().Graph().Remotes() {
		top, found := in.Lookup(r.Top)
		if found != LookupFound {
			continue
		}
		x := ir.NewRemote(r).WithCallers(callers).WithLabelers(labelers).WithComposite(ctx, composites).WithBarriers(g)
		k.checkFile(ctx, x, top, r)
	}
	skipped := k.skipped
	if skipped > 0 {
		st.fail(RuleID{}, facts.InputPath{}, "the run was canceled (%v): %d checks were not run", ctx.Err(), skipped)
	}
	st.finished = true
	sortPlaces(&rep)
	rep.UnreadUses = unreadUsesOf(in, rec)
	rep.Facts = rec.Entries()
	rep.Errors = st.errors
	return rep
}

// compareFindings orders two findings, a and b with the fingerprints fa
// and fb: by input, place, rule, then fingerprint.
func compareFindings(a, b FindingDraft, fa, fb Fingerprint) int {
	if c := facts.CompareInputPaths(a.Location.File.Input, b.Location.File.Input); c != 0 {
		return c
	}
	if a.Location.Span.Start != b.Location.Span.Start {
		return a.Location.Span.Start - b.Location.Span.Start
	}
	if c := strings.Compare(a.Rule.s, b.Rule.s); c != 0 {
		return c
	}
	return strings.Compare(fa.hex, fb.hex)
}

// lazyCallers are the callers among in, read the first time an IR asks
// for them.
func lazyCallers(ctx context.Context, in Inputs, r *composite.Reader) func() *taint.Callers {
	return lazyCallersIn(ctx, in, r, attacker.Outsider)
}

// lazyCallersIn is lazyCallers, whose callers read ifs in the attacker run
// table t.
func lazyCallersIn(ctx context.Context, in Inputs, r *composite.Reader, t attacker.Table) func() *taint.Callers {
	var once sync.Once
	var c *taint.Callers
	return func() *taint.Callers {
		once.Do(func() { c = callersIn(ctx, in, r, t) })
		return c
	}
}

// compositeReader reads the actions the steps of in run: the action.yml
// inputs of in (an action under Excluded or Submodules, or not read, is
// none), and the actions of other repositories r answers
// (action.definition).
func compositeReader(in Inputs, r facts.Resolver) *composite.Reader {
	return composite.NewReader(func(target string) (facts.InputPath, *cst.Tree, *workflow.ActionMetadata, bool) {
		for _, n := range calls.TargetPaths(target) {
			if x, st := in.Lookup(n); st == LookupFound {
				if x.ActionMetadata == nil {
					return facts.InputPath{}, nil, nil, false // a workflow, or an input not read
				}
				return x.Name, x.Tree, x.ActionMetadata, true
			}
		}
		return facts.InputPath{}, nil, nil, false
	}, r)
}

// lazyLabelers are the steps of in that run actions/labeler on an
// attacker's pull request, read the first time an IR asks for them.
func lazyLabelers(in Inputs) func() *labeler.Table { return lazyLabelersIn(in, attacker.Outsider) }

// lazyLabelersIn is lazyLabelers, which reads ifs in the attacker run table
// at.
func lazyLabelersIn(in Inputs, at attacker.Table) func() *labeler.Table {
	var once sync.Once
	var t *labeler.Table
	return func() *labeler.Table {
		once.Do(func() { t = labelersIn(in, at) })
		return t
	}
}

// labelersOf are the steps of in that run actions/labeler on an
// attacker's pull request, with the configurations of in.Root; a
// configuration under Excluded is not read.
func labelersOf(in Inputs) *labeler.Table { return labelersIn(in, attacker.Outsider) }

// labelersIn is labelersOf, which reads ifs in the attacker run table at.
func labelersIn(in Inputs, at attacker.Table) *labeler.Table {
	var fs []calls.File
	for _, x := range in.List {
		if x.Workflow != nil || x.ActionMetadata != nil {
			fs = append(fs, calls.File{Name: x.Name, Tree: x.Tree, Workflow: x.Workflow, Action: x.ActionMetadata})
		}
	}
	return labeler.ReadIn(at, in.Repo, fs, in.Root, func(p facts.InputPath) bool {
		return slices.ContainsFunc(in.Excluded, func(e Exclude) bool { return e.covers(p.String()) })
	})
}

// unreadCallsOf are the inputs not read or not valid that an input of in
// calls by uses: ./… and $/…, directly or through inputs it calls, by
// caller: what the caller runs, the run could not check.
func unreadCallsOf(in Inputs) map[facts.InputPath][]facts.InputPath {
	state := map[facts.InputPath]InputState{}
	for _, x := range in.List {
		state[x.Name] = x.State
	}
	callees := map[facts.InputPath][]facts.InputPath{}
	for _, x := range in.List {
		if x.Tree == nil {
			continue
		}
		f := calls.File{Name: x.Name, Tree: x.Tree, Workflow: x.Workflow, Action: x.ActionMetadata}
		for _, target := range calls.Targets(f, in.Repo) {
			for _, n := range calls.TargetPaths(target) {
				if _, ok := state[n]; ok {
					callees[x.Name] = append(callees[x.Name], n)
					break // the input the target names
				}
			}
		}
	}
	out := map[facts.InputPath][]facts.InputPath{}
	for _, x := range in.List {
		seen := map[facts.InputPath]bool{x.Name: true}
		next := slices.Clone(callees[x.Name])
		for len(next) > 0 {
			n := next[0]
			next = next[1:]
			if seen[n] {
				continue
			}
			seen[n] = true
			if s := state[n]; s == InputStateUnreadable || s == InputStateInvalid {
				out[x.Name] = append(out[x.Name], n)
			}
			next = append(next, callees[n]...)
		}
	}
	return out
}

// callersOf are the callers among in: the calls of a workflow or an action
// of the inputs, by uses: ./… and $/…, and the calls of the remote called
// workflows r reads (addRemotes; none when r is nil).
func callersOf(ctx context.Context, in Inputs, r *composite.Reader) *taint.Callers {
	return callersIn(ctx, in, r, attacker.Outsider)
}

// callersIn is callersOf, whose callers read ifs in the attacker run table
// t.
func callersIn(ctx context.Context, in Inputs, r *composite.Reader, t attacker.Table) *taint.Callers {
	var fs []calls.File
	missing := len(in.Excluded) > 0 || len(in.Submodules) > 0 // a path left out, a submodule, or an input not read, may be a caller
	for _, x := range in.List {
		if x.Tree != nil {
			fs = append(fs, calls.File{Name: x.Name, Tree: x.Tree, Workflow: x.Workflow, Action: x.ActionMetadata})
		} else {
			missing = true
		}
	}
	g := calls.New(fs, in.Complete, missing, in.Repo)
	addRemotes(ctx, g, in, r)
	return taint.NewCallersIn(g, t)
}

// addRemotes adds to g the reusable workflows of other repositories that
// the jobs of the workflows of in call and r reads (composite.Reader.ExpandCall),
// one for each chain of calls. A file that is not a workflow, or that the
// model rejects, is not added: GitHub does not start it.
func addRemotes(ctx context.Context, g *calls.Graph, in Inputs, r *composite.Reader) {
	if r == nil {
		return
	}
	for _, x := range in.List {
		w := x.Workflow
		if x.Tree == nil || w == nil || w.Jobs.Status != workflow.Present {
			continue
		}
		for i := range w.Jobs.Value.Entries {
			j := &w.Jobs.Value.Entries[i].Value.Value
			if boundToInput(g, in, x.Name, j) {
				continue
			}
			e := r.ExpandCall(ctx, j)
			nodes := make([]calls.Node, len(e.Workflows))
			for k, c := range e.Workflows {
				if c.Workflow == nil || len(c.Diagnostics) > 0 || c.By == nil || !calledOnCall(c.Workflow) {
					continue
				}
				caller := calls.InputNode(x.Name)
				var parent *calls.RemoteCalled
				if c.Parent >= 0 {
					caller = nodes[c.Parent]
					parent, _ = caller.Remote()
				}
				if caller.IsZero() {
					continue // the workflow that calls it is not added
				}
				rc := &calls.RemoteCalled{Called: c, Top: x.Name, TopJob: j, Parent: parent}
				nodes[k] = g.AddRemote(rc, calls.Call{Caller: caller, Job: c.By, StepIndex: -1, With: c.By.With, Resolved: true})
			}
		}
	}
}

// boundToInput is whether the job j of the input x calls a workflow of the
// inputs in g, the graph of the inputs alone: by ./ or $/, or by the name
// of the repository of the run. Without the name of the repository, the
// graph binds any owner/repo whose path is an input (calls.New); such a job
// still calls the reusable workflow of another repository that it names.
func boundToInput(g *calls.Graph, in Inputs, x facts.InputPath, j *workflow.Job) bool {
	if j.Uses.Status != workflow.Present {
		return false
	}
	kind := j.Uses.Value.Kind
	if kind == workflow.UsesFolded {
		kind = j.Uses.Value.Folded
	}
	if kind == workflow.UsesRemote && in.Repo.IsZero() {
		return false
	}
	for _, c := range g.CalledBy(calls.InputNode(x)) {
		if _, input := c.Called.Input(); input && c.Job != nil && c.StepIndex < 0 && c.Job.ID.AsString() == j.ID.AsString() {
			return true
		}
	}
	return false
}

// calledOnCall is whether w can be called: it has the event
// workflow_call (GitHub does not start a call of another workflow).
func calledOnCall(w *workflow.Workflow) bool {
	if w.On.Status != workflow.Present {
		return false
	}
	_, ok := w.On.Value.Event(workflow.EventNameWorkflowCall)
	return ok
}

// withCallDiagnostics is in with what GitHub's reader rejects of the calls
// of workflows among its inputs (calls.Diagnostics) added to the callers'
// diagnostics, which makes them InputStateInvalid. in.List is copied when
// it changes. The check after a fix reads one file again, and compares it
// with the diagnostics of that file alone (Input.fileDiagnostics); the
// fixes do not write with, secrets or on.workflow_call.
func withCallDiagnostics(in Inputs) Inputs {
	var fs []calls.File
	for _, x := range in.List {
		if x.Tree != nil {
			fs = append(fs, calls.File{Name: x.Name, Tree: x.Tree, Workflow: x.Workflow, Action: x.ActionMetadata})
		}
	}
	ds := calls.Diagnostics(fs)
	if len(ds) == 0 {
		return in
	}
	l := slices.Clone(in.List)
	for i := range l {
		if d, ok := ds[l[i].Name]; ok {
			l[i].Diagnostics = append(slices.Clip(l[i].Diagnostics), d...)
			l[i].calls += len(d)
			l[i].State = InputStateInvalid
		}
	}
	in.List = l
	return in
}

func check(ctx context.Context, rule Rule, c *RuleContext) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return rule.Check(ctx, c)
}

// inconclusiveOf makes the findings whose certainty is
// CertaintyInconclusive of the inconclusive places that hold to the
// contract: of a kind the rule declares, at a location of an input, with
// related places in an input or in the file of the value of a fact. Each
// has the severity of the rule, the problem of the rule as its
// consequence, InconclusiveRemedy as its remedy, and a fingerprint whose
// anchor is the kind, the text of the place (identityText) and how many
// places of the same element with the same kind and text the rule reported
// before it; a place that relocateGap moved has the anchor remoteAnchor made
// of where it was.
// paths are the lookups the findings of the input share.
func (p pass) inconclusiveOf(paths *ir.Paths, gaps []InconclusiveDraft) []Finding {
	var out []Finding
	seen := map[string]int{}
	for _, g := range gaps {
		i := slices.IndexFunc(p.m.InconclusiveKinds, func(k InconclusiveKind) bool { return k.ID == g.KindID })
		if i < 0 {
			p.fail("an inconclusive place is of the kind %q, which the rule does not declare in InconclusiveKinds", g.KindID.s)
			continue
		}
		if l := g.Location; l.tree == nil || l.File.Input.IsZero() || l.File.Query != nil {
			p.fail("an inconclusive place at a location not made by At or AtSpan of an input")
			continue
		}
		if slices.ContainsFunc(g.Related, func(r Related) bool {
			return r.Location.tree == nil || r.Location.File.Input.IsZero() == (r.Location.File.Query == nil)
		}) {
			p.fail("a related place of an inconclusive place at a location not made by At or AtSpan of an input or of the value of a fact")
			continue
		}
		span, lines := g.Location.identityText()
		key := g.Location.keyPathIn(paths)
		base := g.anchor
		if base == "" {
			base = gapAnchor(g.KindID, span)
		}
		// counted in the element alone, as the fingerprint has its path: a
		// place of another element does not move the count
		seen[key.s+"\x00"+base]++
		note := g.Note
		if note == "" {
			note = p.m.InconclusiveKinds[i].Text
		}
		d := FindingDraft{Rule: p.m.ID, Location: g.Location, Related: g.Related, Anchor: fmt.Sprintf("%s#%d", base, seen[key.s+"\x00"+base])}
		fp, err := fingerprint(d, paths)
		if err != nil {
			p.fail("%v", err)
			continue
		}
		out = append(out, Finding{FindingDraft: d, Severity: p.m.Severity(), Certainty: CertaintyInconclusive, Fingerprint: fp,
			Consequence: p.m.Problem, Remedy: InconclusiveRemedy(p.m.ID), KeyPath: key, SpanText: span, SpanLines: lines,
			InconclusiveKind: g.KindID, Note: note})
	}
	return out
}

// gapAnchorHead starts the anchor of every inconclusive place
// (gapAnchor); finish refuses a finding whose Anchor starts with it, so that
// no finding a rule reports has the fingerprint of an inconclusive place.
const gapAnchorHead = "inconclusive\x00"

// gapAnchor is the anchor of an inconclusive place of the kind k whose
// text is span (identityText), before the count of the places with the
// same one.
func gapAnchor(k InconclusiveKindID, span string) string {
	return gapAnchorHead + k.s + "\x00" + span
}

// finish checks a finding against the registry of rules and the input,
// evaluates its condition and computes its fingerprint. A finding that
// breaks the contract is an internal error; a broken fix is dropped and the
// finding kept.
func (p pass) finish(ctx context.Context, paths *ir.Paths, budget *fixBudget, f FindingDraft) (Finding, bool) {
	fail, m := p.fail, p.m
	f.Rule = m.ID
	if f.Args == nil {
		fail("a finding without Args")
		return Finding{}, false
	}
	if strings.HasPrefix(f.Anchor, gapAnchorHead) {
		fail("a finding whose anchor starts as the anchor of an inconclusive place does (gapAnchor)")
		return Finding{}, false
	}
	if f.Args.Detected() == "" {
		fail("a finding that detects nothing (a report says what each finding detects)")
		return Finding{}, false
	}
	k, ok := m.kind(f.Args.KindID())
	if !ok {
		fail("the finding is of the kind %s, which the rule does not declare in FindingKinds", f.Args.KindID())
		return Finding{}, false
	}
	b, err := f.Args.MarshalJSON()
	var written struct {
		Kind string `json:"kind_id"`
	}
	if err != nil || json.Unmarshal(b, &written) != nil || written.Kind != f.Args.KindID().String() {
		fail("the args of the finding are not an object whose kind is %s (%v)", f.Args.KindID(), err)
		return Finding{}, false
	}
	for i, l := range f.locations() {
		// Evidence and Related may be in a file that is the value of a
		// fact (a remote action.yml); where the finding is, is an input
		inFact := i > 0 && l.File.Input.IsZero() && l.File.Query != nil
		if l.tree == nil || !inFact && (l.File.Input.IsZero() || l.File.Query != nil) {
			fail("a location not made by At or AtSpan of an input, or of the value of a fact in Evidence or Related")
			return Finding{}, false
		}
	}
	res := Finding{FindingDraft: f, Certainty: CertaintyConfirmed, Consequence: k.Consequence, Remedy: k.Remedy, fixTree: p.input.Tree}
	if !p.quality {
		res.Severity = k.Severity() // a quality rule's kinds have no CVSS
	}
	if f.Condition != nil {
		if _, err := f.Condition.MarshalJSON(); err != nil {
			fail("the condition cannot be written: %v", err)
			return Finding{}, false
		}
		for _, q := range f.Condition.Queries() {
			if !slices.Contains(k.FactKinds, q.Kind()) {
				fail("the condition asks about %s, which the kind %s does not declare in Facts", q.Kind(), k.ID)
				return Finding{}, false
			}
		}
		switch holds(ctx, *f.Condition, p.inputs, p.rec) {
		case expr.TruthFalse:
			return Finding{}, false
		case expr.TruthUnknown:
			res.Certainty = CertaintyConditional
		}
	}
	// past the bounds a fix is neither applied nor checked
	checked := budget.take(f.Fix, len(p.input.Tree.Bytes()))
	res.Fix, res.NoFix = p.checkFix(f, checked)
	if !checked && res.Fix != nil {
		res.Fix, res.NoFix = nil, &NoFix{Reason: ir.NoFixReasonTooManyFixes,
			Note: "the input has more fixes of the rule than are checked after they are applied; this one is not checked, so not given"}
	}
	fp, err := fingerprint(res.FindingDraft, paths)
	if err != nil {
		fail("%v", err)
		return Finding{}, false
	}
	res.Fingerprint = fp
	res.KeyPath = f.Location.keyPathIn(paths)
	res.SpanText, res.SpanLines = f.Location.identityText()
	return res, true
}

func (f FindingDraft) locations() []Location {
	ls := []Location{f.Location}
	for _, r := range f.Related {
		ls = append(ls, r.Location)
	}
	for _, r := range f.Evidence {
		ls = append(ls, r.Location)
	}
	return ls
}

// checkFix keeps the fix or the reason for none that holds to the
// contract: a finding of a kind that fixes gives either a fix its kind
// refers to whose edits apply to the input, or a reason, whose facts a fix
// of its kind needs; a finding of a kind that does not fix gives neither.
// When a finding of a kind that fixes breaks it, what it gave is dropped
// and it gets the reason manual, so that it still gives one or the other.
func (p pass) checkFix(f FindingDraft, apply bool) (*Fix, *NoFix) {
	m := p.m
	broken := &NoFix{Reason: ir.NoFixReasonManual, Note: "the fix of the rule, or its reason for none, is broken (see the errors of the report); fix it by hand"}
	fail := p.fail
	k, _ := m.kind(f.Args.KindID()) // finish has checked that the rule declares it
	if len(k.Fixes) == 0 {
		if f.Fix != nil || f.NoFix != nil {
			fail("the kind %s declares no Fixes, but the finding gives a fix or a reason for none", k.ID)
		}
		return nil, nil
	}
	if (f.Fix != nil) == (f.NoFix != nil) {
		given := "neither"
		if f.Fix != nil {
			given = "both"
		}
		fail("a finding of the kind %s, which fixes, must give either a fix or a reason for none, not %s", k.ID, given)
		return nil, broken
	}
	if f.NoFix != nil {
		if _, err := ir.ParseNoFixReason(f.NoFix.Reason.String()); err != nil || f.NoFix.Reason == ir.NoFixReasonTooManyFixes {
			fail("the reason for no fix is %v", f.NoFix.Reason)
			return nil, broken
		}
		for _, q := range f.NoFix.Queries {
			if _, err := facts.EncodeQuery(q); err != nil {
				fail("the reason for no fix names %v", err)
				return nil, broken
			}
			if !slices.Contains(m.fixFacts(k), q.Kind()) {
				fail("the reason for no fix names %s, which no fix of the kind %s needs", q.Kind(), k.ID)
				return nil, broken
			}
		}
		return nil, f.NoFix
	}
	x := f.Fix
	if !slices.Contains(k.Fixes, x.KindID) {
		fail("the fix %q is not of a kind the kind %s refers to", x.KindID, k.ID)
		return nil, broken
	}
	fk, _ := m.FixKind(x.KindID) // the registry has checked that the kinds refer to fixes of the rule
	if err := checkSideEffects(fk.Safety, x.SideEffects); err != nil {
		fail("the fix %s: %v", x.KindID, err)
		return nil, broken
	}
	if e := slices.IndexFunc(x.SideEffects, func(e ir.SideEffect) bool { return !slices.Contains(fk.PossibleSideEffects, e) }); e >= 0 {
		fail("the fix %s has the side effect %v, which its kind does not declare", x.KindID, x.SideEffects[e])
		return nil, broken
	}
	if apply {
		if _, err := edit.Apply(p.input.Tree, x.Edits); err != nil {
			fail("the fix %s does not apply: %v", x.KindID, err)
			return nil, broken
		}
	}
	if slices.ContainsFunc(x.Edits, func(e edit.Edit) bool { return !utf8.Valid(e.New) }) {
		fail("the fix %s writes bytes that are not UTF-8", x.KindID)
		return nil, broken
	}
	return x, nil
}

// holds evaluates c with the facts of rec and the inputs of in.
func holds(ctx context.Context, c Condition, in Inputs, rec *facts.Recorder) expr.Truth {
	fact := func(q facts.Query) facts.RawAnswer { return rec.Resolve(ctx, q) }
	look := func(name facts.InputPath) LookupState { _, s := in.Lookup(name); return s }
	return Eval(c, fact, look)
}

// identitiesOf are the identities of the findings in found that the engine
// would keep: those at a location of an input whose condition is not
// false.
func identitiesOf(ctx context.Context, in Inputs, rec *facts.Recorder, found []FindingDraft) map[identity]bool {
	ids := map[identity]bool{}
	p := ir.NewPaths()
	for _, f := range found {
		if f.Condition != nil && holds(ctx, *f.Condition, in, rec) == expr.TruthFalse {
			continue
		}
		if id, ok := identityOf(f, p); ok {
			ids[id] = true
		}
	}
	return ids
}

// maxCheckedFixes, maxCheckedBytes and maxCheckedReports bound the fixes
// of one rule on one input that are checked after they are applied: each
// check reads the input again and runs the rule on it again, so the time
// is their number times the size of the input and times what the rule
// reports again, its findings and their evidence and related places. A
// workflow written to stall the engine with fixes stops at them: GitHub
// runs a workflow of up to 500 KB (Actions limits), which gets 32 checks
// (of 512 000 bytes; 33 of 500 000 bytes). yaml/corpus has at most 78 fixes of uses in a file, and 99 in 100 of its
// files are under 64 KB, which gets all 256. maxCheckedReports is over the
// reports of the checks of the input of TestReparseBounded (500 000 bytes
// of steps of 34 bytes, a fix and no evidence on every step: about 14 700
// reports a check, 33 checks); with shorter steps, or with evidence, such
// an input gets fewer checks, and the fixes past them are not given. What
// the reports do not count (the work of an analysis that makes no report,
// the leaves of conditions, the inconclusive places) is not bound.
const (
	maxCheckedFixes   = 256
	maxCheckedBytes   = maxCheckedFixes << 16
	maxCheckedReports = 1 << 19
)

// fixBudget is what is left of the bounds for one rule on one input. A
// fix given by several findings (the same edits) is checked once, so it
// counts once. reports is what one check reports again.
type fixBudget struct {
	fixes, bytes, reports, perCheck int
	counted                         map[fixKey]bool
}

// newFixBudget is the bounds for the rule that reported found on an input.
func newFixBudget(found []FindingDraft) fixBudget {
	per := 0
	for _, f := range found {
		per += 1 + len(f.Evidence) + len(f.Related)
	}
	return fixBudget{maxCheckedFixes, maxCheckedBytes, maxCheckedReports, per, map[fixKey]bool{}}
}

// take says whether the fix of a finding of an input of size bytes is
// still checked (no fix is), and counts it when it is and was not counted
// yet.
func (b *fixBudget) take(x *Fix, size int) bool {
	if x == nil || b.counted[fixKeyOf(*x)] {
		return true
	}
	if b.fixes < 1 || size > b.bytes || b.perCheck > b.reports {
		return false
	}
	b.fixes--
	b.bytes -= size
	b.reports -= b.perCheck
	b.counted[fixKeyOf(*x)] = true
	return true
}

// fixKey is the same for two fixes exactly when they make the same edits
// under the same kind (fixKeyOf).
type fixKey struct{ s string }

func fixKeyOf(x Fix) fixKey {
	var b strings.Builder
	b.WriteString(x.KindID.s)
	for _, e := range x.Edits {
		fmt.Fprintf(&b, "\x00%d:%d:%q", e.Span.Start, e.Span.End, e.New)
	}
	return fixKey{b.String()}
}

// checkApplied keeps the fixes of results that hold after they are applied
// (the check after a fix); finish has already put the fixes past
// maxCheckedFixes aside (NoFixReasonTooManyFixes). A fix given by several results is
// applied and checked once; it is kept for each result it closes. The
// checks are independent, so they run at once, one for each CPU; what they
// find is put in the order of results.
func (p pass) checkApplied(ctx context.Context, before map[identity]bool, results []Finding) {
	var fixes []Fix                    // one of each fixKey, in the order first given
	indexOf := map[fixKey]int{}        // the index in fixes of each fixKey
	fixOf := make([]int, len(results)) // the index in fixes of each result's fix; -1: none
	for i := range results {
		fixOf[i] = -1
		x := results[i].Fix
		if x == nil {
			continue
		}
		k, ok := indexOf[fixKeyOf(*x)]
		if !ok {
			k = len(fixes)
			indexOf[fixKeyOf(*x)] = k
			fixes = append(fixes, *x)
		}
		fixOf[i] = k
	}
	type outcome struct {
		after  map[identity]bool // the identities of the findings on the fixed input
		msg    string            // what is wrong other than a finding left
		errors []RunError        // reported after Check returned, on the fixed input
	}
	outcomes := make([]outcome, len(fixes))
	deps := &dependentRuns{p: p, runs: map[facts.InputPath]*dependentRun{}}
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(runtime.GOMAXPROCS(0), len(fixes)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range next {
				local := &runState{}
				after, msg := p.with(local).applyFix(ctx, before, fixes[k], deps)
				local.finished = true
				outcomes[k] = outcome{after, msg, local.errors}
			}
		}()
	}
	for k := range fixes {
		next <- k
	}
	close(next)
	wg.Wait()
	p.st.errors = append(p.st.errors, deps.finish()...)
	reported := make([]bool, len(fixes))
	for i, k := range fixOf {
		if k < 0 {
			continue
		}
		o, res := outcomes[k], &results[i]
		if !reported[k] {
			p.st.errors = append(p.st.errors, o.errors...)
			reported[k] = true
		}
		msg := o.msg
		if self, _ := identityOf(res.FindingDraft, ir.NewPaths()); msg == "" && o.after[self] {
			msg = "does not close its finding"
		}
		if msg != "" {
			p.fail("the fix %s of %s: %s", fixes[k].KindID, res.Fingerprint, msg)
			// the fix is dropped: the finding says so, as a rule that
			// fixes gives a fix or a reason
			res.Fix, res.NoFix = nil, &NoFix{Reason: ir.NoFixReasonManual, Note: "the fix did not hold when it was checked after it was applied (see the errors of the report); fix it by hand"}
		}
	}
}

// applyFix applies x to input, reads the input again and runs the rule on
// it with the same facts, and on the inputs it calls (calls.Graph). It
// gives the identities of the findings on the fixed input, and says what
// is wrong other than a finding the fix leaves: that the rule makes a
// finding it did not make before, there or in an input it calls, that the
// input has a diagnostic it did not have, or that the rule fails; or
// nothing. A
// report the rule makes after its Check returns goes to p.st.
func (p pass) applyFix(ctx context.Context, before map[identity]bool, x Fix, deps *dependentRuns) (map[identity]bool, string) {
	applied, err := edit.Apply(p.input.Tree, x.Edits)
	if err != nil { // checkFix kept only fixes that apply
		return nil, fmt.Sprintf("does not apply: %v", err)
	}
	after := readTree(p.input.Name, p.input.InputKind, applied.Tree)
	if d, ok := newDiagnostic(p.input.fileDiagnostics(), after.Diagnostics); ok {
		return nil, "makes a new diagnostic: " + d.Msg
	}
	in2 := p.inputs
	in2.List = slices.Clone(p.inputs.List)
	if i, ok := slices.BinarySearchFunc(in2.List, p.input.Name, func(x Input, n facts.InputPath) int { return facts.CompareInputPaths(x.Name, n) }); ok {
		in2.List[i] = after
	}
	cl := callersIn(ctx, in2, compositeReader(in2, p.rec), attacker.TableOf(p.barriers))
	callers := func() *taint.Callers { return cl }
	got, err := p.runOn(ctx, after, in2, callers)
	if err != nil {
		return nil, fmt.Sprintf("the rule fails on the fixed input: %v", err)
	}
	if slices.ContainsFunc(slices.Collect(maps.Keys(got)), func(id identity) bool { return !before[id] }) {
		return got, "makes a new finding"
	}
	// the workflows and actions the fixed input calls read their events and
	// inputs from it: the fix must not make a finding there either
	for _, node := range cl.Graph().Dependents(calls.InputNode(after.Name)) {
		name, ok := node.Input()
		if !ok {
			continue
		}
		dep, _ := in2.Lookup(name)
		if dep.Tree == nil || !slices.Contains(p.m.Targets, dep.InputKind) {
			continue
		}
		was, err := deps.before(ctx, dep)
		if err != nil {
			return nil, fmt.Sprintf("the rule fails on %s: %v", name, err)
		}
		now, err := p.runOn(ctx, dep, in2, callers)
		if err != nil {
			return nil, fmt.Sprintf("the rule fails on %s after the fix: %v", name, err)
		}
		if slices.ContainsFunc(slices.Collect(maps.Keys(now)), func(id identity) bool { return !was[id] }) {
			return got, "makes a new finding in " + name.String() + ", which it calls"
		}
	}
	return got, ""
}

// dependentRuns are the runs of the rule, before any fix, on the inputs
// that the input of p calls: the same for every fix of the input, so each
// is made once for all the fixes that checkApplied checks at once.
type dependentRuns struct {
	p    pass
	mu   sync.Mutex
	runs map[facts.InputPath]*dependentRun
}

// dependentRun is the run of the rule on one called input, with the errors
// that the rule reports there after its Check returns.
type dependentRun struct {
	once sync.Once
	st   runState
	ids  map[identity]bool
	err  error
}

// before is the identities of the findings of the rule on dep, an input
// that the input of d.p calls, before any fix.
func (d *dependentRuns) before(ctx context.Context, dep Input) (map[identity]bool, error) {
	d.mu.Lock()
	r, ok := d.runs[dep.Name]
	if !ok {
		r = &dependentRun{}
		d.runs[dep.Name] = r
	}
	d.mu.Unlock()
	r.once.Do(func() { r.ids, r.err = d.p.with(&r.st).runOn(ctx, dep, d.p.inputs, d.p.callers) })
	return r.ids, r.err
}

// finish ends the runs and gives the errors that the rule reported in
// them after its Check returned, in the order of the names of the inputs.
func (d *dependentRuns) finish() []RunError {
	var out []RunError
	for _, name := range slices.SortedFunc(maps.Keys(d.runs), facts.CompareInputPaths) {
		r := d.runs[name]
		r.st.finished = true
		out = append(out, r.st.errors...)
	}
	return out
}

// runOn runs the rule on the input x of in, whose callers are callers, and
// gives the identities of its findings.
func (p pass) runOn(ctx context.Context, x Input, in Inputs, callers func() *taint.Callers) (map[identity]bool, error) {
	c := &RuleContext{input: x, tree: x.Tree, workflow: x.Workflow, action: x.ActionMetadata,
		Resolver: p.rec, inputs: in, repo: in.Repo, access: newIR(x.Name.String(), x.Tree, x.Workflow, x.ActionMetadata).WithCallers(callers).WithLabelers(lazyLabelersIn(in, attacker.TableOf(p.barriers))).WithComposite(ctx, compositeReader(in, p.rec)).WithBarriers(p.barriers).RuleAccess(), run: p.st, rule: p.m.ID,
		pullRequestTarget: pullRequestTargetKinds(p.m, x.Workflow), appChecks: appChecksKinds(p.m, x.Workflow)}
	err := check(ctx, p.rule, c)
	c.done = true
	if err != nil {
		return nil, err
	}
	return identitiesOf(ctx, in, p.rec, c.found), nil
}

// newDiagnostic is a diagnostic of after of a code that after has more of
// than before. Positions are not compared: a fix moves them.
func newDiagnostic(before, after []workflow.Diagnostic) (workflow.Diagnostic, bool) {
	n := map[workflow.Code]int{}
	for _, d := range before {
		n[d.Code]++
	}
	for _, d := range after {
		if n[d.Code] == 0 {
			return d, true
		}
		n[d.Code]--
	}
	return workflow.Diagnostic{}, false
}

// sortPlaces puts the findings and the quality findings of rep in the
// order of their places.
func sortPlaces(rep *Report) {
	slices.SortFunc(rep.Findings, func(a, b Finding) int {
		return compareFindings(a.FindingDraft, b.FindingDraft, a.Fingerprint, b.Fingerprint)
	})
	slices.SortFunc(rep.QualityFindings, func(a, b QualityFinding) int {
		return compareFindings(a.FindingDraft, b.FindingDraft, a.Fingerprint, b.Fingerprint)
	})
}

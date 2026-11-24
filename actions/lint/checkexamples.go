package lint

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// ExampleWhat is which declaration an example shows.
type ExampleWhat uint8

const (
	ExampleTruePositive ExampleWhat = iota
	ExampleTrueNegative
	ExampleFalsePositive
	ExampleUndetected
	ExampleInconclusive
)

var exampleWhatNames = [...]string{"true-positive", "true-negative", "false-positive", "undetected", "inconclusive"}

func (w ExampleWhat) String() string { return exampleWhatNames[w] }

// ExampleRun is a run of an example: with its facts, or with Flipped
// answered with the answers that remove the finding.
type ExampleRun struct {
	Flipped []facts.Kind
	Added   []AddedAttacker // the attackers the run adds as a run of the linter adds them (RunExampleMarked, RunAdded); none for a run that adds none, and for RunExampleAdded
	Inputs  Inputs
	Report  Report
}

// FactLines are the facts the run asked, in the order of Report.Facts
// (sorted by the query, so that the lines are the same each run), each as
// <fact> = <answer>: the value found, absent, or unknown; a fact of a kind
// of Flipped is marked as answered with the answer that removes the finding.
func (r ExampleRun) FactLines() []string {
	out := []string{}
	for _, e := range r.Report.Facts {
		a := "unknown"
		switch e.RawAnswer.State {
		case facts.StateFound:
			a = string(e.RawAnswer.Value)
		case facts.StateAbsent:
			a = "absent"
		}
		l := facts.QueryText(e.Query) + " = " + a
		if slices.Contains(r.Flipped, e.Query.Kind()) {
			l += " (the answer that removes the finding)"
		}
		out = append(out, l)
	}
	return out
}

// ExampleCheck is what came of running the example of a declaration.
type ExampleCheck struct {
	Rule        RuleID
	What        ExampleWhat
	Declaration fmt.Stringer // the ID of the kind of finding, the form or the kind of place
	Text        string       // what the declaration says
	Example     Example
	Runs        []ExampleRun
	Holds       bool
	Why         string // why it does not hold; empty when it does
}

// CheckExamples runs each example of every declaration of the rules only
// (every rule when none), each rule alone, with the facts the example has,
// and tells whether it is what the declaration says:
//
//   - a true positive gives a finding of its kind (with its kind's
//     FactKinds the other way, when not with the example's facts); one
//     whose notes name added attackers gives no finding of the rule in
//     the run that adds none, and a finding of its kind marked with each
//     of them in the run that adds it alone (RunAdded);
//   - a true negative gives no finding;
//   - a false positive form's example gives a finding of one of its kinds,
//     and none with each of its FactKinds the other way; a form of no
//     FactKinds whose kinds hold only on the answers that remove the
//     finding gives it with the kinds' FactKinds the other way, as a true
//     positive;
//   - an undetected form's gives no finding (of its FindingKinds, when it
//     has them), and another rule's disposition's rule gives one; one of
//     no-added-gain gives no inconclusive place either, as the form says
//     the flaw adds nothing to what an attacker gets;
//   - an inconclusive kind's gives a place of that kind and no other.
//
// A run with an error does not hold. It runs every example each call:
// a test of the rules calls it, and --examples. It panics on examples the
// registry refuses (exampledMeta): the examples of package rules are
// embedded, and its TestExamples checks them.
func (r *Registry) CheckExamples(ctx context.Context, only ...RuleID) []ExampleCheck {
	var out []ExampleCheck
	for _, rule := range r.rules {
		if len(only) != 0 && !slices.Contains(only, rule.Meta().ID) {
			continue
		}
		m, err := r.exampledMeta(rule)
		if err != nil {
			panic(err)
		}
		check := func(c ExampleCheck, runs ...[]facts.Kind) (ExampleCheck, bool) {
			for _, flip := range runs {
				run, err := r.runExample(ctx, m.ID, c.Example, flip)
				if err != nil {
					c.Why = err.Error()
					return c, false
				}
				if len(run.Report.Errors) != 0 {
					c.Runs = append(c.Runs, run)
					c.Why = fmt.Sprintf("errors %+v", run.Report.Errors)
					return c, false
				}
				c.Runs = append(c.Runs, run)
			}
			return c, true
		}
		for _, k := range m.FindingKinds {
			for _, e := range k.TruePositives {
				if len(e.Notes.AddedAttackers) != 0 {
					out = append(out, r.checkAddedTruePositive(ctx, m, k, e))
					continue
				}
				c, ok := check(ExampleCheck{Rule: m.ID, What: ExampleTruePositive, Declaration: k.ID, Text: k.Consequence, Example: e}, nil)
				if ok && !slices.Contains(kindsOf(c.Runs[0].Report), k.ID) && len(k.FactKinds) != 0 {
					c.Runs = nil
					c, ok = check(c, k.FactKinds)
				}
				if ok {
					got := kindsOf(c.Runs[len(c.Runs)-1].Report)
					c.Holds = slices.Contains(got, k.ID)
					if !c.Holds {
						c.Why = fmt.Sprintf("no finding of %s: findings %v", k.ID, got)
					}
				}
				out = append(out, c)
			}
			for _, e := range k.TrueNegatives {
				c, ok := check(ExampleCheck{Rule: m.ID, What: ExampleTrueNegative, Declaration: k.ID, Text: TrueNegativeText(k.FindingText), Example: e}, nil)
				if ok {
					got := kindsOf(c.Runs[0].Report)
					c.Holds = len(got) == 0
					if !c.Holds {
						c.Why = fmt.Sprintf("findings %v", got)
					}
				}
				out = append(out, c)
			}
		}
		for _, f := range m.FalsePositiveForms {
			for _, e := range f.Examples {
				if len(f.AddedAttackers) != 0 {
					out = append(out, r.checkAddedFalsePositive(ctx, m, f, e))
					continue
				}
				runs := [][]facts.Kind{nil}
				if len(f.FactKinds) != 0 {
					runs = append(runs, f.FactKinds)
				}
				reported := func(rep Report) bool {
					return slices.ContainsFunc(kindsOf(rep), func(k FindingKindID) bool { return slices.Contains(f.FindingKinds, k) })
				}
				c, ok := check(ExampleCheck{Rule: m.ID, What: ExampleFalsePositive, Declaration: f.ID, Text: f.Text, Example: e}, runs...)
				if flip := m.FalsePositiveFlip(f); ok && !reported(c.Runs[0].Report) && len(f.FactKinds) == 0 && len(flip) != 0 {
					c.Runs = nil
					c, ok = check(c, flip)
				}
				if ok {
					switch {
					case !reported(c.Runs[0].Report):
						c.Why = fmt.Sprintf("none of %v: findings %v", f.FindingKinds, kindsOf(c.Runs[0].Report))
					case len(c.Runs) == 2 && reported(c.Runs[1].Report):
						c.Why = fmt.Sprintf("still with %v the other way: findings %v", f.FactKinds, kindsOf(c.Runs[1].Report))
					default:
						c.Holds = true
					}
				}
				out = append(out, c)
			}
		}
		for _, l := range m.UndetectedForms {
			for _, e := range l.Examples {
				c, ok := check(ExampleCheck{Rule: m.ID, What: ExampleUndetected, Declaration: l.ID, Text: l.Text, Example: e}, nil)
				if ok {
					got := kindsOf(c.Runs[0].Report)
					c.Holds = !slices.ContainsFunc(got, func(k FindingKindID) bool { return slices.Contains(m.UndetectedKinds(l), k) })
					if !c.Holds {
						c.Why = fmt.Sprintf("findings %v", got)
					}
					if gaps := c.Runs[0].Report.FindingsWith(CertaintyInconclusive); c.Holds && l.Disposition.kind == dispositionNoAddedGain && len(gaps) != 0 {
						var ids []string
						for _, g := range gaps {
							ids = append(ids, g.InconclusiveKind.String())
						}
						c.Holds = false
						c.Why = "inconclusive " + strings.Join(ids, ", ")
					}
					if c.Holds {
						c.Holds, c.Why = r.checkAdded(ctx, m.ID, e, l.AddedAttackers, m.UndetectedKinds(l))
					}
					if other, isOther := l.Disposition.OtherRule(); c.Holds && isOther {
						run, err := r.runExample(ctx, other, e, nil)
						if err != nil || len(kindsOf(run.Report)) == 0 {
							c.Holds = false
							c.Why = fmt.Sprintf("it is %s's, but %s reports nothing on it", other, other)
						}
					}
				}
				out = append(out, c)
			}
		}
		for _, k := range m.InconclusiveKinds {
			for _, e := range k.Examples {
				c, ok := check(ExampleCheck{Rule: m.ID, What: ExampleInconclusive, Declaration: k.ID, Text: k.Text, Example: e}, nil)
				if ok {
					var others []string
					n := 0
					for _, g := range c.Runs[0].Report.FindingsWith(CertaintyInconclusive) {
						if g.InconclusiveKind == k.ID {
							n++
						} else {
							others = append(others, g.InconclusiveKind.String())
						}
					}
					c.Holds = n > 0 && len(others) == 0
					if !c.Holds {
						c.Why = fmt.Sprintf("%d places of %s, and of %s", n, k.ID, strings.Join(others, ", "))
					}
				}
				out = append(out, c)
			}
		}
	}
	return out
}

// TrueNegativeText is what a true negative of the kinds ks shows: that the
// rule reports no finding on the input, and what a finding of each kind
// would say, its arguments left as {name}, as no finding fills them. The
// consequence of a kind would read as if it came about on the input. A true
// negative is of several kinds when their fixes are the same input.
func TrueNegativeText(ks ...FindingText) string {
	s := "the rule reports no finding on the input of the example"
	args := false
	for _, k := range ks {
		s += "; a finding of " + k.ID.String() + " would say: " + k.Detected
		args = args || len(k.Arguments) != 0
	}
	if args {
		s += " (a name in braces is an argument of the finding)"
	}
	return s
}

// RunExample runs every rule of r on e, with e's facts, those of the kinds
// flip answered with the answers that remove the finding: the example
// catalog shows what every rule gives on an example.
func (r *Registry) RunExample(ctx context.Context, e Example, flip []facts.Kind) (ExampleRun, error) {
	in, err := e.Inputs()
	if err != nil {
		return ExampleRun{}, err
	}
	res, err := e.resolver()
	if err != nil {
		return ExampleRun{}, err
	}
	if len(flip) != 0 {
		res = flipped{flip, res}
	}
	return ExampleRun{Flipped: slices.Clone(flip), Inputs: in, Report: Run(ctx, in, r, res)}, nil
}

// RunExampleAdded is RunExample with the attacker v added, the facts as
// e has them: whether the rule reports a form on its example when the
// run adds v (UndetectedForm.AddedAttackers).
func (r *Registry) RunExampleAdded(ctx context.Context, e Example, v AddedAttacker) (ExampleRun, error) {
	in, err := e.Inputs()
	if err != nil {
		return ExampleRun{}, err
	}
	res, err := e.resolver()
	if err != nil {
		return ExampleRun{}, err
	}
	return ExampleRun{Inputs: in, Report: RunWithBarriers(ctx, in, r, res, r.barriersOf([]AddedAttacker{v}))}, nil
}

// RunExampleMarked is RunExample with the attacker v added as a run of
// the linter adds it (RunAdded): the places of the run that adds none, and
// those only the added run gives, marked with v.
func (r *Registry) RunExampleMarked(ctx context.Context, e Example, v AddedAttacker) (ExampleRun, error) {
	in, err := e.Inputs()
	if err != nil {
		return ExampleRun{}, err
	}
	res, err := e.resolver()
	if err != nil {
		return ExampleRun{}, err
	}
	return ExampleRun{Added: []AddedAttacker{v}, Inputs: in, Report: RunAdded(ctx, in, r, res, []AddedAttacker{v})}, nil
}

// RunExampleAs runs every rule of r on e the way run was: adding its
// attacker (RunExampleMarked), or with its facts flipped (RunExample).
// The example catalog shows a run of a declaration with every rule so.
func (r *Registry) RunExampleAs(ctx context.Context, e Example, run ExampleRun) (ExampleRun, error) {
	if len(run.Added) != 0 {
		return r.RunExampleMarked(ctx, e, run.Added[0])
	}
	return r.RunExample(ctx, e, run.Flipped)
}

// runExampleMarked runs the rule id alone on e, adding v as a run of the
// linter adds it (RunExampleMarked).
func (r *Registry) runExampleMarked(ctx context.Context, id RuleID, e Example, v AddedAttacker) (ExampleRun, error) {
	one, err := r.Select(Only(Selector{id}), FactSources{})
	if err != nil {
		return ExampleRun{}, err
	}
	return one.RunExampleMarked(ctx, e, v)
}

// runExampleAdded runs the rule id alone on e, adding v (RunExampleAdded).
func (r *Registry) runExampleAdded(ctx context.Context, id RuleID, e Example, v AddedAttacker) (ExampleRun, error) {
	one, err := r.Select(Only(Selector{id}), FactSources{})
	if err != nil {
		return ExampleRun{}, err
	}
	return one.RunExampleAdded(ctx, e, v)
}

// runExample runs the rule id alone on e (RunExample).
func (r *Registry) runExample(ctx context.Context, id RuleID, e Example, flip []facts.Kind) (ExampleRun, error) {
	one, err := r.Select(Only(Selector{id}), FactSources{})
	if err != nil {
		return ExampleRun{}, err
	}
	return one.RunExample(ctx, e, flip)
}

// flipped answers the kinds with the answer that removes the finding, and
// the rest as base does.
type flipped struct {
	kinds []facts.Kind
	base  facts.Resolver
}

func (f flipped) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if slices.Contains(f.kinds, q.Kind()) {
		for _, i := range facts.Kinds() {
			if i.Kind == q.Kind() {
				v := "true"
				if string(i.AssumedValue) == "true" {
					v = "false"
				}
				return facts.RawAnswer{State: facts.StateFound, Value: []byte(v)}
			}
		}
	}
	return f.base.Resolve(ctx, q)
}

// kindsOf are the finding kinds of the findings of rep, those whose
// certainty is CertaintyInconclusive left out, and of its quality findings.
func kindsOf(rep Report) []FindingKindID {
	out := []FindingKindID{}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		out = append(out, f.Args.KindID())
	}
	for _, f := range rep.QualityFindings {
		out = append(out, f.Args.KindID())
	}
	return out
}

// FalsePositiveFlip is the kinds of facts a check of the example of f, a
// form of m, answers the other way when the example alone gives none of
// its kinds: the FactKinds of its kinds, when f has none of its own.
func (m Meta) FalsePositiveFlip(f FalsePositiveForm) []facts.Kind {
	if len(f.FactKinds) != 0 {
		return nil
	}
	var out []facts.Kind
	for _, k := range m.FindingKinds {
		if !slices.Contains(f.FindingKinds, k.ID) {
			continue
		}
		for _, q := range k.FactKinds {
			if !slices.Contains(out, q) {
				out = append(out, q)
			}
		}
	}
	return out
}

// checkAdded is whether the rule id reports a finding of kinds on e in a
// run that adds each of vs, and why not. A finding of a run that adds
// variables-writer or secrets-writer must have a reference of vars or of
// secrets at its place or in its evidence: the attacker writes those
// values and nothing else.
func (r *Registry) checkAdded(ctx context.Context, id RuleID, e Example, vs []AddedAttacker, kinds []FindingKindID) (bool, string) {
	for _, v := range vs {
		run, err := r.runExampleAdded(ctx, id, e, v)
		if err != nil {
			return false, err.Error()
		}
		if len(run.Report.Errors) != 0 {
			return false, fmt.Sprintf("adding %s: errors %+v", v, run.Report.Errors)
		}
		n := 0
		for _, f := range run.Report.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
			if !slices.Contains(kinds, f.Args.KindID()) {
				continue
			}
			n++
			if ctx := valueContext(v); ctx != "" && !fromContext(run.Inputs, f, ctx) {
				return false, fmt.Sprintf("adding %s: a finding of %s at %q, whose evidence has no reference of %s", v, f.Args.KindID(), placeText(run.Inputs, f.Location), ctx)
			}
		}
		if n == 0 {
			return false, fmt.Sprintf("adding %s: no finding of %v: findings %v", v, kinds, kindsOf(run.Report))
		}
	}
	return true, ""
}

// checkAddedTruePositive checks the true positive e of the kind k of the
// rule of m, whose notes name added attackers: the run that adds none
// reports no finding of the rule on e, and the run that adds each of them
// alone (RunAdded) reports a finding of k marked with it, whose place or
// evidence has a reference of the context the attacker writes, if any
// (checkAdded).
func (r *Registry) checkAddedTruePositive(ctx context.Context, m Meta, k FindingKind, e Example) ExampleCheck {
	c := ExampleCheck{Rule: m.ID, What: ExampleTruePositive, Declaration: k.ID, Text: k.Consequence, Example: e}
	run, err := r.runExample(ctx, m.ID, e, nil)
	if err != nil {
		c.Why = err.Error()
		return c
	}
	c.Runs = append(c.Runs, run)
	if len(run.Report.Errors) != 0 {
		c.Why = fmt.Sprintf("errors %+v", run.Report.Errors)
		return c
	}
	if got := kindsOf(run.Report); len(got) != 0 {
		c.Why = fmt.Sprintf("a run that adds no attacker reports findings %v", got)
		return c
	}
	for _, v := range e.Notes.AddedAttackers {
		run, err := r.runExampleMarked(ctx, m.ID, e, v)
		if err != nil {
			c.Why = err.Error()
			return c
		}
		c.Runs = append(c.Runs, run)
		if len(run.Report.Errors) != 0 {
			c.Why = fmt.Sprintf("adding %s: errors %+v", v, run.Report.Errors)
			return c
		}
		found := false
		for _, f := range run.Report.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
			if f.Args.KindID() != k.ID || !slices.Contains(f.AddedAttackers, v) {
				continue
			}
			if written := valueContext(v); written != "" && !fromContext(run.Inputs, f, written) {
				c.Why = fmt.Sprintf("adding %s: a finding of %s at %q, whose evidence has no reference of %s", v, k.ID, placeText(run.Inputs, f.Location), written)
				return c
			}
			found = true
		}
		if !found {
			c.Why = fmt.Sprintf("adding %s: no finding of %s marked %s: findings %v", v, k.ID, v, kindsOf(run.Report))
			return c
		}
	}
	c.Holds = true
	return c
}

// checkAddedFalsePositive checks the example e of the false positive form
// f, which a run reports only when it adds one of f.AddedAttackers: the run
// that adds none reports none of f.FindingKinds on e, and each run that
// adds one does.
func (r *Registry) checkAddedFalsePositive(ctx context.Context, m Meta, f FalsePositiveForm, e Example) ExampleCheck {
	c := ExampleCheck{Rule: m.ID, What: ExampleFalsePositive, Declaration: f.ID, Text: f.Text, Example: e}
	run, err := r.runExample(ctx, m.ID, e, nil)
	if err != nil {
		c.Why = err.Error()
		return c
	}
	c.Runs = append(c.Runs, run)
	if got := kindsOf(run.Report); slices.ContainsFunc(got, func(k FindingKindID) bool { return slices.Contains(f.FindingKinds, k) }) {
		c.Why = fmt.Sprintf("a run that adds no attacker reports %v", got)
		return c
	}
	c.Holds, c.Why = r.checkAdded(ctx, m.ID, e, f.AddedAttackers, f.FindingKinds)
	return c
}

// valueContext is the context whose values the attacker v writes: vars or
// secrets; empty for an attacker who writes neither.
func valueContext(v AddedAttacker) string {
	switch v {
	case AddedAttackerVariablesWriter:
		return "vars"
	case AddedAttackerSecretsWriter:
		return "secrets"
	}
	return ""
}

// placeText is the text of the place at in the input of in it is in; empty
// when the input is not there.
func placeText(in Inputs, at Location) string {
	i, state := in.Lookup(at.File.Input)
	if state != LookupFound || i.Tree == nil {
		return ""
	}
	b := i.Tree.Bytes()
	if at.Span.Start < 0 || at.Span.End > len(b) || at.Span.Start > at.Span.End {
		return ""
	}
	return string(b[at.Span.Start:at.Span.End])
}

// fromContext is whether the place of f, or a place of its evidence, is a
// reference of the context ctx (vars, secrets).
func fromContext(in Inputs, f Finding, ctx string) bool {
	at := []Location{f.Location}
	for _, e := range f.Evidence {
		at = append(at, e.Location)
	}
	for _, l := range at {
		t := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(placeText(in, l), "${{")))
		if strings.HasPrefix(t, ctx+".") {
			return true
		}
	}
	return false
}

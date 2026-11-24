package cli

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// view is a report as the text shows it: the confirmed findings in folds,
// the conditional ones by what
// decides them, and the inputs not read by why.
type view struct {
	confirmed    []fold
	conditional  []ruleConditionals
	inconclusive []ruleInconclusive
	inputs       []inputGroup
}

// ruleInconclusive are how many places of each kind a rule did not examine.
type ruleInconclusive struct {
	rule  lint.RuleID
	kinds []kindCount
}

type kindCount struct {
	kind lint.InconclusiveKindID
	n    int
}

// fold is confirmed findings the text shows under one head: the same rule,
// severity, kind, kind of fix, and reason and note for no fix. Its rows are its findings by what they detect, the most first.
type fold struct {
	rule     lint.RuleID
	severity lint.Severity
	kind     lint.FindingKindID
	fix      *fixLine // by kind, as the registry titles it
	noFix    *lint.NoFix
	facts    []factLine                      // the facts found out that its findings' conditions rest on, once each
	factsOf  map[lint.Fingerprint][]factLine // those of each finding
	impact   string                          // of its kind: the same for each of its findings
	remedy   string                          // of its kind, too
	rows     []group
}

// count is how many findings f has.
func (f fold) count() int {
	n := 0
	for _, g := range f.rows {
		n += len(g.results)
	}
	return n
}

// group is the findings of a fold that detect one thing: a row of the fold.
type group struct {
	detected string
	results  []lint.Finding // in the order of their places
}

// factLine is a fact found out that a condition rests on, and its answer.
type factLine struct {
	query facts.Query
	raw   facts.RawAnswer
}

func (x factLine) text() string {
	v := "absent"
	if x.raw.State == facts.StateFound {
		v = clean(string(x.raw.Value))
	}
	from := map[facts.Source]string{facts.SourceFile: "the file of facts", facts.SourceGitHub: "the GitHub API"}[x.raw.Source]
	if from == "" {
		return queryText(x.query) + " = " + v
	}
	return queryText(x.query) + " = " + v + " (" + from + ")"
}

// factsOf are the facts found out that the condition of r rests on: asked
// and known.
func factsOf(r lint.Finding, known map[string]facts.RawAnswer) []factLine {
	if r.Condition == nil {
		return nil
	}
	var out []factLine
	for _, q := range r.Condition.Queries() {
		if raw, ok := known[queryKey(q)]; ok && raw.State != facts.StateUnknown {
			out = append(out, factLine{q, raw})
		}
	}
	return out
}

type fixLine struct {
	kind        lint.FixKindID
	safety      lint.Safety
	title       string
	sideEffects []ir.SideEffect // in the order of the values, each once
}

// addSideEffects adds those of es that x does not have.
func (x *fixLine) addSideEffects(es []ir.SideEffect) {
	for _, e := range es {
		if !slices.Contains(x.sideEffects, e) {
			x.sideEffects = append(x.sideEffects, e)
		}
	}
	slices.Sort(x.sideEffects)
}

// ruleConditionals are the conditional findings of one rule, by what
// decides them.
type ruleConditionals struct {
	rule     lint.RuleID
	severity lint.Severity
	results  []lint.Finding // in the order of their places
	by       []decider
	why      []string             // the reasons of the facts not known, each once, in order
	kinds    []lint.FindingKindID // each once, by ID
}

// decider is what is not known of the conditions of some findings: facts,
// and inputs not among those read.
type decider struct {
	facts   []facts.Query
	inputs  []facts.InputPath
	results []lint.Finding
}

func (d decider) what() string {
	var parts []string
	for _, q := range d.facts {
		parts = append(parts, queryText(q))
	}
	for _, n := range d.inputs {
		parts = append(parts, "input "+clean(n.String())+" not read")
	}
	if len(parts) == 0 {
		return "nothing listed"
	}
	return strings.Join(parts, ", ")
}

// key tells deciders apart.
func (d decider) key() string {
	var b strings.Builder
	for _, q := range d.facts {
		fmt.Fprintf(&b, "%q ", queryKey(q))
	}
	for _, n := range d.inputs {
		fmt.Fprintf(&b, "input %q ", n)
	}
	return b.String()
}

// inputGroup is inputs not read, or not valid, for one reason.
type inputGroup struct {
	state       lint.InputState
	diagnostics bool   // the inputs have no Reason: their diagnostics say why
	reason      string // as clean makes it
	inputs      []lint.Input
}

// knownFacts are the answers of the report, by the bytes of their queries.
func knownFacts(rep lint.Report) map[string]facts.RawAnswer {
	known := map[string]facts.RawAnswer{}
	for _, e := range rep.Facts {
		known[queryKey(e.Query)] = e.RawAnswer
	}
	return known
}

func buildView(rep lint.Report, in lint.Inputs, reg *lint.Registry) view {
	known := knownFacts(rep)
	lookup := func(n facts.InputPath) lint.LookupState { _, s := in.Lookup(n); return s }
	var v view
	folds := map[string]*fold{}
	rows := map[string]map[string]*group{} // by the key of the fold, then by what is detected
	conds := map[lint.RuleID]*ruleConditionals{}
	for _, r := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if r.Certainty == lint.CertaintyConditional {
			c := conds[r.Rule]
			if c == nil {
				c = &ruleConditionals{rule: r.Rule, severity: r.Severity}
				conds[r.Rule] = c
			}
			c.results = append(c.results, r)
			if k := r.Args.KindID(); !slices.Contains(c.kinds, k) {
				c.kinds = append(c.kinds, k)
			}
			continue
		}
		f := fold{rule: r.Rule, severity: r.Severity, kind: r.Args.KindID(), fix: kindFix(reg, r), noFix: r.NoFix, impact: r.Consequence, remedy: r.Remedy}
		k := f.key()
		if folds[k] == nil {
			f.factsOf = map[lint.Fingerprint][]factLine{}
			folds[k] = &f
			rows[k] = map[string]*group{}
		}
		if x := folds[k].fix; x != nil && r.Fix != nil {
			x.addSideEffects(r.Fix.SideEffects)
		}
		fs := factsOf(r, known)
		folds[k].factsOf[r.Fingerprint] = fs
		for _, x := range fs {
			if !slices.ContainsFunc(folds[k].facts, func(y factLine) bool { return queryKey(y.query) == queryKey(x.query) }) {
				folds[k].facts = append(folds[k].facts, x)
			}
		}
		m := r.Detected()
		if rows[k][m] == nil {
			rows[k][m] = &group{detected: m}
		}
		rows[k][m].results = append(rows[k][m].results, r)
	}
	for k, f := range folds {
		for _, g := range rows[k] {
			slices.SortFunc(g.results, compareLocations)
		}
		f.rows = sorted(rows[k], compareRows)
	}
	v.confirmed = sorted(folds, func(a, b fold) int {
		return cmp.Or(cmp.Compare(b.severity, a.severity), compareLocations(a.rows[0].results[0], b.rows[0].results[0]), strings.Compare(a.key(), b.key()))
	})
	for _, c := range conds {
		slices.SortFunc(c.results, compareLocations)
		slices.SortFunc(c.kinds, func(a, b lint.FindingKindID) int { return strings.Compare(a.String(), b.String()) })
		c.by, c.why = decide(c.results, known, lookup)
	}
	v.conditional = sorted(conds, func(a, b ruleConditionals) int {
		return cmp.Or(cmp.Compare(b.severity, a.severity), strings.Compare(a.rule.String(), b.rule.String()))
	})
	v.inconclusive = inconclusiveKinds(rep.FindingsWith(lint.CertaintyInconclusive))
	v.inputs = inputGroups(rep.ReportedInputs())
	return v
}

// sorted are the values of m, in the order of by.
func sorted[K comparable, V any](m map[K]*V, by func(a, b V) int) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	slices.SortFunc(out, by)
	return out
}

// inconclusiveKinds count the inconclusive findings by rule and kind: the
// rules by ID, their kinds the most first.
func inconclusiveKinds(gaps []lint.Finding) []ruleInconclusive {
	by := map[lint.RuleID]*ruleInconclusive{}
	counts := map[lint.RuleID]map[lint.InconclusiveKindID]int{}
	for _, g := range gaps {
		if by[g.Rule] == nil {
			by[g.Rule] = &ruleInconclusive{rule: g.Rule}
			counts[g.Rule] = map[lint.InconclusiveKindID]int{}
		}
		counts[g.Rule][g.InconclusiveKind]++
	}
	for id, r := range by {
		for k, n := range counts[id] {
			r.kinds = append(r.kinds, kindCount{k, n})
		}
		slices.SortFunc(r.kinds, func(a, b kindCount) int {
			return cmp.Or(cmp.Compare(b.n, a.n), strings.Compare(a.kind.String(), b.kind.String()))
		})
	}
	return sorted(by, func(a, b ruleInconclusive) int { return strings.Compare(a.rule.String(), b.rule.String()) })
}

// key tells folds apart; findings with the same key are one fold. Each
// part is quoted, so that no byte of a note (an attacker's) moves the
// border between two parts. The title of a fix is not in it: it differs
// in each finding (its SHA, its number of edits).
func (f fold) key() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%q %d %q", f.rule, f.severity, f.kind)
	if f.noFix != nil {
		fmt.Fprintf(&b, " nofix %d %q", f.noFix.Reason, f.noFix.Note)
	}
	if x := f.fix; x != nil {
		fmt.Fprintf(&b, " fix %q %d", x.kind, x.safety)
	}
	return b.String()
}

// compareRows orders the rows of a fold: the most findings first, then by
// their first places, then by what they detect.
func compareRows(a, b group) int {
	return cmp.Or(cmp.Compare(len(b.results), len(a.results)), compareLocations(a.results[0], b.results[0]), strings.Compare(a.detected, b.detected))
}

// decide groups conditional findings by what of their conditions is not
// known, the most findings first, and gives the reasons of the facts not
// known.
func decide(results []lint.Finding, known map[string]facts.RawAnswer, lookup func(facts.InputPath) lint.LookupState) ([]decider, []string) {
	by := map[string]*decider{}
	var why []string
	for _, r := range results {
		var d decider
		if r.Condition != nil {
			for _, q := range r.Condition.Queries() {
				raw, ok := known[queryKey(q)]
				if !ok || raw.State != facts.StateUnknown {
					continue // not asked: Eval did not need it
				}
				d.facts = append(d.facts, q)
				if raw.Reason != "" && !slices.Contains(why, clean(raw.Reason)) {
					why = append(why, clean(raw.Reason))
				}
			}
			for _, n := range r.Condition.Inputs() {
				if lookup(n) == lint.LookupUnknown {
					d.inputs = append(d.inputs, n)
				}
			}
		}
		k := d.key()
		if by[k] == nil {
			by[k] = &d
		}
		by[k].results = append(by[k].results, r)
	}
	slices.Sort(why)
	return sorted(by, func(a, b decider) int {
		return cmp.Or(cmp.Compare(len(b.results), len(a.results)), strings.Compare(a.key(), b.key()))
	}), why
}

func inputGroups(inputs []lint.Input) []inputGroup {
	by := map[string]*inputGroup{}
	for _, i := range inputs {
		if i.State == lint.InputStateRead {
			continue
		}
		g := inputGroup{state: i.State, diagnostics: i.Reason == "", reason: clean(i.Reason)}
		k := fmt.Sprintf("%d %t %q", g.state, g.diagnostics, g.reason)
		if by[k] == nil {
			by[k] = &g
		}
		by[k].inputs = append(by[k].inputs, i)
	}
	return sorted(by, func(a, b inputGroup) int {
		return cmp.Or(cmp.Compare(a.state, b.state), cmp.Compare(len(b.inputs), len(a.inputs)), cmp.Compare(boolInt(a.diagnostics), boolInt(b.diagnostics)), strings.Compare(a.reason, b.reason))
	})
}

// compareLocations orders findings by where they are: the inputs by name,
// then the files of facts, then by offset; the fingerprint settles the
// rest.
func compareLocations(a, b lint.Finding) int {
	fa, fb := a.Location.File.Query != nil, b.Location.File.Query != nil
	c := cmp.Compare(boolInt(fa), boolInt(fb))
	if c == 0 && !fa {
		c = facts.CompareInputPaths(a.Location.File.Input, b.Location.File.Input)
	}
	if c == 0 && fa {
		c = strings.Compare(queryKey(a.Location.File.Query), queryKey(b.Location.File.Query))
	}
	return cmp.Or(c, cmp.Compare(a.Location.Span.Start, b.Location.Span.Start), strings.Compare(a.Fingerprint.String(), b.Fingerprint.String()))
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// kindFix is the fix of r by kind, titled as the registry titles the
// kind: the same for every finding of a fold. A kind the registry does
// not have (lint.Run drops such fixes) is titled by its ID, not by the
// title of the first finding. It is nil when r has no fix.
func kindFix(reg *lint.Registry, r lint.Finding) *fixLine {
	f := r.Fix
	if f == nil {
		return nil
	}
	k, ok := fixKind(reg, r.Rule, f.KindID)
	title := k.Title
	if !ok {
		title = "a fix of the kind " + f.KindID.String()
	}
	return &fixLine{kind: f.KindID, safety: k.Safety, title: title, sideEffects: slices.Clone(f.SideEffects)}
}

// findingFix is the fix of r with its own title (--detail full), or nil.
func findingFix(reg *lint.Registry, r lint.Finding) *fixLine {
	f := r.Fix
	if f == nil {
		return nil
	}
	k, _ := fixKind(reg, r.Rule, f.KindID)
	return &fixLine{kind: f.KindID, safety: k.Safety, title: f.Title, sideEffects: slices.Clone(f.SideEffects)}
}

// fixKind is the fix kind k of the rule id in the registry.
func fixKind(reg *lint.Registry, id lint.RuleID, k lint.FixKindID) (lint.FixKind, bool) {
	m, _ := reg.Meta(id)
	return m.FixKind(k)
}

// kindsText is ks for people, joined.
func kindsText(ks []lint.FindingKindID) string {
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = k.String()
	}
	return strings.Join(parts, ", ")
}

// queryKey is the bytes of q, as the report writes it.
func queryKey(q facts.Query) string {
	b, err := facts.EncodeQuery(q)
	if err != nil {
		return fmt.Sprintf("%#v", q)
	}
	return string(b)
}

// queryText is q for people (facts.QueryText), as clean makes it.
func queryText(q facts.Query) string { return clean(facts.QueryText(q)) }

// worstShown is how many rows worst shows.
const worstShown = 5

// worstRow is a row of worst: the head of its fold, the row, and the key
// of the fold with what is detected, which settles ties.
type worstRow struct {
	severity lint.Severity
	kind     string // as args.kind_id of the report has it (lint.Finding.KindText)
	row      group
	key      string
	// inconclusive is whether the row is a finding whose certainty is
	// inconclusive, one finding a row
	inconclusive bool
}

// worst are the rows of the highest severity, of the confirmed folds and
// of the findings whose certainty is inconclusive (one finding a row), the
// rows of the folds first and the most findings first, at most limit of
// them; more is how many are left
// out. folds are as buildView orders them; inconclusive are those no
// acceptance matched.
func worst(folds []fold, inconclusive []lint.Finding, limit int) (rows []worstRow, more int) {
	if len(folds) == 0 && len(inconclusive) == 0 {
		return nil, 0
	}
	var top lint.Severity
	if len(folds) > 0 {
		top = folds[0].severity
	}
	for _, g := range inconclusive {
		top = max(top, g.Severity)
	}
	for _, f := range folds {
		if f.severity != top {
			continue
		}
		for _, g := range f.rows {
			rows = append(rows, worstRow{f.severity, f.kind.String(), g, fmt.Sprintf("%s %q", f.key(), g.detected), false})
		}
	}
	for _, g := range inconclusive {
		if g.Severity == top {
			rows = append(rows, worstRow{g.Severity, g.KindText(), group{detected: g.Detected(), results: []lint.Finding{g}}, "inconclusive " + g.Fingerprint.String(), true})
		}
	}
	slices.SortFunc(rows, func(a, b worstRow) int {
		return cmp.Or(cmp.Compare(boolInt(a.inconclusive), boolInt(b.inconclusive)), cmp.Compare(len(b.row.results), len(a.row.results)), compareLocations(a.row.results[0], b.row.results[0]), strings.Compare(a.key, b.key))
	})
	if len(rows) > limit {
		return rows[:limit], len(rows) - limit
	}
	return rows, 0
}

package lint

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/analysis"
	"reflect"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/cvss4"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
)

// Meta is the description of a rule in the registry of rules: the only
// place the severities of its kinds are found (FindingKind.Severity).
type Meta struct {
	ID RuleID
	// Problem is what the rule detects, and why it is a problem; Expected,
	// the state the rule asks for (the ideal): the rule reports a finding
	// where a workflow departs from the state, but for the undetected forms
	// (no finding), the inconclusive kinds (an inconclusive place instead)
	// and the false positive forms (a finding where the consequence of the
	// kind does not occur); whether a finding is a false positive is decided
	// by the consequence of its kind, not by the state. Each is one sentence of
	// the rule as a whole, with no argument (a finding says what it detects
	// by its kind, FindingKind.Detected).
	Problem  string
	Expected string
	// Facets are where the rule sorts on each axis, for people to find
	// rules alike.
	Facets Facets
	Threat Threat // the actors, preconditions and incidents the kinds refer to
	// Citations are what the rule as a whole rests on, which nothing of its
	// text (a precondition, a metric, an incident) cites.
	Citations    []Citation
	Targets      []InputKind   // InputKindWorkflow, InputKindActionMetadata
	FindingKinds []FindingKind // the kinds of findings it reports, one at least
	FixKinds     []FixKind     // the kinds refer to them
	// UndetectedForms are the forms the rule does not detect, each with why;
	// actions/rules holds each to an input on which the rule reports
	// nothing.
	UndetectedForms []UndetectedForm
	// InconclusiveKinds are the kinds of place the rule reports as
	// inconclusive (RuleContext.Inconclusive): places where the rule cannot
	// decide whether the workflow departs from Expected, or whether the
	// consequence of one of its finding kinds can occur there, since the
	// value or the content that decides it is outside what the rule reads.
	InconclusiveKinds []InconclusiveKind
	// FalsePositiveForms are the forms on which the rule reports a finding
	// of a kind though the consequence of the kind does not occur on the
	// inputs of the form, as far as the forms are known; actions/rules
	// holds each to an input on which the rule reports one of its kinds.
	FalsePositiveForms []FalsePositiveForm
	// ViewFields are the fields of the summaries of the IR the rule reads; a
	// rule of WithView has those of its view, and no other.
	ViewFields []ir.SummaryField
	// DefaultRun is whether the rule runs in a run that does not name the
	// rule (Registry.Select); the zero DefaultRun is always.
	DefaultRun DefaultRun
}

// UndetectedForm is a form a rule does not detect, and why (Disposition);
// Examples show the form, the main one first. FindingKinds are the kinds of finding the rule
// does not report on the form, when it reports a finding of another of its
// kinds there (as a kind whose conditions the form also meets); none when
// the rule reports nothing on the form.
type UndetectedForm struct {
	ID           UndetectedFormID
	Text         string
	FindingKinds []FindingKindID
	Disposition  Disposition
	Examples     []Example
	// AddedAttackers are the added attackers such that a run that adds one
	// of them reports a finding of the rule on each of Examples (RunAdded);
	// a test of the rules holds each to them
	AddedAttackers []AddedAttacker
}

// InconclusiveKind is a kind of place a rule reports as inconclusive, and
// what would decide it (Disposition: a limitation or a todo); Examples
// show the kind of place, the main one first.
type InconclusiveKind struct {
	ID          InconclusiveKindID
	Text        string
	Disposition Disposition
	Examples    []Example
}

// FalsePositiveForm is a form on which the rule reports a finding of one of
// its kinds, though the consequence of that kind does not occur on the
// inputs of the form. Disposition is what the rule would need to stop
// reporting it, a limitation or a todo; FactKinds are the kinds of facts
// whose answer that removes the finding (the boolean other than the
// x-assume value of the kind) removes it. A form has one of the two.
type FalsePositiveForm struct {
	ID           FalsePositiveFormID
	Text         string
	FindingKinds []FindingKindID // one at least, of the rule
	Disposition  Disposition
	FactKinds    []facts.Kind
	Examples     []Example // the main one first
	// AddedAttackers, when there are any, are the added attackers such that
	// a run that adds one of them reports the findings of FindingKinds on
	// each of Examples, which a run that adds none does not report
	AddedAttackers []AddedAttacker
}

// Example is an input that shows what a declaration of the registry is
// about; a test of the rules holds it to what the declaration says. With
// Others, it is a repository: the file Name and the others, run as the
// whole repository (a caller and the workflow it calls).
type Example struct {
	InputKind InputKind
	Name      facts.InputPath // the name of the file
	Text      string          // UTF-8
	Others    []ExampleFile   // the other files of the repository, by name
	// Facts are the answers it runs with: a test of the rules
	// (CheckExamples) and the example catalog (RunExample, every rule) ask
	// nothing else, and a fact not here is unknown.
	Facts []facts.Entry
	Notes ExampleNotes // what it is about: the comments its file starts with
}

// ExampleFile is another file of an Example of several files.
type ExampleFile struct {
	InputKind InputKind
	Name      facts.InputPath
	Text      string // UTF-8
}

// IsZero is whether e is none.
func (e Example) IsZero() bool { return e.Name.IsZero() && e.Text == "" }

// Severity is the worst of the severities of m's kinds: the rule's worst
// case.
func (m Meta) Severity() Severity {
	var s Severity
	for _, k := range m.FindingKinds {
		s = max(s, k.Severity())
	}
	return s
}

// InconclusiveRemedy is the remedy of every finding of the rule id whose
// certainty is CertaintyInconclusive: what a person does about the place.
func InconclusiveRemedy(id RuleID) string {
	return "the rule " + id.String() + " examined the place and could not decide whether the place has the problem that the rule looks for. " +
		"A person decides: look at the place and at where the value at the place comes from. When the place does not have the problem, an entry for the place in a file of acceptances " +
		"(--accept; the form of the file is schema/acceptances-v0.json) makes the place no longer add 8 to the exit code"
}

// kind is the kind id of m's.
func (m Meta) kind(id FindingKindID) (FindingKind, bool) {
	i := slices.IndexFunc(m.FindingKinds, func(k FindingKind) bool { return k.ID == id })
	if i < 0 {
		return FindingKind{}, false
	}
	return m.FindingKinds[i], true
}

// UndetectedKinds are the kinds of finding the rule of m does not report on
// the form l: its FindingKinds, or every kind of the rule when it has none.
func (m Meta) UndetectedKinds(l UndetectedForm) []FindingKindID {
	if len(l.FindingKinds) != 0 {
		return l.FindingKinds
	}
	out := []FindingKindID{}
	for _, k := range m.FindingKinds {
		out = append(out, k.ID)
	}
	return out
}

// FixKind is the fix kind id of m.
func (m Meta) FixKind(id FixKindID) (FixKind, bool) {
	i := slices.IndexFunc(m.FixKinds, func(f FixKind) bool { return f.ID == id })
	if i < 0 {
		return FixKind{}, false
	}
	return m.FixKinds[i], true
}

// checkSideEffects is whether es, the side effects of a fix kind or of a
// fix of safety s, hold to the contract: values, each once and in the
// order of the values, none when it is safe and one at least when it is
// to review.
func checkSideEffects(s Safety, es []ir.SideEffect) error {
	if (s == SafetyReview) != (len(es) > 0) {
		return fmt.Errorf("it is %v with the side effects %v: one at least to review, a safe one none", s, es)
	}
	for i, e := range es {
		if _, err := ir.ParseSideEffect(e.String()); err != nil {
			return fmt.Errorf("%v is not a side effect", e)
		}
		if slices.Contains(es[:i], e) {
			return fmt.Errorf("the side effect %v is there twice", e)
		}
		if i > 0 && es[i-1] > e {
			return fmt.Errorf("the side effects %v are not in the order of the values", es)
		}
	}
	return nil
}

// fixFacts are the kinds of facts the fixes k refers to need.
func (m Meta) fixFacts(k FindingKind) []facts.Kind {
	var out []facts.Kind
	for _, f := range m.FixKinds {
		if slices.Contains(k.Fixes, f.ID) {
			out = append(out, f.FactKinds...)
		}
	}
	return out
}

// cited are what m's text cites, each once, in the order --explain writes
// the text: its preconditions' citations, its incidents' advisories, then
// its kinds' metrics' citations.
func (m Meta) cited() []Citation {
	var out []Citation
	add := func(cs ...Citation) {
		for _, c := range cs {
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	for _, p := range m.Threat.Preconditions {
		add(p.Cites...)
	}
	for _, x := range m.Threat.Incidents {
		add(x.Advisory)
	}
	for _, k := range m.FindingKinds {
		for _, e := range k.metrics() {
			add(e.cites...)
		}
	}
	return out
}

// citations are m's Citations, then what its text cites: all it rests on,
// as --explain lists it. NewRegistry refuses a source twice, and one the
// text cites too, so none is there twice.
func (m Meta) citations() []Citation { return append(slices.Clone(m.Citations), m.cited()...) }

// FindingText is what a kind of finding says: its ID; the text of what it
// detects, {name} standing for the argument name; why it is bad and what a
// person does about it, the same for every finding of the kind; and its
// arguments: first those the text of what it detects names, in the order
// the text first names them, then the rest in the order the schema
// requires them (schema/findings-v0.json of actions/rules, which it is
// generated from).
// The JSON of the registry does not have the arguments.
type FindingText struct {
	ID          FindingKindID
	Detected    string
	Consequence string
	Remedy      string
	Arguments   []KindArgument
}

// FindingKind is a kind of finding a rule reports: what it says, the parts
// of its rule's Threat and the fixes it refers to, the kinds of facts its
// condition asks about, and the CVSS metrics its severity is found from.
type FindingKind struct {
	FindingText
	Attackers       []Attacker // one at least
	Preconditions   []PreconditionID
	Incidents       []IncidentID // the reports ExploitMaturity rests on
	Fixes           []FixKindID  // what a finding of it may give
	FactKinds       []facts.Kind // what its Condition asks about
	CVSS            CVSS
	ExploitMaturity Metric[ExploitMaturity] // for reference: it does not change Severity
	// TruePositives are inputs on which the rule reports a finding of the
	// kind (one whose notes name added attackers: in a run that adds one of
	// them alone, and no finding of the rule in the run that adds none);
	// TrueNegatives, inputs close to them on which it reports nothing
	// and the consequence of the kind does not occur (the input of a true
	// positive, fixed as the remedy says, or an input without a condition
	// the kind needs). One of each at least,
	// when the registry requires examples.
	TruePositives []Example
	TrueNegatives []Example
}

// Severity is how bad the kind's threat is on any repository: its worst
// case, not the risk to one organization. It is found from CVSS by a
// table, not by CVSS scoring, in the form of the likelihood and impact
// matrix of the OWASP Risk Rating Methodology:
//
//   - the impact is the highest of VC, VI, VA, SC, SI and SA;
//   - the likelihood is high for AV:N, PR:N and AT:N; medium for AV:N with
//     PR:N and AT:P, or with PR:L and AT:N; low otherwise. AC:H or UI:A
//     lowers it one step (once, however many of them there are);
//   - impact H is medium, high, critical for low, medium, high likelihood;
//     L is info, low, medium; N is info.
func (k FindingKind) Severity() Severity { return severityOf(k.CVSS).Severity }

// SeverityBasis is how Severity was found.
func (k FindingKind) SeverityBasis() SeverityBasis { return severityOf(k.CVSS) }

// vector is the CVSS v4.0 vector of k: its Base metrics and E.
func (k FindingKind) vector() string {
	return k.CVSS.Vector() + "/E:" + k.ExploitMaturity.Value.String()
}

// scores are the CVSS-B and CVSS-BT scores of k by the reference
// calculator (package cvss4): of its Base metrics, and with its Exploit
// Maturity. For reference: they do not change Severity.
func (k FindingKind) scores() (b, bt cvss4.Score, err error) {
	vb, err := cvss4.ParseVector(k.CVSS.Vector())
	if err != nil {
		return b, bt, err
	}
	vbt, err := cvss4.ParseVector(k.vector())
	if err != nil {
		return b, bt, err
	}
	return vb.Score(), vbt.Score(), nil
}

// metrics are the Base metrics and E, in the order of the vector.
func (k FindingKind) metrics() []metricEntry {
	return append(k.CVSS.entries(), entry("E", k.ExploitMaturity))
}

// FixKind is a kind of fix a rule may give.
type FixKind struct {
	ID        FixKindID    // one per rule
	Title     string       // what a fix of the kind does
	FactKinds []facts.Kind // the kinds of facts it needs
	Safety    Safety
	// PossibleSideEffects are what a fix of the kind may change besides
	// the finding, each once: none when it is safe, one at least when it
	// is to review. A fix has those of them it makes.
	PossibleSideEffects []ir.SideEffect
}

// Registry is the registry of rules and quality rules.
type Registry struct {
	rules       []Rule // by ID; a quality rule is there as asRule
	meta        map[RuleID]Meta
	quality     map[RuleID]QualityMeta // the quality rules among rules
	skipped     []RuleID               // by ID: the rules Select left out
	skippedMeta map[RuleID]Meta        // theirs: what ApplyFixes compares for them
	// byDefault are the rules among skipped that Select left out because
	// the run does not name them and their DefaultRun does not hold.
	byDefault map[RuleID]bool
	// barriers are the barriers the attacker of a run that adds some
	// added attackers gets past (WithBarriers); outsider are the rules such
	// a run does not run, which read an attacker outside the repository
	// alone: their places are those of the run that adds none.
	barriers func([]AddedAttacker) analysis.BarrierPasses
	outsider []RuleID
}

// NewRegistry checks the descriptions of rules and quality rules and makes
// the registry. The IDs of both are one namespace.
func NewRegistry(rules []Rule, quality ...QualityRule) (*Registry, error) {
	return newRegistry(rules, false, quality...)
}

// newRegistry is NewRegistry for the tests of this package, whose rules
// may rest on nothing (allowNoCitations).
func newRegistry(rules []Rule, allowNoCitations bool, quality ...QualityRule) (*Registry, error) {
	knownFacts := func(id string, fs []facts.Kind) error {
		for _, f := range fs {
			if _, err := facts.ParseKind(f.String()); err != nil {
				return fmt.Errorf("%s: %v is not a kind of fact", id, f)
			}
		}
		return nil
	}
	r := &Registry{meta: map[RuleID]Meta{}, quality: map[RuleID]QualityMeta{}, barriers: registered.barriers, outsider: slices.Clone(registered.outsider)}
	for _, rule := range rules {
		if rule == nil {
			return nil, errors.New("a nil rule")
		}
		m := rule.Meta()
		if m.ID.IsZero() {
			return nil, errors.New("a rule without an ID")
		}
		if _, dup := r.meta[m.ID]; dup {
			return nil, fmt.Errorf("the ID %s is registered twice", m.ID)
		}
		if m.Problem == "" || m.Expected == "" {
			return nil, fmt.Errorf("%s: a rule needs a Problem and an Expected", m.ID)
		}
		if err := checkFacets(m); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if err := checkThreat(m.Threat); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if slices.Contains(m.Citations, Citation{}) {
			return nil, fmt.Errorf("%s: a source is the zero citation", m.ID)
		}
		cited := m.cited()
		if len(m.Citations)+len(cited) == 0 && !allowNoCitations {
			return nil, fmt.Errorf("%s: no Citations and nothing cited; a rule must say what it rests on", m.ID)
		}
		for i, s := range m.Citations {
			if slices.Contains(m.Citations[:i], s) {
				return nil, fmt.Errorf("%s: the source %s twice", m.ID, s.s)
			}
			if slices.Contains(cited, s) {
				return nil, fmt.Errorf("%s: the citation %s is cited in the text too; Citations are what nothing else cites", m.ID, s.s)
			}
		}
		if len(m.Targets) == 0 || slices.ContainsFunc(m.Targets, func(k InputKind) bool { return k != InputKindWorkflow && k != InputKindActionMetadata }) {
			return nil, fmt.Errorf("%s: Targets must be workflow or action, and at least one", m.ID)
		}
		fixes := map[FixKindID]bool{}
		for _, f := range m.FixKinds {
			if f.ID.IsZero() {
				return nil, fmt.Errorf("%s: a fix without an ID", m.ID)
			}
			if fixes[f.ID] {
				return nil, fmt.Errorf("%s: the fix %s is declared twice", m.ID, f.ID)
			}
			fixes[f.ID] = true
			if f.Title == "" || !f.Safety.valid() {
				return nil, fmt.Errorf("%s: the fix %s needs a Title and a Safety (it has %q and %v)", m.ID, f.ID, f.Title, f.Safety)
			}
			if err := checkSideEffects(f.Safety, f.PossibleSideEffects); err != nil {
				return nil, fmt.Errorf("%s: the fix %s: %w", m.ID, f.ID, err)
			}
			if err := knownFacts(m.ID.s+": fix "+f.ID.s, f.FactKinds); err != nil {
				return nil, err
			}
		}
		if err := checkKinds(m, allowNoCitations); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		for _, k := range m.FindingKinds {
			if err := knownFacts(m.ID.s+": kind "+k.ID.s, k.FactKinds); err != nil {
				return nil, err
			}
		}
		if err := checkUndetectedForms(m); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if err := checkFalsePositiveForms(m); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if err := checkPullRequestTarget(m); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if err := checkAppChecks(m); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if err := checkLines(m); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if err := m.DefaultRun.check(); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		_, exampled := rule.(ExampledRule)
		if err := checkExamples(m, !exampled, false); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		r.meta[m.ID] = m
		r.rules = append(r.rules, rule)
	}
	for _, q := range quality {
		if q == nil {
			return nil, errors.New("a nil quality rule")
		}
		m := q.QualityMeta()
		if m.ID.IsZero() {
			return nil, errors.New("a quality rule without an ID")
		}
		if _, dup := r.meta[m.ID]; dup {
			return nil, fmt.Errorf("the ID %s is registered twice", m.ID)
		}
		_, exampled := q.(ExampledQualityRule)
		if err := checkQuality(m, knownFacts, allowNoCitations, !exampled); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		if err := m.DefaultRun.check(); err != nil {
			return nil, fmt.Errorf("%s: %w", m.ID, err)
		}
		r.meta[m.ID] = m.AsMeta()
		r.quality[m.ID] = m
		r.rules = append(r.rules, asRule{q})
	}
	slices.SortFunc(r.rules, func(a, b Rule) int { return strings.Compare(a.Meta().ID.s, b.Meta().ID.s) })
	return r, nil
}

// checkKinds checks that the rule declares a kind of finding at least,
// each of its own (the part before the dot is its ID; for the tests of
// this package, test), once, with what it detects, an impact and a remedy;
// that each refers to an actor at least, and to what the rule has, each
// once; that each has its CVSS metrics, which package cvss4 scores; and
// that every actor, precondition, incident and fix of the rule is referred
// to by a kind.
func checkKinds(m Meta, forTests bool) error {
	if len(m.FindingKinds) == 0 {
		return errors.New("no FindingKinds; a rule must declare the kinds of findings it reports")
	}
	actors := map[Attacker]bool{}
	for _, a := range m.Threat.Actors {
		actors[a.Attacker] = false
	}
	preconditions := map[PreconditionID]bool{}
	for _, p := range m.Threat.Preconditions {
		preconditions[p.ID] = false
	}
	incidents := map[IncidentID]bool{}
	for _, x := range m.Threat.Incidents {
		incidents[x.ID] = false
	}
	fixes := map[FixKindID]bool{}
	for _, f := range m.FixKinds {
		fixes[f.ID] = false
	}
	seen := map[FindingKindID]bool{}
	for _, k := range m.FindingKinds {
		if k.ID.IsZero() || k.Detected == "" || k.Consequence == "" || k.Remedy == "" {
			return fmt.Errorf("a kind of finding needs an ID, a Detected, a Consequence and a Remedy (%s has %q, %q, %q)", k.ID, k.Detected, k.Consequence, k.Remedy)
		}
		if k.ID.Rule() != m.ID && !(forTests && k.ID.Rule().s == "test") {
			return fmt.Errorf("the kind %s is not of the rule", k.ID)
		}
		if seen[k.ID] {
			return fmt.Errorf("the kind %s is declared twice", k.ID)
		}
		seen[k.ID] = true
		if len(k.Attackers) == 0 {
			return fmt.Errorf("the kind %s refers to no actor: say who the attacker is", k.ID)
		}
		for _, err := range []error{
			refer("actor", k.Attackers, actors),
			refer("precondition", k.Preconditions, preconditions),
			refer("incident", k.Incidents, incidents),
			refer("fix", k.Fixes, fixes),
		} {
			if err != nil {
				return fmt.Errorf("the kind %s %w", k.ID, err)
			}
		}
		if err := checkCVSS(k.metrics(), k.ExploitMaturity.Value, len(k.Incidents)); err != nil {
			return fmt.Errorf("the kind %s: %w", k.ID, err)
		}
		if _, _, err := k.scores(); err != nil {
			return fmt.Errorf("the kind %s: %w", k.ID, err)
		}
	}
	for _, a := range m.Threat.Actors {
		if !actors[a.Attacker] {
			return fmt.Errorf("no kind refers to the actor %v", a.Attacker)
		}
	}
	for _, p := range m.Threat.Preconditions {
		if !preconditions[p.ID] {
			return fmt.Errorf("no kind refers to the precondition %s", p.ID)
		}
	}
	for _, x := range m.Threat.Incidents {
		if !incidents[x.ID] {
			return fmt.Errorf("no kind refers to the incident %s", x.ID)
		}
	}
	for _, f := range m.FixKinds {
		if !fixes[f.ID] {
			return fmt.Errorf("no kind refers to the fix %s", f.ID)
		}
	}
	return nil
}

// refer checks that each of ids is a key of have, once, and marks it as
// referred to.
func refer[T comparable](what string, ids []T, have map[T]bool) error {
	for i, id := range ids {
		if _, ok := have[id]; !ok {
			return fmt.Errorf("refers to the %s %v, which the rule does not have", what, id)
		}
		if slices.Contains(ids[:i], id) {
			return fmt.Errorf("refers to the %s %v twice", what, id)
		}
		have[id] = true
	}
	return nil
}

// checkCVSS checks that every metric of ms is written, with a reason and
// no zero citation, and that an attack said to have happened (exploited)
// has its reports (incidents, how many the kind refers to).
func checkCVSS(ms []metricEntry, exploited ExploitMaturity, incidents int) error {
	for _, e := range ms {
		if !e.written {
			return fmt.Errorf("the metric %s is not written", e.name)
		}
		if e.reason == "" {
			return fmt.Errorf("the metric %s has no Reason", e.name)
		}
		if slices.Contains(e.cites, Citation{}) {
			return fmt.Errorf("the metric %s cites the zero citation", e.name)
		}
	}
	if exploited == ExploitMaturityAttacked && incidents == 0 {
		return errors.New("ExploitMaturity is ExploitMaturityAttacked, but it refers to no Incidents")
	}
	return nil
}

// checkUndetectedForms checks that the undetected forms and the inconclusive kinds
// each have an ID, once, say what they are, and have a Disposition, and
// that the FindingKinds of an undetected form are kinds of the rule, each
// once, not every kind (a form of every kind has none).
func checkUndetectedForms(m Meta) error {
	limits := map[UndetectedFormID]bool{}
	for _, l := range m.UndetectedForms {
		if l.ID.IsZero() || strings.TrimSpace(l.Text) == "" {
			return errors.New("an undetected form needs an ID and a Text")
		}
		if limits[l.ID] {
			return fmt.Errorf("the undetected form %s is declared twice", l.ID)
		}
		limits[l.ID] = true
		for i, k := range l.FindingKinds {
			if _, ok := m.kind(k); !ok {
				return fmt.Errorf("the undetected form %s names %s, which is not a kind of the rule", l.ID, k)
			}
			if slices.Contains(l.FindingKinds[:i], k) {
				return fmt.Errorf("the undetected form %s names %s twice", l.ID, k)
			}
		}
		if len(l.FindingKinds) != 0 && len(l.FindingKinds) == len(m.FindingKinds) {
			return fmt.Errorf("the undetected form %s names every kind of the rule: a form on which the rule reports nothing names no kind", l.ID)
		}
		if err := l.Disposition.check(m.ID, ""); err != nil {
			return fmt.Errorf("the undetected form %s: %w", l.ID, err)
		}
	}
	kinds := map[InconclusiveKindID]bool{}
	for _, k := range m.InconclusiveKinds {
		if k.ID.IsZero() || strings.TrimSpace(k.Text) == "" {
			return errors.New("an inconclusive kind needs an ID and a Text")
		}
		if kinds[k.ID] {
			return fmt.Errorf("the inconclusive kind %s is declared twice", k.ID)
		}
		kinds[k.ID] = true
		if slices.ContainsFunc(m.FindingKinds, func(f FindingKind) bool { return f.ID.String() == InconclusiveKindText(m.ID, k.ID) }) {
			return fmt.Errorf("the inconclusive kind %s has the name of a finding kind of the rule: an inconclusive kind and a finding kind of one rule cannot share a name, because args.kind_id of a finding is <rule>.<kind> for both kinds", k.ID)
		}
		if err := k.Disposition.check(m.ID, "an inconclusive kind may be a place the rule should report"); err != nil {
			return fmt.Errorf("the inconclusive kind %s: %w", k.ID, err)
		}
	}
	return nil
}

// checkFalsePositiveForms checks that each false positive form has an ID,
// once, says what it is, names kinds of the rule, each once, and has a
// Disposition of a limitation or a todo, or FactKinds with an answer that
// removes the finding, each once, but not both.
func checkFalsePositiveForms(m Meta) error {
	seen := map[FalsePositiveFormID]bool{}
	for _, f := range m.FalsePositiveForms {
		if f.ID.IsZero() || strings.TrimSpace(f.Text) == "" {
			return errors.New("a false positive form needs an ID and a Text")
		}
		if seen[f.ID] {
			return fmt.Errorf("the false positive form %s is declared twice", f.ID)
		}
		seen[f.ID] = true
		if len(f.FindingKinds) == 0 {
			return fmt.Errorf("the false positive form %s names no kind of finding", f.ID)
		}
		for i, k := range f.FindingKinds {
			if _, ok := m.kind(k); !ok {
				return fmt.Errorf("the false positive form %s names %s, which is not a kind of the rule", f.ID, k)
			}
			if slices.Contains(f.FindingKinds[:i], k) {
				return fmt.Errorf("the false positive form %s names %s twice", f.ID, k)
			}
		}
		if f.Disposition.IsZero() == (len(f.FactKinds) == 0) {
			return fmt.Errorf("the false positive form %s has a Disposition and FactKinds, or neither: it has one of the two", f.ID)
		}
		if !f.Disposition.IsZero() {
			if err := f.Disposition.check(m.ID, "a false positive form is reported"); err != nil {
				return fmt.Errorf("the false positive form %s: %w", f.ID, err)
			}
		}
		for i, k := range f.FactKinds {
			if _, ok := removingAnswer(kindInfoOf(k)); !ok {
				return fmt.Errorf("the false positive form %s: %v is not a kind of fact with an answer that removes the finding (an x-assume of true or false)", f.ID, k)
			}
			if slices.Contains(f.FactKinds[:i], k) {
				return fmt.Errorf("the false positive form %s names the fact kind %v twice", f.ID, k)
			}
		}
	}
	return nil
}

// providerOf is where the kind of fact k comes from.
func providerOf(k facts.Kind) facts.Provider { return kindInfoOf(k).Provider }

// kindInfoOf is what facts.Kinds says of k.
func kindInfoOf(k facts.Kind) facts.KindInfo {
	for _, i := range facts.Kinds() {
		if i.Kind == k {
			return i
		}
	}
	return facts.KindInfo{} // facts.ParseKind made k: it is one of facts.Kinds
}

// checkExamples checks m's examples: each is of an input kind the rule
// targets, with a name and a text, and notes for a rule or, with quality,
// for a quality rule. With required, every kind of finding
// has a true positive and a true negative, and every undetected form,
// inconclusive kind and false positive form its example.
func checkExamples(m Meta, required, quality bool) error {
	check := func(what string, kind ExampleWhat, e Example) error {
		switch {
		case e.IsZero():
			if required {
				return fmt.Errorf("%s has no example", what)
			}
			return nil
		case e.Name.IsZero() || e.Text == "":
			return fmt.Errorf("the example of %s has no name or no text", what)
		case !slices.Contains(m.Targets, e.InputKind):
			return fmt.Errorf("the example %s of %s is of %v, not a target of the rule", e.Name, what, e.InputKind)
		}
		for _, o := range e.Others {
			if o.Name.IsZero() || o.Text == "" {
				return fmt.Errorf("a file of the example %s of %s has no name or no text", e.Name, what)
			}
		}
		if err := e.Notes.check(kind, quality); err != nil {
			return fmt.Errorf("the notes of the example %s of %s: %w", e.Name, what, err)
		}
		return nil
	}
	for _, k := range m.FindingKinds {
		if required && len(k.TruePositives) == 0 {
			return fmt.Errorf("the kind %s has no true positive", k.ID)
		}
		if required && len(k.TrueNegatives) == 0 {
			return fmt.Errorf("the kind %s has no true negative", k.ID)
		}
		for _, e := range k.TruePositives {
			if err := check("a true positive of "+k.ID.String(), ExampleTruePositive, e); err != nil {
				return err
			}
		}
		for _, e := range k.TrueNegatives {
			if err := check("a true negative of "+k.ID.String(), ExampleTrueNegative, e); err != nil {
				return err
			}
		}
	}
	declaration := func(what string, kind ExampleWhat, es []Example) error {
		if len(es) == 0 {
			return check(what, kind, Example{})
		}
		for _, e := range es {
			if err := check(what, kind, e); err != nil {
				return err
			}
		}
		return nil
	}
	for _, l := range m.UndetectedForms {
		if err := declaration("the undetected form "+l.ID.String(), ExampleUndetected, l.Examples); err != nil {
			return err
		}
	}
	for _, k := range m.InconclusiveKinds {
		if err := declaration("the inconclusive kind "+k.ID.String(), ExampleInconclusive, k.Examples); err != nil {
			return err
		}
	}
	for _, f := range m.FalsePositiveForms {
		if err := declaration("the false positive form "+f.ID.String(), ExampleFalsePositive, f.Examples); err != nil {
			return err
		}
	}
	return nil
}

// exampledMeta is rule's Meta with its examples: ExampledMeta of an
// ExampledRule, which must be its Meta, as NewRegistry checked it, but for
// the examples, and whose examples are checked as NewRegistry checks those
// of another rule; the Meta NewRegistry checked otherwise.
func (r *Registry) exampledMeta(rule Rule) (Meta, error) {
	if a, ok := rule.(asRule); ok {
		m, err := r.exampledQualityMeta(a.q)
		return m.AsMeta(), err
	}
	id := rule.Meta().ID
	e, ok := rule.(ExampledRule)
	if !ok {
		return r.meta[id], nil
	}
	m := e.ExampledMeta()
	if !reflect.DeepEqual(m.withoutExamples(), r.meta[id]) {
		return Meta{}, fmt.Errorf("%s: its ExampledMeta is not its Meta with examples", id)
	}
	if err := checkExamples(m, true, false); err != nil {
		return Meta{}, fmt.Errorf("%s: %w", id, err)
	}
	return m, nil
}

// exampledQualityMeta is q's QualityMeta with its examples, as
// exampledMeta is a rule's: ExampledQualityMeta of an ExampledQualityRule,
// checked as NewRegistry checks the QualityMeta of another quality rule;
// the QualityMeta NewRegistry checked otherwise.
func (r *Registry) exampledQualityMeta(q QualityRule) (QualityMeta, error) {
	id := q.QualityMeta().ID
	e, ok := q.(ExampledQualityRule)
	if !ok {
		return r.quality[id], nil
	}
	m := e.ExampledQualityMeta()
	if !reflect.DeepEqual(m.withoutExamples(), r.quality[id]) {
		return QualityMeta{}, fmt.Errorf("%s: its ExampledQualityMeta is not its QualityMeta with examples", id)
	}
	if err := checkExamples(m.AsMeta(), true, true); err != nil {
		return QualityMeta{}, fmt.Errorf("%s: %w", id, err)
	}
	return m, nil
}

// withoutExamples is m without the examples of its declarations.
func (m Meta) withoutExamples() Meta {
	m.FindingKinds = slices.Clone(m.FindingKinds)
	for i := range m.FindingKinds {
		m.FindingKinds[i].TruePositives, m.FindingKinds[i].TrueNegatives = nil, nil
	}
	m.UndetectedForms = slices.Clone(m.UndetectedForms)
	for i := range m.UndetectedForms {
		m.UndetectedForms[i].Examples = nil
	}
	m.InconclusiveKinds = slices.Clone(m.InconclusiveKinds)
	for i := range m.InconclusiveKinds {
		m.InconclusiveKinds[i].Examples = nil
	}
	m.FalsePositiveForms = slices.Clone(m.FalsePositiveForms)
	for i := range m.FalsePositiveForms {
		m.FalsePositiveForms[i].Examples = nil
	}
	return m
}

// checkLines checks that each sentence of m is one line: --explain writes
// each in an item of a list, which a line break would end.
func checkLines(m Meta) error {
	type text struct{ what, s string }
	texts := []text{{"the Problem", m.Problem}, {"the Expected", m.Expected}}
	for i, a := range m.Threat.Actors {
		texts = append(texts, text{fmt.Sprintf("the Via of the actor %d", i), a.Via})
	}
	for i, p := range m.Threat.Preconditions {
		texts = append(texts, text{fmt.Sprintf("the precondition %d", i), p.Text})
		for j, o := range p.Observed {
			texts = append(texts, text{fmt.Sprintf("the observation %d of the precondition %d", j, i), o.What})
		}
	}
	for i, x := range m.Threat.Incidents {
		texts = append(texts, text{fmt.Sprintf("the Summary of the incident %d", i), x.Summary})
	}
	for _, k := range m.FindingKinds {
		for _, e := range k.metrics() {
			texts = append(texts, text{"the Reason of " + e.name + " of " + k.ID.String(), e.reason})
		}
	}
	for _, k := range m.FindingKinds {
		texts = append(texts, text{"the Detected of " + k.ID.String(), k.Detected}, text{"the Consequence of " + k.ID.String(), k.Consequence}, text{"the Remedy of " + k.ID.String(), k.Remedy})
	}
	for _, f := range m.FixKinds {
		texts = append(texts, text{"the Title of the fix " + f.ID.String(), f.Title})
	}
	for _, l := range m.UndetectedForms {
		texts = append(texts, text{"the Text of the undetected form " + l.ID.String(), l.Text})
	}
	for _, k := range m.InconclusiveKinds {
		texts = append(texts, text{"the Text of the inconclusive kind " + k.ID.String(), k.Text})
	}
	for _, f := range m.FalsePositiveForms {
		texts = append(texts, text{"the Text of the false positive form " + f.ID.String(), f.Text})
	}
	for _, t := range texts {
		if strings.ContainsAny(t.s, "\r\n") {
			return fmt.Errorf("%s has a line break; a sentence of the registry is one line", t.what)
		}
	}
	return nil
}

// Rules are the rules, by ID; not the quality rules (QualityRules).
func (r *Registry) Rules() []Rule {
	var out []Rule
	for _, x := range r.rules {
		if _, quality := x.(asRule); !quality {
			out = append(out, x)
		}
	}
	return out
}

// QualityRules are the quality rules, by ID.
func (r *Registry) QualityRules() []QualityRule {
	var out []QualityRule
	for _, x := range r.rules {
		if a, ok := x.(asRule); ok {
			out = append(out, a.q)
		}
	}
	return out
}

// IsQuality is whether id is a quality rule of r.
func (r *Registry) IsQuality(id RuleID) bool {
	_, ok := r.quality[id]
	return ok
}

// DefaultRun is the DefaultRun of the rule or quality rule id, of r or of
// those Select left out; always for an ID r does not know.
func (r *Registry) DefaultRun(id RuleID) DefaultRun {
	if m, ok := r.meta[id]; ok {
		return m.DefaultRun
	}
	return r.skippedMeta[id].DefaultRun
}

// NotRunByDefault is whether Select left id out because the run did not
// name id and the DefaultRun of id did not hold; not for a rule the
// Selection itself left out.
func (r *Registry) NotRunByDefault(id RuleID) bool { return r.byDefault[id] }

// Meta is the description of the rule id; none for a quality rule
// (QualityMeta); of an ExampledRule, without its examples.
func (r *Registry) Meta(id RuleID) (Meta, bool) {
	if r.IsQuality(id) {
		return Meta{}, false
	}
	m, ok := r.meta[id]
	return m, ok
}

// QualityMeta is the description of the quality rule id.
func (r *Registry) QualityMeta(id RuleID) (QualityMeta, bool) {
	m, ok := r.quality[id]
	return m, ok
}

// RegistrySchema is the value of schema in the JSON of the registry.
const RegistrySchema = "sisakulint/registry/v0"

func (r *Registry) MarshalJSON() ([]byte, error) { return r.marshalJSON(formDefault) }

// MarshalJSONFull is the registry with the facts each example runs with
// (--registry=full).
func (r *Registry) MarshalJSONFull() ([]byte, error) { return r.marshalJSON(formFull) }

// MetaJSON is each rule's and quality rule's object of the registry's JSON
// without its examples (true_positives, true_negatives, example), by its
// ID: what an example catalog shows of the Meta beside the examples it
// runs. It is not the registry's JSON, whose examples are required.
func (r *Registry) MetaJSON() (map[RuleID]json.RawMessage, error) {
	b, err := r.marshalJSON(formNoExamples)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Rules        []json.RawMessage `json:"rules"`
		QualityRules []json.RawMessage `json:"quality_rules"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var ids, qids []RuleID
	for _, rule := range r.Rules() {
		ids = append(ids, rule.Meta().ID)
	}
	for _, q := range r.QualityRules() {
		qids = append(qids, q.QualityMeta().ID)
	}
	out := make(map[RuleID]json.RawMessage, len(ids)+len(qids))
	for _, x := range []struct {
		objs []json.RawMessage
		ids  []RuleID
	}{{doc.Rules, ids}, {doc.QualityRules, qids}} {
		if len(x.objs) != len(x.ids) {
			return nil, fmt.Errorf("the registry's JSON has %d of %d rules", len(x.objs), len(x.ids))
		}
		for i, id := range x.ids {
			var j struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(x.objs[i], &j); err != nil || j.ID != id.String() {
				return nil, fmt.Errorf("the rule %d of the registry's JSON is %q, not %s (%v)", i, j.ID, id, err)
			}
			out[id] = x.objs[i]
		}
	}
	return out, nil
}

// registryForm is what the registry's JSON has of the examples.
type registryForm int

const (
	formDefault    registryForm = iota // the examples, without their facts and notes
	formFull                           // the examples with their facts and notes (--registry=full)
	formNoExamples                     // no example (MetaJSON)
)

func (r *Registry) marshalJSON(form registryForm) ([]byte, error) {
	type sideEffectJSON struct {
		ID   ir.SideEffect `json:"id"`
		Text string        `json:"text"`
	}
	type fixJSON struct {
		ID          FixKindID        `json:"id"`
		Title       string           `json:"title"`
		Facts       []facts.Kind     `json:"fact_kinds"`
		Safety      Safety           `json:"safety"`
		SideEffects []sideEffectJSON `json:"possible_side_effects"`
	}
	type metricJSON struct {
		Metric string     `json:"metric"`
		Value  string     `json:"value"`
		Reason string     `json:"reason"`
		Cites  []Citation `json:"cites"`
	}
	type exampleFileJSON struct {
		InputKind InputKind       `json:"input_kind"`
		Name      facts.InputPath `json:"name"`
		Text      string          `json:"text"`
	}
	type attackValueJSON struct {
		Carrier string `json:"carrier"`
		Value   string `json:"value"`
	}
	type exampleNotesJSON struct {
		Situation         string           `json:"situation"`
		Reason            string           `json:"reason"`
		Cause             string           `json:"cause,omitempty"`
		Attack            string           `json:"attack,omitempty"`
		AttackValue       *attackValueJSON `json:"attack_value,omitempty"`
		AttackRunBehavior string           `json:"attack_run_behavior,omitempty"`
		Advisories        []AdvisoryPage   `json:"advisories,omitempty"`
		Sources           []SourceFile     `json:"sources,omitempty"`
	}
	type exampleJSON struct {
		InputKind      InputKind         `json:"input_kind"`
		Name           facts.InputPath   `json:"name"`
		Text           string            `json:"text"`
		Others         []exampleFileJSON `json:"others,omitempty"`
		AddedAttackers []AddedAttacker   `json:"added_attackers,omitempty"`
		Facts          *[]facts.Entry    `json:"facts,omitempty"` // --registry=full only
		Notes          *exampleNotesJSON `json:"notes,omitempty"` // --registry=full only
	}
	exampleOf := func(e Example) exampleJSON {
		j := exampleJSON{InputKind: e.InputKind, Name: e.Name, Text: e.Text, AddedAttackers: e.Notes.AddedAttackers}
		if form == formFull {
			fs := append([]facts.Entry{}, e.Facts...)
			j.Facts = &fs
			n := e.Notes
			j.Notes = &exampleNotesJSON{Situation: n.Situation, Reason: n.Reason, Cause: n.Cause, Attack: n.Attack, AttackRunBehavior: n.AttackRunBehavior, Advisories: n.Advisories, Sources: n.Sources}
			if !n.AttackValue.IsZero() {
				j.Notes.AttackValue = &attackValueJSON{n.AttackValue.Carrier(), n.AttackValue.Value()}
			}
		}
		for _, o := range e.Others {
			j.Others = append(j.Others, exampleFileJSON(o))
		}
		return j
	}
	examplesOf := func(es []Example) *[]exampleJSON {
		if form == formNoExamples {
			return nil
		}
		out := []exampleJSON{}
		for _, e := range es {
			out = append(out, exampleOf(e))
		}
		return &out
	}
	type undetectedFormJSON struct {
		ID           UndetectedFormID `json:"id"`
		Text         string           `json:"text"`
		FindingKinds []FindingKindID  `json:"finding_kinds"`
		dispositionJSON
		AddedAttackers []AddedAttacker `json:"added_attackers,omitempty"`
		Examples       *[]exampleJSON  `json:"examples,omitempty"`
	}
	type cvssJSON struct {
		Vector  string       `json:"vector"`
		Metrics []metricJSON `json:"metrics"`
		B       scoreJSON    `json:"b"`
		BT      scoreJSON    `json:"bt"`
	}
	type kindJSON struct {
		ID            FindingKindID    `json:"id"`
		Detected      string           `json:"detected"`
		Consequence   string           `json:"consequence"`
		Remedy        string           `json:"remedy"`
		Severity      Severity         `json:"severity"`
		SeverityBasis SeverityBasis    `json:"severity_basis"`
		CVSS          cvssJSON         `json:"cvss"`
		Attackers     []Attacker       `json:"attackers"`
		Preconditions []PreconditionID `json:"preconditions"`
		Incidents     []IncidentID     `json:"incidents"`
		Fixes         []FixKindID      `json:"fixes"`
		FactKinds     []facts.Kind     `json:"fact_kinds"`
		TruePositives *[]exampleJSON   `json:"true_positives,omitempty"`
		TrueNegatives *[]exampleJSON   `json:"true_negatives,omitempty"`
	}
	type inconclusiveKindJSON struct {
		ID   InconclusiveKindID `json:"id"`
		Text string             `json:"text"`
		dispositionJSON
		Examples *[]exampleJSON `json:"examples,omitempty"`
	}
	type factKindJSON struct {
		Kind     facts.Kind     `json:"kind"`
		Provider facts.Provider `json:"provider"`
	}
	type falsePositiveFormJSON struct {
		ID           FalsePositiveFormID `json:"id"`
		Text         string              `json:"text"`
		FindingKinds []FindingKindID     `json:"finding_kinds"`
		*dispositionJSON
		FactKinds      []factKindJSON  `json:"fact_kinds,omitempty"`
		AddedAttackers []AddedAttacker `json:"added_attackers,omitempty"`
		Examples       *[]exampleJSON  `json:"examples,omitempty"`
	}
	type ruleJSON struct {
		ID RuleID `json:"id"`
		defaultRunJSON
		Problem            string                  `json:"problem"`
		Expected           string                  `json:"expected"`
		Facets             Facets                  `json:"facets"`
		Severity           Severity                `json:"severity"`
		Threat             threatJSON              `json:"threat"`
		Citations          []Citation              `json:"citations"`
		Targets            []InputKind             `json:"targets"`
		FindingKinds       []kindJSON              `json:"finding_kinds"`
		FixKinds           []fixJSON               `json:"fix_kinds"`
		UndetectedForms    []undetectedFormJSON    `json:"undetected_forms"`
		InconclusiveKinds  []inconclusiveKindJSON  `json:"inconclusive_kinds"`
		FalsePositiveForms []falsePositiveFormJSON `json:"false_positive_forms"`
	}
	type qualityKindJSON struct {
		ID            FindingKindID  `json:"id"`
		Detected      string         `json:"detected"`
		Consequence   string         `json:"consequence"`
		Remedy        string         `json:"remedy"`
		FactKinds     []facts.Kind   `json:"fact_kinds"`
		TruePositives *[]exampleJSON `json:"true_positives,omitempty"`
		TrueNegatives *[]exampleJSON `json:"true_negatives,omitempty"`
	}
	type qualityJSON struct {
		ID RuleID `json:"id"`
		defaultRunJSON
		Problem            string                  `json:"problem"`
		Expected           string                  `json:"expected"`
		Citations          []Citation              `json:"citations"`
		Targets            []InputKind             `json:"targets"`
		FindingKinds       []qualityKindJSON       `json:"finding_kinds"`
		UndetectedForms    []undetectedFormJSON    `json:"undetected_forms"`
		FalsePositiveForms []falsePositiveFormJSON `json:"false_positive_forms"`
	}
	undetectedOf := func(m Meta) []undetectedFormJSON {
		out := []undetectedFormJSON{}
		for _, l := range m.UndetectedForms {
			out = append(out, undetectedFormJSON{l.ID, l.Text, m.UndetectedKinds(l), l.Disposition.json(), schemaOrder(l.AddedAttackers), examplesOf(l.Examples)})
		}
		return out
	}
	falsePositivesOf := func(m Meta) []falsePositiveFormJSON {
		out := []falsePositiveFormJSON{}
		for _, f := range m.FalsePositiveForms {
			fj := falsePositiveFormJSON{ID: f.ID, Text: f.Text, FindingKinds: f.FindingKinds, AddedAttackers: schemaOrder(f.AddedAttackers), Examples: examplesOf(f.Examples)}
			if !f.Disposition.IsZero() {
				d := f.Disposition.json()
				fj.dispositionJSON = &d
			}
			for _, k := range f.FactKinds {
				fj.FactKinds = append(fj.FactKinds, factKindJSON{k, providerOf(k)})
			}
			out = append(out, fj)
		}
		return out
	}
	out := struct {
		Schema  string        `json:"schema"`
		Rules   []ruleJSON    `json:"rules"`
		Quality []qualityJSON `json:"quality_rules"`
	}{Schema: RegistrySchema, Rules: []ruleJSON{}, Quality: []qualityJSON{}}
	for _, rule := range r.Rules() {
		m := r.meta[rule.Meta().ID]
		if form != formNoExamples {
			var err error
			if m, err = r.exampledMeta(rule); err != nil {
				return nil, err
			}
		}
		j := ruleJSON{
			ID: m.ID, defaultRunJSON: m.DefaultRun.json(), Problem: m.Problem, Expected: m.Expected, Facets: m.Facets, Severity: m.Severity(), Threat: m.Threat.json(),
			Citations: nonNil(m.Citations), Targets: m.Targets, FindingKinds: []kindJSON{}, FixKinds: []fixJSON{},
			UndetectedForms: []undetectedFormJSON{}, InconclusiveKinds: []inconclusiveKindJSON{}, FalsePositiveForms: []falsePositiveFormJSON{},
		}
		for _, k := range m.FindingKinds {
			b, bt, err := k.scores()
			if err != nil {
				return nil, err // NewRegistry refuses such a kind
			}
			kj := kindJSON{
				ID: k.ID, Detected: k.Detected, Consequence: k.Consequence, Remedy: k.Remedy, Severity: k.Severity(), SeverityBasis: k.SeverityBasis(),
				CVSS:      cvssJSON{Vector: k.vector(), B: scoreOf(b), BT: scoreOf(bt)},
				Attackers: k.Attackers, Preconditions: nonNil(k.Preconditions), Incidents: nonNil(k.Incidents), Fixes: nonNil(k.Fixes), FactKinds: nonNil(k.FactKinds),
				TruePositives: examplesOf(k.TruePositives), TrueNegatives: examplesOf(k.TrueNegatives),
			}
			for _, x := range k.metrics() {
				kj.CVSS.Metrics = append(kj.CVSS.Metrics, metricJSON{x.name, x.value, x.reason, nonNil(x.cites)})
			}
			j.FindingKinds = append(j.FindingKinds, kj)
		}
		j.UndetectedForms = undetectedOf(m)
		for _, k := range m.InconclusiveKinds {
			j.InconclusiveKinds = append(j.InconclusiveKinds, inconclusiveKindJSON{k.ID, k.Text, k.Disposition.json(), examplesOf(k.Examples)})
		}
		j.FalsePositiveForms = falsePositivesOf(m)
		for _, f := range m.FixKinds {
			es := []sideEffectJSON{}
			for _, e := range f.PossibleSideEffects {
				es = append(es, sideEffectJSON{e, e.Text()})
			}
			j.FixKinds = append(j.FixKinds, fixJSON{f.ID, f.Title, nonNil(f.FactKinds), f.Safety, es})
		}
		out.Rules = append(out.Rules, j)
	}
	for _, q := range r.QualityRules() {
		m := r.quality[q.QualityMeta().ID]
		if form != formNoExamples {
			var err error
			if m, err = r.exampledQualityMeta(q); err != nil {
				return nil, err
			}
		}
		j := qualityJSON{ID: m.ID, defaultRunJSON: m.DefaultRun.json(), Problem: m.Problem, Expected: m.Expected, Citations: nonNil(m.Citations), Targets: m.Targets,
			FindingKinds: []qualityKindJSON{}, UndetectedForms: undetectedOf(m.AsMeta()), FalsePositiveForms: falsePositivesOf(m.AsMeta())}
		for _, k := range m.FindingKinds {
			j.FindingKinds = append(j.FindingKinds, qualityKindJSON{ID: k.ID, Detected: k.Detected, Consequence: k.Consequence, Remedy: k.Remedy,
				FactKinds: nonNil(k.FactKinds), TruePositives: examplesOf(k.TruePositives), TrueNegatives: examplesOf(k.TrueNegatives)})
		}
		out.Quality = append(out.Quality, j)
	}
	return marshal(out)
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

package reportview

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Page is what a report view shows of a report: the data its script draws.
type Page struct {
	Findings        []Finding        `json:"findings"`
	QualityFindings []QualityFinding `json:"quality_findings"`
	Files           []File           `json:"files"` // the inputs the nodes are in
}

// Finding is a finding of the report, drawn as the path of its evidence.
// KindID is its kind as args.kind_id of the report has it
// (lint.Finding.KindText). A finding whose certainty is inconclusive has
// KindText, the text of its inconclusive kind in the registry
// (lint.InconclusiveKind.Text), which says what places of the kind the
// rule cannot decide on, and Acceptance, the reason of the entry of
// --accept that matched it; both empty when there is none.
type Finding struct {
	Rule        lint.RuleID      `json:"rule"`
	Severity    lint.Severity    `json:"severity"`
	Certainty   lint.Certainty   `json:"certainty"`
	KindID      string           `json:"kind_id"`
	KindText    string           `json:"kind_text,omitempty"`
	Acceptance  string           `json:"acceptance,omitempty"`
	Detected    string           `json:"detected"`
	Consequence string           `json:"consequence"`
	Remedy      string           `json:"remedy"`
	Fingerprint lint.Fingerprint `json:"fingerprint"`
	Args        json.RawMessage  `json:"args"`
	// Path is the events an attacker acts on, if the args name them, the
	// evidence in order, and last the place of the finding.
	Path      []Node     `json:"path"`
	Related   []Node     `json:"related"` // off the path
	Condition *Condition `json:"condition,omitempty"`
	Fix       *Fix       `json:"fix,omitempty"`
	NoFix     *NoFix     `json:"no_fix,omitempty"`
	// AddedAttackers are the added attackers that alone give the finding,
	// which a run that adds no attacker does not report (lint.RunAdded)
	AddedAttackers []lint.AddedAttacker `json:"added_attackers,omitempty"`
}

// QualityFinding is a quality finding of the report, drawn as a Finding is,
// without a severity, a fix or a reason for none.
type QualityFinding struct {
	Rule        lint.RuleID        `json:"rule"`
	Certainty   lint.Certainty     `json:"certainty"`
	KindID      lint.FindingKindID `json:"kind_id"`
	Detected    string             `json:"detected"`
	Consequence string             `json:"consequence"`
	Remedy      string             `json:"remedy"`
	Fingerprint lint.Fingerprint   `json:"fingerprint"`
	Args        json.RawMessage    `json:"args"`
	Path        []Node             `json:"path"`    // as a Finding's
	Related     []Node             `json:"related"` // off the path
	Condition   *Condition         `json:"condition,omitempty"`
}

// Role is what a node is in the drawing of a finding.
type Role uint8

const (
	RoleEvent    Role = iota // the events on which an attacker acts
	RoleEvidence             // a place of the evidence
	RoleFinding              // the place of the finding
	RoleRelated              // a place related to the finding, off the path
)

var roleNames = [...]string{"event", "evidence", "finding", "related"}

func (r Role) MarshalJSON() ([]byte, error) { return json.Marshal(roleNames[r]) }

// Node is a place in the drawing of a finding, or its events.
type Node struct {
	Role    Role                 `json:"role"`
	Events  []workflow.EventName `json:"events,omitempty"` // RoleEvent only
	Input   *facts.InputPath     `json:"input,omitempty"`  // the input the place is in
	Query   json.RawMessage      `json:"query,omitempty"`  // or the fact whose value is its file
	Line    int                  `json:"line,omitempty"`
	Column  int                  `json:"column,omitempty"`
	KeyPath string               `json:"key_path,omitempty"` // the path of keys from the document, for an auditor
	Job     string               `json:"job,omitempty"`      // the ID of the job it is in
	Step    string               `json:"step,omitempty"`     // the name of the step it is in, or #N
	Via     bool                 `json:"via,omitempty"`      // reached through an alias
	Note    string               `json:"note,omitempty"`
	Source  string               `json:"source,omitempty"` // the line it starts on
	// Snippet is the step it is in, when it is in one.
	Snippet []SnippetLine `json:"snippet,omitempty"`
}

// Condition is the condition of a finding, with a truth for each leaf to
// start from.
type Condition struct {
	ID      int         `json:"id"` // in the order of a walk from the root, from 0
	Op      op          `json:"op"`
	Parts   []Condition `json:"parts,omitempty"`
	Text    string      `json:"text,omitempty"` // a leaf, as the report writes it
	Truth   truth       `json:"truth"`          // of a leaf: by the answers of the report
	Assumed bool        `json:"assumed,omitempty"`
}

// op is a lint.ConditionOp as the script reads it.
type op lint.ConditionOp

var opNames = [...]string{lint.ConditionOpLeaf: "leaf", lint.ConditionOpAll: "all", lint.ConditionOpAny: "any"}

func (o op) MarshalJSON() ([]byte, error) { return json.Marshal(opNames[o]) }

// truth is an expr.Truth as the script reads it: true, false or unknown.
type truth expr.Truth

func (t truth) MarshalJSON() ([]byte, error) { return json.Marshal(expr.Truth(t).String()) }

// Build is the page of rep, whose inputs are in.
func Build(rep lint.Report, in lint.Inputs, reg *lint.Registry) (Page, error) {
	p := Page{Findings: []Finding{}, QualityFindings: []QualityFinding{}, Files: []File{}}
	answer := answers(rep.Facts)
	look := func(n facts.InputPath) lint.LookupState { _, s := in.Lookup(n); return s }
	for _, f := range rep.Findings {
		x, err := findingOf(f, in, reg, answer, look)
		if err != nil {
			return Page{}, fmt.Errorf("%s: %w", f.Detected(), err)
		}
		p.Findings = append(p.Findings, x)
	}
	for _, f := range rep.QualityFindings {
		// the events of the args of a quality finding are not those an
		// attacker acts on: a quality rule has no attacker
		d, err := drawingOf(f.FindingDraft, in, answer, look, false)
		if err != nil {
			return Page{}, fmt.Errorf("%s: %w", f.Detected(), err)
		}
		args, err := f.Args.MarshalJSON()
		if err != nil {
			return Page{}, err
		}
		p.QualityFindings = append(p.QualityFindings, QualityFinding{Rule: f.Rule, Certainty: f.Certainty, KindID: f.Args.KindID(), Detected: f.Detected(),
			Consequence: f.Consequence, Remedy: f.Remedy, Fingerprint: f.Fingerprint, Args: args, Path: d.path, Related: d.related, Condition: d.condition})
	}
	p.Files = filesOf(p, in)
	return p, nil
}

// inconclusiveText is the text of the inconclusive kind k of the rule id in
// reg; empty when reg declares no such kind.
func inconclusiveText(reg *lint.Registry, id lint.RuleID, k lint.InconclusiveKindID) string {
	m, _ := reg.Meta(id)
	for _, x := range m.InconclusiveKinds {
		if x.ID == k {
			return x.Text
		}
	}
	return ""
}

func findingOf(f lint.Finding, in lint.Inputs, reg *lint.Registry, answer func(facts.Query) facts.RawAnswer, look func(facts.InputPath) lint.LookupState) (Finding, error) {
	inconclusive := f.Certainty == lint.CertaintyInconclusive
	var args []byte
	var err error
	if inconclusive {
		args, err = json.Marshal(map[string]string{"kind_id": f.KindText()})
	} else {
		args, err = f.Args.MarshalJSON()
	}
	if err != nil {
		return Finding{}, err
	}
	d, err := drawingOf(f.FindingDraft, in, answer, look, true)
	if err != nil {
		return Finding{}, err
	}
	x := Finding{Rule: f.Rule, Severity: f.Severity, Certainty: f.Certainty, KindID: f.KindText(), Detected: f.Detected(),
		Consequence: f.Consequence, Remedy: f.Remedy, Fingerprint: f.Fingerprint, Args: args, Path: d.path, Related: d.related, Condition: d.condition, AddedAttackers: f.AddedAttackers}
	if inconclusive {
		x.KindText = inconclusiveText(reg, f.Rule, f.InconclusiveKind)
		if f.Acceptance != nil {
			x.Acceptance = f.Acceptance.Reason
		}
	}
	if f.Fix != nil {
		if x.Fix, err = fixOf(f, in, reg); err != nil {
			return Finding{}, err
		}
	}
	if f.NoFix != nil {
		x.NoFix = &NoFix{Reason: f.NoFix.Reason, Note: f.NoFix.Note}
	}
	return x, nil
}

// drawing is what a finding and a quality finding draw alike.
type drawing struct {
	path, related []Node
	condition     *Condition
}

// drawingOf is the drawing of d: with attacker, the events its args name,
// if any; the evidence in order and the place of d (Finding.Path); the
// related places; and the condition.
func drawingOf(d lint.FindingDraft, in lint.Inputs, answer func(facts.Query) facts.RawAnswer, look func(facts.InputPath) lint.LookupState, attacker bool) (drawing, error) {
	x := drawing{path: []Node{}, related: []Node{}}
	if ev := eventsOf(d.Args); attacker && len(ev) > 0 {
		x.path = append(x.path, Node{Role: RoleEvent, Events: ev})
	}
	for _, r := range d.Evidence {
		n, err := nodeOf(in, RoleEvidence, r.Location, r.Note)
		if err != nil {
			return drawing{}, err
		}
		x.path = append(x.path, n)
	}
	if n := len(d.Evidence); n > 0 && sameSpot(d.Evidence[n-1].Location, d.Location) {
		x.path[len(x.path)-1].Role = RoleFinding
	} else {
		n, err := nodeOf(in, RoleFinding, d.Location, "")
		if err != nil {
			return drawing{}, err
		}
		i := len(x.path) - len(d.Evidence) + laterStep(in, d.Location, d.Evidence)
		x.path = slices.Insert(x.path, i, n)
	}
	for _, r := range d.Related {
		n, err := nodeOf(in, RoleRelated, r.Location, r.Note)
		if err != nil {
			return drawing{}, err
		}
		x.related = append(x.related, n)
	}
	if d.Condition != nil {
		id := 0
		c, err := conditionOf(*d.Condition, answer, look, &id)
		if err != nil {
			return drawing{}, err
		}
		x.condition = &c
	}
	return x, nil
}

// nodeOf is the node of the place l.
func nodeOf(in lint.Inputs, role Role, l lint.Location, note string) (Node, error) {
	pos := l.Position()
	n := Node{Role: role, Line: pos.Line, Column: pos.Column, KeyPath: l.KeyPath().String(), Via: len(l.Via) > 0, Note: note, Source: l.LineText()}
	if l.File.Query != nil {
		q, err := facts.EncodeQuery(l.File.Query)
		if err != nil {
			return Node{}, err
		}
		n.Query = q
		return n, nil
	}
	name := l.File.Input
	n.Input = &name
	p := locate(in, l)
	n.Job, n.Step = p.job, p.step
	n.Snippet = snippetOf(in, l)
	return n, nil
}

// laterStep is the index of the first of evidence in a later step of the
// job of loc, in the same input: the steps of a job run in order, so a
// checkout or a download (loc) runs before the step of the evidence that
// runs what it brings. It is len(evidence) when there is none; places in
// the same step, another job or another input keep the order of the
// evidence.
func laterStep(in lint.Inputs, loc lint.Location, evidence []lint.Related) int {
	at, ok := find(in, loc)
	if !ok || at.step == nil {
		return len(evidence)
	}
	for i, r := range evidence {
		e, ok := find(in, r.Location)
		if ok && e.step != nil && r.Location.File.Input == loc.File.Input && e.job == at.job && e.step.Order > at.step.Order {
			return i
		}
	}
	return len(evidence)
}

// sameSpot is whether a and b are the same span of the same input, at the
// same path of keys: the places under one alias share its span.
func sameSpot(a, b lint.Location) bool {
	return a.File.Query == nil && b.File.Query == nil && a.File.Input == b.File.Input && a.Span == b.Span && a.KeyPath() == b.KeyPath()
}

var eventNames = reflect.TypeFor[[]workflow.EventName]()

// eventsOf are the events the args name (the fields of the generated args
// that are lists of events: those an attacker acts on), each once.
func eventsOf(args lint.FindingArgs) []workflow.EventName {
	v := reflect.Indirect(reflect.ValueOf(args))
	if v.Kind() != reflect.Struct {
		return nil
	}
	var out []workflow.EventName
	for i := range v.NumField() {
		if !v.Type().Field(i).IsExported() || v.Field(i).Type() != eventNames {
			continue
		}
		for _, e := range v.Field(i).Interface().([]workflow.EventName) {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// answers looks up the answer to a query in entries; an answer not there
// is Unknown.
func answers(entries []facts.Entry) func(facts.Query) facts.RawAnswer {
	by := map[string]facts.RawAnswer{}
	for _, e := range entries {
		if k, err := facts.EncodeQuery(e.Query); err == nil {
			by[string(k)] = e.RawAnswer
		}
	}
	return func(q facts.Query) facts.RawAnswer {
		k, err := facts.EncodeQuery(q)
		if err != nil {
			return facts.RawAnswer{}
		}
		return by[string(k)]
	}
}

// conditionOf is c with the truth of each leaf by answer and look, and IDs
// from *next on.
func conditionOf(c lint.Condition, answer func(facts.Query) facts.RawAnswer, look func(facts.InputPath) lint.LookupState, next *int) (Condition, error) {
	x := Condition{ID: *next, Op: op(c.Op())}
	*next++
	if c.Op() != lint.ConditionOpLeaf {
		x.Parts = []Condition{}
		for _, p := range c.Parts() {
			y, err := conditionOf(p, answer, look, next)
			if err != nil {
				return Condition{}, err
			}
			x.Parts = append(x.Parts, y)
		}
		return x, nil
	}
	b, err := c.MarshalJSON()
	if err != nil {
		return Condition{}, err
	}
	x.Text, x.Truth = string(b), truth(lint.Eval(c, answer, look))
	for _, q := range c.Queries() {
		if answer(q).Assumed() {
			x.Assumed = true
		}
	}
	return x, nil
}

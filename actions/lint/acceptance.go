package lint

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/internal/jsonschema"
)

// AcceptancesSchema is the value of schema in the JSON of a file of
// acceptances (schema/acceptances-v0.json).
const AcceptancesSchema = "sisakulint/acceptances/v0"

// Acceptance is the place of a finding whose certainty is
// CertaintyInconclusive that a person looked at and accepted, and why. It
// matches the findings whose rule, inconclusive kind, input, KeyPath,
// SpanText and SpanLines are its own; such a place does not set bit 8
// (Classify).
type Acceptance struct {
	Rule      RuleID
	KindID    InconclusiveKindID
	Input     facts.InputPath
	KeyPath   KeyPath
	SpanText  string
	SpanLines string
	Reason    string
}

//go:embed schema/acceptances-v0.json
var acceptancesJSON []byte

var loadAcceptancesSchema = sync.OnceValues(func() (*jsonschema.Set, error) {
	return jsonschema.Load(map[string][]byte{"acceptances-v0.json": acceptancesJSON}, jsonschema.Options{})
})

// LoadAcceptances reads a file of acceptances, and checks each entry against
// reg: a rule of reg that declares the kind of the entry. Give it the
// registry before Select, so that an entry of a rule the run leaves out is
// read too. The acceptances are in the order of the file.
func LoadAcceptances(data []byte, reg *Registry) ([]Acceptance, error) {
	s, err := loadAcceptancesSchema()
	if err != nil {
		panic("lint: schema/acceptances-v0.json: " + err.Error())
	}
	if err := s.Validate("acceptances-v0.json", "#", data); err != nil {
		return nil, fmt.Errorf("not a file of acceptances: %w", err)
	}
	var f struct {
		Inconclusive []struct {
			Rule      string `json:"rule"`
			KindID    string `json:"kind_id"`
			Input     string `json:"input"`
			KeyPath   string `json:"key_path"`
			SpanText  string `json:"span_text"`
			SpanLines string `json:"span_lines"`
			Reason    string `json:"reason"`
		} `json:"inconclusive"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	var out []Acceptance
	for i, e := range f.Inconclusive {
		fail := func(format string, a ...any) error {
			return fmt.Errorf("inconclusive/%d: %s", i, fmt.Sprintf(format, a...))
		}
		rule, err := ParseRuleID(e.Rule)
		if err != nil {
			return nil, fail("%v", err)
		}
		last, ok := strings.CutPrefix(e.KindID, e.Rule+".")
		if !ok {
			return nil, fail("the kind_id %q is not of the rule %s: write kind_id in the form of args.kind_id in the report, <rule>.<kind>", e.KindID, e.Rule)
		}
		kind, err := ParseInconclusiveKindID(last)
		if err != nil {
			return nil, fail("%v", err)
		}
		input, err := facts.CleanInputPath(e.Input) // as the names of the inputs are made
		if err != nil {
			return nil, fail("%v", err)
		}
		if input.String() != e.Input {
			return nil, fail("write the input as %s, as the report does", input)
		}
		key, err := ParseKeyPath(e.KeyPath)
		if err != nil {
			return nil, fail("%v", err)
		}
		if reg.IsQuality(rule) {
			return nil, fail("%s is a quality rule, which reports no inconclusive place", rule)
		}
		m, ok := reg.Meta(rule)
		if !ok {
			return nil, fail("%s is not a rule", rule)
		}
		if !slices.ContainsFunc(m.InconclusiveKinds, func(k InconclusiveKind) bool { return k.ID == kind }) {
			return nil, fail("the rule %s declares no inconclusive kind %s", rule, kind)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fail("the reason is white space alone")
		}
		a := Acceptance{Rule: rule, KindID: kind, Input: input, KeyPath: key, SpanText: e.SpanText, SpanLines: e.SpanLines, Reason: e.Reason}
		if j := slices.IndexFunc(out, a.samePlace); j >= 0 {
			return nil, fail("inconclusive/%d has the same values of rule, kind_id, input, key_path, span_text and span_lines", j)
		}
		out = append(out, a)
	}
	return out, nil
}

// Accept is rep with each finding whose certainty is CertaintyInconclusive
// that an acceptance of as matches accepted (Finding.Acceptance), and the acceptances of as that
// match no place though their rule ran (rep.Rules) and their input was read,
// in the order of as. An acceptance of a rule left out of the run, or of an
// input left out or not read, is not among them: the run could not have
// found its place. A place that no acceptance of as matches has none, even
// if rep gave it one. as is what LoadAcceptances gives: a reason that is
// not white space alone, and no two acceptances of the same places. rep
// and as are not changed, and rep shares nothing
// with the result that a change of as would change.
func Accept(rep Report, as []Acceptance) (Report, []Acceptance) {
	rep.Findings = slices.Clone(rep.Findings)
	matched := make([]bool, len(as))
	for i, g := range rep.Findings {
		rep.Findings[i].Acceptance = nil
		if g.Certainty != CertaintyInconclusive {
			continue
		}
		for j, a := range as {
			if a.matches(g) {
				rep.Findings[i].Acceptance = &a
				matched[j] = true
				break
			}
		}
	}
	var unmatched []Acceptance
	for j, a := range as {
		ran := slices.ContainsFunc(rep.Rules, func(r RuleRef) bool { return r.ID == a.Rule })
		read := slices.ContainsFunc(rep.Inputs, func(in Input) bool { return in.Name == a.Input && in.State == InputStateRead })
		if !matched[j] && ran && read {
			unmatched = append(unmatched, a)
		}
	}
	return rep, unmatched
}

// matches is whether a accepts the place of g, a finding whose certainty
// is CertaintyInconclusive.
func (a Acceptance) matches(g Finding) bool {
	return a.Rule == g.Rule && a.KindID == g.InconclusiveKind && a.Input == g.Location.File.Input &&
		a.KeyPath == g.KeyPath && a.SpanText == g.SpanText && a.SpanLines == g.SpanLines
}

// samePlace is whether a and b match the same inconclusive places.
func (a Acceptance) samePlace(b Acceptance) bool {
	a.Reason, b.Reason = "", ""
	return a == b
}

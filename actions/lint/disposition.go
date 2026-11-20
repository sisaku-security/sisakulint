package lint

import (
	"errors"
	"fmt"
	"slices"
)

// Need is what would be added to decide a form or a kind of place a rule
// does not report. Its values and what they mean are the oneOf of
// $defs/need in schema/registry-v0.json (enum_gen.go).
type Need uint8

// Decider is what decides a form or a kind of place that nothing added is
// expected to decide. Its values and what they mean are the oneOf of
// $defs/decider in schema/registry-v0.json (enum_gen.go).
type Decider uint8

// Disposition is why a rule does not report a form (UndetectedForm) or a kind
// of place (InconclusiveKind), as it is judged now: limitation and todo change as what
// can be done is found. It is made by NoAddedGain, OtherRule, Limitation
// and Todo only; the zero Disposition is none, which NewRegistry refuses.
type Disposition struct {
	kind    dispositionKind
	rule    RuleID
	needs   []Need
	decider Decider
}

type dispositionKind uint8

const (
	dispositionUnset dispositionKind = iota
	dispositionNoAddedGain
	dispositionOtherRule
	dispositionLimitation
	dispositionTodo
)

// NoAddedGain is a Disposition: on the form, the flaw the rule detects adds
// nothing to what the attacker of the rule's Threat gets from the
// repository of the input. Either the form does not have the flaw, or the
// flaw gives the attacker nothing; or the attacker gets the same without
// the flaw (the author of a pull request, who can change the workflow of a
// pull_request run), and then the run can give the attacker secrets or a
// token that writes while the rule reports nothing. The value says nothing
// of the threats of other rules, and the value does not mean that a
// workflow with the form is safe.
func NoAddedGain() Disposition { return Disposition{kind: dispositionNoAddedGain} }

// OtherRule is a Disposition: the rule id reports the same form, as a form
// of the threat of the rule id.
func OtherRule(id RuleID) Disposition { return Disposition{kind: dispositionOtherRule, rule: id} }

// Limitation is a Disposition: nothing that can be added is expected to decide it
// now; by decides it.
func Limitation(by Decider) Disposition { return Disposition{kind: dispositionLimitation, decider: by} }

// Todo is a Disposition: adding what n and more name is expected to decide it for
// some of its places.
func Todo(n Need, more ...Need) Disposition {
	return Disposition{kind: dispositionTodo, needs: append([]Need{n}, more...)}
}

// IsZero is whether c is the zero Disposition, which is none.
func (c Disposition) IsZero() bool { return c.kind == dispositionUnset }

// OtherRule is the rule that reports what c is of, when c is of another
// rule.
func (c Disposition) OtherRule() (RuleID, bool) { return c.rule, c.kind == dispositionOtherRule }

// check checks c for the rule self. A declaration that may only be a
// limitation or a todo gives why as only (an inconclusive kind: it may be
// a place the rule should report; a false positive form: it is reported); ""
// takes every Disposition.
func (c Disposition) check(self RuleID, only string) error {
	switch c.kind {
	case dispositionUnset:
		return errors.New("no Disposition")
	case dispositionNoAddedGain, dispositionOtherRule:
		if only != "" {
			return fmt.Errorf("%s: its Disposition is a limitation or a todo", only)
		}
		if c.kind == dispositionOtherRule {
			if c.rule.IsZero() {
				return errors.New("the Disposition names no rule")
			}
			if c.rule == self {
				return errors.New("the Disposition names the rule itself")
			}
		}
	case dispositionLimitation:
		if !c.decider.valid() {
			return fmt.Errorf("the Decider %v is not in the schema", c.decider)
		}
	case dispositionTodo:
		for i, n := range c.needs {
			if !n.valid() {
				return fmt.Errorf("the Need %v is not in the schema", n)
			}
			if slices.Contains(c.needs[:i], n) {
				return fmt.Errorf("the Need %v is given twice", n)
			}
		}
	}
	return nil
}

// dispositionJSON is a Disposition as the JSON of an UndetectedForm or an
// InconclusiveKind holds it: in the same object as the id and the text
// (the object holds the fields of $defs/disposition-fields of
// schema/registry-v0.json).
type dispositionJSON struct {
	Disposition string   `json:"disposition"`
	Rule        *RuleID  `json:"rule,omitempty"`
	DecidedBy   *Decider `json:"decided_by,omitempty"`
	Needs       []Need   `json:"needs,omitempty"`
}

// json is c as its JSON; NewRegistry refuses the zero Disposition first.
func (c Disposition) json() dispositionJSON {
	switch c.kind {
	case dispositionNoAddedGain:
		return dispositionJSON{Disposition: "no-added-gain"}
	case dispositionOtherRule:
		return dispositionJSON{Disposition: "other-rule", Rule: &c.rule}
	case dispositionLimitation:
		return dispositionJSON{Disposition: "limitation", DecidedBy: &c.decider}
	case dispositionTodo:
		return dispositionJSON{Disposition: "todo", Needs: slices.Sorted(slices.Values(c.needs))}
	}
	return dispositionJSON{}
}

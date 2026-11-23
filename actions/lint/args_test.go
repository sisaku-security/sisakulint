package lint

import (
	"encoding/json"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// saidKind is the one kind of finding of the tests' rules, in the domain
// test that newRegistry takes for tests; otherKind is a second one, which
// a rule of the tests declares when it needs two.
var (
	saidKind  = MustFindingKindID("test.said")
	otherKind = MustFindingKindID("test.other")
)

// saidOf is the kind id of the tests' rules: what it says, the actor and
// the precondition of meta, and the metrics of baseFor(SeverityHigh).
func saidOf(id FindingKindID) FindingKind {
	return FindingKind{
		FindingText:     FindingText{ID: id, Detected: "{text}", Consequence: "it was said", Remedy: "say it not"},
		Attackers:       []Attacker{AttackerCommenter},
		Preconditions:   []PreconditionID{preconditionP},
		CVSS:            baseFor(SeverityHigh),
		ExploitMaturity: metric(ExploitMaturityUnreported),
		TruePositives:   []Example{exampleOf(id.String() + ".yml")},
		TrueNegatives:   []Example{exampleOf(id.String() + ".yml")},
	}
}

// ownKinds are the kinds of a rule of the tests for NewRegistry, which
// does not take the domain test: one kind, <id>.said.
func ownKinds(id string) []FindingKind {
	return []FindingKind{saidOf(MustFindingKindID(id + ".said"))}
}

// fixing is m with the fixes fs, which each of its kinds refers to.
func fixing(m Meta, fs ...FixKind) Meta {
	m.FixKinds = fs
	m.FindingKinds = slices.Clone(m.FindingKinds)
	for i := range m.FindingKinds {
		m.FindingKinds[i].Fixes = nil
		for _, f := range fs {
			m.FindingKinds[i].Fixes = append(m.FindingKinds[i].Fixes, f.ID)
		}
	}
	return m
}

// asking is m with each of its kinds asking about the facts ks.
func asking(m Meta, ks ...facts.Kind) Meta {
	m.FindingKinds = slices.Clone(m.FindingKinds)
	for i := range m.FindingKinds {
		m.FindingKinds[i].FactKinds = ks
	}
	return m
}

// said is the args of a finding of the tests: what it detects.
type said string

func (said) KindID() FindingKindID { return saidKind }
func (s said) Detected() string    { return string(s) }
func (s said) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Kind string `json:"kind_id"`
		Text string `json:"text"`
	}{saidKind.String(), string(s)})
}

// other is the args of a finding of otherKind.
type other string

func (other) KindID() FindingKindID { return otherKind }
func (s other) Detected() string    { return string(s) }
func (s other) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Kind string `json:"kind_id"`
		Text string `json:"text"`
	}{otherKind.String(), string(s)})
}

// wrongKind says it is of test.said, and writes another kind.
type wrongKind struct{ said }

func (wrongKind) MarshalJSON() ([]byte, error) { return []byte(`{"kind_id":"test.other"}`), nil }

// undeclared is of a kind no rule of the tests declares.
type undeclared struct{ said }

func (undeclared) KindID() FindingKindID { return otherKind }

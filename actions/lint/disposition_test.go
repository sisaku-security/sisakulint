package lint

import (
	"encoding/json"
	"strings"
	"testing"
)

// dispositionEntry is the JSON of an UndetectedForm of id x and text t
// (with the finding kinds kinds) or an InconclusiveKind (without), with c
// and an example.
func dispositionEntry(c Disposition, kinds ...string) []byte {
	type example struct {
		InputKind string `json:"input_kind"`
		Name      string `json:"name"`
		Text      string `json:"text"`
	}
	b, err := json.Marshal(struct {
		ID           string   `json:"id"`
		Text         string   `json:"text"`
		FindingKinds []string `json:"finding_kinds,omitempty"`
		dispositionJSON
		Examples []example `json:"examples"`
	}{"x", "t", kinds, c.json(), []example{{"workflow", "x.yml", "on: push\n"}}})
	if err != nil {
		panic(err)
	}
	return b
}

func TestDispositionJSON(t *testing.T) {
	s := schemas(t)
	for _, c := range []struct {
		c    Disposition
		want string
	}{
		{NoAddedGain(), `{"id":"x","text":"t","finding_kinds":["r.k"],"disposition":"no-added-gain","examples":[{"input_kind":"workflow","name":"x.yml","text":"on: push\n"}]}`},
		{OtherRule(MustRuleID("commit-sha")), `{"id":"x","text":"t","finding_kinds":["r.k"],"disposition":"other-rule","rule":"commit-sha","examples":[{"input_kind":"workflow","name":"x.yml","text":"on: push\n"}]}`},
		{Limitation(DeciderRemoteCaller), `{"id":"x","text":"t","finding_kinds":["r.k"],"disposition":"limitation","decided_by":"remote-caller","examples":[{"input_kind":"workflow","name":"x.yml","text":"on: push\n"}]}`},
		{Limitation(DeciderDispatcher), `{"id":"x","text":"t","finding_kinds":["r.k"],"disposition":"limitation","decided_by":"dispatcher","examples":[{"input_kind":"workflow","name":"x.yml","text":"on: push\n"}]}`},
		{Todo(NeedFact, NeedSameFile), `{"id":"x","text":"t","finding_kinds":["r.k"],"disposition":"todo","needs":["same-file","fact"],"examples":[{"input_kind":"workflow","name":"x.yml","text":"on: push\n"}]}`}, // in the order of the schema
	} {
		b := dispositionEntry(c.c, "r.k")
		if string(b) != c.want {
			t.Errorf("%s: got %s", c.want, b)
			continue
		}
		if err := s.Validate("registry-v0.json", "#/$defs/undetected-form", b); err != nil {
			t.Errorf("%s does not fit $defs/undetected-form: %v", b, err)
		}
	}
	if s.Validate("registry-v0.json", "#/$defs/undetected-form", dispositionEntry(Disposition{}, "r.k")) == nil {
		t.Error("the zero Disposition fits the schema")
	}
	// the name before no-added-gain (2026-10-22) is no value
	old := []byte(`{"id":"x","text":"t","finding_kinds":["r.k"],"disposition":"out-of-threat","examples":[{"input_kind":"workflow","name":"x.yml","text":"on: push\n"}]}`)
	if s.Validate("registry-v0.json", "#/$defs/undetected-form", old) == nil {
		t.Error("the schema takes out-of-threat")
	}
}

func TestDispositionOtherRule(t *testing.T) {
	if id, ok := OtherRule(MustRuleID("commit-sha")).OtherRule(); !ok || id.String() != "commit-sha" {
		t.Errorf("got %v, %v", id, ok)
	}
	if _, ok := Todo(NeedFact).OtherRule(); ok {
		t.Error("a todo has another rule")
	}
}

// The Needs of a Todo are its own: changing the slice given does not
// change it.
func TestDispositionTodoCopies(t *testing.T) {
	more := []Need{NeedFact}
	c := Todo(NeedSameFile, more...)
	more[0] = NeedRepoFile
	if b := dispositionEntry(c); !strings.Contains(string(b), `"fact"`) {
		t.Errorf("got %s", b)
	}
}

// TestInconclusiveDispositionSchema: the schema, as Go, gives a kind of
// place not examined a limitation or a todo only.
func TestInconclusiveDispositionSchema(t *testing.T) {
	s := schemas(t)
	for _, ok := range []Disposition{Limitation(DeciderDispatcher), Todo(NeedFact)} {
		if err := s.Validate("registry-v0.json", "#/$defs/inconclusive-kind", dispositionEntry(ok)); err != nil {
			t.Errorf("%s: %v", dispositionEntry(ok), err)
		}
	}
	for _, bad := range []Disposition{NoAddedGain(), OtherRule(MustRuleID("commit-sha"))} {
		if s.Validate("registry-v0.json", "#/$defs/inconclusive-kind", dispositionEntry(bad)) == nil {
			t.Errorf("a kind of inconclusive place takes %s", dispositionEntry(bad))
		}
	}
}

// An undetected form names its finding kinds in the JSON: the schema
// refuses one without them.
func TestUndetectedFormNeedsKindsSchema(t *testing.T) {
	if schemas(t).Validate("registry-v0.json", "#/$defs/undetected-form", dispositionEntry(Todo(NeedFact))) == nil {
		t.Error("the schema takes an undetected form without finding_kinds")
	}
}

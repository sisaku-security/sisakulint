package lint

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
)

// leaves of the three truths, for the tables of Kleene's logic.
var (
	qTrue    = facts.TestFlag{Name: "t"}
	qFalse   = facts.TestFlag{Name: "f"}
	qUnknown = facts.TestFlag{Name: "u"}
)

func answers(q facts.Query) facts.RawAnswer {
	switch q {
	case qTrue:
		return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(`true`)}
	case qFalse:
		return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(`false`)}
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "test"}
}

func noInputs(facts.InputPath) LookupState { return LookupUnknown }

func leaf(t *testing.T, v expr.Truth) Condition {
	t.Helper()
	q := map[expr.Truth]facts.Query{expr.TruthTrue: qTrue, expr.TruthFalse: qFalse, expr.TruthUnknown: qUnknown}[v]
	c, err := FactEq(q, true)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestKleene(t *testing.T) {
	vs := []expr.Truth{expr.TruthTrue, expr.TruthFalse, expr.TruthUnknown}
	all := func(xs ...expr.Truth) expr.Truth {
		out := expr.TruthTrue
		for _, x := range xs {
			if x == expr.TruthFalse {
				return expr.TruthFalse
			}
			if x == expr.TruthUnknown {
				out = expr.TruthUnknown
			}
		}
		return out
	}
	anyOf := func(xs ...expr.Truth) expr.Truth {
		out := expr.TruthFalse
		for _, x := range xs {
			if x == expr.TruthTrue {
				return expr.TruthTrue
			}
			if x == expr.TruthUnknown {
				out = expr.TruthUnknown
			}
		}
		return out
	}
	// The table of Kleene's logic, written out for two and three operands.
	for _, a := range vs {
		for _, b := range vs {
			if got := Eval(All(leaf(t, a), leaf(t, b)), answers, noInputs); got != all(a, b) {
				t.Errorf("all(%v, %v) = %v", a, b, got)
			}
			if got := Eval(Any(leaf(t, a), leaf(t, b)), answers, noInputs); got != anyOf(a, b) {
				t.Errorf("any(%v, %v) = %v", a, b, got)
			}
			for _, c := range vs {
				if got := Eval(All(leaf(t, a), leaf(t, b), leaf(t, c)), answers, noInputs); got != all(a, b, c) {
					t.Errorf("all(%v, %v, %v) = %v", a, b, c, got)
				}
				if got := Eval(Any(leaf(t, a), leaf(t, b), leaf(t, c)), answers, noInputs); got != anyOf(a, b, c) {
					t.Errorf("any(%v, %v, %v) = %v", a, b, c, got)
				}
			}
		}
	}
	if Eval(All(), answers, noInputs) != expr.TruthTrue || Eval(Any(), answers, noInputs) != expr.TruthFalse {
		t.Error("empty all must be true and empty any false")
	}
	if got := Eval(Any(leaf(t, expr.TruthUnknown), All(leaf(t, expr.TruthTrue), leaf(t, expr.TruthTrue))), answers, noInputs); got != expr.TruthTrue {
		t.Errorf("nested: %v", got)
	}
}

func TestLeaves(t *testing.T) {
	absent := facts.TestFlag{Name: "absent"}
	text := facts.TestText{Name: "x"}
	list := facts.TestList{Name: "l"}
	fact := func(q facts.Query) facts.RawAnswer {
		switch q {
		case absent:
			return facts.RawAnswer{State: facts.StateAbsent}
		case text:
			return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(`"true"`)}
		case list:
			return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(`[ "a" , "b" ]`)}
		}
		return answers(q)
	}
	inputs := func(n facts.InputPath) LookupState {
		return map[string]LookupState{"found.yml": LookupFound, "gone.yml": LookupAbsent}[n.String()]
	}
	eq := func(q facts.Query, v any) Condition {
		c, err := FactEq(q, v)
		if err != nil {
			t.Fatalf("FactEq(%#v, %v): %v", q, v, err)
		}
		return c
	}
	for _, c := range []struct {
		name string
		cond Condition
		want expr.Truth
	}{
		{"eq true", eq(qTrue, true), expr.TruthTrue},
		{"eq differs", eq(qTrue, false), expr.TruthFalse},
		{"eq on absent", eq(absent, true), expr.TruthFalse},
		{"eq on unknown", eq(qUnknown, true), expr.TruthUnknown},
		{"string is not bool", eq(text, "true"), expr.TruthTrue},
		{"list, spacing does not matter", eq(list, []string{"a", "b"}), expr.TruthTrue},
		{"list order matters", eq(list, []string{"b", "a"}), expr.TruthFalse},
		{"absent leaf on absent", FactAbsent(absent), expr.TruthTrue},
		{"absent leaf on resolved", FactAbsent(qTrue), expr.TruthFalse},
		{"absent leaf on unknown", FactAbsent(qUnknown), expr.TruthUnknown},
		{"input found", InputPresent(facts.MustCleanInputPath("found.yml")), expr.TruthTrue},
		{"input absent", InputPresent(facts.MustCleanInputPath("gone.yml")), expr.TruthFalse},
		{"input unknown", InputPresent(facts.MustCleanInputPath("other.yml")), expr.TruthUnknown},
	} {
		if got := Eval(c.cond, fact, inputs); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
	// A value the resolver gives that has no canonical form is not equal to
	// anything: it is unknown, not false.
	odd := func(facts.Query) facts.RawAnswer {
		return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(`1.5`)}
	}
	if got := Eval(eq(qTrue, true), odd, noInputs); got != expr.TruthUnknown {
		t.Errorf("a value without a canonical form: %v, want unknown", got)
	}
}

func TestFactEqRejects(t *testing.T) {
	for _, c := range []struct {
		name string
		q    facts.Query
		v    any
	}{
		{"value off x-value", qTrue, "yes"},
		{"not an integer", facts.TestText{Name: "x"}, 1.5},
		{"cannot be written", facts.TestRepoFlag{}, true},
		{"no fact", nil, true},
	} {
		if _, err := FactEq(c.q, c.v); err == nil {
			t.Errorf("%s: no error", c.name)
		}
	}
}

func TestCondJSON(t *testing.T) {
	repo, _ := facts.ParseRepo("org/app")
	a, _ := FactEq(facts.TestRepoFlag{Repo: repo}, true)
	c := Any(a, FactAbsent(qFalse), All(InputPresent(facts.MustCleanInputPath(".github/workflows/x.yml"))))
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"any":[{"query":{"kind":"test.repo-flag","repo":"org/app"},"eq":true},{"query":{"kind":"test.flag","name":"f"},"absent":true},{"all":[{"input":".github/workflows/x.yml","present":true}]}]}`
	if string(b) != want {
		t.Errorf("Marshal =\n%s\nwant\n%s", b, want)
	}
	var back Condition
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	b2, _ := json.Marshal(back)
	if string(b2) != want {
		t.Errorf("round trip =\n%s", b2)
	}
	// An example condition, in its own spacing.
	spec := `{"any": [
	  {"query": {"kind": "test.repo-flag", "repo": "Org/App"}, "eq": true},
	  {"query": {"kind": "test.text", "name": "n"}, "eq": "public"}
	]}`
	if err := json.Unmarshal([]byte(spec), &back); err != nil {
		t.Errorf("the example of a condition: %v", err)
	}
}

func TestCondJSONRejects(t *testing.T) {
	for _, src := range []string{
		`{}`,
		`{"all": [], "any": []}`,
		`{"all": [], "query": {"kind": "test.flag", "name": "a"}, "eq": true}`,
		`{"query": {"kind": "test.flag", "name": "a"}}`,
		`{"query": {"kind": "test.flag", "name": "a"}, "eq": true, "absent": true}`,
		`{"query": {"kind": "test.flag", "name": "a"}, "absent": false}`,
		`{"query": {"kind": "test.flag", "name": "a"}, "eq": "x"}`,
		`{"query": {"kind": "test.nope", "name": "a"}, "eq": true}`,
		`{"input": "x.yml"}`,
		`{"input": "x.yml", "present": false}`,
		`{"not": {"all": []}}`,
		`{"all": {}}`,
		`[]`,
	} {
		var c Condition
		if err := json.Unmarshal([]byte(src), &c); err == nil {
			t.Errorf("Unmarshal(%s): no error", src)
		}
	}
}

func TestCondFacts(t *testing.T) {
	x, _ := FactEq(qTrue, true)
	y, _ := FactEq(qFalse, true)
	c := All(Any(x, FactAbsent(qFalse)), y, InputPresent(facts.MustCleanInputPath("a.yml")), x)
	var got []string
	for _, q := range c.Queries() {
		b, _ := facts.EncodeQuery(q)
		got = append(got, string(b))
	}
	want := `{"kind":"test.flag","name":"f"} {"kind":"test.flag","name":"t"}`
	if strings.Join(got, " ") != want {
		t.Errorf("Facts = %s", strings.Join(got, " "))
	}
}

func TestCondInputs(t *testing.T) {
	a, b := facts.MustCleanInputPath("a.yml"), facts.MustCleanInputPath("b.yml")
	c := All(InputPresent(b), Any(InputPresent(a), FactAbsent(facts.TestFlag{Name: "x"}), InputPresent(b)))
	got := c.Inputs()
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("Inputs = %v, want [a.yml b.yml]", got)
	}
	if got := FactAbsent(facts.TestFlag{Name: "x"}).Inputs(); len(got) != 0 {
		t.Errorf("a fact leaf has inputs %v", got)
	}
}

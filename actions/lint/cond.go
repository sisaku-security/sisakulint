package lint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/jsonschema"
)

// Condition is when a finding holds: a tree of all (and), any (or) and leaves
// that are a fact equal to a value, a fact absent, or an input present.
// There is no not; "holds when it is not there" is an absent leaf. The
// meaning is the table of Kleene's logic (true, false and unknown); Eval
// is its reference.
type Condition struct {
	kind  condKind
	subs  []Condition
	fact  facts.Query
	eq    json.RawMessage // canonical
	input facts.InputPath
}

type condKind uint8

const (
	condAll condKind = iota
	condAny
	condEq
	condAbsent
	condInput
)

// All holds when every c holds; with none, it holds.
func All(cs ...Condition) Condition { return Condition{kind: condAll, subs: slices.Clone(cs)} }

// Any holds when some c holds; with none, it does not.
func Any(cs ...Condition) Condition { return Condition{kind: condAny, subs: slices.Clone(cs)} }

// ConditionOp is what a node of a Condition is.
type ConditionOp uint8

const (
	ConditionOpLeaf ConditionOp = iota // a fact equal to a value, a fact absent, or an input present
	ConditionOpAll
	ConditionOpAny
)

// Op is what c is.
func (c Condition) Op() ConditionOp {
	switch c.kind {
	case condAll:
		return ConditionOpAll
	case condAny:
		return ConditionOpAny
	}
	return ConditionOpLeaf
}

// Parts are the parts of an all or an any, copied; a leaf has none.
func (c Condition) Parts() []Condition {
	ps := make([]Condition, len(c.subs))
	for i, s := range c.subs {
		ps[i] = s.clone()
	}
	return ps
}

// clone copies c and its parts.
func (c Condition) clone() Condition {
	c.subs = slices.Clone(c.subs)
	for i := range c.subs {
		c.subs[i] = c.subs[i].clone()
	}
	return c
}

// FactEq holds when q is Resolved to v. v must fit the value of q's kind.
func FactEq(q facts.Query, v any) (Condition, error) {
	if q == nil {
		return Condition{}, errors.New("no fact")
	}
	if _, err := facts.EncodeQuery(q); err != nil {
		return Condition{}, err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return Condition{}, err
	}
	c := facts.Checked(q, facts.RawAnswer{State: facts.StateFound, Value: b})
	if c.State != facts.StateFound {
		return Condition{}, fmt.Errorf("%s: %s", q.Kind(), c.Reason)
	}
	return Condition{kind: condEq, fact: q, eq: c.Value}, nil
}

// FactAbsent holds when q is Absent.
func FactAbsent(q facts.Query) Condition { return Condition{kind: condAbsent, fact: q} }

// InputPresent holds when the input named name is in the set of inputs.
func InputPresent(name facts.InputPath) Condition { return Condition{kind: condInput, input: name} }

// Eval is the truth of c, given the answers about facts and the states of
// inputs.
func Eval(c Condition, fact func(facts.Query) facts.RawAnswer, input func(name facts.InputPath) LookupState) expr.Truth {
	switch c.kind {
	case condAll, condAny:
		stop, rest := expr.TruthFalse, expr.TruthTrue // all: one false is false
		if c.kind == condAny {
			stop, rest = expr.TruthTrue, expr.TruthFalse // any: one true is true
		}
		out := rest
		for _, s := range c.subs {
			switch Eval(s, fact, input) {
			case stop:
				return stop
			case expr.TruthUnknown:
				out = expr.TruthUnknown
			}
		}
		return out
	case condEq:
		r := fact(c.fact)
		switch r.State {
		case facts.StateFound:
			v, err := jsonschema.Canonical(r.Value)
			if err != nil {
				return expr.TruthUnknown
			}
			if bytes.Equal(v, c.eq) {
				return expr.TruthTrue
			}
			return expr.TruthFalse
		case facts.StateAbsent:
			return expr.TruthFalse
		}
		return expr.TruthUnknown
	case condAbsent:
		switch fact(c.fact).State {
		case facts.StateAbsent:
			return expr.TruthTrue
		case facts.StateFound:
			return expr.TruthFalse
		}
		return expr.TruthUnknown
	case condInput:
		switch input(c.input) {
		case LookupFound:
			return expr.TruthTrue
		case LookupAbsent:
			return expr.TruthFalse
		}
	}
	return expr.TruthUnknown
}

// Queries are the facts of the leaves, each once, in the order of their
// EncodeQuery bytes.
func (c Condition) Queries() []facts.Query {
	type kv struct {
		key []byte
		q   facts.Query
	}
	var all []kv
	seen := map[facts.Query]bool{}
	var walk func(Condition)
	walk = func(c Condition) {
		if c.fact != nil && !seen[c.fact] {
			seen[c.fact] = true
			key, _ := facts.EncodeQuery(c.fact)
			all = append(all, kv{key, c.fact})
		}
		for _, s := range c.subs {
			walk(s)
		}
	}
	walk(c)
	slices.SortFunc(all, func(a, b kv) int { return bytes.Compare(a.key, b.key) })
	out := make([]facts.Query, len(all))
	for i, x := range all {
		out[i] = x.q
	}
	return out
}

// Inputs are the inputs of the leaves, each once, in the order of their
// names.
func (c Condition) Inputs() []facts.InputPath {
	var out []facts.InputPath
	var walk func(Condition)
	walk = func(c Condition) {
		if c.kind == condInput {
			out = append(out, c.input)
		}
		for _, s := range c.subs {
			walk(s)
		}
	}
	walk(c)
	slices.SortFunc(out, facts.CompareInputPaths)
	return slices.Compact(out)
}

func (c Condition) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	switch c.kind {
	case condAll, condAny:
		b.WriteString(map[condKind]string{condAll: `{"all":[`, condAny: `{"any":[`}[c.kind])
		for i, s := range c.subs {
			if i > 0 {
				b.WriteByte(',')
			}
			sb, err := s.MarshalJSON()
			if err != nil {
				return nil, err
			}
			b.Write(sb)
		}
		b.WriteString("]}")
	case condEq, condAbsent:
		q, err := facts.EncodeQuery(c.fact)
		if err != nil {
			return nil, err
		}
		b.WriteString(`{"query":`)
		b.Write(q)
		if c.kind == condEq {
			b.WriteString(`,"eq":`)
			b.Write(c.eq)
		} else {
			b.WriteString(`,"absent":true`)
		}
		b.WriteByte('}')
	case condInput:
		n, err := json.Marshal(c.input)
		if err != nil {
			return nil, err
		}
		b.WriteString(`{"input":`)
		b.Write(n)
		b.WriteString(`,"present":true}`)
	}
	return b.Bytes(), nil
}

func (c *Condition) UnmarshalJSON(data []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("a condition must be an object: %w", err)
	}
	has := func(keys ...string) bool {
		if len(m) != len(keys) {
			return false
		}
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				return false
			}
		}
		return true
	}
	isTrue := func(raw json.RawMessage) bool {
		var v bool
		return json.Unmarshal(raw, &v) == nil && v
	}
	switch {
	case has("all"), has("any"):
		kind, raw := condAll, m["all"]
		if raw == nil {
			kind, raw = condAny, m["any"]
		}
		var subs []Condition
		if err := json.Unmarshal(raw, &subs); err != nil {
			return err
		}
		*c = Condition{kind: kind, subs: subs}
	case has("query", "eq"):
		q, err := facts.DecodeQuery(m["query"])
		if err != nil {
			return err
		}
		var v any
		if err := json.Unmarshal(m["eq"], &v); err != nil {
			return err
		}
		chk := facts.Checked(q, facts.RawAnswer{State: facts.StateFound, Value: m["eq"]})
		if chk.State != facts.StateFound {
			return fmt.Errorf("%s: %s", q.Kind(), chk.Reason)
		}
		*c = Condition{kind: condEq, fact: q, eq: chk.Value}
	case has("query", "absent") && isTrue(m["absent"]):
		q, err := facts.DecodeQuery(m["query"])
		if err != nil {
			return err
		}
		*c = Condition{kind: condAbsent, fact: q}
	case has("input", "present") && isTrue(m["present"]):
		var s string
		if err := json.Unmarshal(m["input"], &s); err != nil {
			return err
		}
		n, err := facts.CleanInputPath(s)
		if err != nil {
			return err
		}
		*c = Condition{kind: condInput, input: n}
	default:
		return fmt.Errorf("a condition must be one of all, any, query with eq, query with absent true, input with present true")
	}
	return nil
}

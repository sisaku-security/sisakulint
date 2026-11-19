package attackrun

import (
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Substitution is a value of an example in which the carrier stands in
// ${{ }}, with the attack value put in its place: what GitHub makes of it
// before the run.
type Substitution struct {
	File  facts.InputPath `json:"file"`  // the example's file
	Where string          `json:"where"` // the key: jobs.<id>.steps[<i>].run, jobs.<id>.env.<name>, …
	Text  string          `json:"text"`
}

// canon is the text of an expression as compared to a carrier: without
// the spaces outside its string literals, and in lower case outside them,
// since names in expressions are compared without case.
func canon(s string) string {
	var b strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '\'':
			quoted = !quoted
			b.WriteRune(r)
		case quoted:
			b.WriteRune(r)
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
		default:
			b.WriteString(strings.ToLower(string(r)))
		}
	}
	return b.String()
}

// carrierOf is the canonical text of a's carrier, and whether it is an
// expression.
func carrierOf(a lint.AttackValue) (string, bool) {
	n, errs := expr.Parse(a.Carrier())
	if n == nil || len(errs) > 0 {
		return "", false
	}
	if _, ok := expr.AccessPath(n); !ok {
		return "", false
	}
	return canon(a.Carrier()), true
}

// partKind is how a part of a value stands to the carrier.
type partKind uint8

const (
	partText    partKind = iota // not an expression
	partCarrier                 // ${{ <carrier> }}
	partWrapped                 // an expression with the carrier inside it
	partOther                   // another expression
)

func kindOf(s workflow.String, p workflow.Part, carrier string) partKind {
	if !p.Expr {
		return partText
	}
	inner := s.Text()[p.Inner.Start:p.Inner.End]
	if canon(inner) == carrier {
		return partCarrier
	}
	if p.Tree != nil && containsCarrier(inner, p.Tree, carrier) {
		return partWrapped
	}
	return partOther
}

func containsCarrier(src string, n expr.Node, carrier string) bool {
	sp := n.Span()
	if canon(src[sp.Start:sp.End]) == carrier {
		return true
	}
	for _, c := range expr.Children(n) {
		if containsCarrier(src, c, carrier) {
			return true
		}
	}
	return false
}

// put is s with value in place of each ${{ <carrier> }}, and how its parts
// stand to the carrier.
func put(s workflow.String, carrier, value string) (text string, kinds []partKind) {
	t := s.Text()
	if s.Parts == nil {
		return t, nil
	}
	var b strings.Builder
	for _, p := range s.Parts {
		k := kindOf(s, p, carrier)
		kinds = append(kinds, k)
		if k == partCarrier {
			b.WriteString(value)
		} else {
			b.WriteString(t[p.Span.Start:p.Span.End])
		}
	}
	return b.String(), kinds
}

func has(kinds []partKind, k partKind) bool {
	for _, x := range kinds {
		if x == k {
			return true
		}
	}
	return false
}

// visit calls f with each string of the files of e that a step or a job
// reads, and the key it is under.
func visit(e lint.Example, f func(file facts.InputPath, where string, s workflow.String)) {
	files := append([]lint.ExampleFile{{InputKind: e.InputKind, Name: e.Name, Text: e.Text}}, e.Others...)
	for _, x := range files {
		tree := cst.ParseMode([]byte(x.Text), cst.ModeGitHub)
		name := x.Name
		mapping := func(where string, m workflow.Field[workflow.Map[workflow.String]]) {
			if m.Status != workflow.Present {
				return
			}
			for _, en := range m.Value.Entries {
				if en.Value.Status == workflow.Present {
					f(name, where+"."+en.Key.AsString(), en.Value.Value)
				}
			}
		}
		steps := func(where string, ss workflow.Field[workflow.List[workflow.Step]]) {
			if ss.Status != workflow.Present {
				return
			}
			for _, st := range ss.Value.Items {
				w := where + "." + st.Place.String()
				mapping(w+".env", st.Env)
				mapping(w+".with", st.With)
				if st.Run.Status == workflow.Present {
					f(name, w+".run", st.Run.Value)
				}
			}
		}
		if x.InputKind == lint.InputKindActionMetadata {
			a, _ := workflow.ParseActionMetadata(tree)
			if a != nil && a.Runs.Status == workflow.Present {
				steps("runs", a.Runs.Value.Steps)
			}
			continue
		}
		w, _ := workflow.Parse(tree)
		if w == nil {
			continue
		}
		mapping("env", w.Env)
		if w.Jobs.Status != workflow.Present {
			continue
		}
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			where := "jobs." + je.Key.AsString()
			mapping(where+".env", j.Env)
			mapping(where+".with", j.With)
			steps(where, j.Steps)
		}
	}
}

// Substitute are the values of e in which its attack value's carrier
// stands in ${{ }}, with the value put in, in the order of the files (the
// main file first) and of the keys: what to show of the attack. None when
// e has no attack value, or its carrier is no expression.
func Substitute(e lint.Example) []Substitution {
	a := e.Notes.AttackValue
	carrier, ok := carrierOf(a)
	if a.IsZero() || !ok {
		return nil
	}
	var out []Substitution
	visit(e, func(file facts.InputPath, where string, s workflow.String) {
		text, kinds := put(s, carrier, a.Value())
		if has(kinds, partCarrier) {
			out = append(out, Substitution{file, where, text})
		}
	})
	return out
}

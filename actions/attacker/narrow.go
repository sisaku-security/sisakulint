package attacker

import (
	"encoding/json"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
)

// Narrowing is what an if tells of the values it compares with strings:
// where the if is true, a reference it compares by == with plain literals
// only (plain) is one of them, but for the case of its letters. GitHub
// compares strings ignoring case, on its server and on the runner
// (https://github.com/github/docs/blob/935221fd662811fa04955b1759bf67b96b7ae028/content/actions/reference/workflows-and-actions/expressions.md,
// https://github.com/actions/runner/blob/397b032cbf865e9c3ddfab89d533ec19325e1273/src/Sdk/DTExpressions2/Expressions2/EvaluationResult.cs#L256),
// and both took as equal only letters to letters, when one of the two was
// not ASCII (2026-10-23, on GitHub-hosted runners: K and the Kelvin sign
// on both, s and the long s on the server).
type Narrowing struct {
	p      PlacedIf
	t      Table // the attacker run table the if is read with
	groups []compared
}

// compared is a reference an if compares with strings, and the strings.
type compared struct {
	path       []expr.PathElem
	candidates []string
	plain      bool // every candidate is plain
}

// NarrowingOf reads the comparisons of the if p with strings: == and != of a
// reference and a string literal, and contains of fromJSON of an array of
// strings and a reference. A number is not a candidate: a string that
// GitHub reads as the number (with spaces around it, 0x1) equals it too.
func (t Table) NarrowingOf(p PlacedIf) Narrowing {
	n := Narrowing{p: p, t: t}
	for _, cmp := range comparisons(p.c) {
		cands, ok := candidatesOf(cmp)
		if !ok {
			continue
		}
		p, ok := expr.AccessPath(cmp.Path)
		if !ok || !named(p) {
			continue
		}
		i := n.group(p)
		if i < 0 {
			n.groups = append(n.groups, compared{path: p, plain: true})
			i = len(n.groups) - 1
		}
		for _, s := range cands {
			n.groups[i].candidates = append(n.groups[i].candidates, s)
			n.groups[i].plain = n.groups[i].plain && plain(s)
		}
	}
	return n
}

// Narrows is whether, in every run of e in which the if is true (in e
// alone for an event without runs), the value at path is one of the
// strings the if compares a reference with: path is a reference the if
// compares, or one below it. The if is read with the reference set to a string that is none
// of them (excluded), and is false in each run.
func (n Narrowing) Narrows(e analysis.EventActivity, path []expr.PathElem) bool {
	for _, g := range n.groups {
		if !g.plain || !prefix(g.path, path) {
			continue
		}
		if len(Runs(e)) == 0 {
			if n.p.truth(e, g.over(eventLookup(e)), nil) == expr.TruthFalse {
				return true
			}
			continue
		}
		all := true // and so when the attacker of n.t starts no run of e
		for _, k := range n.t.runs(e) {
			if n.p.truth(e, g.over(n.t.lookupFor(e, k)), nil) != expr.TruthFalse {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// NarrowsAnyEvent is Narrows with nothing known but the reference: the
// event, its payload and the other contexts are not known.
func (n Narrowing) NarrowsAnyEvent(path []expr.PathElem) bool {
	none := func([]expr.PathElem) (expr.Value, bool) { return expr.Value{}, false }
	for _, g := range n.groups {
		if g.plain && prefix(g.path, path) && n.p.truth(analysis.EventActivity{}, g.over(none), nil) == expr.TruthFalse {
			return true
		}
	}
	return false
}

// over is lookup with the reference of g set to a string none of its
// candidates is.
func (g compared) over(lookup func([]expr.PathElem) (expr.Value, bool)) func([]expr.PathElem) (expr.Value, bool) {
	v := expr.AbstractValue(excluded(g.candidates))
	return func(p []expr.PathElem) (expr.Value, bool) {
		if samePath(g.path, p) {
			return v, true
		}
		return lookup(p)
	}
}

func (n Narrowing) group(p []expr.PathElem) int {
	for i, g := range n.groups {
		if samePath(g.path, p) {
			return i
		}
	}
	return -1
}

// candidatesOf are the strings of cmp: of == or != with a string literal,
// or of contains of fromJSON of an array whose items are all strings.
func candidatesOf(cmp Comparison) ([]string, bool) {
	switch x := cmp.Node.(type) {
	case *expr.Compare:
		if s, ok := stringLit(x.X); ok {
			return []string{s}, true
		}
		if s, ok := stringLit(x.Y); ok {
			return []string{s}, true
		}
	case *expr.Call:
		if !cmp.Array || len(x.Args) != 2 {
			return nil, false
		}
		f, ok := x.Args[0].(*expr.Call)
		if !ok || len(f.Args) != 1 {
			return nil, false
		}
		src, ok := stringLit(f.Args[0])
		if !ok {
			return nil, false
		}
		var out []string
		if json.Unmarshal([]byte(src), &out) != nil {
			return nil, false // an item that is not a string
		}
		return out, true
	}
	return nil, false
}

// named is whether every step of p is a name: no star, no index by an
// expression.
func named(p []expr.PathElem) bool {
	for _, e := range p {
		if e.Star || e.Dynamic != nil {
			return false
		}
	}
	return true
}

// prefix is whether the reference p is, or is below, the reference of g:
// a property of a string is null.
func prefix(g, p []expr.PathElem) bool {
	return len(g) <= len(p) && named(p[:len(g)]) && samePath(g, p[:len(g)])
}

// samePath compares two references as GitHub does (expr.EqualName), but
// the name below env with its case: the env of a runner on Linux or macOS
// tells names by their case.
func samePath(a, b []expr.PathElem) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Star || b[i].Star || a[i].Dynamic != nil || b[i].Dynamic != nil {
			return false
		}
		if i == 1 && expr.EqualName(a[0].Name, "env") {
			if a[i].Name != b[i].Name {
				return false
			}
			continue
		}
		if !expr.EqualName(a[i].Name, b[i].Name) {
			return false
		}
	}
	return true
}

// plain is whether s is a plain literal: ASCII letters, digits, spaces,
// -, _, . and /, and no word that starts with -. A value GitHub takes as
// equal to s differs from s only in letters.
func plain(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9', b == ' ', b == '_', b == '.', b == '/':
		case b == '-':
			if i == 0 || s[i-1] == ' ' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// excluded is a string equal to none of its strings, ignoring ASCII case.
type excluded []string

func (excluded) Truthy() expr.Truth { return expr.TruthUnknown }

func (x excluded) Equal(v expr.Value) expr.Truth {
	s, ok := v.Str()
	if !ok || !ascii(s) {
		return expr.TruthUnknown
	}
	for _, c := range x {
		if strings.EqualFold(c, s) {
			return expr.TruthFalse
		}
	}
	return expr.TruthUnknown
}

func (excluded) Within(string) expr.Truth     { return expr.TruthUnknown }
func (excluded) Prefix(string) expr.Truth     { return expr.TruthUnknown }
func (excluded) Suffix(string) expr.Truth     { return expr.TruthUnknown }
func (excluded) Contains(string) expr.Truth   { return expr.TruthUnknown }
func (excluded) StartsWith(string) expr.Truth { return expr.TruthUnknown }
func (excluded) EndsWith(string) expr.Truth   { return expr.TruthUnknown }

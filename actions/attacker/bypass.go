package attacker

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Comparison is a comparison of an if with a string: == or != of a
// reference and a string, contains, startsWith or endsWith of a string and
// a reference or of a reference and a string, or contains of fromJSON of
// an array and a reference.
type Comparison struct {
	Node    expr.Node
	Path    expr.Node
	Literal string // the string; the strings of an array, joined by ", "
	Func    string // contains, startsWith, endsWith; empty for == and !=
	Array   bool   // contains of fromJSON of an array, compared by element
	// ReferenceFirst is whether the reference is the first argument of
	// Func: a value with the string as a part passes
	ReferenceFirst bool
	// Fits is whether, of a call SubstringBypasses gives with
	// ReferenceFirst, the string has the form of the attacker's value of
	// the reference (a login, an ID, owner/name), so that == of the two is
	// a comparison some value passes
	Fits bool
}

// dependabotPaths are those whose value a run of Dependabot changes.
var dependabotPaths = []string{"actor", "triggering_actor", "event.sender.login", "actor_id", "triggering_actor_id", "event.sender.id"}

// DependabotBypasses are the comparisons of the if p that a run of
// Dependabot lets through, on an event of evs that p keeps the attacker out of when
// they push themselves: the if is false in the own run with the attacker
// as its actor, not in the run of Dependabot, and false again in it when
// the comparison alone is read as in the own run.
func DependabotBypasses(p PlacedIf, evs []analysis.EventActivity) []Comparison {
	var out []Comparison
	for _, e := range evs {
		own, dep := lookupRows(e, Outsider.rowsOf(e, RunOwn, true)), Outsider.lookupFor(e, RunDependabot)
		// the own run reads a part of a string as the whole: a login that is
		// a part is unsound-contains', not a run of Dependabot
		exact := exactCalls(p.c, own)
		if !hasRun(e, RunDependabot) || !acts(e) || p.truth(eventOf(e), own, exact) != expr.TruthFalse || p.truth(eventOf(e), dep, nil) == expr.TruthFalse {
			continue
		}
		for _, cmp := range comparisons(p.c) {
			if !actorPath(cmp.Path) || cmp.ReferenceFirst {
				continue // a reference first is bot-conditions' path-first, not read
			}
			v, ok := exact(cmp.Node)
			if !ok {
				v = expr.PartialWith(cmp.Node, own, nil)
			}
			if p.truth(eventOf(e), dep, only(cmp.Node, v)) == expr.TruthFalse {
				out = appendNew(out, cmp)
			}
		}
	}
	return out
}

// OtherBots are the comparisons of an actor with a name of a bot ([bot] at
// its end) in the if p, when p keeps the attacker out of every run of every event
// of evs where they act themselves (acting): whether the attacker can have that bot act for them is not known.
// dependabot[bot] is among them only where no event has a run of
// Dependabot. An if some run passes has none: the attacker is in already.
func OtherBots(p PlacedIf, evs []analysis.EventActivity) []Comparison {
	dependabot, any := false, false
	for _, e := range evs {
		for _, l := range acting(e) {
			if p.truth(eventOf(e), l, nil) != expr.TruthFalse {
				return nil
			}
			any = true
		}
		dependabot = dependabot || hasRun(e, RunDependabot)
	}
	if !any {
		return nil // no run the attacker acts in: what the if keeps out is not theirs
	}
	var out []Comparison
	for _, cmp := range comparisons(p.c) {
		if actorPath(cmp.Path) && !cmp.ReferenceFirst && strings.HasSuffix(strings.ToLower(cmp.Literal), "[bot]") && (!dependabot || !strings.EqualFold(cmp.Literal, "dependabot[bot]")) {
			out = appendNew(out, cmp)
		}
	}
	return out
}

// SubstringBypasses are the calls of contains, startsWith and endsWith of
// a string and a reference in the if p that let a part of a value through: p is
// not false in some run of an event of evs where the attacker acts
// (acting), and false in every such run when the call alone is read as
// comparing whole values (wordsEqual); and the reference is not the
// attacker's ID in any such run (notID).
func SubstringBypasses(p PlacedIf, evs []analysis.EventActivity) []Comparison {
	var out []Comparison
	for _, cmp := range comparisons(p.c) {
		if cmp.Func == "" || cmp.Array || cmp.Literal == "" {
			continue
		}
		passed, closed := false, true
		for _, e := range evs {
			for _, l := range actingOwn(e) {
				if p.truth(eventOf(e), l, nil) == expr.TruthFalse {
					continue
				}
				passed = true
				exact := wordsEqual(cmp, l)
				if p.truth(eventOf(e), l, only(cmp.Node, exact)) != expr.TruthFalse {
					closed = false
				}
			}
		}
		if passed && closed && everyRun(p, cmp, evs, notID) {
			cmp.Fits = cmp.ReferenceFirst && everyRun(p, cmp, evs, func(v expr.Value) bool { return fits(v, strings.ToLower(cmp.Literal)) })
			out = appendNew(out, cmp)
		}
	}
	return out
}

// everyRun is whether ok holds of the attacker's value of the reference of
// cmp in every run of evs where they act and p is not false, and in one at
// least.
func everyRun(p PlacedIf, cmp Comparison, evs []analysis.EventActivity, ok func(expr.Value) bool) bool {
	some := false
	for _, e := range evs {
		for _, l := range actingOwn(e) {
			if p.truth(eventOf(e), l, nil) == expr.TruthFalse {
				continue
			}
			if !ok(expr.Partial(cmp.Path, l)) {
				return false
			}
			some = true
		}
	}
	return some
}

// notID is whether v is not the attacker's ID, nor may be: GitHub numbers
// accounts, so whether an attacker can have an ID that is a part of the
// string, or that has the string as a part, is not known.
func notID(v expr.Value) bool {
	a, ok := v.AbstractOf()
	if !ok {
		return true
	}
	switch x := a.(type) {
	case own:
		return x.form != formID
	case oneOf:
		for _, m := range x {
			if !notID(m) {
				return false
			}
		}
	}
	return true
}

// fits is whether lit has the form of the attacker's name v.
func fits(v expr.Value, lit string) bool {
	return eachName(v, func(o own) bool { return o.is(lit) })
}

// eachName is whether v is the attacker's own name, ok of each name it may
// be (self is a login; null, of a deleted fork, is none), and one at least.
func eachName(v expr.Value, ok func(own) bool) bool {
	a, isAbstract := v.AbstractOf()
	if !isAbstract {
		return false
	}
	switch x := a.(type) {
	case own:
		return ok(x)
	case self:
		return ok(own{form: formLogin})
	case oneOf:
		some := false
		for _, m := range x {
			if _, isAbstract := m.AbstractOf(); !isAbstract {
				continue
			}
			if !eachName(m, ok) {
				return false
			}
			some = true
		}
		return some
	}
	return false
}

// wordsEqual is the value of cmp read as comparing whole values: its
// reference being equal to its string, when ReferenceFirst; else one of
// the words of its string being equal to its reference.
func wordsEqual(cmp Comparison, l func([]expr.PathElem) (expr.Value, bool)) expr.Value {
	ref := expr.Partial(cmp.Path, l)
	if cmp.ReferenceFirst {
		switch equal(ref, cmp.Literal) {
		case expr.TruthTrue:
			return expr.Bool(true)
		case expr.TruthFalse:
			return expr.Bool(false)
		}
		return expr.Value{}
	}
	out := expr.TruthFalse
	for _, w := range Words(cmp.Literal) {
		switch equal(ref, w) {
		case expr.TruthTrue:
			return expr.Bool(true)
		case expr.TruthUnknown:
			out = expr.TruthUnknown
		}
	}
	if out == expr.TruthFalse {
		return expr.Bool(false)
	}
	return expr.Value{}
}

// equal is == of v and the string w.
func equal(v expr.Value, w string) expr.Truth { return valuesEqual(v, expr.String(w)) }

// Words are the words of a string a contains of it reads: split by white
// space and commas, the empty ones left out.
func Words(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
}

// acting are the lookups of the runs of e with the attacker as the actor
// where they act themselves: the reading of an if as a guard against them.
func acting(e analysis.EventActivity) []func([]expr.PathElem) (expr.Value, bool) {
	var out []func([]expr.PathElem) (expr.Value, bool)
	if !acts(e) {
		return nil // the attacker does not trigger it: one who can write does (labeled)
	}
	for _, k := range Runs(e) {
		if k != RunOthersComment { // someone else writes it
			out = append(out, lookupRows(e, Outsider.rowsOf(e, k, k != RunDependabot)))
		}
	}
	return out
}

// actingOwn is acting without the run of Dependabot: what passes there is
// bot-conditions'.
func actingOwn(e analysis.EventActivity) []func([]expr.PathElem) (expr.Value, bool) {
	if !acts(e) {
		return nil
	}
	var out []func([]expr.PathElem) (expr.Value, bool)
	for _, k := range Runs(e) {
		if k != RunOthersComment && k != RunDependabot {
			out = append(out, lookupRows(e, Outsider.rowsOf(e, k, true)))
		}
	}
	return out
}

// exactCalls overrides each call of c that compares a part of a string with
// the reading of its words as whole values, in the run l.
func exactCalls(c workflow.Field[workflow.If], l func([]expr.PathElem) (expr.Value, bool)) func(expr.Node) (expr.Value, bool) {
	vals := map[expr.Node]expr.Value{}
	for _, cmp := range comparisons(c) {
		if cmp.Func != "" && !cmp.Array && cmp.Literal != "" {
			vals[cmp.Node] = wordsEqual(cmp, l)
		}
	}
	return func(n expr.Node) (expr.Value, bool) {
		v, ok := vals[n]
		return v, ok
	}
}

// only overrides the node n with v.
func only(n expr.Node, v expr.Value) func(expr.Node) (expr.Value, bool) {
	return func(m expr.Node) (expr.Value, bool) {
		if m == n {
			return v, true
		}
		return expr.Value{}, false
	}
}

func hasRun(e analysis.EventActivity, k RunKind) bool {
	for _, r := range Runs(e) {
		if r == k {
			return true
		}
	}
	return false
}

func actorPath(n expr.Node) bool {
	p, ok := expr.AccessPath(n)
	if !ok {
		return false
	}
	key, ok := below("github", p)
	if !ok {
		return false
	}
	for _, d := range dependabotPaths {
		if key == d {
			return true
		}
	}
	return false
}

func appendNew(out []Comparison, c Comparison) []Comparison {
	for _, o := range out {
		if o.Node == c.Node {
			return out
		}
	}
	return append(out, c)
}

// comparisons are the comparisons of c's expression, in order.
func comparisons(c workflow.Field[workflow.If]) []Comparison {
	if c.Status != workflow.Present || c.Value.Expr == nil || c.Value.Expr.Tree == nil {
		return nil
	}
	var out []Comparison
	var walk func(n expr.Node)
	walk = func(n expr.Node) {
		if cmp, ok := comparisonOf(n); ok {
			out = append(out, cmp)
		}
		for _, k := range expr.Children(n) {
			walk(k)
		}
	}
	walk(c.Value.Expr.Tree)
	return out
}

func comparisonOf(n expr.Node) (Comparison, bool) {
	switch x := n.(type) {
	case *expr.Compare:
		if x.Op != expr.OpEq && x.Op != expr.OpNe {
			return Comparison{}, false
		}
		if s, ok := stringLit(x.Y); ok && isPath(x.X) {
			return Comparison{Node: n, Path: x.X, Literal: s}, true
		}
		if s, ok := stringLit(x.X); ok && isPath(x.Y) {
			return Comparison{Node: n, Path: x.Y, Literal: s}, true
		}
		if lit, ok := x.Y.(*expr.Literal); ok && lit.Kind == expr.LitNumber && isPath(x.X) {
			return Comparison{Node: n, Path: x.X, Literal: lit.Raw}, true
		}
		if lit, ok := x.X.(*expr.Literal); ok && lit.Kind == expr.LitNumber && isPath(x.Y) {
			return Comparison{Node: n, Path: x.Y, Literal: lit.Raw}, true
		}
	case *expr.Call:
		name := strings.ToLower(x.Name)
		if len(x.Args) != 2 || name != "contains" && name != "startswith" && name != "endswith" {
			return Comparison{}, false
		}
		if !isPath(x.Args[1]) {
			if s, ok := stringLit(x.Args[1]); ok && isPath(x.Args[0]) {
				return Comparison{Node: n, Path: x.Args[0], Literal: s, Func: x.Name, ReferenceFirst: true}, true
			}
			return Comparison{}, false
		}
		if s, ok := stringLit(x.Args[0]); ok {
			return Comparison{Node: n, Path: x.Args[1], Literal: s, Func: x.Name}, true
		}
		if name == "contains" {
			if ws, ok := arrayLit(x.Args[0]); ok {
				return Comparison{Node: n, Path: x.Args[1], Literal: strings.Join(ws, ", "), Func: x.Name, Array: true}, true
			}
		}
	}
	return Comparison{}, false
}

// arrayLit is the strings of fromJSON of a string that is a JSON array of
// strings and numbers.
func arrayLit(n expr.Node) ([]string, bool) {
	c, ok := n.(*expr.Call)
	if !ok || !strings.EqualFold(c.Name, "fromJSON") || len(c.Args) != 1 {
		return nil, false
	}
	s, ok := stringLit(c.Args[0])
	if !ok {
		return nil, false
	}
	var vs []any
	if json.Unmarshal([]byte(s), &vs) != nil {
		return nil, false
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = fmt.Sprint(v)
	}
	return out, true
}

func stringLit(n expr.Node) (string, bool) {
	if g, ok := n.(*expr.Group); ok {
		return stringLit(g.X)
	}
	l, ok := n.(*expr.Literal)
	if !ok || l.Kind != expr.LitString {
		return "", false
	}
	return l.Str, true
}

func isPath(n expr.Node) bool { _, ok := expr.AccessPath(n); return ok }

// PathText is the reference n as its names joined by dots, as written.
func PathText(n expr.Node) string {
	p, _ := expr.AccessPath(n)
	names := make([]string, len(p))
	for i, e := range p {
		names[i] = e.Name
	}
	return strings.Join(names, ".")
}

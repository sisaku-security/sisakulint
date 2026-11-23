package attacker

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// self is the attacker's login in a run in which they are the actor too:
// the author of what they comment on, when it is theirs. It is the actor's
// login (own), unlike two names of the attacker's that may be of two
// accounts.
type self struct{}

var selfName = expr.AbstractValue(self{})

func (self) Truthy() expr.Truth { return expr.TruthTrue }

func (self) Equal(v expr.Value) expr.Truth {
	if a, ok := v.AbstractOf(); ok {
		switch a := a.(type) {
		case self:
			return expr.TruthTrue
		case own:
			if a.form == formLogin {
				return expr.TruthTrue
			}
			return expr.TruthFalse
		case symbol, others:
			return expr.TruthFalse
		}
		return expr.TruthUnknown
	}
	if v.Known() {
		return expr.TruthFalse
	}
	return expr.TruthUnknown
}

func (self) Within(s string) expr.Truth { return own{form: formLogin}.Within(s) }
func (self) Prefix(s string) expr.Truth { return own{form: formLogin}.Prefix(s) }
func (self) Suffix(s string) expr.Truth { return own{form: formLogin}.Suffix(s) }

func (self) Contains(s string) expr.Truth   { return own{form: formLogin}.Contains(s) }
func (self) StartsWith(s string) expr.Truth { return own{form: formLogin}.StartsWith(s) }
func (self) EndsWith(s string) expr.Truth   { return own{form: formLogin}.EndsWith(s) }

// others is a name of an account that is not the attacker's: the author of
// what they comment on, when it is another's.
type others struct{}

var othersName = expr.AbstractValue(others{})

func (others) Truthy() expr.Truth { return expr.TruthTrue }

func (others) Equal(v expr.Value) expr.Truth {
	if a, ok := v.AbstractOf(); ok {
		if _, ok := a.(own); ok {
			return expr.TruthFalse
		}
	}
	return expr.TruthUnknown
}

func (others) Within(string) expr.Truth { return expr.TruthUnknown }
func (others) Prefix(string) expr.Truth { return expr.TruthUnknown }
func (others) Suffix(string) expr.Truth { return expr.TruthUnknown }

func (others) Contains(string) expr.Truth   { return expr.TruthUnknown }
func (others) StartsWith(string) expr.Truth { return expr.TruthUnknown }
func (others) EndsWith(string) expr.Truth   { return expr.TruthUnknown }

// ActorListed is whether v, the value of an input that opens the gate of
// an agent action, lets in the attacker who triggers e themselves, as its
// actor, in a run past ifs. The actions compare the run's actor with v as
// GitHub evaluates it: '*' after a trim lets anyone in, else each element,
// split by commas and trimmed, is a name. So an element that is one ${{ }}
// whose value is the actor's login lets them in. anyone is whether a run
// in which v lets them in reads it as '*'.
func (t Table) ActorListed(ifs []PlacedIf, e analysis.EventActivity, v workflow.String) (listed expr.Truth, anyone bool) {
	listed = expr.TruthFalse
	for _, rows := range t.gateRuns(e) {
		lookup := lookupRows(e, rows)
		if slices.ContainsFunc(ifs, func(p PlacedIf) bool { return p.truth(eventOf(e), lookup, nil) == expr.TruthFalse }) {
			continue
		}
		switch t, star := listedIn(v, lookup); t {
		case expr.TruthTrue:
			listed, anyone = expr.TruthTrue, anyone || star
		case expr.TruthUnknown:
			if listed == expr.TruthFalse {
				listed = expr.TruthUnknown
			}
		}
	}
	return listed, anyone
}

// gateRuns are the rows of the runs of e whose actor is the attacker
// (actorRuns). On an event of a comment, the attacker comments on what
// they wrote, whose rows are theirs, or on what another wrote, whose
// author is not them.
func (t Table) gateRuns(e analysis.EventActivity) [][]row {
	on := objects[e.Name()].on
	var out [][]row
	for _, k := range t.actorRuns(e) {
		rows := t.rowsOf(e, k, true)
		if k != RunOwn || on == nil {
			out = append(out, rows)
			continue
		}
		self := selfRows(on)
		if e.Name() == workflow.EventNamePullRequestReview {
			// GitHub lets no author approve their own pull request
			self = append(self, row{"event.review.state", unapprovedState})
		}
		out = append(out, slices.Concat(rows, self), slices.Concat(rows, othersRows(on)))
	}
	return out
}

// unapproved is the state of a review that the author of a pull request
// writes on their own pull request: not approved, as GitHub lets no author
// approve their own pull request; which other state it is is not known.
type unapproved struct{}

var unapprovedState = expr.AbstractValue(unapproved{})

func (unapproved) Truthy() expr.Truth { return expr.TruthUnknown }

func (unapproved) Equal(v expr.Value) expr.Truth {
	if s, ok := v.Str(); ok && strings.EqualFold(s, "approved") {
		return expr.TruthFalse
	}
	return expr.TruthUnknown
}

func (unapproved) Within(string) expr.Truth     { return expr.TruthUnknown }
func (unapproved) Prefix(string) expr.Truth     { return expr.TruthUnknown }
func (unapproved) Suffix(string) expr.Truth     { return expr.TruthUnknown }
func (unapproved) Contains(string) expr.Truth   { return expr.TruthUnknown }
func (unapproved) StartsWith(string) expr.Truth { return expr.TruthUnknown }
func (unapproved) EndsWith(string) expr.Truth   { return expr.TruthUnknown }

// selfRows are on as the attacker's: the login of its author is the
// actor's (self), whose author_association is an outsider's.
func selfRows(on []row) []row {
	out := slices.Clone(on)
	for i, r := range out {
		if strings.HasSuffix(r.path, ".user.login") {
			out[i].value = selfName
		}
	}
	return out
}

// othersRows are the names of the authors of on as another's: their
// author_association is not known.
func othersRows(on []row) []row {
	var out []row
	for _, r := range on {
		if strings.HasSuffix(r.path, ".user.login") || strings.HasSuffix(r.path, ".user.id") {
			out = append(out, row{r.path, othersName})
		}
	}
	return out
}

// segment is a part of a gate's value in a run: text, or the value of a
// ${{ }}.
type segment struct {
	text  string
	known bool // text, or a string
	actor bool // the attacker's login
	none  bool // no login of theirs and no comma: a name of the repository, another's, their ID or repository
}

// listedIn is whether v, with its ${{ }} read by lookup, lets the actor
// in, and whether as '*'.
func listedIn(v workflow.String, lookup func([]expr.PathElem) (expr.Value, bool)) (expr.Truth, bool) {
	text := v.Text()
	var segs []segment
	for _, p := range v.Parts {
		if !p.Expr {
			segs = append(segs, segment{text: text[p.Span.Start:p.Span.End], known: true})
			continue
		}
		segs = append(segs, valueSegment(p, lookup))
	}
	whole, known := "", true
	for _, s := range segs {
		known = known && s.known
		whole += s.text
	}
	if known && strings.TrimSpace(whole) == "*" {
		return expr.TruthTrue, true
	}
	unknown := slices.ContainsFunc(segs, func(s segment) bool { return !s.known && !s.actor && !s.none })
	var elem []segment
	// alone is whether elem is the actor's login and white space
	alone := func() bool {
		n, actor := 0, false
		for _, s := range elem {
			if !s.known {
				n, actor = n+1, s.actor
			} else if strings.TrimSpace(s.text) != "" {
				return false
			}
		}
		return n == 1 && actor
	}
	for _, s := range segs {
		if !s.known {
			elem = append(elem, s)
			continue
		}
		for i, t := range strings.Split(s.text, ",") {
			if i > 0 {
				if alone() {
					return expr.TruthTrue, false
				}
				elem = nil
			}
			elem = append(elem, segment{text: t, known: true})
		}
	}
	switch {
	case alone():
		return expr.TruthTrue, false
	case unknown:
		return expr.TruthUnknown, false
	}
	return expr.TruthFalse, false
}

// valueSegment is the value of the ${{ }} p in a run.
func valueSegment(p workflow.Part, lookup func([]expr.PathElem) (expr.Value, bool)) segment {
	if p.Tree == nil {
		return segment{}
	}
	x := expr.Partial(p.Tree, lookup)
	if s, ok := x.Str(); ok {
		return segment{text: s, known: true}
	}
	if x.Known() {
		return segment{none: true} // null, a bool or a number: neither '*' nor a login, and no comma
	}
	if a, ok := x.AbstractOf(); ok {
		switch a := a.(type) {
		case own:
			if a.form == formLogin {
				return segment{actor: true}
			}
			return segment{none: true}
		case self:
			return segment{actor: true}
		case symbol, others:
			return segment{none: true}
		case oneOf:
			// the attacker chooses which: their login, if it is one of them
			if slices.ContainsFunc(a, func(m expr.Value) bool {
				b, ok := m.AbstractOf()
				return ok && b == expr.Abstract(own{form: formLogin})
			}) {
				return segment{actor: true}
			}
		}
	}
	return segment{}
}

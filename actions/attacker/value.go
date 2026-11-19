package attacker

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
)

// nameForm is the form of a name an attacker has or gives.
type nameForm uint8

const (
	formLogin nameForm = iota + 1 // a login: letters, digits and single dashes inside, 39 at most
	formID                        // the number of an account
	formRepo                      // owner/name of a repository
)

// own is a name of the attacker's own account or repository. No name
// written in the workflow is it: those are of the people the author
// trusts, and no symbol of the repository is it either.
type own struct{ form nameForm }

// chosen is a name the attacker gives: a branch's (git-check-ref-format).
type chosen struct{}

// symbol is a value of the repository the workflow runs in, which the
// attacker does not decide: equal to itself, to nothing of the attacker's.
type symbol string

const (
	repository      symbol = "repository"       // github.repository
	repositoryOwner symbol = "repository-owner" // github.repository_owner
)

// set is one of the values, the attacker choosing which.
type set []string

// outsiderAssociations are the author_association an attacker obtains by
// their own hand.
var outsiderAssociations = []string{"NONE", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "CONTRIBUTOR"}

func (own) Truthy() expr.Truth { return expr.TruthTrue }

func (o own) Equal(v expr.Value) expr.Truth {
	if a, ok := v.AbstractOf(); ok {
		switch a := a.(type) {
		case symbol, others:
			return expr.TruthFalse
		case self:
			return a.Equal(expr.AbstractValue(o))
		}
		return expr.TruthUnknown
	}
	if v.Known() {
		return expr.TruthFalse
	}
	return expr.TruthUnknown
}

func (o own) Within(s string) expr.Truth { return maybe(o.fits(s, strings.Contains)) }
func (o own) Prefix(s string) expr.Truth { return maybe(o.fits(s, strings.HasPrefix)) }
func (o own) Suffix(s string) expr.Truth { return maybe(o.fits(s, strings.HasSuffix)) }

func (o own) Contains(s string) expr.Truth   { return maybe(o.has(s, true, true)) }
func (o own) StartsWith(s string) expr.Truth { return maybe(o.has(s, false, true)) }
func (o own) EndsWith(s string) expr.Truth   { return maybe(o.has(s, true, false)) }

// has is whether some name of o's form has s as a part: s with characters
// of the form before it (before) or after it (after), or s alone. A
// repository's characters may be of its owner, /, and of its name.
func (o own) has(s string, before, after bool) bool {
	if s == "" {
		return true
	}
	if o.form == formRepo && !before && strings.Contains(s, "/") {
		return false // the start up to / is a whole owner, a name written in the workflow: never the attacker's (own)
	}
	fill := []string{"a"}
	switch o.form {
	case formID:
		fill = []string{"1"}
	case formRepo:
		fill = []string{"a", "a/", "/a", "a/a"}
	}
	pres, posts := []string{""}, []string{""}
	if before {
		pres = append(pres, fill...)
	}
	if after {
		posts = append(posts, fill...)
	}
	for _, pre := range pres {
		for _, post := range posts {
			if o.is(pre + s + post) {
				return true
			}
		}
	}
	return false
}

// fits is whether some name of o's form is a part of s, as at reads a part:
// one letter or digit is a login and an ID's digit, a/b a repository.
func (o own) fits(s string, at func(s, part string) bool) bool {
	for i := 0; i < len(s); i++ {
		for j := i + 1; j <= len(s) && j-i <= 100; j++ {
			if o.is(s[i:j]) && at(s, s[i:j]) {
				return true
			}
		}
	}
	return false
}

func (o own) is(p string) bool {
	switch o.form {
	case formLogin:
		return login(p)
	case formID:
		return p != "" && strings.Trim(p, "0123456789") == ""
	case formRepo:
		owner, name, ok := strings.Cut(p, "/")
		return ok && login(owner) && name != "" && strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-_.") == ""
	}
	return false
}

// login is whether p is a login: letters, digits and dashes, not first,
// not last and not two together, 39 at most.
func login(p string) bool {
	if p == "" || len(p) > 39 || p[0] == '-' || p[len(p)-1] == '-' || strings.Contains(p, "--") {
		return false
	}
	return strings.Trim(p, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func (chosen) Truthy() expr.Truth { return expr.TruthTrue }

func (c chosen) Equal(v expr.Value) expr.Truth {
	if s, ok := v.Str(); ok && !refName(s) {
		return expr.TruthFalse
	}
	return expr.TruthUnknown
}

func (chosen) Within(s string) expr.Truth { return maybe(strings.IndexFunc(s, refByte) >= 0) }
func (chosen) Prefix(s string) expr.Truth { return maybe(s != "" && refByte(rune(s[0]))) }
func (chosen) Suffix(s string) expr.Truth { return maybe(s != "" && refByte(rune(s[len(s)-1]))) }

func (chosen) Contains(s string) expr.Truth   { return maybe(refPart(s)) }
func (chosen) StartsWith(s string) expr.Truth { return maybe(refPart(s)) }
func (chosen) EndsWith(s string) expr.Truth   { return maybe(refPart(s)) }

// refPart is whether s may be a part of the name of a branch: bytes a
// name may have, and no "..".
func refPart(s string) bool {
	return !strings.Contains(s, "..") && strings.IndexFunc(s, func(r rune) bool { return !refByte(r) }) < 0
}

// refName is whether s may be the name of a branch: no space, control
// character, ~ ^ : ? * [ \, no .. and not empty (git-check-ref-format).
func refName(s string) bool {
	return s != "" && !strings.Contains(s, "..") && strings.IndexFunc(s, func(r rune) bool { return !refByte(r) }) < 0
}

func refByte(r rune) bool { return r > ' ' && r != 0x7f && !strings.ContainsRune("~^:?*[\\", r) }

func (symbol) Truthy() expr.Truth { return expr.TruthTrue }

func (y symbol) Equal(v expr.Value) expr.Truth {
	a, ok := v.AbstractOf()
	if !ok {
		if v.Known() && v.Truthy() == expr.TruthFalse && !isString(v) {
			return expr.TruthFalse // null or false: a name of the repository is neither, nor 0
		}
		return expr.TruthUnknown
	}
	switch o := a.(type) {
	case symbol:
		if o == y {
			return expr.TruthTrue
		}
	case own:
		return expr.TruthFalse
	}
	return expr.TruthUnknown
}

func (symbol) Within(string) expr.Truth { return expr.TruthUnknown }
func (symbol) Prefix(string) expr.Truth { return expr.TruthUnknown }
func (symbol) Suffix(string) expr.Truth { return expr.TruthUnknown }

func (symbol) Contains(string) expr.Truth   { return expr.TruthUnknown }
func (symbol) StartsWith(string) expr.Truth { return expr.TruthUnknown }
func (symbol) EndsWith(string) expr.Truth   { return expr.TruthUnknown }

func (s set) Truthy() expr.Truth {
	return maybeAll(len(s), slices.IndexFunc(s, func(v string) bool { return v != "" }) >= 0, !slices.Contains(s, ""))
}

func (s set) Equal(v expr.Value) expr.Truth {
	str, ok := v.Str()
	if !ok || !ascii(str) {
		return expr.TruthUnknown // as expr compares: case is ignored of ASCII only
	}
	return s.count(func(m string) bool { return strings.EqualFold(m, str) })
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isString(v expr.Value) bool { _, ok := v.Str(); return ok }

// oneOf is one of the values, the attacker choosing which: their fork's
// head, or null once they delete the fork.
type oneOf []expr.Value

func (o oneOf) Truthy() expr.Truth {
	return o.all(func(v expr.Value) expr.Truth { return v.Truthy() })
}

func (o oneOf) Equal(v expr.Value) expr.Truth {
	return o.all(func(m expr.Value) expr.Truth { return valuesEqual(m, v) })
}

func (o oneOf) Within(s string) expr.Truth { return o.part(s, expr.Abstract.Within) }
func (o oneOf) Prefix(s string) expr.Truth { return o.part(s, expr.Abstract.Prefix) }
func (o oneOf) Suffix(s string) expr.Truth { return o.part(s, expr.Abstract.Suffix) }

func (o oneOf) Contains(s string) expr.Truth   { return o.part(s, expr.Abstract.Contains) }
func (o oneOf) StartsWith(s string) expr.Truth { return o.part(s, expr.Abstract.StartsWith) }
func (o oneOf) EndsWith(s string) expr.Truth   { return o.part(s, expr.Abstract.EndsWith) }

// part is f of the abstract members, s a part of a member or a member a
// part of s; of a known member it is not known (contains casts null to the
// empty string, which is a part of every string).
func (o oneOf) part(s string, f func(expr.Abstract, string) expr.Truth) expr.Truth {
	return o.all(func(m expr.Value) expr.Truth {
		if a, ok := m.AbstractOf(); ok {
			return f(a, s)
		}
		return expr.TruthUnknown
	})
}

// all is true when f is true of every member, false when of none and not
// known of none.
func (o oneOf) all(f func(expr.Value) expr.Truth) expr.Truth {
	t, f0 := 0, 0
	for _, m := range o {
		switch f(m) {
		case expr.TruthTrue:
			t++
		case expr.TruthFalse:
			f0++
		}
	}
	switch {
	case t == len(o):
		return expr.TruthTrue
	case f0 == len(o):
		return expr.TruthFalse
	}
	return expr.TruthUnknown
}

// valuesEqual is == of a and b, as Partial reads it.
func valuesEqual(a, b expr.Value) expr.Truth {
	return expr.Partial(eqNode, func(p []expr.PathElem) (expr.Value, bool) {
		if expr.HasPrefix(p, "a") {
			return a, true
		}
		return b, true
	}).Truthy()
}

var eqNode = func() expr.Node {
	n, errs := expr.Parse("a == b")
	if len(errs) > 0 {
		panic(errs)
	}
	return n
}()

func (s set) Within(t string) expr.Truth {
	return s.count(func(m string) bool { return strings.Contains(t, strings.ToLower(m)) })
}
func (s set) Prefix(t string) expr.Truth {
	return s.count(func(m string) bool { return strings.HasPrefix(t, strings.ToLower(m)) })
}
func (s set) Suffix(t string) expr.Truth {
	return s.count(func(m string) bool { return strings.HasSuffix(t, strings.ToLower(m)) })
}

func (s set) Contains(t string) expr.Truth {
	return s.count(func(m string) bool { return strings.Contains(strings.ToLower(m), t) })
}
func (s set) StartsWith(t string) expr.Truth {
	return s.count(func(m string) bool { return strings.HasPrefix(strings.ToLower(m), t) })
}
func (s set) EndsWith(t string) expr.Truth {
	return s.count(func(m string) bool { return strings.HasSuffix(strings.ToLower(m), t) })
}

// count is true when f holds of every member, false when of none.
func (s set) count(f func(string) bool) expr.Truth {
	n := 0
	for _, m := range s {
		if f(m) {
			n++
		}
	}
	return maybeAll(len(s), n > 0, n == len(s))
}

// maybe is unknown when the attacker may make it true, else false.
func maybe(may bool) expr.Truth {
	if may {
		return expr.TruthUnknown
	}
	return expr.TruthFalse
}

func maybeAll(n int, some, all bool) expr.Truth {
	switch {
	case n > 0 && all:
		return expr.TruthTrue
	case some:
		return expr.TruthUnknown
	}
	return expr.TruthFalse
}

// nameOfNamed is a name of an account the attacker holds when they may hold any
// account the workflow names (analysis.BarrierActorName): a maintainer's
// or a bot's, so equal or not to any name written in the workflow.
type nameOfNamed struct{}

var namedName = expr.AbstractValue(nameOfNamed{})

func (nameOfNamed) Truthy() expr.Truth           { return expr.TruthTrue }
func (nameOfNamed) Equal(expr.Value) expr.Truth  { return expr.TruthUnknown }
func (nameOfNamed) Within(string) expr.Truth     { return expr.TruthUnknown }
func (nameOfNamed) Prefix(string) expr.Truth     { return expr.TruthUnknown }
func (nameOfNamed) Suffix(string) expr.Truth     { return expr.TruthUnknown }
func (nameOfNamed) Contains(string) expr.Truth   { return expr.TruthUnknown }
func (nameOfNamed) StartsWith(string) expr.Truth { return expr.TruthUnknown }
func (nameOfNamed) EndsWith(string) expr.Truth   { return expr.TruthUnknown }

// present is an object the payload has, whose fields are not known: the
// pull_request of the issue of a comment on a pull request.
type present struct{}

func (present) Truthy() expr.Truth           { return expr.TruthTrue }
func (present) Equal(expr.Value) expr.Truth  { return expr.TruthUnknown }
func (present) Within(string) expr.Truth     { return expr.TruthUnknown }
func (present) Prefix(string) expr.Truth     { return expr.TruthUnknown }
func (present) Suffix(string) expr.Truth     { return expr.TruthUnknown }
func (present) Contains(string) expr.Truth   { return expr.TruthUnknown }
func (present) StartsWith(string) expr.Truth { return expr.TruthUnknown }
func (present) EndsWith(string) expr.Truth   { return expr.TruthUnknown }

package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// parseFact reads --fact KIND[ARG=VALUE,...]=VALUE: the fact of the kind
// KIND with its arguments, and its value as JSON. The brackets close at
// their last ]=, since a value such as jobs.a.steps[2] has brackets; an
// argument is split at its first =. A kind whose repository may be left
// out (facts.WithRepo) takes the one of --repo; naming another, or naming
// one without --repo, is an error, since the rules would never ask that
// fact.
func parseFact(s string, repo facts.Repo) (facts.Entry, error) {
	fail := func(format string, a ...any) (facts.Entry, error) {
		return facts.Entry{}, fmt.Errorf("%s: %s", s, fmt.Sprintf(format, a...))
	}
	var kind, args, value string
	eq := strings.IndexByte(s, '=')
	if br := strings.IndexByte(s, '['); br >= 0 && (eq < 0 || br < eq) {
		end := strings.LastIndex(s, "]=")
		if end < br {
			return fail("a [ without its ]=")
		}
		kind, args, value = s[:br], s[br+1:end], s[end+2:]
	} else {
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return fail("not KIND=VALUE")
		}
		kind, value = k, v
	}
	obj := map[string]string{"kind": kind}
	if args != "" {
		for _, a := range strings.Split(args, ",") {
			n, v, ok := strings.Cut(a, "=")
			switch {
			case !ok || n == "":
				return fail("the argument %q is not NAME=VALUE", a)
			case n == "kind":
				return fail("kind is not an argument")
			}
			if _, dup := obj[n]; dup {
				return fail("the argument %s is given twice", n)
			}
			obj[n] = v
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return fail("%v", err)
	}
	q, err := facts.DecodeQuery(b)
	if err != nil {
		return fail("%v", err)
	}
	if none, ok := facts.WithRepo(q, facts.Repo{}); ok {
		named, _ := facts.WithRepo(q, repo)
		switch {
		case q != none && repo.IsZero():
			return fail("names a repository, but --repo is not given: the rules ask the fact of no name")
		case q != none && q != named:
			return fail("names a repository that is not the one of --repo (%s)", repo)
		}
		q = named
	}
	if !json.Valid([]byte(value)) {
		return fail("the value %q is not JSON (a string is written in double quotes)", value)
	}
	raw := facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(value)}
	if c := facts.Checked(q, raw); c.State != facts.StateFound {
		return fail("%s", c.Reason)
	}
	return facts.Entry{Query: q, RawAnswer: raw}, nil
}

package facts

import (
	"context"
	"fmt"
)

// Arguments answers the facts given one by one on the command line
// (--fact): each found, with the source argument. A fact given twice, an
// answer that is not found, and a value that does not fit its kind are
// errors. Unlike a file of facts (Store), it derives nothing: the
// git.commit-ref of a git.ref-commit given is not known unless given too.
func Arguments(entries []Entry) (Resolver, error) {
	m := map[Query]RawAnswer{}
	for _, e := range entries {
		key, err := EncodeQuery(e.Query)
		if err != nil {
			return nil, err
		}
		if _, dup := m[e.Query]; dup {
			return nil, fmt.Errorf("the fact %s is given twice", key)
		}
		if e.RawAnswer.State != StateFound {
			return nil, fmt.Errorf("the fact %s: only a value may be given", key)
		}
		c := Checked(e.Query, e.RawAnswer)
		if c.State != StateFound {
			return nil, fmt.Errorf("the fact %s: %s", key, c.Reason)
		}
		c.Source = SourceArgument
		m[e.Query] = c
	}
	return arguments(m), nil
}

type arguments map[Query]RawAnswer

func (a arguments) Resolve(_ context.Context, q Query) RawAnswer {
	if r, ok := a[q]; ok {
		return r
	}
	return RawAnswer{State: StateUnknown, Reason: "not given by an argument"}
}

package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// worstCase answers as below does (nothing when below is nil) and, where
// below does not know a fact, by the x-assume value of the fact's kind:
// the answer with which the findings of the kind's false positive forms
// hold. A run of the command does not answer so; a test answers so to
// check what a rule reports when those facts hold, without writing each
// fact in a file of facts.
func worstCase(below facts.Resolver) facts.Resolver { return worstCaseResolver{below} }

type worstCaseResolver struct{ below facts.Resolver }

func (w worstCaseResolver) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if w.below != nil {
		if r := facts.Checked(q, w.below.Resolve(ctx, q)); r.State != facts.StateUnknown {
			return r
		}
	}
	for _, i := range facts.Kinds() {
		if i.Kind == q.Kind() && i.AssumedValue != nil {
			return facts.RawAnswer{State: facts.StateFound, Value: i.AssumedValue}
		}
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "neither the test's facts nor an x-assume answer the fact"}
}

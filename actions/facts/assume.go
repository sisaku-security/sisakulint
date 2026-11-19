package facts

import "context"

// Assumptions answers a kind with an x-assume by that value, marked
// Assumed, and any other kind Unknown.
func Assumptions() Resolver { return assumptions{} }

type assumptions struct{}

func (assumptions) Resolve(_ context.Context, q Query) RawAnswer {
	if k, ok := kindOf(q); ok {
		for _, i := range kinds {
			if i.Kind == k && i.AssumedValue != nil {
				return RawAnswer{State: StateFound, Value: i.AssumedValue, Source: SourceAssumption}
			}
		}
	}
	return RawAnswer{State: StateUnknown, Reason: "nothing assumes " + q.Kind().String()}
}

// Assume answers as r does and, where r does not know, by Assumptions. So
// what was found out wins, and what is neither found out nor assumed keeps
// the reason r gave.
func Assume(r Resolver) Resolver { return assume{r} }

type assume struct{ below Resolver }

func (a assume) Resolve(ctx context.Context, q Query) RawAnswer {
	r := Checked(q, a.below.Resolve(ctx, q))
	if r.State != StateUnknown {
		return r
	}
	if s := Checked(q, assumptions{}.Resolve(ctx, q)); s.State != StateUnknown {
		return s
	}
	return r
}

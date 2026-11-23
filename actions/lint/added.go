package lint

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
)

// AddedAttacker is an attacker that the rules do not count in a run by
// default, and that a run counts when the user adds it: each value names
// one credential the attacker holds. Its values and what they mean are
// the oneOf of $defs/added-attacker in schema/registry-v0.json
// (enum_gen.go).
type AddedAttacker uint8

// AddedAttackers are the values of AddedAttacker, in their order.
func AddedAttackers() []AddedAttacker { return addedAttackerValues() }

// schemaOrder is vs as the registry writes it ($defs/added-attackers): each
// once, in the order of the values of AddedAttacker, which is the order of
// $defs/added-attacker; nil for none.
func schemaOrder(vs []AddedAttacker) []AddedAttacker {
	if len(vs) == 0 {
		return nil
	}
	out := slices.Clone(vs)
	slices.Sort(out)
	return slices.Compact(out)
}

// registered are the barriers and the outsider rules RegisterBarriers
// gives: a registry starts with them.
var registered struct {
	barriers func([]AddedAttacker) analysis.BarrierPasses
	outsider []RuleID
}

// RegisterBarriers gives every registry made after it the barriers the
// attackers that a run adds get past, and the rules such a run does not
// run (WithBarriers): the package of the rules calls it once, when it is
// initialized, as the rows of the boundary say.
func RegisterBarriers(barriers func([]AddedAttacker) analysis.BarrierPasses, outsider ...RuleID) {
	registered.barriers, registered.outsider = barriers, slices.Clone(outsider)
}

// WithBarriers is r, whose runs that add attackers read the barriers those
// attackers get past from barriers, and do not run the rules outsider,
// which read an attacker outside the repository alone.
func (r *Registry) WithBarriers(barriers func([]AddedAttacker) analysis.BarrierPasses, outsider ...RuleID) *Registry {
	r.barriers, r.outsider = barriers, slices.Clone(outsider)
	return r
}

// barriersOf are the barriers an attacker of any of vs gets past: none for
// none. A registry without WithBarriers cannot add an attacker.
func (r *Registry) barriersOf(vs []AddedAttacker) analysis.BarrierPasses {
	if len(vs) == 0 {
		return analysis.BarrierPasses{}
	}
	if r.barriers == nil {
		panic("lint: a run adds attackers, and the registry has no barriers (WithBarriers)")
	}
	return r.barriers(vs)
}

// readsOutsider is whether the rule id reads an attacker outside the
// repository alone, so that a run that adds attackers does not run it.
func (r *Registry) readsOutsider(id RuleID) bool { return slices.Contains(r.outsider, id) }

// RunAdded is Run with the attackers vs added (each once; in the order of
// AddedAttacker): it runs the rules adding none and adding each of vs
// alone (RunWithBarriers), and reports every place of the run that adds
// none, each as that run gives it, and the places only the added runs
// give, each marked with the added attackers that alone give it. Each of
// vs is a separate attacker: a place that only two or more of vs together
// give is not reported. A place that the run adding none gives in another
// form (its certainty or its condition) is reported as the added run
// gives it, marked. With no vs it is Run.
func RunAdded(ctx context.Context, in Inputs, reg *Registry, r facts.Resolver, vs []AddedAttacker) Report {
	vs = uniqueAdded(vs)
	base := Run(ctx, in, reg, r)
	if len(vs) == 0 {
		return base
	}
	type added struct {
		vs  []AddedAttacker
		rep Report
	}
	var runs []added
	for _, v := range vs {
		one := []AddedAttacker{v}
		runs = append(runs, added{one, RunWithBarriers(ctx, in, reg, r, reg.barriersOf(one))})
	}
	out := base
	out.AddedAttackers = vs
	out.Findings = slices.Clone(base.Findings)
	at := map[Fingerprint]int{}
	for i, f := range out.Findings {
		at[f.Fingerprint] = i
	}
	// the forms of the places of each added run, and the marks
	findingMarks := func(f Finding) []AddedAttacker {
		var marks []AddedAttacker
		for _, a := range runs {
			if slices.ContainsFunc(a.rep.Findings, func(g Finding) bool { return g.Fingerprint == f.Fingerprint && sameForm(g, f) }) {
				marks = append(marks, a.vs...)
			}
		}
		return marks
	}
	// the runs from the last value first: when two runs give a place in two
	// forms, the form the later value gives is reported
	for i := len(runs) - 1; i >= 0; i-- {
		a := runs[i]
		for _, f := range a.rep.Findings {
			if j, ok := at[f.Fingerprint]; ok {
				if out.Findings[j].AddedAttackers != nil || sameForm(out.Findings[j], f) {
					continue // marked already, or as the run adding none gives it
				}
				f.AddedAttackers = findingMarks(f)
				out.Findings[j] = f
				continue
			}
			f.AddedAttackers = findingMarks(f)
			at[f.Fingerprint] = len(out.Findings)
			out.Findings = append(out.Findings, f)
		}
		out.Facts = mergeFacts(out.Facts, a.rep.Facts)
		for _, e := range a.rep.Errors {
			if !slices.Contains(out.Errors, e) {
				out.Errors = append(out.Errors, e)
			}
		}
	}
	sortPlaces(&out)
	return out
}

// uniqueAdded are vs, each once, in the order of AddedAttacker.
func uniqueAdded(vs []AddedAttacker) []AddedAttacker {
	out := slices.Clone(vs)
	slices.Sort(out)
	return slices.Compact(out)
}

// sameForm is whether f and g say the same of their place: the same
// certainty and condition.
func sameForm(f, g Finding) bool {
	if f.Certainty != g.Certainty {
		return false
	}
	a, err := json.Marshal(f.Condition)
	if err != nil {
		return false
	}
	b, err := json.Marshal(g.Condition)
	return err == nil && bytes.Equal(a, b)
}

// mergeFacts are the facts of a and of b, each query once, in the order of
// their encoding, as a Recorder gives them.
func mergeFacts(a, b []facts.Entry) []facts.Entry {
	out := slices.Clone(a)
	key := func(e facts.Entry) string {
		k, err := facts.EncodeQuery(e.Query)
		if err != nil {
			return ""
		}
		return string(k)
	}
	for _, e := range b {
		if !slices.ContainsFunc(out, func(x facts.Entry) bool { return key(x) == key(e) }) {
			out = append(out, e)
		}
	}
	slices.SortFunc(out, func(x, y facts.Entry) int { return bytes.Compare([]byte(key(x)), []byte(key(y))) })
	return out
}

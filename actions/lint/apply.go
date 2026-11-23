package lint

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// Applied is what ApplyFixes gives: the new bytes of each input that
// changes, and the rules the registry skipped a field of which the fixes
// change (Unchecked).
type Applied struct {
	Files     map[facts.InputPath][]byte
	Unchecked []Unchecked // by the ID of the rule
}

// ApplyFixes applies the fixes of the findings rep reports (Report.Narrow),
// rep made by Run from in, reg and r (all its findings, so that the run
// again is compared with all), and
// gives the new bytes of each input that changes. With
// safety Safe only the fixes that are safe are applied; with Review, all.
// The same edit in several findings (an anchor's scalar, used through
// aliases) is applied once; edits that overlap otherwise are an error. The
// inputs are then run again: a fixed finding still there, a finding that
// was not there, one there before whose certainty or condition the fixes
// change, or an internal error is an error. On an error nothing is given,
// so that no input is written half fixed. The run again answers each
// fact rep asked as rep has it, Unknown and assumed answers too; a fact
// rep did not ask is what the facts of rep derive, else r's answer. When reg skipped rules, the IRs of each input
// changed are compared before and after the fixes, and each rule skipped
// a field of which changes is in Unchecked; those rules do not run.
func ApplyFixes(ctx context.Context, in Inputs, reg *Registry, r facts.Resolver, rep Report, safety Safety) (Applied, error) {
	byTree := map[*cst.Tree]int{}
	for i, x := range in.List {
		if x.Tree != nil {
			byTree[x.Tree] = i
		}
	}
	edits := map[int][]edit.Edit{}
	fixes := map[int][]fixOf{}
	closed := map[Fingerprint]bool{}
	for _, f := range rep.Narrow().Findings { // the fixes of the findings reported; the run again is compared with all
		x := f.Fix
		if x == nil {
			continue
		}
		m, ok := reg.Meta(f.Rule)
		if !ok {
			return Applied{}, fmt.Errorf("the rule %s of %s is not in the registry", f.Rule, f.Fingerprint)
		}
		k, ok := m.FixKind(x.KindID)
		if !ok {
			return Applied{}, fmt.Errorf("the fix %s of %s is not of a kind its rule declares", x.KindID, f.Fingerprint)
		}
		if safety == SafetySafe && k.Safety != SafetySafe {
			continue
		}
		i, ok := byTree[f.fixTree]
		if !ok {
			return Applied{}, fmt.Errorf("the fix %s of %s edits an input that is not in the inputs given", x.KindID, f.Fingerprint)
		}
		edits[i] = append(edits[i], x.Edits...)
		fixes[i] = append(fixes[i], fixOf{FixBy{f.Rule, x.KindID}, x.Edits})
		closed[f.Fingerprint] = true
	}
	out := map[facts.InputPath][]byte{}
	after := in
	after.List = slices.Clone(in.List)
	for _, i := range slices.Sorted(maps.Keys(edits)) {
		input := in.List[i]
		res, err := edit.Apply(input.Tree, same(edits[i]))
		if err != nil {
			return Applied{}, fmt.Errorf("%s: the fixes do not apply together: %w", input.Name, err)
		}
		if bytes.Equal(res.Tree.Bytes(), input.Tree.Bytes()) {
			continue
		}
		out[input.Name] = res.Tree.Bytes()
		after.List[i] = readTree(input.Name, input.InputKind, res.Tree)
	}
	if len(out) == 0 {
		return Applied{Files: out}, nil
	}
	// compared before the run again, so that a making of summaries that
	// panics is an error here
	var changed []int
	for _, i := range slices.Sorted(maps.Keys(edits)) {
		if _, ok := out[in.List[i].Name]; ok {
			changed = append(changed, i)
		}
	}
	unchecked, err := uncheckedOf(reg, in, after, fixes, changed)
	if err != nil {
		return Applied{}, err
	}
	// a finding whose certainty is CertaintyInconclusive is not compared:
	// a fix that changes the text of its place changes its fingerprint
	was := map[Fingerprint]Finding{}
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		was[f.Fingerprint] = f
	}
	// the facts of rep answer as they did, so that nothing asked is asked
	// again, and a fact Unknown then is Unknown now
	file, err := facts.EncodeFile(rep.Facts)
	if err != nil {
		return Applied{}, fmt.Errorf("the facts of the report cannot be written: %w", err)
	}
	store, err := facts.LoadStore(file) // what the facts of rep derive (actions/facts/derive.go)
	if err != nil {
		return Applied{}, fmt.Errorf("the facts of the report cannot be read again: %w", err)
	}
	asked, err := replayOf(rep.Facts, facts.First(store, r))
	if err != nil {
		return Applied{}, err
	}
	again := Run(ctx, after, reg, asked)
	if len(again.Errors) > 0 {
		return Applied{}, fmt.Errorf("the run on the fixed inputs has internal errors: %s", again.Errors[0].Message)
	}
	for _, f := range again.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		old, there := was[f.Fingerprint]
		switch {
		case closed[f.Fingerprint]:
			return Applied{}, fmt.Errorf("%s: the finding %s of %s is still there after the fixes", f.Location.File.Input, f.Fingerprint, f.Rule)
		case !there:
			return Applied{}, fmt.Errorf("%s: the fixes together make a new finding %s of %s", f.Location.File.Input, f.Fingerprint, f.Rule)
		case old.Certainty != f.Certainty:
			return Applied{}, fmt.Errorf("%s: the fixes make the finding %s of %s from %s to %s", f.Location.File.Input, f.Fingerprint, f.Rule, old.Certainty, f.Certainty)
		case !sameCond(old.Condition, f.Condition):
			return Applied{}, fmt.Errorf("%s: the fixes change the condition of the finding %s of %s", f.Location.File.Input, f.Fingerprint, f.Rule)
		}
	}
	return Applied{Files: out, Unchecked: unchecked}, nil
}

// same drops the edits that are another's again: the same range and the
// same new bytes.
func same(es []edit.Edit) []edit.Edit {
	type key struct {
		start, end int
		new        string
	}
	seen := map[key]bool{}
	var out []edit.Edit
	for _, e := range es {
		k := key{e.Span.Start, e.Span.End, string(e.New)}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, e)
	}
	return out
}

// sameCond is whether a and b are the same condition, or both none: the
// same in JSON, which a rule writes in one order.
func sameCond(a, b *Condition) bool {
	if a == nil || b == nil {
		return a == b
	}
	x, err := a.MarshalJSON()
	if err != nil {
		return false
	}
	y, err := b.MarshalJSON()
	return err == nil && bytes.Equal(x, y)
}

// replay answers each fact of entries as it is there, and asks below the
// others.
type replay struct {
	answers map[string]facts.RawAnswer // by the JSON of the query
	below   facts.Resolver
}

// replayOf is the replay of the entries of a report over r.
func replayOf(entries []facts.Entry, r facts.Resolver) (replay, error) {
	x := replay{answers: map[string]facts.RawAnswer{}, below: r}
	for _, e := range entries {
		b, err := facts.EncodeQuery(e.Query)
		if err != nil {
			return replay{}, fmt.Errorf("the facts of the report cannot be asked again: %w", err)
		}
		x.answers[string(b)] = e.RawAnswer
	}
	return x, nil
}

func (x replay) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if b, err := facts.EncodeQuery(q); err == nil {
		if raw, ok := x.answers[string(b)]; ok {
			return raw
		}
	}
	return x.below.Resolve(ctx, q)
}

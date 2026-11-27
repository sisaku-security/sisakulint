package lint

import (
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// UnreadUses is a uses of an input that names a reusable workflow or an
// action of another repository whose definition the run did not ask
// (workflow.definition or action.definition): no rule read what it runs,
// and the run cannot tell it from one with nothing to find. It is no
// finding and sets no bit of the exit code (Classify).
type UnreadUses struct {
	Location Location    // the uses
	Uses     string      // the uses as written
	Query    facts.Query // the fact not asked
	Reason   string      // the reason of the answer no one gave
}

// notAskedReason is the reason of an UnreadUses whose fact no rule that ran
// asked.
const notAskedReason = "no rule that ran asked the fact"

// unreadUsesOf are the uses of the inputs of in whose fact rec did not
// record, or recorded unknown with no source (UnreadUses), in the order of
// the inputs and the places in them, each place and fact once. Nothing is
// asked: a fact the rules did not ask stays out of the facts of the run.
func unreadUsesOf(in Inputs, rec *facts.Recorder) []UnreadUses {
	var out []UnreadUses
	add := func(input Input, f workflow.Field[workflow.Uses], call bool) {
		if f.Status != workflow.Present {
			return
		}
		for _, q := range composite.Queries(f.Value, call) {
			a, ok := rec.Asked(q)
			if !ok {
				a = facts.RawAnswer{State: facts.StateUnknown, Reason: notAskedReason}
			}
			if a.State != facts.StateUnknown || a.Source != facts.SourceUnset {
				continue
			}
			out = append(out, UnreadUses{Location: At(input, f.Value.Base), Uses: f.Value.AsString(), Query: q, Reason: a.Reason})
		}
	}
	steps := func(input Input, f workflow.Field[workflow.List[workflow.Step]]) {
		if f.Status != workflow.Present {
			return
		}
		for i := range f.Value.Items {
			add(input, f.Value.Items[i].Uses, false)
		}
	}
	for _, input := range in.List {
		if input.Tree == nil {
			continue
		}
		if w := input.Workflow; w != nil && w.Jobs.Status == workflow.Present {
			for i := range w.Jobs.Value.Entries {
				j := &w.Jobs.Value.Entries[i].Value.Value
				if j.Kind == workflow.JobCall {
					add(input, j.Uses, true)
				} else {
					steps(input, j.Steps)
				}
			}
		}
		if m := input.ActionMetadata; m != nil && m.Runs.Status == workflow.Present && m.Runs.Value.Kind == workflow.RunsComposite {
			steps(input, m.Runs.Value.Steps)
		}
	}
	return out
}

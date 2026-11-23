package reportview

import (
	"strconv"

	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// place is the job and the step a location is in, by the IDs and names a
// person reads.
type place struct{ job, step string }

// spot is where a location is: its input, and the job and the step of it
// it is in.
type spot struct {
	input lint.Input
	job   string
	step  *workflow.Step
}

// locate is the job and the step a location is in (find).
func locate(in lint.Inputs, l lint.Location) place {
	s, ok := find(in, l)
	if !ok {
		return place{}
	}
	p := place{job: s.job}
	if s.step != nil {
		p.step = stepName(*s.step)
	}
	return p
}

// find is the job and the step of in whose spans hold the span of l. A
// location reached through aliases is where its outermost alias is: its
// Span may be in the bytes of the anchor (AtSpan), so the first of Via is
// looked up. When a list of steps or a whole job is reached through an
// alias, every step has the alias's span; the step is then the one whose
// content holds the element (Location.NodeSpan). A location in a file of
// a fact is in no input.
func find(in lint.Inputs, l lint.Location) (spot, bool) {
	if l.File.Query != nil {
		return spot{}, false
	}
	input, st := in.Lookup(l.File.Input)
	if st != lint.LookupFound {
		return spot{}, false
	}
	at := l.Span
	if len(l.Via) > 0 {
		at = l.Via[0]
	}
	p := spot{input: input}
	inside := func(b workflow.Base) bool {
		s := b.Primary()
		return s.Start <= at.Start && at.End <= s.End
	}
	node := l.NodeSpan()
	steps := func(f workflow.Field[workflow.List[workflow.Step]]) {
		if f.Status != workflow.Present {
			return
		}
		var in []workflow.Step
		for _, s := range f.Value.Items {
			if inside(s.Base) {
				in = append(in, s)
			}
		}
		for _, s := range in {
			c := s.Node.ContentSpan()
			if len(in) == 1 || c.Start <= node.Start && node.End <= c.End {
				p.step = &s
				return
			}
		}
	}
	switch {
	case input.Workflow != nil && input.Workflow.Jobs.Status == workflow.Present:
		for _, e := range input.Workflow.Jobs.Value.Entries {
			if e.Value.Status != workflow.Present || !inside(e.Value.Value.Base) {
				continue
			}
			p.job = e.Value.Value.ID.Text()
			steps(e.Value.Value.Steps)
			break
		}
	case input.ActionMetadata != nil && input.ActionMetadata.Runs.Status == workflow.Present:
		steps(input.ActionMetadata.Runs.Value.Steps)
	}
	return p, true
}

// stepName is the name of s, or #N for the Nth step when it has none, and
// #N.M for the Mth step of the parallel group that is the Nth step.
func stepName(s workflow.Step) string {
	if s.Name.Status == workflow.Present {
		return s.Name.Value.Text()
	}
	n := "#" + strconv.Itoa(s.Place.Steps+1)
	if k, ok := s.Place.Parallel(); ok {
		n += "." + strconv.Itoa(k+1)
	}
	return n
}

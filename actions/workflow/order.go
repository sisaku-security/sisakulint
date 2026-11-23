package workflow

import "github.com/gh-intel/sisakulint/actions/expr"

// StepOrder is when the steps of a job end, for the order of steps that
// run alongside others: the steps of a parallel group and background
// steps. OrderOf makes it.
type StepOrder struct {
	doneAt []int // the order of the first step that runs after the step is done and its outputs and env are applied
	waitOf []int // the order of the wait or wait-all step that waits for the step; -1 for none
	long   []int // the steps done after the next step starts: those of groups, background ones
}

// OrderOf is the order of steps, a list of Step.Order 0, 1, ...
func OrderOf(steps []Step) StepOrder {
	n := len(steps)
	// a step of a parallel group is done before the first step after the
	// group (its implicit wait), and so is what a wait in the group waits
	// for, read as if the wait ran alongside the group's other steps:
	// GitHub rejects a wait in a group and runs none of
	// the workflow, but the rules still read its steps
	after := make([]int, n) // the order of the first step that starts after the step ends
	for i := 0; i < n; {
		if _, ok := steps[i].Place.Parallel(); !ok {
			after[i] = i + 1
			i++
			continue
		}
		end := i
		for end < n && steps[end].Place.Steps == steps[i].Place.Steps {
			if _, ok := steps[end].Place.Parallel(); !ok {
				break
			}
			end++
		}
		for k := i; k < end; k++ {
			after[k] = end
		}
		i = end
	}
	o := StepOrder{doneAt: make([]int, n), waitOf: make([]int, n)}
	pending := map[string][]int{} // background steps not in a group, by expr.FoldName of their id, not waited for yet
	var anon []int                // those without an id, which only wait-all waits for
	for i, s := range steps {
		o.doneAt[i] = n // never, until a wait is found
		o.waitOf[i] = -1
		switch {
		case s.WaitAll:
			for _, js := range pending {
				for _, j := range js {
					o.doneAt[j], o.waitOf[j] = after[i], i
				}
			}
			for _, j := range anon {
				o.doneAt[j], o.waitOf[j] = after[i], i
			}
			clear(pending)
			anon = nil
		case s.Wait.Status == Present:
			for _, id := range s.Wait.Value.Items {
				f := expr.FoldName(id.AsString())
				for _, j := range pending[f] {
					o.doneAt[j], o.waitOf[j] = after[i], i
				}
				delete(pending, f)
			}
		}
		switch _, inGroup := s.Place.Parallel(); {
		case inGroup || !s.Background:
			o.doneAt[i] = after[i]
		case s.ID.Status == Present:
			f := expr.FoldName(s.ID.Value.AsString())
			pending[f] = append(pending[f], i)
		default:
			anon = append(anon, i)
		}
	}
	for i, d := range o.doneAt {
		if d > i+1 {
			o.long = append(o.long, i)
		}
	}
	return o
}

// RunningAt are the steps before step i that may run after it starts: of
// its parallel group, or background steps not waited for yet.
func (o StepOrder) RunningAt(i int) []int {
	var out []int
	for _, j := range o.long {
		if j >= i {
			break
		}
		if o.doneAt[j] > i {
			out = append(out, j)
		}
	}
	return out
}

// DoneBefore is whether step i is done, and its outputs and env applied,
// before step j starts.
func (o StepOrder) DoneBefore(i, j int) bool { return i < j && j >= o.doneAt[i] }

// DoneAt is the order of the first step that runs after step i is done
// (the order after the steps when no step waits for i: the implicit
// wait-all before the post steps), and the order of the wait or wait-all
// step that waits for i, when one does. A step that is not a background
// step, or that is in a parallel group (done at the end of the group), is
// waited for by no step.
func (o StepOrder) DoneAt(i int) (at, wait int, waited bool) {
	return o.doneAt[i], o.waitOf[i], o.waitOf[i] >= 0
}

// MayRunAfter is whether step j may run after step i has started, and so
// see what i wrote to files.
func (o StepOrder) MayRunAfter(i, j int) bool { return i != j && !o.DoneBefore(j, i) }

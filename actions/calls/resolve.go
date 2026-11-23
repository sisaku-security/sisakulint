package calls

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// found is a call and the path it names, relative to the repository; repo
// is the owner/repo of a uses: owner/repo/path@ref, "" for ./ and $/.
type found struct {
	Call
	target string
	repo   string
}

// callsIn are the calls of f: its jobs' uses: ./… and $/…, and its
// steps'.
func callsIn(f File) []found {
	var out []found
	if w := f.Workflow; w != nil && w.Jobs.Status == workflow.Present {
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			if j.Kind == workflow.JobCall {
				// a job's ./ and $/ are the caller's commit
				if t, ok := localTarget(j.Uses); ok {
					out = append(out, found{Call{Caller: f.Node(), Job: &j, StepIndex: -1, With: j.With, Resolved: true}, t, ""})
				} else {
					for _, t := range remoteTargets(j.Uses) {
						out = append(out, found{Call{Caller: f.Node(), Job: &j, StepIndex: -1, With: j.With}, t.path, t.repo})
					}
				}
				continue
			}
			steps := j.Steps.Value.Items
			order, prev := workflow.OrderOf(steps), prevCheckouts(steps)
			for i := range steps {
				s := &steps[i]
				if t, ok := localTarget(s.Uses); ok {
					out = append(out, found{Call{Caller: f.Node(), Job: &j, StepIndex: i, Step: s, With: s.With, Resolved: resolved(s.Uses, steps, order, prev, i)}, t, ""})
				} else {
					for _, t := range remoteTargets(s.Uses) {
						out = append(out, found{Call{Caller: f.Node(), Job: &j, StepIndex: i, Step: s, With: s.With}, t.path, t.repo})
					}
				}
			}
		}
	}
	if a := f.Action; a != nil && a.Runs.Status == workflow.Present && a.Runs.Value.Kind == workflow.RunsComposite {
		steps := a.Runs.Value.Steps.Value.Items
		for i := range steps {
			s := &steps[i]
			if t, ok := localTarget(s.Uses); ok {
				// ./… in a composite action is the workspace of the job
				// that runs it, which the action does not know
				out = append(out, found{Call{Caller: f.Node(), StepIndex: i, Step: s, With: s.With, Resolved: kindOf(s.Uses.Value) == workflow.UsesSelf}, t, ""})
			} else {
				for _, t := range remoteTargets(s.Uses) {
					out = append(out, found{Call{Caller: f.Node(), StepIndex: i, Step: s, With: s.With}, t.path, t.repo})
				}
			}
		}
	}
	return out
}

// localTarget is the path uses names in the repository: ./path or $/path,
// resolved as GitHub resolves it (LocalPath); false for one that goes
// above the root.
func localTarget(f workflow.Field[workflow.Uses]) (string, bool) {
	if f.Status != workflow.Present {
		return "", false
	}
	u := f.Value
	switch kindOf(u) {
	case workflow.UsesLocal, workflow.UsesSelf:
		return u.LocalPath.String(), u.HasLocalPath
	}
	return "", false
}

// remoteTarget is a path and the owner/repo of a uses of another
// repository: owner/repo/path@ref or owner/repo@ref (the path "", the
// root).
type remoteTarget struct{ path, repo string }

// remoteTargets are the remote targets of the actions the uses runs
// (Actions): more than one when the uses goes above the root of its
// repository and its readings are not decided.
func remoteTargets(f workflow.Field[workflow.Uses]) []remoteTarget {
	if f.Status != workflow.Present || kindOf(f.Value) == workflow.UsesLocal {
		return nil
	}
	var out []remoteTarget
	for _, a := range f.Value.Actions() {
		out = append(out, remoteTarget{a.Path.String(), a.Owner + "/" + a.Repo})
	}
	return out
}

// resolved is whether the step i of steps uses the input it names: $/…
// is the repository at the run's commit; ./… is the workspace, which is
// the input when the checkouts it may see have no ref, repository or path.
// Those are the checkouts it may run after (order, the steps of a parallel
// group and background steps among them), but one that another of them
// checks out over, done before the step starts. prev is, for each step,
// the latest checkout before it (prevCheckouts), so that the checkouts
// done before the step are found without reading the steps before it.
func resolved(f workflow.Field[workflow.Uses], steps []workflow.Step, order workflow.StepOrder, prev []int, i int) bool {
	if kindOf(f.Value) == workflow.UsesSelf {
		return true
	}
	isCheckout := func(k int) bool { return steps[k].Uses.Status == workflow.Present && IsCheckout(steps[k].Uses.Value) }
	var seen []int
	for _, k := range order.RunningAt(i) { // written before, may run after the step starts
		if isCheckout(k) {
			seen = append(seen, k)
		}
	}
	for k := i + 1; k < len(steps) && !order.DoneBefore(i, k); k++ { // written after, alongside
		if isCheckout(k) {
			seen = append(seen, k)
		}
	}
	last := prev[i]
	for last >= 0 && !order.DoneBefore(last, i) {
		last = prev[last] // one that runs alongside is in seen already
	}
	if last >= 0 {
		seen = append(seen, last)
		for _, k := range order.RunningAt(last) { // done before the step, maybe after last
			if isCheckout(k) && order.DoneBefore(k, i) {
				seen = append(seen, k)
			}
		}
	}
	plain := false
	for _, k := range seen {
		if slices.ContainsFunc(seen, func(l int) bool { return order.DoneBefore(k, l) && order.DoneBefore(l, i) }) {
			continue // checked out over
		}
		if !plainCheckout(steps[k]) {
			return false
		}
		plain = true
	}
	return plain
}

// prevCheckouts is, for each step of steps, the latest checkout before it,
// or -1.
func prevCheckouts(steps []workflow.Step) []int {
	out := make([]int, len(steps))
	last := -1
	for i := range steps {
		out[i] = last
		if steps[i].Uses.Status == workflow.Present && IsCheckout(steps[i].Uses.Value) {
			last = i
		}
	}
	return out
}

// plainCheckout is whether s checks out the input: no ref, repository or
// path in its with.
func plainCheckout(s workflow.Step) bool {
	switch s.With.Status {
	case workflow.Present:
		for _, k := range []string{"ref", "repository", "path"} {
			if _, ok := s.With.Value.Lookup(k); ok {
				return false
			}
		}
	case workflow.Absent:
	default:
		return false
	}
	return true
}

func kindOf(u workflow.Uses) workflow.UsesKind {
	if u.Kind == workflow.UsesFolded {
		return u.Folded
	}
	return u.Kind
}

// IsCheckout is whether u runs actions/checkout at any ref: its owner and
// name compared as GitHub compares them, without a path.
func IsCheckout(u workflow.Uses) bool {
	_, ok := CheckoutRef(u)
	return ok
}

// CheckoutRef is the ref of actions/checkout that u runs: the ref of the
// action that runs, which is not the ref written after @ when the path of
// u goes above the root of its repository.
func CheckoutRef(u workflow.Uses) (string, bool) {
	for _, a := range u.Actions() {
		if a.Is("actions", "checkout", workflow.RootActionPath) {
			return a.Ref, true
		}
	}
	return "", false
}

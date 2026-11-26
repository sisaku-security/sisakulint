package job

import (
	"strconv"

	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Reach is the one answer to whether a job or a step of a workflow ever
// runs: the ifs that a run of it goes through, the ifs of the job and of
// the jobs it depends on through needs (attacker.JobIfs, which reads
// attacker.NeedJobs), then, for a step, the if of the step
// (attacker.StepIf). JobReach and StepReach make it; the skip table of the
// IR (ir.skippedJobs) and the reads of called workflows read it.
//
// A uses step is read as its job: its if is left out. Whether the action
// has a pre step is not known from the read files, and the pre step of an
// action runs whatever the if of its step is, so a uses step stays
// reported even when its if is false.
type Reach struct {
	w    *workflow.Workflow
	j    *workflow.Job
	ifs  []attacker.PlacedIf
	step *attacker.PlacedIf // the if of a run step, read on the matrix of j too
}

// JobReach is the Reach of the job j of w.
func JobReach(w *workflow.Workflow, j *workflow.Job) Reach {
	return Reach{w: w, j: j, ifs: attacker.JobIfs(w, j)}
}

// StepReach is the Reach of the step s of the job j of w: that of j, with
// the if of s after it unless s is a uses step.
func StepReach(w *workflow.Workflow, j *workflow.Job, s *workflow.Step) Reach {
	r := JobReach(w, j)
	if s.Uses.Status == workflow.Absent && s.If.Status == workflow.Present {
		p := attacker.StepIf(w, j, s.If)
		r.ifs = append(r.ifs, p)
		r.step = &p
	}
	return r
}

// Ifs are the ifs that a run goes through, the job's first.
func (r Reach) Ifs() []attacker.PlacedIf { return r.ifs }

// AlwaysSkipped is whether GitHub skips it in every run: on every event
// and activity type that the on of its workflow may start a run on
// (taint.WorkflowEvents), one of its ifs is false, read by
// github.event_name and github.event.action alone (attacker.EventOnly),
// which also reads an if that calls a status function after every job
// that its job depends on is skipped (if: failure() after a job whose if
// is false, for one). The if of a run step is also read on every value of
// the matrix of its job that it reads (matrixSkipped). A workflow without
// on, or with an on of no event, starts no run.
func (r Reach) AlwaysSkipped() bool {
	if skippedOnEvery(r.w, r.ifs) {
		return true
	}
	return r.step != nil && matrixSkipped(r.w, r.j, *r.step)
}

// skippedOnEvery is whether one of ifs is false on every event and
// activity type of taint.WorkflowEvents of w.
func skippedOnEvery(w *workflow.Workflow, ifs []attacker.PlacedIf) bool {
	evs, _, known := taint.WorkflowEvents(w)
	if !known {
		return false
	}
	for _, e := range evs {
		stopped := false
		for _, p := range ifs {
			if attacker.EventOnly(p, e) == expr.TruthFalse {
				stopped = true
				break
			}
		}
		if !stopped {
			return false
		}
	}
	return true
}

// maxMatrixCombinations bounds the combinations of values matrixSkipped
// reads an if on.
const maxMatrixCombinations = 1024

// matrixSkipped is whether the step if p of the job j of w is false on
// every event of taint.WorkflowEvents of w and every value of the matrix
// of j that p reads (matrix.<name>): each written value of the name (as a
// string, and as the number or boolean it may be read as), and null, for
// a combination without the name; exclude only takes combinations away.
// A matrix that is a ${{ }}, or a name whose values are not known before
// the run (workflow.MatrixVariable.Known), is not read so.
func matrixSkipped(w *workflow.Workflow, j *workflow.Job, p attacker.PlacedIf) bool {
	if j.Matrix.Status != workflow.Present {
		return false
	}
	evs, _, known := taint.WorkflowEvents(w)
	if !known || len(evs) == 0 {
		return false
	}
	for _, e := range evs {
		// Read first with the matrix not known: the matrix paths that
		// the reading asks for are the ones its truth may depend on.
		var names []string
		ok := true
		t := attacker.EventOnlyWith(p, e, func(path []expr.PathElem) (expr.Value, bool) {
			if !expr.HasPrefix(path, "matrix") {
				return expr.Value{}, false
			}
			if len(path) != 2 {
				ok = false
				return expr.Value{}, false
			}
			names = appendName(names, path[1].Name)
			return expr.Value{}, false
		})
		if t == expr.TruthFalse {
			continue
		}
		if !ok || len(names) == 0 {
			return false
		}
		values, ok := matrixValues(j, names)
		if !ok {
			return false
		}
		combo := make([]int, len(names))
		for {
			t := attacker.EventOnlyWith(p, e, func(path []expr.PathElem) (expr.Value, bool) {
				if len(path) == 2 && expr.HasPrefix(path, "matrix") {
					for i, n := range names {
						if expr.EqualName(n, path[1].Name) {
							return values[i][combo[i]], true
						}
					}
				}
				return expr.Value{}, false
			})
			if t != expr.TruthFalse {
				return false
			}
			i := 0
			for ; i < len(combo); i++ {
				combo[i]++
				if combo[i] < len(values[i]) {
					break
				}
				combo[i] = 0
			}
			if i == len(combo) {
				break
			}
		}
	}
	return true
}

func appendName(names []string, n string) []string {
	for _, x := range names {
		if expr.EqualName(x, n) {
			return names
		}
	}
	return append(names, n)
}

// matrixValues are the values that each of names may have in a
// combination of the matrix of j, as matrixSkipped reads them: each
// written value of the name, of its type in the matrix context
// (workflow.MatrixVariable.Types), and null when a combination may not
// have the name (workflow.MatrixVariable.InEvery); not ok when a name has
// values not known before the run, when a name has no value (os: [] with
// no include that gives os a value), or when there are more than
// maxMatrixCombinations combinations.
func matrixValues(j *workflow.Job, names []string) ([][]expr.Value, bool) {
	for _, v := range j.MatrixVariables {
		if !v.Known {
			return nil, false // a key or an include that is a ${{ }} may give any name values
		}
	}
	out := make([][]expr.Value, len(names))
	total := 1
	for i, n := range names {
		var vs []expr.Value
		inEvery := false
		for _, v := range j.MatrixVariables {
			if !expr.EqualName(v.Name, n) {
				continue
			}
			if len(v.Types) != len(v.Values) {
				return nil, false
			}
			inEvery = v.InEvery
			for k, s := range v.Values {
				x, ok := matrixValue(s, v.Types[k])
				if !ok {
					return nil, false
				}
				vs = append(vs, x)
			}
		}
		if !inEvery {
			vs = append(vs, expr.Null())
		}
		if len(vs) == 0 {
			return nil, false
		}
		out[i] = vs
		total *= len(vs)
		if total > maxMatrixCombinations {
			return nil, false
		}
	}
	return out, true
}

// matrixValue is the scalar s of the matrix as a value of the type t.
func matrixValue(s workflow.String, t expr.ValueType) (expr.Value, bool) {
	if s.HasExpr() {
		return expr.Value{}, false
	}
	str := s.AsString()
	switch t {
	case expr.ValueString:
		return expr.String(str), true
	case expr.ValueNull:
		return expr.Null(), true
	case expr.ValueBoolean:
		b, err := strconv.ParseBool(str)
		return expr.Bool(b), err == nil
	case expr.ValueNumber:
		f, err := strconv.ParseFloat(str, 64)
		return expr.Number(f), err == nil
	}
	return expr.Value{}, false
}

package job

import (
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// RunnerLabel is a label of runs-on: as written, or a value of the matrix that
// a whole ${{ matrix.<name> }} takes (Matrix). At is where it is written. A
// label no runner can have is no RunnerLabel.
//
// With are the other labels of the same runs-on that the analysis knows a
// runner of Label also has: the labels as written beside it, or the other
// items of the array a whole ${{ }} of runs-on evaluates to. A job runs
// only on a runner that has every label of its runs-on.
type RunnerLabel struct {
	Label              workflow.RunnerLabelName
	HasSelfHostedLabel bool
	Matrix             bool
	With               []workflow.RunnerLabelName
	At                 workflow.Base
}

// InconclusiveLabel is a label of runs-on that is a ${{ }} the analysis cannot read as
// values written in the matrix, or such a value. Dispatch is whether the
// ${{ }} has an input of workflow_dispatch (DispatchInputs): whoever
// dispatches the workflow chooses the label.
type InconclusiveLabel struct {
	Text     string
	At       workflow.Base
	Dispatch bool
}

// runnerLabelsOf are the labels of the runs-on of j, a job of w. A group is
// not a label: a runs-on of a group alone has none. A nil w marks no label
// Dispatch.
func runnerLabelsOf(w *workflow.Workflow, j workflow.Job) ([]RunnerLabel, []InconclusiveLabel) {
	gap := func(s workflow.String) InconclusiveLabel {
		return InconclusiveLabel{Text: s.Text(), At: s.Base, Dispatch: DispatchInputs(w, s)}
	}
	switch j.RunsOn.Status {
	case workflow.Dynamic:
		if j.RunsOn.Expr != nil {
			if rs, ok := evaluatedLabels(j, *j.RunsOn.Expr); ok {
				return rs, nil
			}
			return nil, []InconclusiveLabel{gap(*j.RunsOn.Expr)}
		}
		return nil, nil
	case workflow.Present:
	default:
		return nil, nil
	}
	var rs []RunnerLabel
	var gs []InconclusiveLabel
	trim := j.RunsOnForm != workflow.RunsOnFormSequence
	seen := map[place]bool{} // the values of the matrix taken
	for _, l := range j.RunsOn.Value.Items {
		if l.Parts == nil {
			r, ok := runnerLabel(l, false, trim)
			if !ok {
				return nil, nil // a label no runner has: the job runs on none
			}
			rs = append(rs, r)
			continue
		}
		vals, ok := MatrixValues(j, l)
		if !ok {
			if ers, ok := evaluatedLabels(j, l); ok {
				rs = append(rs, ers...)
				continue
			}
			gs = append(gs, gap(l))
			continue
		}
		for _, v := range vals {
			if k := placeOf(v.Base); seen[k] {
				continue // another label took the same values
			} else {
				seen[k] = true
			}
			if v.Parts != nil {
				gs = append(gs, gap(v))
				continue
			}
			r, ok := runnerLabel(v, true, false)
			if !ok {
				continue // that value's job runs on no runner
			}
			rs = append(rs, r)
		}
	}
	var written []workflow.RunnerLabelName // the labels as written, which every runner of the job has
	for _, r := range rs {
		if !r.Matrix {
			written = append(written, r.Label)
		}
	}
	for i := range rs {
		rs[i].With = append(others(written, rs[i].Label), rs[i].With...)
	}
	return rs, gs
}

// others are the labels of ls but l.
func others(ls []workflow.RunnerLabelName, l workflow.RunnerLabelName) []workflow.RunnerLabelName {
	var out []workflow.RunnerLabelName
	for _, o := range ls {
		if !o.Equal(l) {
			out = append(out, o)
		}
	}
	return out
}

// maxCombinations bounds the combinations of matrix values evaluatedLabels
// tries: past it, the runs-on stays inconclusive.
const maxCombinations = 256

// evaluatedLabels are the labels of s, a whole ${{ }} of runs-on, that
// reads no context but matrix variables whose values are all written: s is
// evaluated (expr.Partial) for each combination of the values of the
// variables it reads, which takes in every combination the matrix makes,
// and must give a string or an array of strings each time. The labels are
// Matrix, at s. ok is false when s reads anything else, or a combination
// gives another value.
func evaluatedLabels(j workflow.Job, s workflow.String) ([]RunnerLabel, bool) {
	if !s.IsExpr() {
		return nil, false // text beside the ${{ }}
	}
	var tree expr.Node
	for _, p := range s.Parts {
		if p.Expr {
			tree = p.Tree
		}
	}
	if tree == nil {
		return nil, false
	}
	// the matrix variables s reads, each with its values
	var vars []workflow.MatrixVariable
	var values [][]expr.Value
	readsOther := false
	expr.Partial(tree, func(path []expr.PathElem) (expr.Value, bool) {
		v, ok := matrixVariable(j, path)
		if !ok {
			readsOther = true
			return expr.Value{}, false
		}
		for _, w := range vars {
			if expr.EqualName(w.Name, v.Name) {
				return expr.Value{}, false
			}
		}
		vs, ok := scalarValues(v)
		if !ok {
			readsOther = true
			return expr.Value{}, false
		}
		vars, values = append(vars, v), append(values, vs)
		return expr.Value{}, false
	})
	if readsOther || len(vars) == 0 {
		return nil, false
	}
	n := 1
	for _, vs := range values {
		n *= len(vs)
		if n > maxCombinations || n == 0 {
			return nil, false
		}
	}
	var rs []RunnerLabel
	seen := map[string]bool{}
	pick := make([]int, len(vars))
	for c := 0; c < n; c++ {
		k := c
		for i := range pick {
			pick[i] = k % len(values[i])
			k /= len(values[i])
		}
		v := expr.Partial(tree, func(path []expr.PathElem) (expr.Value, bool) {
			mv, ok := matrixVariable(j, path)
			if !ok {
				return expr.Value{}, false
			}
			for i, w := range vars {
				if expr.EqualName(w.Name, mv.Name) {
					return values[i][pick[i]], true
				}
			}
			return expr.Value{}, false
		})
		set, ok := labelSet(v)
		if !ok {
			return nil, false
		}
		if set == nil {
			continue // a label no runner has: that combination's job runs on none
		}
		var key strings.Builder
		for _, l := range set {
			key.WriteString(strings.ToLower(l.String()))
			key.WriteByte(0)
		}
		if seen[key.String()] {
			continue
		}
		seen[key.String()] = true
		for _, l := range set {
			rs = append(rs, RunnerLabel{Label: l, HasSelfHostedLabel: l.Equal(workflow.SelfHostedLabel), Matrix: true, With: others(set, l), At: s.Base})
		}
	}
	return rs, true
}

// matrixVariable is the variable of the matrix of j that path, a whole
// matrix.<name>, names.
func matrixVariable(j workflow.Job, path []expr.PathElem) (workflow.MatrixVariable, bool) {
	if j.Matrix.Status != workflow.Present || len(path) != 2 || !expr.HasPrefix(path, "matrix") || path[1].Name == "" {
		return workflow.MatrixVariable{}, false
	}
	for _, v := range j.MatrixVariables {
		if expr.EqualName(v.Name, path[1].Name) {
			return v, true
		}
	}
	return workflow.MatrixVariable{}, false
}

// scalarValues are the values of v as an expression reads them; ok is
// false when they are not all written, or one is not a null, a boolean, a
// number or a string.
func scalarValues(v workflow.MatrixVariable) ([]expr.Value, bool) {
	if !v.Known || len(v.Types) != len(v.Values) || len(v.Values) == 0 {
		return nil, false
	}
	out := make([]expr.Value, len(v.Values))
	for i, s := range v.Values {
		if s.Parts != nil {
			return nil, false
		}
		text := s.AsString()
		switch v.Types[i] {
		case expr.ValueString:
			out[i] = expr.String(text)
		case expr.ValueNull:
			out[i] = expr.Null()
		case expr.ValueBoolean:
			b, err := strconv.ParseBool(text)
			if err != nil {
				return nil, false
			}
			out[i] = expr.Bool(b)
		case expr.ValueNumber:
			f, err := strconv.ParseFloat(text, 64)
			if err != nil {
				return nil, false
			}
			out[i] = expr.Number(f)
		default:
			return nil, false
		}
	}
	return out, true
}

// labelSet is the labels of v, the value of a whole ${{ }} of runs-on: a
// string (trimmed, as GitHub trims a runs-on string) or an array of
// strings. It is nil, with ok, when no runner has a label of it.
func labelSet(v expr.Value) ([]workflow.RunnerLabelName, bool) {
	if s, ok := v.Str(); ok {
		l, err := workflow.ParseRunnerLabelName(strings.TrimSpace(s))
		if err != nil {
			return nil, true
		}
		return []workflow.RunnerLabelName{l}, true
	}
	elems, ok := v.Elems()
	if !ok || len(elems) == 0 {
		return nil, false
	}
	var out []workflow.RunnerLabelName
	for _, e := range elems {
		s, ok := e.Str()
		if !ok {
			return nil, false
		}
		l, err := workflow.ParseRunnerLabelName(s)
		if err != nil {
			return nil, true
		}
		out = append(out, l)
	}
	return out, true
}

// runnerLabel is the label s: trimmed when trim (a string or a mapping's
// labels); ok is false when no runner has it.
func runnerLabel(s workflow.String, matrix, trim bool) (RunnerLabel, bool) {
	text := s.AsString()
	if trim {
		text = strings.TrimSpace(text)
	}
	l, err := workflow.ParseRunnerLabelName(text)
	if err != nil {
		return RunnerLabel{}, false
	}
	return RunnerLabel{Label: l, HasSelfHostedLabel: l.Equal(workflow.SelfHostedLabel), Matrix: matrix, At: s.Base}, true
}

// MatrixValues are the values of the matrix that s, a whole
// ${{ matrix.<name> }}, takes; ok is false when s is another value, or they
// are not all written. The runs-on of a job and the image of its container
// and services read them.
func MatrixValues(j workflow.Job, s workflow.String) ([]workflow.String, bool) {
	if !s.IsExpr() || j.Matrix.Status != workflow.Present {
		return nil, false
	}
	var tree expr.Node
	for _, p := range s.Parts {
		if p.Expr {
			tree = p.Tree
		}
	}
	if tree == nil {
		return nil, false
	}
	path, ok := expr.AccessPath(tree)
	if !ok || len(path) != 2 || !expr.HasPrefix(path, "matrix") || path[1].Name == "" {
		return nil, false
	}
	for _, v := range j.MatrixVariables {
		if expr.EqualName(v.Name, path[1].Name) {
			return v.Values, v.Known
		}
	}
	return nil, false
}

// place is where a value is written: its node, and the outermost alias it
// is reached through, which tells apart the places an anchor is used.
type place struct{ node, via cst.Node }

func placeOf(b workflow.Base) place {
	p := place{node: b.Node}
	if len(b.Via) > 0 {
		p.via = b.Via[0]
	}
	return p
}

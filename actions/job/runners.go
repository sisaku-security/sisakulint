package job

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// RunnerLabel is a label of runs-on: as written, or a value of the matrix that
// a whole ${{ matrix.<name> }} takes (Matrix). At is where it is written. A
// label no runner can have is no RunnerLabel.
type RunnerLabel struct {
	Label              workflow.RunnerLabelName
	HasSelfHostedLabel bool
	Matrix             bool
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
	return rs, gs
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

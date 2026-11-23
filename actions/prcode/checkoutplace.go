package prcode

import (
	"path"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// CheckoutPlacement is where the step at of steps, a checkout, puts the
// tree in the workspace, and placed false when the checkout fails before
// it puts anything. j is the job of steps, nil for a composite action;
// order is the order of steps.
//
// actions/checkout v2 on resolves path from github.workspace and fails
// when it is not under it
// (https://github.com/actions/checkout/blob/f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a/src/input-helper.ts,
// lines 40 to 52), after it trims the input. The runner puts runner.temp
// at <work>/_temp and github.workspace at <work>/<r>/<r>, <r> the name of
// the repository
// (https://github.com/actions/runner/blob/310a370bf3605f5b092f8af63b3126627de2a210/src/Runner.Worker/TrackingConfig.cs,
// lines 61 and 62): a path ${{ runner.temp }}<rest> is Clean("_temp" +
// rest) from <work>, under github.workspace when its first two elements
// are the same name. Where that is not sure (a runner that is not
// GitHub's, a step before that may move github.workspace, a \ that may be
// a separator), the path is any directory of the workspace.
func CheckoutPlacement(j *workflow.Job, steps []workflow.Step, order workflow.StepOrder, at int) (p Placement, placed bool) {
	s := steps[at]
	anywhere := workspacePlacement(anyDir())
	if mayBeV1(s.Uses.Value) {
		return v1Placement(s), true
	}
	switch s.With.Status {
	case workflow.Absent:
		return workspacePlacement(relDirOf(".")), true
	case workflow.Present:
	default:
		return anywhere, true
	}
	e, ok := s.With.Value.Lookup("path")
	if !ok {
		return workspacePlacement(relDirOf(".")), true
	}
	if e.Value.Status != workflow.Present {
		return anywhere, true
	}
	v := e.Value.Value
	if v.Parts == nil {
		return workspacePlacement(literalDir(v.AsString())), true
	}
	head, rest, ok := exprHeadAndRest(v)
	if !ok {
		return anywhere, true
	}
	switch {
	case head.Tree != nil && expr.IsPath(head.Tree, "github", "workspace"):
		switch {
		case rest == "":
			return workspacePlacement(relDirOf(".")), true
		case strings.HasPrefix(rest, "/"):
			return workspacePlacement(literalDir("." + rest)), true
		}
	case isRunnerTemp(head):
		if j == nil || job.Hosted(*j) != analysis.RunnerHostingGitHub || strings.Contains(rest, `\`) || mayMoveWorkspace(steps, order, at) {
			return anywhere, true
		}
		q := path.Clean("_temp" + rest)
		if q == ".." || strings.HasPrefix(q, "../") {
			return anywhere, true
		}
		segs := strings.Split(q, "/")
		if len(segs) < 2 || segs[0] != segs[1] {
			return Placement{}, false
		}
		return workspacePlacement(relDirOf(strings.Join(append([]string{"."}, segs[2:]...), "/"))), true
	}
	return anywhere, true
}

// v1Placement is where the checkout s of v1 puts the tree: v1 moves
// github.workspace to the tree of the repository of the workflow, which is
// then the workspace itself; it puts another repository beside the
// workspace, under runner.workspace, and a path not known anywhere.
func v1Placement(s workflow.Step) Placement {
	switch s.With.Status {
	case workflow.Absent:
		return workspacePlacement(relDirOf("."))
	case workflow.Present:
	default:
		return workspacePlacement(anyDir())
	}
	if !ownRepository(s) {
		return workspacePlacement(anyDir())
	}
	e, ok := s.With.Value.Lookup("path")
	if !ok || e.Value.Status == workflow.Present && e.Value.Value.Parts == nil {
		return workspacePlacement(relDirOf("."))
	}
	return workspacePlacement(anyDir())
}

// literalDir is the directory of the literal path p of a checkout, as
// actions/checkout trims it: any directory when it has a \ or a drive
// (C:), which Windows reads, or is absolute or leaves the workspace.
func literalDir(p string) relDir {
	p = strings.TrimSpace(p)
	if p == "" {
		return relDirOf(".")
	}
	if strings.Contains(p, `\`) || len(p) >= 2 && p[1] == ':' {
		return anyDir()
	}
	return relDirOf(p)
}

// exprHeadAndRest are the ${{ }} that v (trimmed) starts with and the
// literal after it, trimmed at its end; false when v starts with a
// literal or has another ${{ }}.
func exprHeadAndRest(v workflow.String) (head workflow.Part, rest string, ok bool) {
	text := v.Text()
	parts := v.Parts
	if len(parts) > 0 && !parts[0].Expr && strings.TrimSpace(text[parts[0].Span.Start:parts[0].Span.End]) == "" {
		parts = parts[1:]
	}
	if len(parts) == 0 || !parts[0].Expr {
		return workflow.Part{}, "", false
	}
	var b strings.Builder
	for _, p := range parts[1:] {
		if p.Expr {
			return workflow.Part{}, "", false
		}
		b.WriteString(text[p.Span.Start:p.Span.End])
	}
	return parts[0], strings.TrimRight(b.String(), " \t\r\n"), true
}

// ownRepository is whether the checkout s checks out the repository of
// the workflow: no repository, or ${{ github.repository }}.
func ownRepository(s workflow.Step) bool {
	e, ok := s.With.Value.Lookup("repository")
	if !ok {
		return true
	}
	if e.Value.Status != workflow.Present {
		return false
	}
	head, rest, ok := exprHeadAndRest(e.Value.Value)
	return ok && rest == "" && head.Tree != nil && expr.IsPath(head.Tree, "github", "repository")
}

// mayMoveWorkspace is whether a step of steps that may start before the
// step at is done (order.MayRunAfter) may move github.workspace: a step
// other than a run and a checkout that is not v1 may run the checkout
// plugin of the runner, which the runner runs for any action whose
// metadata says runs: plugin
// (https://github.com/actions/runner/blob/310a370bf3605f5b092f8af63b3126627de2a210/src/Runner.Worker/ActionManager.cs,
// lines 794 to 809).
func mayMoveWorkspace(steps []workflow.Step, order workflow.StepOrder, at int) bool {
	for k, x := range steps {
		if k == at || !order.MayRunAfter(k, at) {
			continue
		}
		switch {
		case x.Run.Status == workflow.Present && x.Uses.Status == workflow.Absent:
		case x.Uses.Status == workflow.Present && calls.IsCheckout(x.Uses.Value) && !mayBeV1(x.Uses.Value):
		default:
			return true
		}
	}
	return false
}

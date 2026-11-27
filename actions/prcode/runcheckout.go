package prcode

import (
	"path"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// RunCheckoutSite is a command of a run step of a workflow that brings the
// code of a pull request into the directory of the shell, gh pr checkout
// <n>, where <n> is a literal number or a whole ${{ }} of the number of the
// pull request of the event, and what the rules read of it.
type RunCheckoutSite struct {
	Step workflow.Step
	Job  *workflow.Job
	Path facts.StepPath

	Text    string     // the command, as written
	Span    shell.Span // of the command in the run
	Ref     string     // the number, as written
	RefSpan shell.Span // of the number in the run

	PRCodeOn    []analysis.EventActivity // the privileged events the step can run on on which the number names a pull request
	Approval    analysis.Approval
	Environment facts.EnvironmentName // when ApprovalEnvironment
	// CodeRunSteps are the commands after it in the same run and the
	// steps after it that run what it brings
	CodeRunSteps []CodeRunStep
}

// AnalyzeRunCheckouts is the commands of the run steps of w that bring
// the code of a pull request (RunCheckoutSite) on a privileged event, with
// the events of the input name, when it is called, read from its callers c.
// A step of an action.yml is not read.
func AnalyzeRunCheckouts(c *taint.Callers, name calls.Node, w *workflow.Workflow, m *shell.Memo) []RunCheckoutSite {
	if w == nil {
		return nil
	}
	var out []RunCheckoutSite
	evs := c.EventsOr(name, prCodeEvents, true, func() []analysis.EventActivity { return taint.EventsOf(w, prCodeEvents) })
	for _, je := range w.Jobs.Value.Entries {
		j := je.Value.Value
		jobEvs := taint.FilterCode(c.Table(), evs, attacker.JobIfs(w, &j)...)
		steps := j.Steps.Value.Items
		for _, s := range steps {
			if s.Run.Status != workflow.Present {
				continue
			}
			switch taint.ShellOf(w, &j, s) {
			case taint.ShellBash, taint.ShellSh, taint.ShellUnknown:
			default:
				continue
			}
			on := taint.FilterCode(c.Table(), jobEvs, attacker.StepIf(w, &j, s.If))
			if len(on) == 0 {
				continue
			}
			path, err := stepPath(&j, s)
			if err != nil {
				continue // a job id the model reports as invalid
			}
			for _, site := range ghCheckouts(s, on, m) {
				site.Job, site.Path = &j, path
				site.Approval, site.Environment = job.ApprovalOf(site.PRCodeOn, &j)
				site.CodeRunSteps = site.runs(w, steps, m)
				out = append(out, site)
			}
		}
	}
	return out
}

// ghCheckouts are the commands gh pr checkout <n> of the run of s whose
// number names a pull request on some of on.
func ghCheckouts(s workflow.Step, on []analysis.EventActivity, m *shell.Memo) []RunCheckoutSite {
	v := s.Run.Value
	text, masked := v.Text(), taint.Masked(v)
	var out []RunCheckoutSite
	shell.WalkSimple(taint.ReadScript(m, v).Script.List, func(c *shell.Simple) {
		ws := shell.WordsOf(masked, c)
		k, ok := ghCheckoutNumber(ws)
		if !ok {
			return
		}
		evs, ok := numberOn(v, c.Words[k], on)
		if !ok {
			return
		}
		sp := shell.Span{Start: c.Words[0].Span.Start, End: c.Words[len(c.Words)-1].Span.End}
		ref := c.Words[k].Parts[0].Span // numberOn: one part, without its quotes
		out = append(out, RunCheckoutSite{Step: s, Text: text[sp.Start:sp.End], Span: sp, Ref: text[ref.Start:ref.End], RefSpan: ref, PRCodeOn: evs})
	})
	return out
}

// ghCheckoutNumber is the index of the word of the pull request in ws, of
// gh pr checkout: its first operand, past the options and the values of
// those that take one (gh pr checkout --help of gh 2.x).
func ghCheckoutNumber(ws []shell.CommandWord) (int, bool) {
	if len(ws) < 4 || !ws[0].Known || path.Base(ws[0].Text) != "gh" || !ws[1].Known || ws[1].Text != "pr" || !ws[2].Known || ws[2].Text != "checkout" {
		return 0, false
	}
	for i := 3; i < len(ws); i++ {
		w := ws[i]
		switch {
		case w.Known && (w.Text == "-b" || w.Text == "--branch" || w.Text == "-R" || w.Text == "--repo"):
			i++ // its value
		case w.Known && strings.HasPrefix(w.Text, "-"):
		default:
			return i, true
		}
	}
	return 0, false
}

// numberOn is the events of on on which the word wd of the run v names a
// pull request: a literal number on all of them, or a whole ${{ }} of a
// reference of prNumbers on the events whose payload has it.
func numberOn(v workflow.String, wd shell.Word, on []analysis.EventActivity) ([]analysis.EventActivity, bool) {
	if len(wd.Parts) != 1 || wd.Parts[0].Kind != shell.PartLiteral {
		return nil, false
	}
	sp := wd.Parts[0].Span
	exprs := exprsIn(v, sp)
	if len(exprs) == 0 {
		lit, ok := shell.Literal(v.Text(), wd)
		if n, err := strconv.Atoi(lit); !ok || err != nil || n <= 0 {
			return nil, false
		}
		return on, true
	}
	p := exprs[0]
	if len(exprs) != 1 || p.Tree == nil || p.Span.Start != sp.Start || p.Span.End != sp.End {
		return nil, false
	}
	path, ok := expr.AccessPath(p.Tree)
	if !ok {
		return nil, false
	}
	row, ok := numberRow(path)
	if !ok {
		return nil, false
	}
	r := CheckoutRef{events: row.events}
	var evs []analysis.EventActivity
	for _, e := range on {
		if r.on(e) {
			evs = append(evs, e)
		}
	}
	return evs, len(evs) > 0
}

// runs are the commands after s in the same run, and the steps after its
// step, that run what it brings to the directory of the shell: the
// workspace when the step starts there and the run changes no directory,
// else any directory of the workspace.
func (s RunCheckoutSite) runs(w *workflow.Workflow, steps []workflow.Step, m *shell.Memo) []CodeRunStep {
	at := workspacePlacement(anyDir())
	if cwd := stepCwd(w, s.Job, s.Step); cwd.base == wordWorkspace && !cwd.open && path.Clean(cwd.path) == "." && !changesDirectoryIn(s.Step, m) {
		at = workspacePlacement(relDirOf("."))
	}
	var out []CodeRunStep
	for _, e := range runs(w, s.Job, s.Step, at, m) {
		if e.Span.Start >= s.Span.End {
			e.Step, e.Name = s.Step, StepName(s.Step)
			out = append(out, e)
		}
	}
	return append(out, codeRuns(w, s.Job, steps, workflow.OrderOf(steps), s.Step.Order, at, m)...)
}

// changesDirectoryIn is whether the run of x has a cd, pushd or popd.
func changesDirectoryIn(x workflow.Step, m *shell.Memo) bool {
	masked := taint.Masked(x.Run.Value)
	changes := false
	shell.WalkSimple(taint.ReadScript(m, x.Run.Value).Script.List, func(c *shell.Simple) {
		changes = changes || changesDirectoryWords(shell.WordsOf(masked, c))
	})
	return changes
}

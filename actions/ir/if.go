package ir

import (
	"slices"

	"encoding/json"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

func (x *IR) allIfSites() []*IfSite {
	x.once(SummaryIfSite, func() {
		var out []*IfSite
		add := func(c workflow.Field[workflow.If], evs []analysis.EventActivity, j *workflow.Job) {
			if s := x.projectIfSite(c, evs, j); s != nil {
				out = append(out, s)
			}
		}
		if w := x.workflow; w != nil {
			evs := x.ownEventsOn(job.Privileged())
			// a called workflow's ifs run on its callers' events too, when
			// they decide them; else as before, on its own alone
			if got, cov := x.callersOf().Events(x.name, job.Privileged(), false); cov == analysis.CallerCoverageAll {
				evs = got
			}
			for _, je := range w.Jobs.Value.Entries {
				if je.Value.Status != workflow.Present {
					continue
				}
				j := je.Value.Value
				jobIfs := attacker.JobIfs(w, &j)
				add(j.If, taint.FilterEventOnly(evs, jobIfs...), &j)
				jobEvs := taint.Filter(x.table(), evs, jobIfs...)
				for _, s := range j.Steps.Value.Items {
					add(s.If, taint.FilterEventOnly(jobEvs, attacker.StepIf(s.If)), nil)
				}
			}
		}
		if a := x.action; a != nil {
			evs := taint.EventsAll(job.Privileged())
			if got, cov := x.callersOf().Events(x.name, job.Privileged(), false); cov == analysis.CallerCoverageAll {
				evs = got
			}
			for _, s := range a.Runs.Value.Steps.Value.Items {
				add(s.If, taint.FilterEventOnly(evs, attacker.StepIf(s.If)), nil)
			}
		}
		x.ifSites = out
	})
	return x.ifSites
}

// projectIfSite is the summary of the if c on evs, the if of the job j or,
// when j is nil, of a step: nil without an if read as an expression or
// without events. The if of a job reads the needs context of the job
// (attacker.JobIf).
func (x *IR) projectIfSite(c workflow.Field[workflow.If], evs []analysis.EventActivity, j *workflow.Job) *IfSite {
	if c.Status != workflow.Present || c.Value.Expr == nil || c.Value.Expr.Tree == nil || len(evs) == 0 {
		return nil
	}
	s := &IfSite{key: keyOf(x.paths, x.input, x.tree, c.Value.Base), at: x.handleOf(c.Value.Base), attackerOn: evs}
	p := attacker.StepIf(c)
	if j != nil {
		p = attacker.JobIf(x.workflow, j)
		s.automaticApproval = x.automaticApprovalThrough(evs, []attacker.PlacedIf{p})
	} else {
		s.automaticApproval = x.automaticApprovalOf(evs, nil, p)
	}
	for _, b := range attacker.DependabotBypasses(p, evs) {
		path := attacker.PathText(b.Path)
		s.dependabotBypasses = append(s.dependabotBypasses, DependabotBypass{Path: path, Literal: b.Literal, Replacement: authorOf(path, evs), At: x.nodeHandle(c, b.Path)})
	}
	for _, b := range attacker.OtherBots(p, evs) {
		s.otherBots = append(s.otherBots, OtherBot{Text: attacker.PathText(b.Path) + " compared with " + b.Literal, At: x.nodeHandle(c, b.Node)})
	}
	for _, b := range attacker.SubstringBypasses(p, evs) {
		s.substringBypasses = append(s.substringBypasses, SubstringBypass{Func: b.Func, Literal: b.Literal, Path: attacker.PathText(b.Path), ReferenceFirst: b.ReferenceFirst, Fits: b.Fits, Standalone: standalone(c.Value.Expr.Tree, b.Node), At: x.nodeHandle(c, b.Node)})
	}
	if slices.Contains(s.automaticApproval.AutomaticLabels, analysis.AutomaticLabelFree) {
		names := make([]string, len(s.automaticApproval.LabelNames))
		for i, n := range s.automaticApproval.LabelNames {
			names[i] = n.String()
		}
		for _, b := range attacker.LabelBypasses(p, names) {
			s.substringBypasses = append(s.substringBypasses, SubstringBypass{Func: b.Func, Literal: b.Literal, Path: attacker.PathText(b.Path), ReferenceFirst: b.ReferenceFirst, Fits: b.Fits, Standalone: standalone(c.Value.Expr.Tree, b.Node), At: x.nodeHandle(c, b.Node)})
		}
	}
	x.ifSiteOf[s] = c
	return s
}

// nodeHandle is the handle on the node n of c's expression: on its span in
// the value, or on the whole value when c is folded (workflow.Part.InValue).
func (x *IR) nodeHandle(c workflow.Field[workflow.If], n expr.Node) Handle {
	return x.spanOf(c.Value.String, c.Value.Expr.InValue(n.Span()))
}

// foldedIf is the fix of an if that is folded (workflow.If.Folded): none,
// as the spans of its expression are in the folded string, not in the
// input; why gives the reason (form, or manual when the condition must be
// written by hand also without the fold), and todo says what to write in
// the condition.
func foldedIf(why func(string) *NoFix, todo string) FixPlan {
	return FixPlan{NoFix: why("the value of the key if is exactly one string literal in ${{ }}, and GitHub reads the text inside the string literal as the condition of the if; the linter does not edit text inside a string literal; remove the single quotes around the text, replace each pair of single quotes ('') inside the text with one single quote ('), and then " + todo)}
}

// authorOf is the context of the author of the pull request in place of
// the actor path, when every event of evs is pull_request_target; empty
// when there is none (Dependabot cannot be made to open a pull request).
func authorOf(path string, evs []analysis.EventActivity) string {
	for _, e := range evs {
		if e.Name() != workflow.EventNamePullRequestTarget {
			return ""
		}
	}
	switch strings.ToLower(path) {
	case "github.actor", "github.triggering_actor", "github.event.sender.login":
		return "github.event.pull_request.user.login"
	case "github.actor_id", "github.triggering_actor_id", "github.event.sender.id":
		return "github.event.pull_request.user.id"
	}
	return ""
}

// authorContext is the fix that writes the author of the pull request in
// place of the actor of the bypass i.
func (s *IfSite) authorContext(q *RuleAccess, i int) FixPlan {
	b := s.dependabotBypasses[i]
	folded := q.ir.ifSiteOf[s].Value.Folded()
	if b.Replacement == "" {
		if folded {
			return foldedIf(manual, "compare the author of what the event is about (github.event.pull_request.user.login on pull_request_target) instead of "+b.Path+", on each event the if runs on")
		}
		return FixPlan{NoFix: manual("compare the author of what the event is about (github.event.pull_request.user.login on pull_request_target) in place of " + b.Path + ", on each event the if runs on")}
	}
	if folded {
		return foldedIf(form, "compare "+b.Replacement+" instead of "+b.Path)
	}
	ed, err := b.At.Replace(b.Replacement)
	if err != nil {
		return FixPlan{NoFix: form("the reference cannot be written in place (" + err.Error() + "); write " + b.Replacement + " by hand")}
	}
	return FixPlan{Fix: &Fix{Kind: FixAuthorContext, Title: "compare the author of the pull request: " + b.Path + " becomes " + b.Replacement, Edits: []edit.Edit{ed}, SideEffects: []SideEffect{SideEffectActorNotCompared}}}
}

// containsArray is the fix that compares the words of the string of the
// bypass i as the elements of an array.
func (s *IfSite) containsArray(q *RuleAccess, i int) FixPlan {
	b := s.substringBypasses[i]
	if !strings.EqualFold(b.Func, "contains") {
		return FixPlan{NoFix: manual(b.Func + " compares a part of the string; compare whole values, as contains(fromJSON('[...]'), " + b.Path + ")")}
	}
	if q.ir.ifSiteOf[s].Value.Folded() {
		return foldedIf(form, "compare whole values: write contains(fromJSON('[...]'), "+b.Path+") instead of the function call "+b.Func+"(...), with each word of "+exprString(b.Literal)+" as one element of the JSON array")
	}
	if strings.ContainsAny(b.Literal, "|;") {
		return FixPlan{NoFix: manual("the string may part its values by | or ;, which the fix does not read; write contains(fromJSON('[...]'), " + b.Path + ") with the whole values")}
	}
	text := "contains(fromJSON(" + exprString(jsonArray(attacker.Words(b.Literal))) + "), " + b.Path + ")"
	ed, err := b.At.Replace(text)
	if err != nil {
		return FixPlan{NoFix: form("the call cannot be written in place (" + err.Error() + "); write " + text + " by hand")}
	}
	return FixPlan{Fix: &Fix{Kind: FixContainsArray, Title: "compare whole values: " + text, Edits: []edit.Edit{ed}, SideEffects: []SideEffect{SideEffectSubstringNotMatched}}}
}

// equality is the fix that compares the reference of the bypass i, the
// first argument of contains, with the whole string by ==, in place of the
// call where it stands alone (standalone).
func (s *IfSite) equality(q *RuleAccess, i int) FixPlan {
	b := s.substringBypasses[i]
	text := b.Path + " == " + exprString(b.Literal)
	switch {
	case !strings.EqualFold(b.Func, "contains"):
		return FixPlan{NoFix: manual(b.Func + " compares a part of the value at one end; when the whole value is meant, compare " + text)}
	case !b.Fits:
		return FixPlan{NoFix: manual("'" + b.Literal + "' does not have the form of a value of " + b.Path + "; compare whole values by ==")}
	case !b.Standalone:
		return FixPlan{NoFix: form("the call is an operand of an operator other than && and ||; replace the call with (" + text + ") by hand")}
	case q.ir.ifSiteOf[s].Value.Folded():
		return foldedIf(form, "write "+text+" instead of the function call "+b.Func+"(...)")
	}
	ed, err := b.At.Replace(text)
	if err != nil {
		return FixPlan{NoFix: form("the linter failed to rewrite the call (" + err.Error() + "); write " + text + " by hand")}
	}
	return FixPlan{Fix: &Fix{Kind: FixEquality, Title: "compare the whole value: " + text, Edits: []edit.Edit{ed}, SideEffects: []SideEffect{SideEffectSuperstringNotMatched}}}
}

// standalone is whether n, in the tree t, is the whole expression, in
// parentheses, or an operand of && or ||: == binds more tightly than these,
// so a == in place of n keeps the meaning of what is around it.
func standalone(t, n expr.Node) bool {
	var parentOf func(x, up expr.Node) (expr.Node, bool)
	parentOf = func(x, up expr.Node) (expr.Node, bool) {
		if x == n {
			return up, true
		}
		for _, k := range expr.Children(x) {
			if p, ok := parentOf(k, x); ok {
				return p, true
			}
		}
		return nil, false
	}
	p, ok := parentOf(t, nil)
	if !ok {
		return false
	}
	switch p.(type) {
	case nil, *expr.Group, *expr.Logical:
		return true
	}
	return false
}

// jsonArray is the JSON array of the strings ws, with < > & as they are.
func jsonArray(ws []string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ws); err != nil {
		panic(err) // a []string always encodes
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// exprString is s as a string literal of an expression: in single quotes,
// a single quote doubled.
func exprString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

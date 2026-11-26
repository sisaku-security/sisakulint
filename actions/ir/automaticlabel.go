package ir

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/labeler"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// labeledOn are the events of evs that a label starts: pull_request_target
// on labeled.
func labeledOn(evs []analysis.EventActivity) []analysis.EventActivity {
	var out []analysis.EventActivity
	for _, e := range evs {
		if e.Name() == workflow.EventNamePullRequestTarget && e.ActivityType() == workflow.ActivityTypeLabeled {
			out = append(out, e)
		}
	}
	return out
}

// automaticApprovalOf is how the labelers of the repository let the
// attacker into the labeled runs of evs of the job j (nil in an action)
// past the ifs of its steps: the ifs that a run of j goes through
// (attacker.JobIfs), and the ifs of the jobs and steps that call the input
// from a workflow on the labeled event.
func (x *IR) automaticApprovalOf(evs []analysis.EventActivity, j *workflow.Job, steps ...attacker.PlacedIf) AutomaticApproval {
	own := slices.Clone(steps)
	if j != nil {
		own = append(own, attacker.JobIfs(x.workflow, j)...)
	}
	out := x.automaticApprovalThrough(evs, own)
	if isFree(out) && j != nil {
		out.Environment = writtenEnvironment(j)
	}
	return out
}

// automaticApprovalThrough is how the labelers of the repository let the
// attacker into the labeled runs of evs past the ifs own, and the ifs of
// the jobs and steps that call the input from a workflow on the labeled
// event.
func (x *IR) automaticApprovalThrough(evs []analysis.EventActivity, own []attacker.PlacedIf) AutomaticApproval {
	labeled := labeledOn(evs)
	if len(labeled) == 0 {
		return AutomaticApproval{}
	}
	tab := x.labelersOf()
	if len(tab.Steps()) == 0 {
		return AutomaticApproval{}
	}
	var out AutomaticApproval
	for _, e := range labeled {
		for _, chain := range x.callersOf().Chains(x.name, &e) {
			ifs := append(slices.Clone(own), chain...)
			for _, s := range tab.Steps() {
				a := admits(x.table(), s, e, ifs)
				if len(a.AutomaticLabels) == 0 {
					continue
				}
				a.At = Handle{input: s.Input.String(), tree: s.Tree, base: s.Step.Base, exact: true}
				a.Token = s.Token
				out = stronger(out, a)
			}
		}
	}
	return out
}

// stepIfs are the ifs cs of steps of composite actions (composite.Step.Ifs),
// which do not read the needs context of the job.
func stepIfs(cs []workflow.Field[workflow.If]) []attacker.PlacedIf {
	out := make([]attacker.PlacedIf, len(cs))
	for i, c := range cs {
		out[i] = attacker.StepIf(nil, nil, c)
	}
	return out
}

// admits is how the labeler s lets the attacker past every if of ifs, in
// the attacker run table t,
// the run of e that a label starts. A labeler that may not run
// (labeler.Step.MayNotRun) lets the attacker in only undecided
// (AutomaticLabelUnknown), when the labels it adds when it runs let the
// attacker in.
func admits(t attacker.Table, s labeler.Step, e analysis.EventActivity, ifs []attacker.PlacedIf) AutomaticApproval {
	a := admitsWhenRun(t, s, e, ifs)
	if s.MayNotRun && len(a.AutomaticLabels) > 0 {
		a.AutomaticLabels = []analysis.AutomaticLabel{analysis.AutomaticLabelUnknown}
	}
	return a
}

// admitsWhenRun is admits for the labels s adds when s runs.
func admitsWhenRun(t attacker.Table, s labeler.Step, e analysis.EventActivity, ifs []attacker.PlacedIf) AutomaticApproval {
	passes := func(label string, labels []string) bool {
		return !slices.ContainsFunc(ifs, func(c attacker.PlacedIf) bool {
			return t.LabelTruth(c, e, label, labels) == expr.TruthFalse
		})
	}
	if s.Unknown || s.AnyLabel {
		// the attacker who writes the configuration names the label the ifs ask for
		if slices.ContainsFunc(ifs, func(c attacker.PlacedIf) bool {
			return t.Truth(c, e, attacker.RunOwn) == expr.TruthFalse
		}) {
			return AutomaticApproval{}
		}
		if s.Unknown {
			return AutomaticApproval{AutomaticLabels: []analysis.AutomaticLabel{analysis.AutomaticLabelUnknown}}
		}
		return AutomaticApproval{AutomaticLabels: []analysis.AutomaticLabel{analysis.AutomaticLabelFree}}
	}
	var all []string
	for _, name := range sortedLabels(s.Labels) {
		if !s.Labels[name].Never() {
			all = append(all, name)
		}
	}
	var out AutomaticApproval
	for _, name := range all {
		var a AutomaticApproval
		switch {
		case passes(name, []string{name}):
			a = AutomaticApproval{AutomaticLabels: s.Labels[name].Labels()}
		case len(all) > 1 && passes(name, all):
			a = AutomaticApproval{AutomaticLabels: []analysis.AutomaticLabel{analysis.AutomaticLabelLabelSet}}
		default:
			continue
		}
		if n, err := analysis.NewLabelName(name); err == nil {
			a.LabelNames = []analysis.LabelName{n}
		}
		out = stronger(out, a)
	}
	return out
}

func isFree(a AutomaticApproval) bool {
	return slices.Contains(a.AutomaticLabels, analysis.AutomaticLabelFree)
}

// tokenRank orders the sources of the token of a labeler by what the
// labeled run gives the attacker: an account, whose run any gate that lets
// in those who can write lets in, before a source not known, before an
// app, whose bot a gate may refuse.
var tokenRank = map[labeler.TokenSource]int{labeler.TokenSourceAccount: 0, labeler.TokenSourceUnknown: 1, labeler.TokenSourceApp: 2}

// stronger is the one of a and b that lets the attacker in more: Free over
// the rest, and of two Free the token first in tokenRank; else the
// conditions of both. The labels of two of the same strength are joined,
// at the place of the first.
func stronger(a, b AutomaticApproval) AutomaticApproval {
	switch {
	case len(a.AutomaticLabels) == 0:
		return b
	case len(b.AutomaticLabels) == 0:
		return a
	case isFree(a) != isFree(b):
		if isFree(b) {
			return b
		}
		return a
	case isFree(a) && tokenRank[a.Token] != tokenRank[b.Token]:
		if tokenRank[b.Token] < tokenRank[a.Token] {
			return b
		}
		return a
	}
	if !isFree(a) {
		for _, l := range b.AutomaticLabels {
			if !slices.Contains(a.AutomaticLabels, l) {
				a.AutomaticLabels = append(a.AutomaticLabels, l)
			}
		}
		slices.Sort(a.AutomaticLabels)
	}
	for _, n := range b.LabelNames {
		if !slices.Contains(a.LabelNames, n) {
			a.LabelNames = append(a.LabelNames, n)
		}
	}
	slices.SortFunc(a.LabelNames, func(x, y analysis.LabelName) int { return strings.Compare(x.String(), y.String()) })
	return a
}

func sortedLabels(m map[string]labeler.Reach) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// writtenEnvironment is the environment of j when its name is written out.
func writtenEnvironment(j *workflow.Job) facts.EnvironmentName {
	if j.Environment.Status != workflow.Present || j.Environment.Value.Parts != nil {
		return facts.EnvironmentName{}
	}
	n, err := facts.ParseEnvironmentName(j.Environment.Value.AsString())
	if err != nil {
		return facts.EnvironmentName{}
	}
	return n
}

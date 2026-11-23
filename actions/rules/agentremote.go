package rules

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// agentPlace reports the findings and the inconclusive places of an agent
// step: at their own place for a step of the inputs; for a step of a
// composite action of another repository (chain set), at the uses of the
// step of the input that runs the action, with the place in the file of
// the action as the evidence (as a related place, for an inconclusive
// place), as a finding is at a place of an input.
type agentPlace struct {
	c     *lint.RuleContext
	at    ir.Handle
	chain []composite.Hop
	inner ir.Handle // the step in the file of the action, when chain is set
}

// where tells the places of the steps of the composite actions of other
// repositories that the step at runs apart: the actions on the way,
// without their refs, which a fix that pins the first changes, and the
// path of the step in the file of the action.
func (p agentPlace) where() string {
	return hopsAnchor(p.chain) + " " + p.c.At(p.inner).KeyPath().String()
}

// At is the location of h (lint.RuleContext.At).
func (p agentPlace) At(h ir.Handle) lint.Location { return p.c.At(h) }

// agentReporter is what reports the places of an agent step: a
// lint.RuleContext, or an agentPlace.
type agentReporter interface {
	Report(lint.FindingDraft)
	Inconclusive(lint.InconclusiveDraft)
	At(ir.Handle) lint.Location
}

// Report reports d.
func (p agentPlace) Report(d lint.FindingDraft) {
	if len(p.chain) == 0 {
		p.c.Report(d)
		return
	}
	if d.Location.File.Query != nil {
		d.Evidence = append([]lint.Related{{Location: d.Location, Note: "in the composite action " + p.chain[len(p.chain)-1].Uses}}, d.Evidence...)
		d.Location = p.c.At(p.at)
	}
	d.Anchor = p.where() + " " + d.Anchor
	p.c.Report(d)
}

// Inconclusive reports d, moved as Report moves a finding: where it was is
// in Related, as an inconclusive place has no Evidence.
func (p agentPlace) Inconclusive(d lint.InconclusiveDraft) {
	if len(p.chain) == 0 {
		p.c.Inconclusive(d)
		return
	}
	if d.Location.File.Query != nil {
		d.Related = append([]lint.Related{{Location: d.Location, Note: "in the composite action " + p.chain[len(p.chain)-1].Uses}}, d.Related...)
		d.Location = p.c.At(p.at)
	}
	p.c.Inconclusive(d)
}

// substitutedAgent reports the agent step of a composite action of another
// repository whose archive has the file of the action unlike its blob
// (export-subst) as inconclusive, at the uses of the step of the input.
func substitutedAgent(c *lint.RuleContext, at ir.Handle, chain []composite.Hop) {
	c.Inconclusive(lint.InconclusiveDraft{KindID: archiveSubstituted, Location: c.At(at),
		Note: "the archive the runner downloads of " + chain[len(chain)-1].Uses + " has the file of the action unlike its blob (export-subst), so the step that runs the AI agent may differ from the one the linter read: compare the archive with the blob"})
}

// unansweredCall is a CompositeCall of a view of an AI rule.
type unansweredCall interface {
	At() ir.Handle
	Unanswered() []ir.UnansweredUses
	PrivilegedOn() []analysis.EventActivity
}

// unansweredAgents reports, as inconclusive, the actions of other
// repositories the steps of calls run whose action.definition was asked
// and has no answer: whether they run an AI agent is not known. A step
// that runs on no privileged event of an attacker is left out, and so is a
// step that runs only on status, check_suite and check_run when appRuns is
// false: a rule that does not read the runs of an outside app
// (app-commit-event).
func unansweredAgents[C unansweredCall](c *lint.RuleContext, calls []C, appRuns bool) {
	for _, call := range calls {
		on := call.PrivilegedOn()
		if !appRuns {
			on = slices.DeleteFunc(slices.Clone(on), func(e analysis.EventActivity) bool { return slices.Contains(appCommitEvents, e.Name()) })
		}
		if len(on) == 0 {
			continue // no attacker's event runs the step: no text of theirs reaches an agent there
		}
		for _, u := range call.Unanswered() {
			if u.Asked {
				c.Inconclusive(lint.InconclusiveDraft{KindID: remoteUnknown, Location: c.At(call.At()),
					Note: "the action " + u.Chain[len(u.Chain)-1].Uses + " was asked of action.definition and has no answer (" + u.Reason + "): whether a step of the action runs an AI agent is not known"})
			}
		}
	}
}

// The texts of the declarations of the AI rules about the composite
// actions of other repositories.
const (
	agentRemoteCompositeText    = "a step that runs an AI agent in a composite action of another repository, when action.definition has no answer for the action (a run without --online and without the answer in --facts): the rule reads the steps of a composite action of another repository only from the answer"
	agentRemoteUnknownText      = "an action of another repository that a step uses, which runs on a privileged event that an attacker triggers, whose action.definition was asked and has no answer (the archive is larger than the limit, the run has used up the requests it may send to the GitHub API, the token cannot read the repository, or the action is deeper than the 4 levels of actions the linter reads): whether a step of the action runs an AI agent is not known"
	agentArchiveSubstitutedText = "a step that runs an AI agent in a composite action of another repository whose action.yml (or action.yaml) in the archive the runner downloads is unlike its blob (export-subst): placeholders such as %d and %(describe) take the names of refs created after the commit, so the step the runner runs may differ from the one the linter read"
)

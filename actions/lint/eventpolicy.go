package lint

import (
	"fmt"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// The Actions policies of a repository can block the runs of a workflow on
// an event, and GitHub adds a default policy that blocks pull_request_target
// to a public repository
// (https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).
// A finding of a kind that declares repo.pull-request-target-allowed, in a
// workflow whose own on has pull_request_target and no other event, holds
// only when the runs on pull_request_target start: the engine
// adds that to its condition when the rule reports it, so that the finding
// and the check of a fix (identitiesOf) read the same condition.

// AttackerEvents are the events of the actors of m's threat whose attacker
// is one of k's.
func (m Meta) AttackerEvents(k FindingKind) []workflow.EventName {
	var out []workflow.EventName
	for _, a := range m.Threat.Actors {
		if !slices.Contains(k.Attackers, a.Attacker) {
			continue
		}
		for _, e := range a.Events {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// pullRequestTargetOnly is whether the events of w's own on are
// pull_request_target alone. Any other event, whether or not it is an
// event of the attackers of a kind, keeps the condition off: a rule may
// report a finding on an event that the actors of its threat do not name
// (gollum of a value whose events it reads), and an attacker without
// events (the maintainer of a called action) gets what a run of any event
// holds. workflow_call runs on the events of its callers. A name GitHub
// does not know is not counted.
func pullRequestTargetOnly(w *workflow.Workflow) bool {
	if w == nil || w.On.Status != workflow.Present {
		return false
	}
	target := false
	for _, ev := range w.On.Value.Events {
		n, err := workflow.ParseEventName(ev.Name.AsString())
		switch {
		case err != nil:
		case n == workflow.EventNamePullRequestTarget:
			target = true
		default:
			return false
		}
	}
	return target
}

// pullRequestTargetKinds are the kinds of m whose findings in w get the
// condition repo.pull-request-target-allowed: those that declare the kind
// of fact, when the events of w's own on are pull_request_target alone.
func pullRequestTargetKinds(m Meta, w *workflow.Workflow) []FindingKindID {
	if !pullRequestTargetOnly(w) {
		return nil
	}
	var out []FindingKindID
	for _, k := range m.FindingKinds {
		if slices.Contains(k.FactKinds, facts.KindRepoPullRequestTargetAllowed) {
			out = append(out, k.ID)
		}
	}
	return out
}

// withPullRequestTarget is the condition of d with repo.pull-request-target-allowed
// of the input of c added, when d is of one of kinds.
func withPullRequestTarget(c *RuleContext, kinds []FindingKindID, d FindingDraft) *Condition {
	if d.Args == nil || !slices.Contains(kinds, d.Args.KindID()) {
		return d.Condition
	}
	name, ok := c.input.Name.FactArgument()
	if !ok {
		// no fact names the input, so the condition does not ask the fact,
		// and the finding holds as if the fact were true
		// (https://github.com/gh-intel/sisakulint/issues/738)
		return d.Condition
	}
	allowed, err := FactEq(facts.RepoPullRequestTargetAllowed{Repo: c.repo, InputPath: name}, true)
	if err != nil {
		panic(err) // the kind's value is a boolean
	}
	if d.Condition == nil {
		return &allowed
	}
	all := All(*d.Condition, allowed)
	return &all
}

// checkPullRequestTarget is whether each kind of m declares
// repo.pull-request-target-allowed exactly when pull_request_target is an
// event of its attackers: a kind that does not would keep its findings on a
// workflow whose runs on pull_request_target the policies block.
func checkPullRequestTarget(m Meta) error {
	for _, k := range m.FindingKinds {
		reached := slices.Contains(m.AttackerEvents(k), workflow.EventNamePullRequestTarget)
		if declared := slices.Contains(k.FactKinds, facts.KindRepoPullRequestTargetAllowed); reached != declared {
			return fmt.Errorf("the kind %s: pull_request_target is an event of its attackers: %v, and it declares %s: %v; the two go together", k.ID, reached, facts.KindRepoPullRequestTargetAllowed, declared)
		}
	}
	return nil
}

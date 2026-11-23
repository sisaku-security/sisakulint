package rules

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// The Actions policies of a repository can block the runs of a workflow:
// an event policy of an administrator, and the default policy that GitHub
// adds to a public repository, which blocks pull_request_target
// (https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).
// A rule declares them by withEventPolicy, from its threat, so that no kind
// whose attackers trigger pull_request_target is left out: the kind asks
// repo.pull-request-target-allowed (the engine adds the condition, package
// lint), and the two false positive forms below are the rule's.

var (
	prTargetBlocked = lint.MustFalsePositiveFormID("pull-request-target-blocked")
	actionsPolicy   = lint.MustFalsePositiveFormID("actions-policy")

	prTargetBlockedText = "a workflow whose on has pull_request_target and no other event (no workflow_call event either), in a repository whose Actions policies block the runs of the workflow on pull_request_target (repo.pull-request-target-allowed false): an event policy that an administrator sets without pull_request_target among the allowed events, or the default policy that GitHub adds to a public repository without an applicable event policy, from the time when GitHub enforces the default policy on the repository. GitHub's documents say that GitHub evaluates the policies before a run, and that a run that a policy does not allow fails with an error. The documents do not say whether a job of such a run starts before the run fails; the rule assumes that no job of such a run starts"
	actionsPolicyText   = "a run that the Actions policies of the repository block, in four cases where the rule does not take the policies into account. First, an event policy that blocks an event of the attackers other than pull_request_target (such as issue_comment) in a workflow whose on has that event: the rules ask a fact only for pull_request_target. Second, an actor rule that does not allow the account of the attacker (for example, an actor rule that allows only the repository roles with write access): repo.pull-request-target-allowed is one value for all the runs of a workflow file on pull_request_target, and an actor rule blocks a run by the account that starts the run, so the fact cannot tell what an actor rule blocks. Third, a workflow whose on has pull_request_target and another event: the rule does not ask repo.pull-request-target-allowed for such a workflow, because a run on the other event can reach the job. When the if of the job is false on the other event, so that the job runs only on pull_request_target, and a policy blocks pull_request_target, the finding is a false positive. Fourth, a reusable workflow (on workflow_call) or an action that only workflows on pull_request_target call: the rule asks repo.pull-request-target-allowed only of a workflow whose on has pull_request_target, not of the reusable workflow or the action, so a finding in the reusable workflow or the action is still reported when the policies block the runs of every caller"
)

// withEventPolicy is m with each kind whose attackers trigger
// pull_request_target asking repo.pull-request-target-allowed, and the
// false positive forms pull-request-target-blocked and actions-policy of
// those kinds; m itself when it has no such kind.
func withEventPolicy(m lint.Meta) lint.Meta {
	var kinds []lint.FindingKindID
	m.FindingKinds = slices.Clone(m.FindingKinds)
	for i, k := range m.FindingKinds {
		if !slices.Contains(m.AttackerEvents(k), workflow.EventNamePullRequestTarget) {
			continue
		}
		m.FindingKinds[i].FactKinds = append(slices.Clip(k.FactKinds), facts.KindRepoPullRequestTargetAllowed)
		kinds = append(kinds, k.ID)
	}
	if len(kinds) == 0 {
		return m
	}
	m.FalsePositiveForms = append(slices.Clip(m.FalsePositiveForms),
		lint.FalsePositiveForm{ID: prTargetBlocked, Text: prTargetBlockedText, FindingKinds: kinds, FactKinds: []facts.Kind{facts.KindRepoPullRequestTargetAllowed}},
		lint.FalsePositiveForm{ID: actionsPolicy, Text: actionsPolicyText, FindingKinds: slices.Clone(kinds), Disposition: lint.Todo(lint.NeedFact)})
	return m
}

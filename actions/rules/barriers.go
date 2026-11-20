package rules

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/boundary"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// BarriersOf are the barriers that an attacker of any of vs gets past, as
// the rows of boundary say: what a run that adds vs reads.
func BarriersOf(vs []lint.AddedAttacker) analysis.BarrierPasses { return boundary.BarrierPassesOf(vs) }

// OutsiderRules are the rules that read an attacker outside the
// repository alone, in a run that adds attackers too: their flaw is that
// an outsider gets past an if (bot-conditions, unsound-contains), that a
// ref changes after the approval (untrusted-checkout-toctou), or that one
// who cannot write starts an agent (ai-action-unrestricted-trigger). An
// added attacker that gets past an approval or a gate is the concern of
// untrusted-checkout and of the other rules of agent actions.
func OutsiderRules() []lint.RuleID {
	return []lint.RuleID{UntrustedCheckoutToctouID, AIActionUnrestrictedTriggerID, BotConditionsID, UnsoundContainsID}
}

// The added attackers that get past an approval or a gate, as the rows of
// boundary say: those that open an issue with the author_association of a
// member, a collaborator or the owner (the examples of insider-association
// are of an issue, which a token of the Pull requests permission does not
// open), and the accounts alone, which open a pull request (its example of
// untrusted-checkout is of a pull request); those that add a label the
// repository has; and those that write vars and secrets.
var (
	associationAttackers = []lint.AddedAttacker{lint.AddedAttackerReadMember, lint.AddedAttackerTriageAccount, lint.AddedAttackerWriterIssuesToken, lint.AddedAttackerRequiredReviewer}
	accountAttackers     = []lint.AddedAttacker{lint.AddedAttackerReadMember, lint.AddedAttackerTriageAccount, lint.AddedAttackerRequiredReviewer}
	labelAttackers       = []lint.AddedAttacker{lint.AddedAttackerTriageAccount, lint.AddedAttackerWriterPullRequestsToken, lint.AddedAttackerAppInstallationToken}
	valueAttackers       = []lint.AddedAttacker{lint.AddedAttackerVariablesWriter, lint.AddedAttackerSecretsWriter}
)

// addedForms are, for each rule, the undetected forms whose example the
// rule reports on in a run that adds each of the attackers: the forms of
// an if of author_association (insider-association), of vars and secrets
// (not-attacker), and of a label that the approval waits for. A test of
// the rules holds each to its example (lint.Registry.CheckExamples).
var addedForms = map[lint.RuleID]map[lint.UndetectedFormID][]lint.AddedAttacker{
	ArgumentInjectionID:  {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	ArtifactPoisoningID:  {insiderAssociationLimit.ID: associationAttackers},
	CachePoisoningID:     labelForms(scriptLabelLimit, outsideBotLabelLimit, labelerPullRequestLimit, labelerOtherEventLimit, labelerCallLimit, labelerNotInputLimit),
	CodeInjectionID:      {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	DangerousTriggersID:  withForm(labelForms(scriptLabelLimit, outsideBotLabelLimit, labelerPullRequestLimit, labelerOtherEventLimit, labelerNotInputLimit), insiderAssociationLimit.ID, associationAttackers),
	EnvpathInjectionID:   {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	EnvvarInjectionID:    {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	OutputClobberingID:   {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	RequestForgeryID:     {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	SetOutputInjectionID: {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	UnsecureCommandsID:   {insiderAssociationLimit.ID: associationAttackers, notAttackerLimit.ID: valueAttackers},
	UntrustedCheckoutID: withForm(withForm(labelForms(scriptLabelLimit, outsideBotLabelLimit, labelerPullRequestLimit, labelerOtherEventLimit, labelerCallLimit, labelerNotInputLimit),
		approvedLimitID, labelAttackers), insiderAssociationLimit.ID, accountAttackers),
}

// approvedLimitID is the undetected form approved of untrusted-checkout.
var approvedLimitID = lint.MustUndetectedFormID("approved")

// labelForms are the forms fs, each with the attackers that add a label.
func labelForms(fs ...lint.UndetectedForm) map[lint.UndetectedFormID][]lint.AddedAttacker {
	out := map[lint.UndetectedFormID][]lint.AddedAttacker{}
	for _, f := range fs {
		out[f.ID] = labelAttackers
	}
	return out
}

// withForm is m with the form id and the attackers vs.
func withForm(m map[lint.UndetectedFormID][]lint.AddedAttacker, id lint.UndetectedFormID, vs []lint.AddedAttacker) map[lint.UndetectedFormID][]lint.AddedAttacker {
	m[id] = vs
	return m
}

// absentLabelRules are the rules that read a label that the approval waits
// for as a label the attacker adds, in a run that adds an attacker who
// adds a label (analysis.BarrierLabelApproval): those that report on the
// job of such an approval, and so report it falsely when the repository
// has no such label.
var absentLabelRules = []lint.RuleID{UntrustedCheckoutID, DangerousTriggersID, CachePoisoningID}

// absentApprovalLabel is the false positive form of absentLabelRules, of
// the kinds of the rule.
func absentApprovalLabel(kinds []lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("absent-approval-label"),
		Text:         "a job that runs only when a label is added (pull_request_target with the activity type labeled), whose if compares the label with a name that no label of the repository has, in a run of the linter that adds the attacker triage-account: the rule reads every label that the if compares with as a label of the repository, and reads the attacker as able to add the label; when the repository has no such label, the attacker cannot add the label, because the triage role cannot create a label, and the job does not run on the pull request of the attacker. The linter does not read the labels of the repository",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedFact), AddedAttackers: []lint.AddedAttacker{lint.AddedAttackerTriageAccount}}
}

// valueRules are the rules that report a value of vars or secrets in a
// run that adds variables-writer or secrets-writer: those of the form
// not-attacker, and those of agent actions, which read such a value that
// reaches the agent in a run anyone starts (ir.EveryRunRef). They report
// it also on a job that runs only for a pull request from a fork, where
// the run has no secret and a token that only reads.
var valueRules = []lint.RuleID{ArgumentInjectionID, CodeInjectionID, EnvpathInjectionID, EnvvarInjectionID, OutputClobberingID, RequestForgeryID, SetOutputInjectionID, UnsecureCommandsID,
	AIActionPromptInjectionID, AIActionExcessiveToolsID, AIActionExecutionOrderID, AIActionUnsafeSandboxID}

// forkPullRequest is the false positive form of valueRules, of the kinds
// of the rule.
func forkPullRequest(kinds []lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("fork-pull-request"),
		Text: "a job that runs only for a pull request from a fork (pull_request, pull_request_review or pull_request_review_comment, with an if that compares github.event.pull_request.head.repo.fork with true, or github.event.pull_request.head.repo.full_name with github.repository), in a repository that is not a fork, in a run of the linter that adds variables-writer or secrets-writer: the rule reads each value of vars and secrets as a value that the attacker writes in every workflow run of the event; the workflow run for a pull request from a fork has no secret except GITHUB_TOKEN and a GITHUB_TOKEN that only reads, unless the settings of a private repository send secrets or a GITHUB_TOKEN that writes to such workflow runs (the facts repo.fork-pr-secrets and repo.fork-pr-write-tokens), and the attacker who writes a variable or a secret gets nothing from the job that the author of the pull request does not get from the code of the pull request. " +
			"A job with no such if, in a repository where every pull request comes from a fork, is a false positive in the same way. " +
			"The linter does not tell a workflow run for a pull request from a fork from a workflow run for a pull request from a branch of the repository. " +
			"A fix: the linter splits the workflow runs of the three events into the runs for a pull request from a fork and the runs for a pull request from a branch of the repository, reads the comparisons of the if with the fork in each, and counts a run for a pull request from a fork only when the facts repo.fork-pr-secrets or repo.fork-pr-write-tokens say that the run gets secrets or a GITHUB_TOKEN that writes. A job with no such if keeps the runs for a pull request from a branch of the repository, and the finding stays. A fact of the rulesets of the repository (a ruleset with the rule Restrict creations on every branch and no actor that may bypass the ruleset) could say that no new branch, and so no pull request from a new branch, can be made, and remove a part of the false positives of a job with no such if; the actors that may bypass a ruleset, the branches made before the ruleset and the names of branches outside the patterns of the ruleset remain. The fix is not observed on GitHub",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile, lint.NeedFact), AddedAttackers: valueAttackers}
}

// combinedCredentials is the undetected form of the rules in absentLabelRules that
// only one attacker who holds two credentials gets past: the linter reads
// each added attacker as a separate attacker.
var combinedCredentials = lint.UndetectedForm{ID: lint.MustUndetectedFormID("combined-credentials"),
	Text:        "a job that runs only when a label is added to a pull request (pull_request_target with the activity type labeled), whose if needs both a label and the author_association MEMBER or COLLABORATOR of the author of the pull request, in a run of the linter that adds read-member and writer-pull-requests-token or app-installation-token, and does not add triage-account: one attacker who holds both credentials opens the pull request from the account with the read role and adds the label with the token, and the job runs for the pull request of the attacker in the same way that the job runs for a pull request after a person who can add labels adds the label to approve the pull request. The linter runs the rules once for each added attacker alone and reads each added attacker as a separate attacker, so no run lets one attacker past both the if of author_association and the approval by the label. A run that adds triage-account reports the job, as an account with the triage role both has the author_association MEMBER or COLLABORATOR and adds a label",
	Disposition: lint.Todo(lint.NeedSameFile), AddedAttackers: []lint.AddedAttacker{lint.AddedAttackerTriageAccount}}

// withAddedAttackers is m with the added attackers of its forms
// (addedForms), with absentApprovalLabel for absentLabelRules, with
// forkPullRequest for valueRules, with combinedCredentials for
// absentLabelRules, and with refusedActorValueRun for
// refusedActorRules.
func withAddedAttackers(m lint.Meta) lint.Meta {
	var kinds []lint.FindingKindID
	for _, k := range m.FindingKinds {
		kinds = append(kinds, k.ID)
	}
	if slices.Contains(absentLabelRules, m.ID) {
		m.FalsePositiveForms = append(slices.Clone(m.FalsePositiveForms), absentApprovalLabel(kinds))
	}
	if slices.Contains(valueRules, m.ID) {
		m.FalsePositiveForms = append(slices.Clone(m.FalsePositiveForms), forkPullRequest(kinds))
	}
	if slices.Contains(absentLabelRules, m.ID) {
		m.UndetectedForms = append(slices.Clone(m.UndetectedForms), combinedCredentials)
	}
	if slices.Contains(refusedActorRules, m.ID) {
		m.FalsePositiveForms = append(slices.Clone(m.FalsePositiveForms), refusedActorValueRun(kinds))
	}
	forms, ok := addedForms[m.ID]
	if !ok {
		return m
	}
	m.UndetectedForms = slices.Clone(m.UndetectedForms)
	for i, f := range m.UndetectedForms {
		if vs, ok := forms[f.ID]; ok {
			m.UndetectedForms[i].AddedAttackers = vs
		}
	}
	return m
}

func init() { lint.RegisterBarriers(BarriersOf, OutsiderRules()...) }

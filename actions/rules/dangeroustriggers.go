package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// DangerousTriggers is the rule dangerous-triggers: a job that an
// attacker's privileged event runs and no one approves, whose GITHUB_TOKEN
// may write or which reads secrets. It does not look for the flaw that
// would run the attacker's code there (the other rules do): it reports
// what such a flaw would give.
var DangerousTriggers lint.Rule = withExamples(lint.WithView[ir.DangerousTriggersReader](dangerousTriggers{}, ir.DangerousTriggersView))

// DangerousTriggersID is the ID of dangerous-triggers.
var DangerousTriggersID = lint.MustRuleID("dangerous-triggers")

type dangerousTriggers struct{}

func (dangerousTriggers) Meta() lint.Meta { return dangerousTriggersMeta }

// The anchors tell apart the two findings a job may have: the fingerprint
// does not have the kind.
const (
	anchorToken   = "token"
	anchorSecrets = "secrets"
)

func (dangerousTriggers) Check(_ context.Context, c *lint.RuleContext, v ir.DangerousTriggersReader) error {
	for _, j := range v.Jobs() {
		evs := j.PrivilegedOn()
		if len(evs) == 0 {
			continue
		}
		if s := j.Secrets(); j.TokenWrite() == analysis.TokenWriteNo && !s.All && len(s.Names) == 0 {
			continue // nothing to expose
		}
		approval, ok := approvalCond(c, j.Approval(), j.Environment(), j.AutomaticApproval(), j.At(), "the job", nil)
		if !ok {
			continue
		}
		labeler := labelerRelated(c, j.Approval(), j.AutomaticApproval())
		names := eventsOf(evs)
		switch j.TokenWrite() {
		case analysis.TokenWriteYes:
			c.Report(lint.FindingDraft{Location: c.At(j.At()), Anchor: anchorToken, Args: DangerousTriggersTokenWrite{PrivilegedOn: names}, Condition: approval, Related: labeler})
		case analysis.TokenWriteUnwritten:
			c.Report(lint.FindingDraft{Location: c.At(j.At()), Anchor: anchorToken, Args: DangerousTriggersTokenWrite{PrivilegedOn: names}, Condition: allOf(approval, defaultWrites(c)), Related: labeler})
		}
		if s := j.Secrets(); s.All || len(s.Names) > 0 {
			secrets := s.Names
			if s.All {
				secrets = []string{"*"}
			}
			c.Report(lint.FindingDraft{Location: c.At(j.At()), Anchor: anchorSecrets, Args: DangerousTriggersSecrets{PrivilegedOn: names, Secrets: secrets}, Condition: approval, Related: labeler})
		}
	}
	return nil
}

// exposureGains are what code run in an exposed job gets.
var exposureGains = []lint.Gain{lint.GainReadSecrets, lint.GainWriteWithToken}

// exposureActorsWith are those who trigger the attacker's privileged
// events (actions/job), each with gains.
func exposureActorsWith(gains []lint.Gain) []lint.Actor {
	return []lint.Actor{
		{Attacker: lint.AttackerForkPRAuthor, Via: "opens or updates a pull request from a fork, which runs pull_request_target, and workflow_run after its pull_request",
			Events: []workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameWorkflowRun}, RunStarters: startedBy([]workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameWorkflowRun}), Gains: gains},
		{Attacker: lint.AttackerIssueAuthor, Via: "opens an issue or a discussion",
			Events: []workflow.EventName{workflow.EventNameIssues, workflow.EventNameDiscussion}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameIssues, workflow.EventNameDiscussion}), Gains: gains},
		{Attacker: lint.AttackerCommenter, Via: "comments on an issue, a pull request or a discussion, or reviews a pull request from a branch of the repository or comments on the diff of the pull request",
			Events: []workflow.EventName{workflow.EventNameIssueComment, workflow.EventNameDiscussionComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameIssueComment, workflow.EventNameDiscussionComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}), Gains: gains},
		{Attacker: lint.AttackerAnyoneWhoForks, Via: "forks the repository",
			Events: []workflow.EventName{workflow.EventNameFork}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameFork}), Gains: gains},
	}
}

// exposureActors are those who trigger the attacker's privileged events
// (actions/job): what they get is the job's, through a flaw that runs
// their code there.
var exposureActors = exposureActorsWith(exposureGains)

var exposureAttackers = []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerAnyoneWhoForks}

// the CVSS of the kinds: what a flaw in the job gives; that a flaw is there
// is the requirement of the attack
var (
	exposedToken = lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker opens an issue, a comment, a review or a pull request over the network"),
		AC: metric(lint.AttackComplexityLow, "once a flaw runs their code in the job, the token is in its environment"),
		AT: metric(lint.AttackRequirementsPresent, "a flaw has to run the attacker's code in the job: an injection, a checkout of their code, a cache or an artifact of theirs"),
		PR: metric(lint.PrivilegesRequiredNone, "on a public repository anyone opens an issue or a pull request from a fork, or reviews a pull request"),
		UI: metric(lint.UserInteractionNone, "the event runs the job with nobody doing anything"),
		VC: metric(lint.ImpactHigh, "the token reads what the job may read"),
		VI: metric(lint.ImpactHigh, "the token writes what the job may write: pushes, releases"),
		VA: metric(lint.ImpactLow, "the token can cancel runs or delete what the job may"),
		SC: metric(lint.ImpactNone, "the GITHUB_TOKEN opens only this repository"),
		SI: metric(lint.ImpactHigh, "what it pushes or releases reaches those who use the repository"),
		SA: metric(lint.ImpactNone, "nothing past the repository is made unavailable by this as such"),
	}
	exposedSecrets = lint.CVSS{
		AV: exposedToken.AV, AC: exposedToken.AC, AT: exposedToken.AT, PR: exposedToken.PR, UI: exposedToken.UI,
		VC: metric(lint.ImpactHigh, "the attacker reads the secrets"),
		VI: metric(lint.ImpactNone, "the secrets do not write to the repository as such"),
		VA: metric(lint.ImpactNone, "the secrets do not act on the repository as such"),
		SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
		SI: metric(lint.ImpactHigh, "they write what the secrets may: deployments, packages"),
		SA: metric(lint.ImpactLow, "they can delete what the secrets may"),
	}
)

// sawCalledReads is what the jobs of a called workflow got in their
// runners: the runs observed for secret-exposure, and the runs of
// 2026-11-06.
var sawCalledReads = lint.Observation{Date: observedCalledReads, Runner: runner, What: "the reusable workflows were called by ./ and by owner/repo/path@sha from the same repository, from another repository of the same organization, and two calls deep. A job of a called workflow got in its runner only the secrets that the job read by name, with secrets: inherit and with secrets passed one by one. The job got every secret that the caller passed when the job read toJSON(secrets), and a secret passed one by one that the job did not read was not in the runner of the job"}

var observedCalledReads = lint.MustDate("2026-11-06")

var (
	privilegedJob = lint.MustPreconditionID("privileged-job")
	flawInJob     = lint.MustPreconditionID("flaw-in-job")
	readsSecrets  = lint.MustPreconditionID("reads-secrets")

	forkedSecrets = lint.MustCitation("https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets")
	reusingDocs   = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations")
)

var dangerousTriggersMeta = lint.Meta{
	ID:       DangerousTriggersID,
	Problem:  "a job that an attacker's event runs, which no one approves, holds a GITHUB_TOKEN that may write or the repository's secrets: a flaw that runs the attacker's code there gives them all of it",
	Expected: "a job of an attacker's event with permissions of only the scopes it needs and no secrets, or one a person approves",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessExcessivePrivilege}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textDangerousTriggersTokenWrite,
			Attackers:       exposureAttackers,
			Preconditions:   []lint.PreconditionID{privilegedJob, noApproval, tokenWrites, flawInJob, appStatusCheck},
			FactKinds:       []facts.Kind{facts.KindRepoDefaultTokenWrite, facts.KindRepoEnvironmentProtected},
			CVSS:            exposedToken,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "the reports found name what a flaw took from such a job as a personal access token among its secrets (spotbugs-2024), not its GITHUB_TOKEN"),
		},
		{
			FindingText:     textDangerousTriggersSecrets,
			Attackers:       exposureAttackers,
			Preconditions:   []lint.PreconditionID{privilegedJob, noApproval, readsSecrets, flawInJob, appStatusCheck},
			Incidents:       []lint.IncidentID{spotbugs2024},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected},
			CVSS:            exposedSecrets,
			ExploitMaturity: metric(lint.ExploitMaturityAttacked, "in 2024-12 a pull request ran its code in a pull_request_target job of spotbugs/sonar-findbugs that held a maintainer's personal access token, the start of the tj-actions compromise", unit42),
		},
	},
	Threat: lint.Threat{
		Actors: withAppCommitEventsAdded(exposureActors),
		Preconditions: []lint.Precondition{
			appStatusCheckPre,
			{ID: privilegedJob, Text: "the job runs on an event that one without write access triggers and whose run has the repository's secrets and a token that may write: pull_request_target, workflow_run, issue_comment, issues, discussion, discussion_comment, fork, each run on the default branch; status, check_suite and check_run, each run on the default branch where an app outside GitHub Actions makes a commit status or a check run for a commit whose message an attacker writes (the precondition app-status-check); pull_request_review and pull_request_review_comment of a pull request from a branch of the repository, each run on the merge ref of the pull request (anyone with read access can open a pull request between two branches that the repository already has; a run of a review of a pull request that one without write access opened between two branches that others pushed to the repository is inferred to have the same secrets and token: the runs that the authors of the linter saw were of reviews of pull requests that the owner opened); not pull_request, whose author can change its workflow; not a review of a pull request from a fork, whose run takes the workflow of the merge commit of the pull request, which the author of the pull request can change (a review of another's pull request from a fork is the undetected form fork-review); not workflow_dispatch, which one with write access to the permission Actions dispatches and for which the one who dispatches the workflow chooses only a branch or a tag of the repository and the inputs, so that the run takes the repository's code",
				Observed: []lint.Observation{{Date: observedCheckout, Runner: runner, What: "a pull request from a fork ran pull_request_target, workflow_run after its pull_request, and issue_comment on a comment, each with the repository's secret and a token that created a ref"}, sawOutsiderReview, sawForkReviewWorkflow},
				Cites:    []lint.Citation{prTarget, forkedSecrets}},
			{ID: noApproval, Text: "no one approves the run: either the job runs on at least one event other than pull_request_target with the activity type labeled, and a run on the other event starts with no label added, or no person adds the label that starts the run, as the label is " + labelerAddedLabel + "; and the job has no environment that has required reviewers (repo.environment-protected, assumed false: an environment is made with no protection rules)",
				Observed: []lint.Observation{{Date: observedCheckout, Runner: runner, What: "a push after the label ran no labeled run, and ran pull_request_target on synchronize"}}},
			{ID: tokenWrites, Text: "the job's token may write: a scope other than id-token written write, or no permissions written and the repository's default writes (repo.default-token-write, assumed true)", Cites: []lint.Citation{tokenDocs}},
			{ID: readsSecrets, Text: "the job reads secrets other than GITHUB_TOKEN: in the env of the workflow, the job or a step, the outputs of the job, a step's run, with, name, working-directory, timeout-minutes or continue-on-error, the env or the credentials of the job's container or of a service, or, for a job that calls a reusable workflow, the secrets that GitHub passes to the runners of the jobs of the called workflow: with secrets: inherit, the secrets that those jobs read by name, and every secret when one of those jobs reads the secrets context without naming a secret (toJSON(secrets), secrets[<an expression>], secrets.* (an object filter)); with secrets passed one by one under the secrets: of the calling job, the passed secrets that those jobs read by the names that the calling job gives the secrets. The rule reads a called workflow whose contents the linter has: a workflow that is among the inputs and that the job calls by ./ or $/, or a reusable workflow of another repository that the fact workflow.definition answers. The runs that showed what GitHub passes called a reusable workflow of the same repository and of another repository of the same organization; the rule assumes the same for a repository of another organization of the same enterprise. When the linter is not given the name of the repository (--repo), a call of the repository's own workflow by owner/repo/path@ref is read as a call of another repository; with the name, the rule does not read the input file for such a call, as the ref of the call may name another version of the file. For a called workflow whose contents the linter does not have, the rule assumes that the jobs of the called workflow read every secret that the job passes (with secrets: inherit, every secret of the job)", Cites: []lint.Citation{forkedSecrets, reusingDocs, runnerContainerInfo},
				Observed: []lint.Observation{{Date: observedOtherKeys, Runner: runner, What: "a secret that the job reads in the username or in the password of the credentials of the job's container, and nowhere else, was in the memory of the process Runner.Worker of the runner on the host, and a step in the job's container read that memory through the docker socket that the runner mounts in the job's container on Linux"}, sawCalledReads}},
			{ID: flawInJob, Text: "a flaw runs the attacker's code in the job: an injection, a checkout of their code, an artifact or a cache of theirs; the rule does not look for it, the other rules report those they see", Cites: []lint.Citation{pwnRequests}},
		},
		Incidents: []lint.Incident{
			{ID: spotbugs2024, Date: lint.MustDate("2024-12-06"), Advisory: unit42,
				Compromised: repos("spotbugs/sonar-findbugs"),
				Downstream:  repos("tj-actions/changed-files"),
				Summary:     "a pull_request_target job with write scopes held a maintainer's personal access token as a secret; a pull request ran its code there by a checkout of its mvnw, and the token was the start of the tj-actions compromise"},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		forkReviewLimit, labelApprovedCheckoutLimit,
		// actions/labeler in a reusable workflow or in a composite action
		// (labeler-call) is a miss that the rule does not declare: the label
		// that the called actions/labeler adds starts a job on labeled, and
		// the rule does not report that job. The form is not declared, as
		// the example of the form has a job that calls the reusable workflow
		// on an event of an attacker and passes the reusable workflow a
		// secret, the rule reports dangerous-triggers.secrets on the calling
		// job, and an example of an undetected form must have no finding of
		// the rule. That finding on the calling job is the false positive
		// no-sink: no code of the attacker runs in the calling job.
		outsideBotLabelLimit, labelerPullRequestLimit, labelerNotInputLimit, scriptLabelLimit, labelerOtherEventLimit,
		{ID: lint.MustUndetectedFormID("remote-caller"), Text: "a reusable workflow called from another repository: the caller's events, token and secrets are not seen", Disposition: lint.Limitation(lint.DeciderRemoteCaller)},
		{ID: lint.MustUndetectedFormID("id-token"), Text: "a job with id-token write and no other: code run there takes an OIDC token for the clouds that trust the repository", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("watch"), Text: "a job on watch: anyone can star the repository, and the run has its secrets, but the event carries no value of the attacker's, so it is not counted among the attacker's events", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("gollum"), Text: "a job on gollum, which an attacker triggers only where anyone may edit the wiki (repo.wiki-open)", Disposition: lint.Todo(lint.NeedFact)},
		newActivityTypeLimit,
		insiderAssociationLimit,
	}),
	InconclusiveKinds: withRemoteCalleeUnknown(automaticLabelKinds),
	FalsePositiveForms: append([]lint.FalsePositiveForm{
		forkFlagReview(kindDangerousTriggersSecrets, kindDangerousTriggersTokenWrite),
		{ID: lint.MustFalsePositiveFormID("approval-if"), Text: "an if that lets in only the comments of the owner and the members (author_association OWNER, MEMBER), in a job that reads nothing of the issue or pull request the comment is on, where every member has a role that can write: such a comment on an attacker's issue runs the job, but the job reads nothing that the attacker wrote; the rule does not tell such a job apart from a job that reads what the attacker wrote. A member whose role is read only is the undetected form insider-association", FindingKinds: []lint.FindingKindID{kindDangerousTriggersTokenWrite, kindDangerousTriggersSecrets}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("no-sink"), Text: "a job in which an attacker can run no code: the rule does not read the sinks, and holds this as the precondition of AT:P", FindingKinds: []lint.FindingKindID{kindDangerousTriggersTokenWrite, kindDangerousTriggersSecrets}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("environment-protected"), Text: "a job whose environment has required reviewers, who approve it before it runs; for the kind dangerous-triggers.secrets of a job that calls a reusable workflow, a job whose called workflow has such an environment on every job that reads the secrets: GitHub passes the secrets only to the runners of the jobs that read the secrets, and the job that calls has no environment of its own (GitHub does not accept environment on a job that calls a reusable workflow)", FindingKinds: []lint.FindingKindID{kindDangerousTriggersTokenWrite, kindDangerousTriggersSecrets}, FactKinds: []facts.Kind{facts.KindRepoEnvironmentProtected}},
		{ID: lint.MustFalsePositiveFormID("inherit-unread"), Text: "a job that calls with secrets: inherit a reusable workflow of the repository whose contents the linter does not have, and whose jobs read no secret, by name or without a name: a workflow file that is not among the inputs, or the repository's own workflow called by owner/repo/path@ref when the linter is given the name of the repository (--repo); also a called workflow whose contents the linter has, when a job of the called workflow calls with secrets: inherit, in turn, such a reusable workflow. GitHub passes the runner of a job of the called workflow only the secrets that the job reads, and the rule assumes that the jobs of a called workflow whose contents the linter does not have read every secret", FindingKinds: []lint.FindingKindID{kindDangerousTriggersSecrets}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustFalsePositiveFormID("remote-inherit-unread"), Text: "a job that calls with secrets: inherit a reusable workflow of another repository that the fact workflow.definition does not answer, and whose jobs read no secret, by name or without a name, directly or through a called workflow whose contents the linter has; or a job of a repository of a user account that calls with secrets: inherit a reusable workflow of a repository of an organization, whose jobs get no secret of the calling repository (observed on 2026-10-22: the called workflow got only github_token). The rule assumes that the jobs of a called workflow whose contents the linter does not have read every secret, and does not compare the owner of the calling repository with the owner of the called repository", FindingKinds: []lint.FindingKindID{kindDangerousTriggersSecrets}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("named-unread"), Text: "a job that passes secrets one by one under secrets: to a reusable workflow whose contents the linter does not have (a workflow file that is not among the inputs, the repository's own workflow called by owner/repo/path@ref, or a reusable workflow of another repository that the fact workflow.definition does not answer), when no job of the called workflow reads any of the passed secrets: GitHub passes the runner of a job of the called workflow only the passed secrets that the job reads, so no passed secret reaches a runner, and the rule assumes that the jobs of the called workflow read every passed secret. When the jobs read some of the passed secrets, the finding holds, and the argument secrets names more secrets than GitHub passes", FindingKinds: []lint.FindingKindID{kindDangerousTriggersSecrets}, Disposition: lint.Todo(lint.NeedRepoFile, lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("default-token-read"), Text: "a job that writes no permissions, in a repository whose default token is read", FindingKinds: []lint.FindingKindID{kindDangerousTriggersTokenWrite}, FactKinds: []facts.Kind{facts.KindRepoDefaultTokenWrite}},
		labelNameIf(kindDangerousTriggersTokenWrite, kindDangerousTriggersSecrets),
	}, automaticLabelFalsePositives(kindDangerousTriggersTokenWrite, kindDangerousTriggersSecrets)...),
}

// labelApprovedCheckoutLimit is a job that a label approves and whose checkout
// takes code that the label does not approve: the rule reads the label as
// the approval of the job, and untrusted-checkout-toctou reads the
// checkout.
var labelApprovedCheckoutLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("label-approved-checkout"),
	Text:        "a job that runs only when a label is added to a pull request (pull_request_target with the activity type labeled), and whose checkout takes code that the person who adds the label did not see: a ref that moves after the label is added (refs/pull/<number>/head, which follows the branch of the pull request), or the head commit at the time of the label (github.event.pull_request.head.sha), which can be a commit that the author of the pull request pushed after a review and before the label. The rule reads the label as the approval of the job. untrusted-checkout-toctou reports the checkout of a ref that moves (the kind untrusted-checkout-toctou.mutable-ref), and declares the checkout of the head commit at the time of the label as the undetected form sha-ref of untrusted-checkout-toctou",
	Disposition: lint.OtherRule(UntrustedCheckoutToctouID)}

package rules

import (
	"fmt"
	"github.com/gh-intel/sisakulint/actions/analysis"
	"slices"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// What the injection rules share: code-injection, envvar-injection and
// output-clobbering read the same analysis (actions/taint), so they have
// the same attackers, the same preconditions of the events, the same forms
// of no added gain and the same inconclusive kinds of the values
// they read.

// inconclusiveKind is the ID of the inconclusive kind of k, a kind of
// reference or of write of actions/analysis: its String.
func inconclusiveKind[K analysis.InconclusiveRefKind | analysis.InconclusiveWriteKind](k K) lint.InconclusiveKindID {
	return lint.MustInconclusiveKindID(fmt.Sprint(k))
}

// anchors counts the findings of one scalar by the text each reports, so
// that the anchor of each says which of the same text it is.
type anchors map[string]int

// next is the anchor of one more reference of text that gets o, counted
// whether the reference gives a finding or not, so that the anchor of one
// reference does not move with what another gives. Those with a fix and
// those without are counted apart, so that those a fix leaves keep their
// anchors after it.
func (a anchors) next(text string, o ir.FixPlan) string {
	key := text
	if o.NoFix != nil {
		key += "#nofix"
	}
	a[key]++
	return fmt.Sprintf("%s#%d", key, a[key])
}

// envEvidence is where each env a value went through gets its value, the
// first first: that is where text, which reads it, gets its own.
func envEvidence(c *lint.RuleContext, env []ir.Handle, text string) []lint.Related {
	var out []lint.Related
	for i, e := range env {
		note := "the env it reads gets its value here"
		if i == 0 {
			note = text + " gets its value here"
		}
		out = append(out, lint.Related{Location: c.At(e), Note: note})
	}
	return out
}

// valueEvidence is where the value of r, whose text is text, comes from:
// the with of each caller it came through, the outermost first (or the
// input's default, in the input itself), then each env it went through; and, as related, the with of each other caller that
// gives it what an attacker controls.
func valueEvidence(c *lint.RuleContext, r ir.ExprRef, text string) (evidence, related []lint.Related) {
	for i, w := range r.With {
		note := "the caller gives it here"
		// the default is in the file of the reference: a reference in a
		// composite action of the inputs that a step of the input runs is
		// in another input than the one of the rule
		def := c.InFile(w)
		if !c.InFile(r.At) {
			def = w.InputName() != "" && w.InputName() == r.At.InputName()
		}
		switch {
		case def:
			note = "the input's default gives " + text + " here"
		case i == 0:
			note = "a caller gives " + text + " here"
		}
		evidence = append(evidence, lint.Related{Location: c.At(w), Note: note})
	}
	evidence = append(evidence, envEvidence(c, r.Env, text)...)
	for _, o := range r.OtherCallers {
		related = append(related, lint.Related{Location: c.At(o), Note: "another caller gives " + text + " here"})
	}
	return evidence, related
}

// withFix gives f the fix of o, or else its reason for none. When the plan
// gives neither, the engine keeps f with the reason manual and reports the
// error (lint.Run); the rule does not fail, which would lose its findings.
func withFix(f *lint.FindingDraft, o ir.FixPlan) {
	fix, no := fixOf(o)
	if fix != nil {
		f.Fix = fix
	} else {
		f.NoFix = no
	}
}

// eventsOf are the names of the events of evs, once each, in order.
func eventsOf(evs []analysis.EventActivity) []workflow.EventName {
	var names []workflow.EventName
	for _, e := range evs {
		if !slices.Contains(names, e.Name()) {
			names = append(names, e.Name())
		}
	}
	return names
}

// onlyGollum is whether gollum is the one event of evs: then only who may
// edit the wiki controls the value, which is a setting of the repository.
func onlyGollum(evs []analysis.EventActivity) bool {
	for _, e := range evs {
		if e.Name() != workflow.EventNameGollum {
			return false
		}
	}
	return len(evs) > 0
}

// wikiOpenCond is the condition of a finding on gollum alone.
func wikiOpenCond(c *lint.RuleContext) *lint.Condition {
	return factCond(facts.RepoWikiOpen{Repo: c.Repo()}, true)
}

var (
	prTarget        = lint.MustCitation("https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target")
	workflowCall    = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_call")
	ultralyticsGHSA = lint.MustCitation("https://github.com/advisories/GHSA-7x29-qqmq-v6qc")

	wikiAccess = lint.MustCitation("https://docs.github.com/en/communities/documenting-your-project-with-wikis/changing-access-permissions-for-wikis")
)

// The observations of the runs of a review (pull_request_review and
// pull_request_review_comment), of a pull request from a branch of the
// repository and from a fork.
var (
	sawOutsiderReview     = lint.Observation{Date: lint.MustDate("2026-10-30"), Runner: lint.MustVersion("2.338.0"), What: "a review and a comment on the diff, by an account with no role in a public repository, of a pull request from a branch of the repository that the owner opened: each run started with no approval, with the repository's secret and a token that created a ref"}
	sawForkReviewWorkflow = lint.Observation{Date: lint.MustDate("2026-11-01"), Runner: lint.MustVersion("2.338.2"), What: "a review and a comment on the diff of a pull request from a fork whose branch changed a workflow on pull_request_review and pull_request_review_comment: each run ran the workflow as the pull request changed it, from the merge ref of the pull request"}
)

var (
	attackerEvent = lint.MustPreconditionID("attacker-event")
	callersEvents = lint.MustPreconditionID("callers-events")
	wikiOpen      = lint.MustPreconditionID("wiki-open")

	attackerEventPre = lint.Precondition{
		ID:   attackerEvent,
		Text: "the job runs on an event whose payload has what an attacker wrote, with the token and the secrets of the repository: the attacker starts the run by an act of the attacker, or the act of another person or a schedule starts the run (run starters); not pull_request, whose run takes the workflow from the branch of the pull request: the author of the pull request can change the workflow of the pull request, so the author gets what the run has (read-only from a fork, or what a private repository sends to the runs of pull requests from forks) without the flaw of the rule",
		Observed: []lint.Observation{
			{Date: observedInjection, Runner: runner, What: "a pull_request run took its workflow from the pull request's branch"},
		},
		Cites: []lint.Citation{prTarget},
	}
	callersEventsPre = lint.Precondition{
		ID:    callersEvents,
		Text:  "a reusable workflow or a composite action that is among the inputs runs on the events of the callers of the workflow or the action, whoever the callers are; when the inputs are the whole repository and hold every caller of the workflow or the action, the rule reads the workflow or the action on the events of the callers, with the values that the callers give under with",
		Cites: []lint.Citation{workflowCall, ultralyticsGHSA},
	}
	wikiOpenPre = lint.Precondition{
		ID:   wikiOpen,
		Text: "on gollum, an account with no role in the repository can edit the wiki only in a public repository whose settings let anyone with an account edit the wiki (the fact repo.wiki-open). The finding holds only when repo.wiki-open is true, and the finding is conditional when no source answers repo.wiki-open",
		Observed: []lint.Observation{
			{Date: observedInjection, Runner: runner, What: "a wiki page titled with $( ) and backticks, written into run as github.event.pages[0].title, ran the commands; GitHub kept $, (, ), backticks and ;"},
			{Date: lint.MustDate("2026-10-30"), Runner: lint.MustVersion("2.338.0"), What: "in a public repository whose settings let anyone with an account edit the wiki, an account with no role in the repository created a wiki page on the web interface of GitHub and edited the page; the creation and the edit each started a run of gollum, and each run had the repository's secret, and a step of each run created a ref with the token of the run, which the workflow asked for with contents: write"},
		},
		Cites: []lint.Citation{wikiAccess},
	}
)

// forkPREvents are the events of the author of a pull request from a fork
// in injectionActors: pull_request_target, workflow_run, and the events of
// a commit status or a check run (appCommitEvents).
var forkPREvents = append([]workflow.EventName{workflow.EventNamePullRequestTarget, workflow.EventNameWorkflowRun}, appCommitEvents...)

// mergedCommitEvents are the events of the author of a merged commit in
// injectionActors: push, merge_group, and the events of a commit status or
// a check run that an app outside GitHub Actions makes for the merged
// commit; one who can write merges the commit, so another person starts
// each of their runs.
var mergedCommitEvents = append([]workflow.EventName{workflow.EventNamePush, workflow.EventNameMergeGroup}, appCommitEvents...)

// injectionActors are those who write what the injection rules read, by
// event, each getting gains.
func injectionActors(gains []lint.Gain) []lint.Actor {
	return []lint.Actor{
		{Attacker: lint.AttackerForkPRAuthor, Via: "writes the title, the body or the branch name of a pull request from a fork, or the message, the author name or the committer name of a commit of the pull request",
			Events: forkPREvents, RunStarters: startedBy(forkPREvents), Gains: gains},
		{Attacker: lint.AttackerIssueAuthor, Via: "writes the title or the body of an issue or a discussion",
			Events: []workflow.EventName{workflow.EventNameIssues, workflow.EventNameDiscussion}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameIssues, workflow.EventNameDiscussion}), Gains: gains},
		{Attacker: lint.AttackerCommenter, Via: "writes a comment or a review",
			Events: []workflow.EventName{workflow.EventNameIssueComment, workflow.EventNameDiscussionComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameIssueComment, workflow.EventNameDiscussionComment, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}), Gains: gains},
		{Attacker: lint.AttackerMergedCommitAuthor, Via: "writes the message of a commit that is merged, or put in a merge queue",
			Events: mergedCommitEvents, RunStarters: startedBy(mergedCommitEvents, mergedCommitEvents...), Gains: gains},
		{Attacker: lint.AttackerAnyoneWhoForks, Via: "forks the repository, and names the fork",
			Events: []workflow.EventName{workflow.EventNameFork}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameFork}), Gains: gains},
		{Attacker: lint.AttackerWikiEditor, Via: "writes the title of a wiki page, where anyone may edit the wiki",
			Events: []workflow.EventName{workflow.EventNameGollum}, RunStarters: startedBy([]workflow.EventName{workflow.EventNameGollum}), Gains: gains},
	}
}

// withoutWikiEditor are actors but the editor of a wiki, for
// set-output-injection: the title of a wiki page holds no -, and the name
// of a wiki page made on the web interface holds no blank, so that the
// name holds no command that takes a property, such as set-output; the
// rule gives the values of gollum an inconclusive place, for a page pushed
// by git keeps its blanks.
func withoutWikiEditor(actors []lint.Actor) []lint.Actor {
	return slices.DeleteFunc(actors, func(a lint.Actor) bool { return a.Attacker == lint.AttackerWikiEditor })
}

// wikiSummaryLimit is the summary of a wiki page, which the rules read as
// a value nobody writes: the gollum payloads seen had a null summary each
// time, and an edit by an account with no role was not tried.
var wikiSummaryLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("wiki-summary"), Text: "the summary of a wiki page (github.event.pages[*].summary) in a job that runs on gollum: the rule reads the summary as a value that nobody writes. The gollum payloads that the authors of the linter saw had a null summary each time: for pages made and edited on the web interface of GitHub and pushed by git, an edit message on the web interface and a commit message of git did not go into the summary. The authors saw only pages that the owner of a public repository made and edited, and did not try an edit by an account with no role in the repository", Disposition: lint.Limitation(lint.DeciderRunTime)}

// withoutGollum is evs without the events of gollum, in a new slice.
func withoutGollum(evs []analysis.EventActivity) []analysis.EventActivity {
	return slices.DeleteFunc(slices.Clone(evs), func(e analysis.EventActivity) bool { return e.Name() == workflow.EventNameGollum })
}

var (
	// pullRequestLimit: a job of the workflow of a ruleset, which the
	// author of the pull request cannot change, is seen in the documents
	// only
	// (https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-workflows-to-pass-before-merging).
	pullRequestLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("pull-request"), Text: "a job that runs only on pull_request, in one of two cases. In the first case, only the pull requests of the repository run the workflow: the author of a pull request can change the workflow itself, so the run of the job gives the author what the run has (read-only from a fork, or what a private repository sends to the runs of pull requests from forks: secrets, a token that writes) without the flaw of the rule, and the flaw of the rule adds nothing to what the author gets. In the second case, a ruleset of the organization or the enterprise runs the workflow on the pull requests of its other repositories (Require workflows to pass before merging, of GitHub Enterprise): the author of such a pull request cannot change the workflow, and whether the run has more than the pull_request workflow of the author would get (the token, secrets) is known from GitHub's documentation only, as no such run was observed; making a required check pass is outside the threat model of the rule. The workflow does not say which case holds, and the rule does not read which case holds", Disposition: lint.Todo(lint.NeedFact)}
	// forkReviewLimit is the form of a review of another's pull request from
	// a fork, which the attacker run table does not count (package
	// attacker: a review of the attacker's own pull request from a fork gives
	// the attacker nothing more).
	forkReviewLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("fork-review"), Text: "a job on pull_request_review or pull_request_review_comment that runs only for a pull request from a fork, such as a job whose if: condition is github.event.pull_request.head.repo.full_name != github.repository: the run of a review that the attacker writes on the pull request of another person from a fork has the secrets of the repository or a token that writes only where a private repository gives secrets or a token that writes to the runs of pull requests from forks (repo.fork-pr-secrets, repo.fork-pr-write-tokens). The rule does not read the facts repo.fork-pr-secrets and repo.fork-pr-write-tokens for the runs of a review, and does not count the run of a review of a pull request from a fork as a run of the attacker. When the attacker opened the pull request from a fork, a review of that pull request gives the attacker nothing more than the pull request itself gives: the run takes the workflow of the merge commit of the pull request (GitHub's documentation gives refs/pull/<n>/merge as the ref of the run of a review), and the attacker can change that workflow in the pull request", Disposition: lint.Todo(lint.NeedFact)}
	dispatchLimit   = lint.UndetectedForm{ID: lint.MustUndetectedFormID("dispatch"), Text: "a value of the event of workflow_dispatch other than its inputs, in a job that runs only on workflow_dispatch: the event has the ref, which is a branch or a tag that the repository already has, and values that GitHub fills, such as the login of the account that dispatches the workflow; the event has no text of an issue, a comment or a pull request. Whoever dispatches the workflow chooses the ref and the inputs of the dispatch, and nothing else of the event. A token that cannot change the files of the repository can dispatch the workflow, such as a fine-grained token that has the permission Actions with write access and no permission Contents. The rule reports an input of the dispatch with the inconclusive kind input-dispatch", Disposition: lint.NoAddedGain()}

	// repositoryDispatchLimit and dispatchRelayLimit are the forms of
	// repository_dispatch of the rules that read the payload of an event as
	// the attacker's values: the sender is outside the threat model, and a
	// sender that relays the attacker's values is not read.
	repositoryDispatchLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("repository-dispatch"), Text: "a value of the client_payload of repository_dispatch (github.event.client_payload): only a credential with write access to the permission Contents of the repository can send repository_dispatch, and the credential premise assumes that no attacker holds such a credential; the sender chooses the whole client_payload", Disposition: lint.NoAddedGain()}
	// appCommitEventLimit is the form of the runs that an app outside
	// GitHub Actions starts by a commit status or a check run, for a rule
	// that reads the runs of the attacker run table alone: the actor of
	// such a run is the app, and the table has no rows of the three events.
	appCommitEventLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("app-commit-event"), Text: "a value of the payload of status, check_suite or check_run, such as the message of the commit (commit.commit.message of status, check_suite.head_commit.message of check_suite), when an app outside GitHub Actions, such as an outside CI, makes a commit status or a check run for a commit whose message an attacker writes: the run of status, check_suite or check_run starts on the default branch with the commit in the payload, and the actor of the run is the app. This rule reads a run of a privileged event only in two cases, as the attacker run table says: the attacker is the actor of the run, or another person (such as a maintainer) acts on what the attacker wrote, and the act starts the run. The attacker run table has no rows of a run whose actor is an app. The rule also does not read a value of the payload of deployment_status, because the rule does not read deployment_status as an event that an attacker starts", Disposition: lint.Todo(lint.NeedSameFile)}
	dispatchRelayLimit  = lint.UndetectedForm{ID: lint.MustUndetectedFormID("dispatch-relay"), Text: "a workflow on an event of an attacker that puts a value the attacker writes into the client_payload of a repository_dispatch that the workflow sends (gh api with client_payload to the endpoint dispatches, peter-evans/repository-dispatch), and a workflow on repository_dispatch that uses the value: the flaw is in the workflow that sends the repository_dispatch, and the rule does not read what a workflow sends to another workflow", Disposition: lint.Todo(lint.NeedRepoFile)}
	// dispatchInputCallLimit and dispatchDerivedLimit are the forms of an
	// input of workflow_dispatch that a value does not refer to itself: given
	// through a call, or made into another value in the job.
	dispatchInputCallLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("dispatch-input-call"), Text: "an input of workflow_dispatch that a caller of the same repository passes, as an input of the call (under the key with: of the calling job or step), to a reusable workflow or a composite action, which uses the input as a value: the one who dispatches the caller chooses the value, and the rule reads the events of a called workflow or action from the table of the callers, and does not follow the value of an input of workflow_dispatch that the caller gives", Disposition: lint.Todo(lint.NeedRepoFile)}
	dispatchDerivedLimit   = lint.UndetectedForm{ID: lint.MustUndetectedFormID("dispatch-derived"), Text: "a value that an env or the output of a step makes from an input of workflow_dispatch, in a job that runs only on workflow_dispatch (env: REF: refs/pull/${{ inputs.pr }}/head; the output of gh pr view with the input pr), used as the ref of a checkout, the run that a download takes (the input run-id of actions/download-artifact), the key or the path of the cache, or a prompt: the one who dispatches the workflow chooses the value too, and the rule reports only an input of workflow_dispatch that the value refers to directly (input-dispatch)", Disposition: lint.Todo(lint.NeedSameFile)}
	notAttackerLimit       = lint.UndetectedForm{ID: lint.MustUndetectedFormID("not-attacker"), Text: "secrets, vars, runner, the outcome of a step, the result of a job. A run of the linter that adds the attacker variables-writer reports a reference of vars where the rule reads the value as written by the attacker, and a run of the linter that adds the attacker secrets-writer reports such a reference of secrets except secrets.GITHUB_TOKEN (--add-attacker); no run reports runner, the outcome of a step or the result of a job", Disposition: lint.NoAddedGain()}
	// mergedPusherLimit declares what the table of what an attacker controls
	// does not check: the table reads merged_by of a pull request and the
	// pusher of push as the account that merged or pushed, which holds a
	// credential that can merge or push. The pusher of a push, of a merge
	// commit and of a squash was seen on GitHub; the pusher of a merge by a
	// rebase, by auto-merge or from a merge queue, and merged_by of any merge,
	// were not.
	mergedPusherLimit    = lint.UndetectedForm{ID: lint.MustUndetectedFormID("merged-pusher"), Text: "a value that the author of a pull request writes in the profile of the account of the author (the profile name, the public email of the profile), in github.event.pull_request.merged_by of a merged pull request, or in github.event.pusher of the push that GitHub makes when GitHub merges a pull request by a rebase, by auto-merge or from a merge queue: the rule reads merged_by and the pusher as the account that merged or pushed, and the account that merged or pushed holds a credential that can merge or push; whether GitHub sets merged_by of a merged pull request, or the pusher of the push that GitHub makes when GitHub merges a pull request by a rebase, by auto-merge or from a merge queue, to the account of the author of the merged pull request was not checked", Disposition: lint.Todo(lint.NeedFact)}
	newActivityTypeLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("new-activity-type"), Text: "an activity type GitHub added after the schemas the tables are made from, written in types: a value of types the tables do not have is dropped, as GitHub drops one it has no such activity type for", Disposition: lint.Todo(lint.NeedPinUpdate)}
	outsideCallerLimit   = lint.UndetectedForm{ID: lint.MustUndetectedFormID("outside-caller"), Text: "a reusable workflow or composite action that callers in the repository decide, called from another repository on an event, or with a value, an attacker controls: the caller's run has the caller's token and secrets, not the repository's", Disposition: lint.NoAddedGain()}
	comparedLimit        = lint.UndetectedForm{ID: lint.MustUndetectedFormID("compared"), Text: "a context compared, negated, or given to contains, startsWith, endsWith or hashFiles: what is written out is a bool or a hash", Disposition: lint.NoAddedGain()}
)

// inputDispatch is the inconclusive kind of a value that has an input of
// workflow_dispatch, which whoever dispatches the workflow chooses: of the
// injection rules, and of the label of runs-on and the image that
// self-hosted-runner and unpinned-images read.
var inputDispatch = inconclusiveKind(analysis.InconclusiveRefInputDispatch)

// dispatcherChooses is why an input of workflow_dispatch is the
// inconclusive kind input-dispatch (limitation, decided by dispatcher), for
// the texts of the kind in the rules that have it.
const dispatcherChooses = "whoever dispatches the workflow chooses the value of the input. A credential whose only write access is to the permission Actions can dispatch the workflow, and the credential premise keeps the holder of such a credential as a possible attacker; the linter does not know whether such a credential exists or who holds it. The rule reports the value in a job with an environment that has required reviewers too, where a required reviewer of the environment can stop the run"

// valueGaps are the inconclusive kinds of a value a rule reads:
// what an attacker may control of it is not analyzed.
var valueGaps = []lint.InconclusiveKind{
	{ID: inconclusiveKind(analysis.InconclusiveRefStepRun), Text: "the output of a step that runs a script (steps.<id>.outputs), which the script writes to $GITHUB_OUTPUT", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: inconclusiveKind(analysis.InconclusiveRefStepLocalAction), Text: "the output of a step that uses a local action (./, in the workspace of the job, which is the repository that the job checks out; $/, the repository of the action)", Disposition: lint.Todo(lint.NeedRepoFile)},
	{ID: inconclusiveKind(analysis.InconclusiveRefStepRemoteAction), Text: "the output of a step that uses an action of another repository", Disposition: lint.Todo(lint.NeedFact)},
	{ID: inconclusiveKind(analysis.InconclusiveRefStepDocker), Text: "the output of a step that runs a Docker image (docker://), which the image writes at run time", Disposition: lint.Limitation(lint.DeciderRunTime)},
	{ID: inconclusiveKind(analysis.InconclusiveRefJob), Text: "the output of another job of the workflow (needs.<id>.outputs)", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: inconclusiveKind(analysis.InconclusiveRefJobLocalCall), Text: "the output of a job that calls a reusable workflow of the same repository", Disposition: lint.Todo(lint.NeedRepoFile)},
	{ID: inconclusiveKind(analysis.InconclusiveRefJobRemoteCall), Text: "the output of a job that calls a reusable workflow of another repository", Disposition: lint.Todo(lint.NeedFact)},
	{ID: inputDispatch, Text: "an input of workflow_dispatch (inputs, github.event.inputs): " + dispatcherChooses, Disposition: lint.Limitation(lint.DeciderDispatcher)},
	{ID: inconclusiveKind(analysis.InconclusiveRefInputCall), Text: "an input of a reusable workflow or a composite action (inputs), which the caller gives", Disposition: lint.Todo(lint.NeedRepoFile, lint.NeedFact)},
	{ID: inconclusiveKind(analysis.InconclusiveRefMatrix), Text: "a value of a matrix that is not written out in the workflow", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: inconclusiveKind(analysis.InconclusiveRefEnvUnset), Text: "an env the workflow does not set, which a step before may set at run time ($GITHUB_ENV)", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedFact)},
	{ID: inconclusiveKind(analysis.InconclusiveRefEnvDynamic), Text: "a variable of the env of the workflow, a job or a step, where the whole env of the workflow, the job or the step is one ${{ }}", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: inconclusiveKind(analysis.InconclusiveRefEnvWhole), Text: "the whole env (toJSON(env)), or an env whose name is not known, which has what steps set at run time", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedFact)},
}

var (
	observedDelimiter = lint.MustDate("2026-09-25")
	observedFileCmd   = lint.MustDate("2026-09-27")

	workflowCommands = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#multiline-strings")
	bashStartup      = lint.MustCitation("https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html")
	ghsl2024173      = lint.MustCitation("https://securitylab.github.com/advisories/GHSL-2024-173_Feign/")
	ghsl2026229      = lint.MustCitation("https://securitylab.github.com/advisories/GHSL-2026-229_ipdxco_unified-github-workflows/")
	ghsl2026208      = lint.MustCitation("https://securitylab.github.com/advisories/GHSL-2026-208_kptdev_kpt_repository/")

	runnerReadsLines    = lint.MustPreconditionID("runner-reads-lines")
	attackerWritesLines = lint.MustPreconditionID("attacker-writes-lines")
	bashEnv             = lint.MustPreconditionID("bash-env")
	wikiTitleLines      = lint.MustPreconditionID("wiki-title-lines")

	wikiTitleLinesPre = lint.Precondition{
		ID:   wikiTitleLines,
		Text: "the title of a wiki page holds a line break: inferred, not seen; the title comes from the name of the page's file or a field of one line, and only the titles of issues and pull requests were seen to keep one",
		Observed: []lint.Observation{
			{Date: observedInjection, Runner: runner, What: "a wiki page's title with $( ) and backticks came into github.event.pages[0].title as it was written; a line break in it was not tried"},
		},
	}

	runnerReadsLinesPre = lint.Precondition{
		ID:   runnerReadsLines,
		Text: "the runner reads $GITHUB_ENV and $GITHUB_OUTPUT after the step by lines split at \\n alone; a line whose first = comes before any << is name=value, and name<<DELIM takes the lines up to the first that is DELIM",
		Observed: []lint.Observation{
			{Date: observedDelimiter, Runner: runner, What: "a value ending in a line break and approved=true, written to $GITHUB_OUTPUT or $GITHUB_ENV as name=value or in name<<EOF_SISAKULINT, set approved; with x<<EOF_SISAKULINT after it the step still succeeded"},
			{Date: observedFileCmd, Runner: runner, What: "the same value with its line breaks taken out by tr -d set no other name; written in name<<DELIM whose delimiter was ghadelimiter_ and 16 random bytes, it set none either, on ubuntu, macos and windows"},
		},
		Cites: []lint.Citation{workflowCommands},
	}
	attackerWritesLinesPre = lint.Precondition{
		ID:   attackerWritesLines,
		Text: "the value is one an attacker writes with line breaks: a title, a body, a comment, a commit message, and what else the table of contexts says an attacker writes freely; not a branch name, a SHA or a URL GitHub makes",
		Observed: []lint.Observation{
			{Date: observedFileCmd, What: "GitHub kept a line break in the title of an issue and of a pull request sent through the API"},
		},
	}
	bashEnvPre = lint.Precondition{
		ID:   bashEnv,
		Text: "a variable set in $GITHUB_ENV is in the environment of the steps after it, NODE_OPTIONS alone refused; BASH_ENV there makes the bash of each run after it expand the value, $( ) included, before the script",
		Observed: []lint.Observation{
			{Date: observedFileCmd, Runner: runner, What: "BASH_ENV=$( ... ) after a line break of a value written to $GITHUB_ENV ran its command in the bash of the next step"},
		},
		Cites: []lint.Citation{workflowCommands, bashStartup},
	}
)

// wikiOf is the CVSS base b for a finding on gollum alone: the attacker
// gets there by an edit of the wiki; what the value does (VC to SA) is
// that of b. text is what in the title of the page is all it takes.
func wikiOf(b lint.CVSS, text string) lint.CVSS {
	b.AV = metric(lint.AttackVectorNetwork, "the attacker edits a page of the wiki over the network")
	b.AC = metric(lint.AttackComplexityLow, text+" in the title of the page are all it takes")
	b.AT = metric(lint.AttackRequirementsNone, "where anyone may edit the wiki, on which the finding holds (repo.wiki-open), nothing more is needed")
	b.PR = metric(lint.PrivilegesRequiredNone, "nothing of the repository is needed where anyone may edit the wiki")
	b.UI = metric(lint.UserInteractionNone, "an edit of the wiki triggers the workflow with nobody doing anything")
	return b
}

// fileEnvBase is the CVSS of envvar-injection.controlled: the attacker's
// code runs in the bash of the steps after (bash-env), so what it does in
// the job is that of code-injection.
var fileEnvBase = func() lint.CVSS {
	b := controlledBase
	b.AC = metric(lint.AttackComplexityLow, "a line break and BASH_ENV=$( ... ) in the text are all it takes")
	return b
}()

// fileOutputBase is the CVSS of output-clobbering.controlled: the attacker
// sets outputs of the step; what reads them decides the harm, which is not
// counted here.
var fileOutputBase = lint.CVSS{
	AV: controlledBase.AV, AC: metric(lint.AttackComplexityLow, "a line break and name=value in the text are all it takes"),
	AT: controlledBase.AT, PR: controlledBase.PR, UI: controlledBase.UI,
	VC: metric(lint.ImpactNone, "the attacker reads nothing of the job by this"),
	VI: metric(lint.ImpactHigh, "the outputs of the step are what the attacker writes, and the steps and jobs after it take them as the step's"),
	VA: metric(lint.ImpactLow, "a line of neither = nor << fails the step"),
	SC: metric(lint.ImpactNone, "nothing past the job is read by this as such"),
	SI: metric(lint.ImpactNone, "what reads the outputs decides what goes past the job; that is not counted here"),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

var (
	scriptVarLimit   = lint.UndetectedForm{ID: lint.MustUndetectedFormID("script-var"), Text: "a shell variable no env of the workflow sets: one the script sets (from a file, an artifact, an API), a positional parameter of a function the script calls with the value, or the runner", Disposition: lint.Todo(lint.NeedSameFile)}
	nestedShellLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("nested-shell"), Text: "what another shell or program the script starts writes to the environment file, from its code (eval; bash -c and sh -c whose code is not one word in single quotes, or whose code reads the arguments after it as $1 and the like, or whose -c comes after an option of the shell the rule does not read, or whose code reads a variable the script assigns before the command (T=\"pre-$T\"; bash -c '...'): one word in single quotes is read as a script of its own) or from the environment it reads itself (python -c and the like)", Disposition: lint.Todo(lint.NeedSameFile)}
	wrappedTeeLimit  = lint.UndetectedForm{ID: lint.MustUndetectedFormID("wrapped-tee"), Text: "tee run through another command or by its path (sudo tee, command tee, /usr/bin/tee): the rule reads tee by its name alone", Disposition: lint.Todo(lint.NeedSameFile)}
	otherShellLimit  = lint.UndetectedForm{ID: lint.MustUndetectedFormID("other-shell"), Text: "a run of pwsh, cmd or python, and a run whose shell the rule cannot determine to be bash or sh: a shell: value whose command is not bash or sh, such as pwsh -File {0}; a shell: value of bash or sh with an option that the rule does not read, such as bash -c 'make' {0}, bash -v {0} or bash -O extglob {0}; a shell: value that names bash or sh by a path, such as /usr/bin/bash -e {0}, on a runner where the rule does not know that the path exists (any runner other than one whose runs-on is a single label that starts with ubuntu-, or with macos- for /bin/bash and /bin/sh) or in a step of a composite action; a shell: that is an expression; or a step without shell: whose job and workflow have no defaults.run.shell and whose job has a runs-on that is not a single label that starts with ubuntu-, macos- or windows-, such as self-hosted or an expression: the rule reads the runs of bash and sh only", Disposition: lint.Todo(lint.NeedSameFile)}
)

// injectionFalsePositives are the false positive forms the injection rules
// share, of the rule's kinds controlled and wiki.
func injectionFalsePositives(controlled, wiki lint.FindingKindID) []lint.FalsePositiveForm {
	return []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("wiki-closed"), Text: "gollum in a repository whose wiki is off or that only collaborators may edit", FindingKinds: []lint.FindingKindID{wiki}, FactKinds: []facts.Kind{facts.KindRepoWikiOpen}},
		writerString(controlled),
		ifUnnarrowedFalsePositive(controlled),
		forkFlagReview(controlled),
	}
}

// writerString is the false positive of a string that only those who can
// write to the repository, or moderate or administer its organization, set,
// but that the webhook schema leaves free: the table reads it as arbitrary.
func writerString(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("writer-string"), Text: "a string only those who can write to the repository, or moderate or administer its organization, set, which the webhook schema leaves free and the table reads as arbitrary, such as the name of a label (https://docs.github.com/en/issues/using-labels-and-milestones-to-track-work/managing-labels), the reason a comment is hidden (https://docs.github.com/en/communities/moderating-comments-and-conversations/managing-disruptive-comments), the name of an issue field or of its option (https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/managing-issue-fields-in-your-organization)", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// forkFlagReview is the false positive of a job on the review events that
// runs only when the head repository of the pull request is a fork: the
// attacker run table counts a review of a pull request from a branch of
// the repository, whose head repository is the repository itself, and
// does not know whether the repository is a fork.
func forkFlagReview(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("fork-flag-review"), Text: "a job on pull_request_review or pull_request_review_comment whose if: condition lets the job run only when the head repository of the pull request is a fork, such as a job whose if: condition is github.event.pull_request.head.repo.fork: on a pull request from a branch of the repository, the head repository is the repository itself, so in a repository that is not a fork the job runs only for a review of a pull request from a fork. The run of a review of a pull request from a fork has the secrets of the repository or a token that writes only where a private repository gives secrets or a token that writes to the runs of pull requests from forks (the undetected form fork-review). The rule does not read whether the repository that runs the workflow (not the head repository of the pull request) is a fork, and reports the job as if the job ran for a review of a pull request from a branch of the repository", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedFact)}
}

// ifUnnarrowedFalsePositive is the false positive of a value that an if
// compares with plain strings where the reading of the if (attacker.Narrowing)
// does not reach, of kinds.
func ifUnnarrowedFalsePositive(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("if-unnarrowed"), Text: "a value that an if compares with strings that the workflow writes in the if (strings compared by == with the value and joined by ||, or the strings of contains(fromJSON('[...]'), value)), where each string has only ASCII letters, digits, spaces, -, _, . and /, does not start with -, and has no - right after a space, where the rule reports the value although the if limits the value to those strings, because the rule does not read the if in one of three forms. (1) A reusable workflow or a composite action gets the value through an input, and the if of the calling job or the calling step compares the value. The rule reports the value in the file of the reusable workflow or the composite action. The value is harmless when the if of every caller of that file, inside and outside the repository, compares the value. (2) The if compares the value under one name, and the script writes the value under another name: for example, the if compares env.BODY, which the env of the step sets to ${{ github.event.comment.body }}, and the script writes ${{ github.event.comment.body }}; or the if compares ${{ github.head_ref }}, and the script writes ${{ github.event.pull_request.head.ref }}. The value is harmless when the two names hold the same value in the step; the rule does not check that the two names hold the same value. (3) The if of a step that uses an action compares a value that the with or the env of the same step holds. At the start of the job, the runner runs the pre step of each action from another repository whose action.yml has runs.pre, under the condition runs.pre-if of that action.yml and not under the if of the step. For the pre step, the runner evaluates the with and the env of the step, and the code of the pre step may read the inputs. The runner runs no pre step of a local action (./). The value is harmless when the action has no pre step, or when the code of the pre step does not read the value. In each form, the value is harmless only where the case of the letters does not change what the value names (the undetected form if-compared)", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// ifComparedLimit is a value that an if narrows to strings of letters,
// digits and a few marks (attacker.Narrowing): the attacker still chooses
// the case of its letters.
var ifComparedLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("if-compared"), Text: "a value that an if compares with strings that the workflow writes in the if (strings compared by == with the value and joined by ||, or the strings of contains(fromJSON('[...]'), value)), where each string has only ASCII letters, digits, spaces, -, _, . and /, does not start with -, and has no - right after a space. The if of the job limits the value in every step of the job, and the if of a step with a run: script limits the value in that step only. In those steps the value equals one of the strings when the case of the letters is ignored, so the rule does not report the value. The attacker still chooses the case of each letter of the value. GitHub's server, which evaluates the if of a job, also takes the Kelvin sign as equal to the letter k and the long s as equal to the letter s; the runner, which evaluates the if of a step, takes the Kelvin sign as equal to the letter k. Where the case of a letter changes what the value names, such as a command, a variable, a file on a file system that tells names apart by their case (the default file system of a Linux runner), a host or a tool, the choice of the case can cause harm", Disposition: lint.Todo(lint.NeedSameFile)}

// caseArmLimit is a write to a file command inside an arm of a case,
// which the shell parser does not read.
var caseArmLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("case-arm"), Text: "a write to the environment file, or an exec (the builtin of the shell) that opens the environment file, inside an arm of a case statement of the shell: the rule finds the case statement and does not read the commands in the arms of the case statement", Disposition: lint.Todo(lint.NeedSameFile)}

// fileCommandFalsePositives are the false positive forms envvar-injection
// and output-clobbering share, of the rule's kind controlled: a way of
// taking out line breaks or a delimiter the rule does not read, and the
// reads of the shell that are wider than what bash runs.
func fileCommandFalsePositives(controlled lint.FindingKindID) []lint.FalsePositiveForm {
	return []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("tr-in-substitution"), Text: "a ${{ }} written in a $( ) whose tr takes out the line breaks: the whole substitution is read as the attacker's value", FindingKinds: []lint.FindingKindID{controlled}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("own-random-delimiter"), Text: "a heredoc delimiter the author made random, such as D=$(uuidgen): the rule reads only its own fix's form as random", FindingKinds: []lint.FindingKindID{controlled}, Disposition: lint.Todo(lint.NeedSameFile)},
		branchNotRun(controlled),
	}
}

// fileContentLimit is the content of a file that the script copies into
// the file command file (such as $GITHUB_ENV) as it is: the bytes that an
// artifact or a download brings, which the rule does not follow.
func fileContentLimit(file string) lint.UndetectedForm {
	return lint.UndetectedForm{ID: lint.MustUndetectedFormID("file-content"), Text: "the content of a file that a command of the script writes into " + file + " by printing the file, not through a shell variable (cat values.txt >> " + file + ", tee -a " + file + " < values.txt, or the content passed through sed or tr between the file and " + file + "), such as a file of an artifact that was uploaded by a run that an attacker started: the rule reads the text of the script, and does not follow where the file comes from (the step that downloads the file)", Disposition: lint.Todo(lint.NeedSameFile)}
}

// lastpipeLimit is an assignment or an exec in the last command of a
// pipeline after a shopt -s lastpipe whose option name is not literal: the
// shell walk does not read the option's value.
var lastpipeLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("lastpipe-not-literal"), Text: "an assignment or an exec in the last command of a pipeline after a shopt -s lastpipe whose option name the script does not write as a literal word (shopt -s \"$o\"): bash runs the last command of the pipeline in the shell that runs the pipeline, so the assignment or the exec stays after the pipeline, and the rule reads the last command as a command in a subshell", Disposition: lint.Todo(lint.NeedSameFile)}

// callAfterExecLimit is a write by a function the script defines before an
// exec that points the standard output to the environment file and calls
// after the exec: the rule reads the commands after the exec by their
// place in the script, and the body is before the exec there.
var callAfterExecLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("call-after-exec"), Text: "a write by a function that the script defines before an exec that points the standard output to $GITHUB_ENV, and that the script calls after the exec (f() { echo \"V=$V\"; }; exec >>\"$GITHUB_ENV\"; f): bash writes what the body of the function prints to $GITHUB_ENV; the rule reads the commands that run after the exec by the place of each command in the text of the script, and does not read the body of the function, which comes before the exec in the text, as a command that runs after the exec", Disposition: lint.Todo(lint.NeedSameFile)}

// nameNotLiteralLimit is an assignment whose variable name is not literal,
// which the shell walk does not follow.
var nameNotLiteralLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("name-not-literal"), Text: "an assignment whose variable name the script does not write as a literal word (n=key; declare \"$n=$X\"; or read -r \"$n\"): bash assigns the word after = (with declare) or the line that read reads (with read) to the variable whose name is the value of n, and the rule does not read the assignment", Disposition: lint.Todo(lint.NeedSameFile)}

// recursiveUnsetLocalLimit is a variable a function unsets in a recursive
// call deeper than the shell walk reads in place, where a calling function
// made the variable local: the walk reads that call without the calls in
// between, and misses the value the unset reveals.
var recursiveUnsetLocalLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("recursive-unset-local"), Text: "a variable that a shell function unsets inside a recursive call of a function, where a function between the two calls made the variable local (f() { if [ -z \"$inner\" ]; then inner=1; h; else g; fi; }; h() { s=x; local s=y; f; }; g() { unset s; }): bash takes away the local of the nearest calling function that made the variable local, and the variable then holds the value from before the nearest calling function made the variable local; the rule reads the recursive call where the first call of the function runs, without the calls in between, and does not read the value that the unset reveals", Disposition: lint.Todo(lint.NeedSameFile)}

// unsetCallerLocalLimit is an unset that takes away the local of a calling
// function, followed by an assignment or a second unset.
var unsetCallerLocalLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("unset-caller-local"), Text: "a variable that a shell function unsets after a calling function made the variable local, when an assignment to the variable or a second unset of the variable follows the unset (s=x; reset() { unset s; }; point() { local s=y; reset; s=z; }; point): bash takes away the local of the calling function, so that the assignment after the unset sets the variable outside the calling function, and a second unset takes away the local of the next calling function or unsets the variable outside the functions; the rule keeps the local of the calling function after the unset, gives the variable back the value from before the calling function made the variable local when the calling function returns, and reads the second unset as the first unset", Disposition: lint.Todo(lint.NeedSameFile)}

// severalDestinationsLimit is a destination variable that more than one
// assignment reaches: the rule reads the last one in the script.
var severalDestinationsLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("several-destination-values"), Text: "a request whose host comes from a variable that more than one assignment of the script may set before the request (if c; then U=https://hooks.example.com; else U=https://api.github.com; fi; curl -H \"x-apikey: $KEY\" \"$U/x\"): the rule reads the host of the request from the assignment that comes last in the text of the script, and does not judge the hosts of the other assignments", Disposition: lint.Todo(lint.NeedSameFile)}

// nameNotLiteralFalsePositive is a variable of env the script sets again
// by an assignment whose variable name is not literal: the rule reads the
// variable as env's value.
func nameNotLiteralFalsePositive(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("name-not-literal"), Text: "a variable of the env of the step that the script sets again by an assignment whose variable name the script does not write as a literal word (n=TITLE; declare \"$n=echo safe\"): bash assigns the word after = to the variable whose name is the value of n, so after the assignment the variable of the env holds the word that the script assigns, and the rule still reads the variable as holding the value of the env of the step", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// reassignedEnvFalsePositive is a variable of env the script sets again,
// in the shell that writes the variable to the environment file file, before
// the write: the rule reads the variable as env's value. example is a script
// of the form that writes to file.
func reassignedEnvFalsePositive(file, example string, kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("reassigned-variable"), Text: "a variable of env that the script sets again, before the script writes the variable to " + file + ", by an assignment that bash runs each time the script reaches the write, in the same shell as the write (not in a subshell, a $( ) or a command of a pipeline, not before a command name, and not as local in a shell function), and whose value holds nothing of the variable of env (" + example + "): at the write the variable holds the value of the assignment, and the rule still reads the variable as holding the value of env", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// backgroundWriteFalsePositive is a write to the environment file file by a
// command the script runs in the background with no wait, which writes after
// the shell of the script ends: the write does not reach the steps after the
// step, and the rule reads the write as one that reaches them. example is a
// script of the form that writes to file.
func backgroundWriteFalsePositive(file, example string, kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("background-write"), Text: "a write to " + file + " by a command that the script runs in the background (&) with no wait for the command, where the command writes after the shell of the script ends (for example: " + example + "): a write that the command makes after the shell of the script ends does not reach the steps after the step; the rule reads the write as a write that reaches " + file + ", because whether the command writes before the shell of the script ends depends on how long the commands take when the step runs", FindingKinds: kinds, Disposition: lint.Limitation(lint.DeciderRunTime)}
}

// lastpipeFalsePositive is a variable of env the script sets again in the
// last command of a pipeline after a lastpipe whose option name is not
// literal: the rule reads the variable as env's value.
func lastpipeFalsePositive(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("lastpipe-not-literal"), Text: "a variable of the env of the step that the script sets again in the last command of a pipeline after a shopt -s lastpipe whose option name the script does not write as a literal word (shopt -s \"$o\"): bash runs the last command of the pipeline in the shell that runs the pipeline, so after the pipeline the variable holds the value that the script sets, and the rule reads the variable as holding the value of the env", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// branchNotRun is an assignment in a branch bash does not run, which the
// rule reads as one that may run.
func branchNotRun(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("branch-not-run"), Text: "an assignment in a branch of if, after && or ||, in the body of a loop, or in the body of a function called there, that bash does not run (if false; then s=$KEY; fi): the rule does not read the value of a condition, so the rule reads the assignment as one that may run, and reads the variable as one that may hold the value of the assignment", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// fileLimits are the forms the two rules of $GITHUB_ENV and $GITHUB_OUTPUT
// do not report, but the file the other rule reads.
var fileLimits = []lint.UndetectedForm{
	pullRequestLimit, dispatchLimit, repositoryDispatchLimit, appWrittenLimit, deploymentStatusLimit, dispatchRelayLimit, dispatchInputCallLimit, notAttackerLimit, mergedPusherLimit, comparedLimit, newActivityTypeLimit, outsideCallerLimit,
	{ID: lint.MustUndetectedFormID("no-line-break"), Text: "a context that cannot hold a line break, written after the = of a line or in the body of name<<DELIM: a SHA, a number, a date, the name of an account, a repository or a branch, the description of a fork (github.event.forkee.description), a URL (before the =, any value an attacker controls is reported)", Disposition: lint.NoAddedGain()},
	{ID: lint.MustUndetectedFormID("line-free"), Text: "a value written through $( ) whose pipeline starts with echo or printf '%s' of it and ends with tr -d with \\n in the set, or tr turning \\n into another byte", Disposition: lint.NoAddedGain()},
	{ID: lint.MustUndetectedFormID("random-delimiter"), Text: "the body of name<<DELIM whose delimiter is $GHA_DELIM, set before it to ghadelimiter_ and 16 random bytes in hex as the fix writes it", Disposition: lint.NoAddedGain()},
	scriptVarLimit,
	nestedShellLimit,
	lastpipeLimit,
	nameNotLiteralLimit,
	recursiveUnsetLocalLimit,
	unsetCallerLocalLimit,
	wrappedTeeLimit,
	ifComparedLimit,
	otherShellLimit,
	{ID: lint.MustUndetectedFormID("github-script"), Text: "core.exportVariable and core.setOutput of actions/github-script: @actions/core writes a random delimiter, and refuses a value that has it", Disposition: lint.NoAddedGain()},
	{ID: lint.MustUndetectedFormID("other-file"), Text: "a value written to the file $GITHUB_STATE, which the post step of a JavaScript action reads", Disposition: lint.NoAddedGain()},
	{ID: lint.MustUndetectedFormID("github-path"), Text: "a value written to $GITHUB_PATH", Disposition: lint.OtherRule(EnvpathInjectionID)},
	caseArmLimit,
}

// writeGaps are the inconclusive kinds of a write to a file
// command.
var writeGaps = []lint.InconclusiveKind{
	{ID: inconclusiveKind(analysis.InconclusiveWriteWriterUnknown), Text: "what a command other than echo, printf and cat writes to the environment file, with what an attacker may control in the arguments of the command or in what a pipe gives the command; and also what the echo of dash writes of a value, what printf writes of a value split into more arguments, a write inside a case statement of the shell, and a write to the environment file that the script names in a way the rule does not read", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: inconclusiveKind(analysis.InconclusiveWriteSubstValue), Text: "a $( ), ` ` or $(( )), or ${ } with an operator, written to the environment file with what an attacker may control in it, whose line breaks are not known to be taken out", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: inconclusiveKind(analysis.InconclusiveWriteExecRedirect), Text: "what the script writes after exec sends its output to the environment file", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: inconclusiveKind(analysis.InconclusiveWriteAfterStop), Text: "what the script writes to the environment file after the point where the rule stops following the script", Disposition: lint.Todo(lint.NeedSameFile)},
}

// fileGaps are the inconclusive kinds of the two rules of file
// commands.
var fileGaps = append(slices.Clone(valueGaps), writeGaps...)

// fileKinds are the kinds of findings of a rule of file commands, of
// controlled and of wiki, and the precondition that is its own, if any.
func fileKinds(controlled, wiki lint.FindingText, base lint.CVSS, exploited lint.Metric[lint.ExploitMaturity], own ...lint.PreconditionID) []lint.FindingKind {
	pre := append([]lint.PreconditionID{runnerReadsLines, attackerWritesLines, attackerEvent, callersEvents, appStatusCheck}, own...)
	wpre := append([]lint.PreconditionID{runnerReadsLines, wikiTitleLines, attackerEvent, callersEvents, wikiOpen}, own...)
	return []lint.FindingKind{
		{
			FindingText:     controlled,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerMergedCommitAuthor, lint.AttackerAnyoneWhoForks},
			Preconditions:   pre,
			Fixes:           []lint.FixKindID{EnvVarReviewID},
			CVSS:            base,
			ExploitMaturity: exploited,
		},
		{
			FindingText:     wiki,
			Attackers:       []lint.Attacker{lint.AttackerWikiEditor},
			Preconditions:   wpre,
			Fixes:           []lint.FixKindID{EnvVarReviewID},
			FactKinds:       []facts.Kind{facts.KindRepoWikiOpen},
			CVSS:            wikiOf(base, "a line break"),
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of an attack through the title of a wiki page"),
		},
	}
}

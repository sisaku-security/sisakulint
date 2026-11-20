package boundary

import (
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// docsCommit is the commit of github/docs the quotes are of.
const docsCommit = "7b807926df3ccb7f3d1bcd4ad1c652fb42b0931d"

var retrieved = lint.MustDate("2026-10-08")

// source is the text of path of the repository repo on GitHub at commit,
// word for word, retrieved on d.
func source(repo, commit, path, text string, d lint.Date) Quote {
	return Quote{Citation: lint.MustCitation("https://github.com/" + repo + "/blob/" + commit + "/" + path), Text: text, Retrieved: d}
}

// doc is the text of path of github/docs at docsCommit, word for word.
func doc(path, text string) Quote { return source("github/docs", docsCommit, path, text, retrieved) }

// is holds when the fact q of the repository of the inputs is v.
func is(q facts.Query, v bool) lint.Condition {
	c, err := lint.FactEq(q, v)
	if err != nil {
		panic("boundary: " + err.Error())
	}
	return c
}

const (
	eventsDoc   = "content/actions/reference/workflows-and-actions/events-that-trigger-workflows.md"
	privateDoc  = "data/reusables/actions/private-repository-forks-options.md"
	prTargetDoc = "content/actions/reference/security/securely-using-pull_request_target.md"
	jobsDoc     = "data/reusables/actions/jobs/section-assigning-permissions-to-jobs.md"
	cachingDoc  = "content/actions/reference/workflows-and-actions/dependency-caching.md"
)

// The quotes of the grants.
var (
	forkedSecrets = doc("data/reusables/actions/forked-secrets.md",
		"With the exception of `GITHUB_TOKEN`, secrets are not passed to the runner when a workflow is triggered from a forked repository.")
	forkReadOnly = doc("data/reusables/developer-site/pull_request_forked_repos_link.md",
		"The `GITHUB_TOKEN` has read-only permissions in pull requests from forked repositories.")
	writeToRead = doc("content/actions/reference/workflows-and-actions/workflow-syntax.md",
		"Finally, if the workflow was triggered by a pull request event other than `pull_request_target` from a forked repository, and the **Send write tokens to workflows from pull requests** setting is not selected, the permissions are adjusted to change any write permissions to read only.")
	permissionsAsk = doc(jobsDoc,
		"You can use `permissions` to modify the default permissions granted to the `GITHUB_TOKEN`, adding or removing access as required")
	prTargetSecrets = doc(prTargetDoc,
		"the job receives the base repository's `GITHUB_TOKEN` and access to repository and organization secrets.")
	prTargetWrite = doc(jobsDoc,
		"the `GITHUB_TOKEN` is granted read/write repository permission, even when it is triggered from a public fork.")
	reviewReadOnly = doc(prTargetDoc,
		"restricts these events to a read-only `GITHUB_TOKEN`, withholds access to other secrets")
	workflowRunWrite = doc(eventsDoc,
		"The workflow started by the `workflow_run` event is able to access secrets and write tokens, even if the previous workflow was not.")
	branchWithin = doc("content/actions/concepts/security/compromised-runners.md",
		"However, these permissions differ for various event triggers such as `issue_comment`, `issues`, `push` and `pull_request` from a branch within the repository, where the attacker could attempt to steal repository secrets or use the write permission of the job's")
	privateRun = doc(privateDoc,
		"* **Run workflows from fork pull requests** - Allows users to run workflows from fork pull requests, using a `GITHUB_TOKEN` with read-only permission, and with no access to secrets.")
	privateWrite = doc(privateDoc,
		"* **Send write tokens to workflows from pull requests** - Allows pull requests from forks to use a `GITHUB_TOKEN` with write permission.")
	privateSecrets = doc(privateDoc,
		"* **Send secrets to workflows from pull requests** - Makes all secrets available to the pull request.")
	scheduleDefault = doc(eventsDoc, "Scheduled workflows will only run on the default branch.")
	cacheAsk        = doc(cachingDoc,
		"A job or workflow that explicitly declares `cache-mode: write` or `cache-mode: write-only` overrides the secure read-only default that would otherwise apply to a run triggered by a low-trust event.")
	cacheTriggers = doc(cachingDoc,
		"To reduce this risk, only these workflow triggers can create or overwrite caches in the default branch’s scope:")
	cacheMergeRef = doc(cachingDoc,
		"When a cache is created by a workflow run triggered on a pull request, the cache is created for the merge ref (`refs/pull/.../merge`).")
)

// The observations of 2026-10-13, in a private
// repository, of jobs that saved a cache with cache-mode written and not.
var (
	observedE3       = lint.MustDate("2026-10-13")
	sawCachePRTarget = lint.Observation{Date: observedE3, Runner: runner2337, What: "a run of pull_request_target of a pull request from a branch of the repository saved a cache to the default branch's scope from a job with cache-mode: write, and not from one without it"}
	sawCacheRun      = lint.Observation{Date: observedE3, Runner: runner2337, What: "a run of workflow_run after a pull_request run saved a cache to the default branch's scope from a job with cache-mode: write, and not from one without it"}
	sawCacheComment  = lint.Observation{Date: observedE3, Runner: runner2337, What: "a run of issue_comment saved a cache to the default branch's scope from a job with cache-mode: write, and not from one without it"}
	sawCachePR       = lint.Observation{Date: observedE3, Runner: runner2337, What: "a run of pull_request saved its caches, with cache-mode: write too, to refs/pull/<n>/merge only"}
)

// eventRow is, of an event, what events-that-trigger-workflows says of the
// commit it runs (GITHUB_SHA and GITHUB_REF): a commit of the repository,
// not of a fork (the default branch, the ref pushed, created or dispatched,
// the merge group, the commit deployed, the release, the package).
var eventRow = map[workflow.EventName]Quote{
	workflow.EventNameDiscussion:           doc(eventsDoc, "| [`discussion`](/webhooks/webhook-events-and-payloads#discussion) | - `created`<br/>- `edited`<br/>- `deleted`<br/>- `transferred`<br/>- `pinned`<br/>- `unpinned`<br/>- `labeled`<br/>- `unlabeled`<br/>- `locked`<br/>- `unlocked`<br/>- `category_changed`<br/> - `answered`<br/> - `unanswered` | Last commit on default branch | Default branch |"),
	workflow.EventNameDiscussionComment:    doc(eventsDoc, "| [`discussion_comment`](/webhooks/webhook-events-and-payloads#discussion_comment) | - `created`<br/>- `edited`<br/>- `deleted`<br/> | Last commit on default branch | Default branch |"),
	workflow.EventNameFork:                 doc(eventsDoc, "| [`fork`](/webhooks/webhook-events-and-payloads#fork) | Not applicable | Last commit on default branch |  Default branch |"),
	workflow.EventNameGollum:               doc(eventsDoc, "| [`gollum`](/webhooks/webhook-events-and-payloads#gollum) | Not applicable | Last commit on default branch |  Default branch |"),
	workflow.EventNameIssueComment:         doc(eventsDoc, "| [`issue_comment`](/webhooks/webhook-events-and-payloads#issue_comment) | - `created`<br/>- `edited`<br/>- `deleted`<br/> | Last commit on default branch | Default branch |"),
	workflow.EventNameIssues:               doc(eventsDoc, "- `typed`<br/> - `untyped`{% ifversion issue-fields %}<br/> - `field_added`<br/> - `field_removed`{% endif %} | Last commit on default branch | Default branch |"),
	workflow.EventNameSchedule:             doc(eventsDoc, "| Not applicable | Not applicable | Last commit on default branch | Default branch |"),
	workflow.EventNameWorkflowRun:          doc(eventsDoc, "| [`workflow_run`](/webhooks/webhook-events-and-payloads#workflow_run) | - `completed`<br/>- `requested`<br/>- `in_progress` | Last commit on default branch | Default branch |"),
	workflow.EventNameWorkflowDispatch:     doc(eventsDoc, "| [workflow_dispatch](/webhooks/webhook-events-and-payloads#workflow_dispatch) | Not applicable | Last commit on the `GITHUB_REF` branch or tag | Branch or tag that received dispatch |"),
	workflow.EventNameMergeGroup:           doc(eventsDoc, "| [`merge_group`](/webhooks/webhook-events-and-payloads#merge_group) | `checks_requested` | SHA of the merge group | Ref of the merge group |"),
	workflow.EventNamePush:                 doc(eventsDoc, "This includes workflows that are not merged into the default branch."),
	workflow.EventNameBranchProtectionRule: doc(eventsDoc, "| [`branch_protection_rule`](/webhooks/webhook-events-and-payloads#branch_protection_rule) | - `created`<br/>- `edited`<br/>- `deleted` | Last commit on default branch | Default branch |"),
	workflow.EventNameCheckRun:             doc(eventsDoc, "| [`check_run`](/webhooks/webhook-events-and-payloads#check_run) | - `created`<br/>- `rerequested`<br/>- `completed`<br/>- `requested_action` | Last commit on default branch | Default branch |"),
	workflow.EventNameCheckSuite:           doc(eventsDoc, "| [`check_suite`](/webhooks/webhook-events-and-payloads#check_suite) | - `completed` | Last commit on default branch | Default branch |"),
	workflow.EventNameCreate:               doc(eventsDoc, "| [`create`](/webhooks/webhook-events-and-payloads#create) | Not applicable | Last commit on the created branch or tag | Branch or tag created |"),
	workflow.EventNameDelete:               doc(eventsDoc, "| [`delete`](/webhooks/webhook-events-and-payloads#delete) | Not applicable | Last commit on default branch | Default branch |"),
	workflow.EventNameDeployment:           doc(eventsDoc, "| [`deployment`](/webhooks/webhook-events-and-payloads#deployment) | Not applicable | Commit to be deployed | Branch or tag to be deployed (empty if created with a commit SHA)|"),
	workflow.EventNameDeploymentStatus:     doc(eventsDoc, "| [`deployment_status`](/webhooks/webhook-events-and-payloads#deployment_status) | Not applicable | Commit to be deployed | Branch or tag to be deployed (empty if commit)|"),
	workflow.EventNameLabel:                doc(eventsDoc, "| [`label`](/webhooks/webhook-events-and-payloads#label) | - `created`<br/>- `edited`<br/>- `deleted`<br/> | Last commit on default branch | Default branch |"),
	workflow.EventNameMilestone:            doc(eventsDoc, "| [`milestone`](/webhooks/webhook-events-and-payloads#milestone) | - `created`<br/>- `closed`<br/>- `opened`<br/>- `edited`<br/>- `deleted`<br/> | Last commit on default branch | Default branch |"),
	workflow.EventNameRegistryPackage:      doc(eventsDoc, "| [`registry_package`](/webhooks/webhook-events-and-payloads#package) | - `published`<br/>- `updated` | Commit of the published package | Branch or tag of the published package |"),
	workflow.EventNamePageBuild:            doc(eventsDoc, "| [`page_build`](/webhooks/webhook-events-and-payloads#page_build) | Not applicable | Last commit on default branch | Default branch |"),
	workflow.EventNamePublic:               doc(eventsDoc, "| [`public`](/webhooks/webhook-events-and-payloads#public) | Not applicable | Last commit on default branch |  Default branch |"),
	workflow.EventNameRelease:              doc(eventsDoc, "| [`release`](/webhooks/webhook-events-and-payloads#release) | - `published` <br/>- `unpublished` <br/>- `created` <br/>- `edited` <br/>- `deleted` <br/>- `prereleased`<br/> - `released` | Last commit in the tagged release | Tag ref of release `refs/tags/<tag_name>` |"),
	workflow.EventNameRepositoryDispatch:   doc(eventsDoc, "| [repository_dispatch](/webhooks/webhook-events-and-payloads#repository_dispatch) | Custom | Last commit on default branch | Default branch |"),
	workflow.EventNameStatus:               doc(eventsDoc, "| [`status`](/webhooks/webhook-events-and-payloads#status) | Not applicable | Last commit on default branch | Default branch |"),
	workflow.EventNameWatch:                doc(eventsDoc, "| [`watch`](/webhooks/webhook-events-and-payloads#watch) | - `started` | Last commit on default branch | Default branch |"),
	workflow.EventNameWorkflowCall:         doc(eventsDoc, "| Same as the caller workflow | Not applicable | Same as the caller workflow | Same as the caller workflow |"),
}

// The observations of 2026-09-28, in a private repository whose fork
// pull requests run, with a harmless secret, on a pull request from a
// fork.
var (
	observedPRCode = lint.MustDate("2026-09-28")
	runner2337     = lint.MustVersion("2.337.0")
	sawPRTarget    = lint.Observation{Date: observedPRCode, Runner: runner2337, What: "a run of pull_request_target of a pull request from a fork had the repository's secret, and its token, asked for contents: write, created a ref"}
	sawWorkflowRun = lint.Observation{Date: observedPRCode, Runner: runner2337, What: "a run of workflow_run after the pull_request run of a pull request from a fork had the repository's secret, and its token wrote to the repository"}
	sawComment     = lint.Observation{Date: observedPRCode, Runner: runner2337, What: "a run of issue_comment of a comment on a pull request from a fork had the repository's secret, and its token wrote to the repository"}
)

// The observations of 2026-10-08, in a private
// repository with a harmless secret, on a pull request from a fork whose
// workflow asked for contents: write and printed the length of the secret
// and the status of creating a ref.
var (
	observedE1     = lint.MustDate("2026-10-08")
	sawForkRead    = lint.Observation{Date: observedE1, Runner: runner2337, What: "with fork pull requests run and neither write tokens nor secrets sent, the run had no secret and a read token (creating a ref: 403)"}
	sawForkWrite   = lint.Observation{Date: observedE1, Runner: runner2337, What: "with write tokens sent and no secrets, the run had no secret and a write token (creating a ref: 201)"}
	sawForkSecrets = lint.Observation{Date: observedE1, Runner: runner2337, What: "with secrets sent and no write tokens, the run had the secret and a read token (creating a ref: 403)"}
	sawForkNoRun   = lint.Observation{Date: observedE1, Runner: runner2337, What: "with fork pull requests not run, a push to the pull request started no pull_request run"}
)

const (
	unknownInferred      = "no sentence says that this run has the secrets; it is inferred: secrets are withheld only from a run triggered from a fork, and this run is of a commit of the repository"
	unknownPrivateReview = "whether the fork pull request settings of a private repository apply to pull_request_review and pull_request_review_comment is not seen; the rows read them as those of pull_request, as workflow-syntax reads every pull request event but pull_request_target"
	unknownMergeGroup    = "no sentence says what a run of merge_group has; its workflow is that of the merge group, which only those who may merge put in the queue"
	unknownNoRow         = "the GitHub document events-that-trigger-workflows (the page of the events that trigger workflows) has no row of this event, which the workflow schema names; the linter's row of this event reads the token permissions and the secrets of a run of this event as those of a run of a commit of the repository, and no sentence of the GitHub documents says so"
	unknownCalled        = "the row of workflow_call in the GitHub document events-that-trigger-workflows says that the payload, GITHUB_SHA and GITHUB_REF of a called workflow are those of the calling workflow. The token permissions and the secrets of the run of a called workflow are those of the run of the calling workflow. The linter's row of workflow_call reads the token permissions and the secrets as those of a run of a commit of the repository; the rules read the event of the calling workflow through the callers"
)

// noRowEvents are the events of the workflow schema that
// events-that-trigger-workflows does not name (at docsCommit): the rules
// that take every event (artifact-poisoning) need a row of each.
var noRowEvents = []workflow.EventName{workflow.EventNameImageVersion, workflow.EventNameInteractiveComponent, workflow.EventNameMember, workflow.EventNameProject, workflow.EventNameProjectCard, workflow.EventNameProjectColumn, workflow.EventNameDynamic, workflow.EventNamePullRequestComment}

// defaultBranchGrant is a run of a workflow of the repository, not of a
// fork: it has the secrets, and its workflow may ask for a token that
// writes and for a cache it writes.
func defaultBranchGrant(e workflow.EventName, more ...Quote) RunGrant {
	qs := append([]Quote{forkedSecrets, eventRow[e], permissionsAsk, cacheAsk}, more...)
	return RunGrant{Event: e, Head: PRHeadNone, Token: AccessWrite, Cache: AccessWrite, Secrets: SecretsAccessAll, Basis: BasisDocumented, Quotes: qs}
}

// forkPRGrants are the rows of a pull request event e from a fork, which
// runs the workflow of the pull request's merge commit; seenPublic are the
// observations of the row of a public repository, which make that row
// observed.
func forkPRGrants(e workflow.EventName, seenPublic []lint.Observation, quotes ...Quote) []RunGrant {
	public, private := is(facts.RepoPublic{}, true), is(facts.RepoPublic{}, false)
	run, noRun := is(facts.RepoForkPRRunWorkflows{}, true), is(facts.RepoForkPRRunWorkflows{}, false)
	write, noWrite := is(facts.RepoForkPRWriteTokens{}, true), is(facts.RepoForkPRWriteTokens{}, false)
	secrets, noSecrets := is(facts.RepoForkPRSecrets{}, true), is(facts.RepoForkPRSecrets{}, false)
	rows := []RunGrant{
		{Event: e, Head: PRHeadFork, Condition: public, Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisDocumented, Quotes: append(quotes, cacheMergeRef), Observed: seenPublic},
		{Event: e, Head: PRHeadFork, Condition: lint.All(private, noRun), Token: AccessNone, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisObserved, Quotes: []Quote{privateRun, cacheMergeRef}, Observed: []lint.Observation{sawForkNoRun}},
		{Event: e, Head: PRHeadFork, Condition: lint.All(private, run, noWrite, noSecrets), Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisObserved, Quotes: []Quote{privateRun, writeToRead, cacheMergeRef}, Observed: []lint.Observation{sawForkRead}},
		{Event: e, Head: PRHeadFork, Condition: lint.All(private, run, noWrite, secrets), Token: AccessRead, Cache: AccessNone, Secrets: SecretsAccessAll, Basis: BasisObserved, Quotes: []Quote{privateSecrets, writeToRead, cacheMergeRef}, Observed: []lint.Observation{sawForkSecrets}},
		{Event: e, Head: PRHeadFork, Condition: lint.All(private, run, write, noSecrets), Token: AccessWrite, Cache: AccessNone, Secrets: SecretsAccessNone, Basis: BasisObserved, Quotes: []Quote{privateWrite, cacheMergeRef}, Observed: []lint.Observation{sawForkWrite}},
		{Event: e, Head: PRHeadFork, Condition: lint.All(private, run, write, secrets), Token: AccessWrite, Cache: AccessNone, Secrets: SecretsAccessAll, Basis: BasisDocumented, Quotes: []Quote{privateWrite, privateSecrets, cacheMergeRef}},
	}
	if len(seenPublic) > 0 {
		rows[0].Basis = BasisObserved
	}
	if e != workflow.EventNamePullRequest {
		// the experiment ran pull_request alone
		for i := 1; i < len(rows); i++ {
			rows[i].Basis, rows[i].Observed, rows[i].Uncertainty = BasisUnverified, nil, unknownPrivateReview
		}
	}
	return rows
}

// branchPRGrant is a pull request event e from a branch of the
// repository: not from a fork.
func branchPRGrant(e workflow.EventName) RunGrant {
	return RunGrant{Event: e, Head: PRHeadRepository, Token: AccessWrite, Cache: AccessNone, Secrets: SecretsAccessAll, Basis: BasisDocumented, Quotes: []Quote{branchWithin, forkedSecrets, permissionsAsk, cacheMergeRef}}
}

func grantList() []RunGrant {
	var g []RunGrant
	g = append(g, forkPRGrants(workflow.EventNamePullRequest, []lint.Observation{sawForkPRPublic}, forkedSecrets, forkReadOnly)...)
	g = append(g, forkPRGrants(workflow.EventNamePullRequestReview, []lint.Observation{sawForkReviewPub}, forkedSecrets, reviewReadOnly)...)
	g = append(g, forkPRGrants(workflow.EventNamePullRequestReviewComment, nil, forkedSecrets, reviewReadOnly)...)
	pr := branchPRGrant(workflow.EventNamePullRequest)
	pr.Observed = []lint.Observation{sawCachePR}
	g = append(g, pr)
	for _, e := range []workflow.EventName{workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment} {
		// compromised-runners names pull_request from a branch, not these
		x := branchPRGrant(e)
		x.Basis, x.Observed = BasisObserved, []lint.Observation{sawReviewNone}
		g = append(g, x)
	}
	g = append(g,
		RunGrant{Event: workflow.EventNamePullRequestTarget, Head: PRHeadFork, Token: AccessWrite, Cache: AccessWrite, Secrets: SecretsAccessAll, Basis: BasisObserved,
			Quotes: []Quote{prTargetSecrets, prTargetWrite, cacheAsk}, Observed: []lint.Observation{sawPRTarget, sawPRTargetNone}},
		RunGrant{Event: workflow.EventNamePullRequestTarget, Head: PRHeadRepository, Token: AccessWrite, Cache: AccessWrite, Secrets: SecretsAccessAll, Basis: BasisDocumented,
			Quotes: []Quote{prTargetSecrets, prTargetWrite, cacheAsk}, Observed: []lint.Observation{sawCachePRTarget}})
	wr := defaultBranchGrant(workflow.EventNameWorkflowRun, workflowRunWrite)
	wr.Basis, wr.Observed = BasisObserved, []lint.Observation{sawWorkflowRun, sawCacheRun, sawWorkflowRunNone}
	ic := defaultBranchGrant(workflow.EventNameIssueComment, branchWithin)
	ic.Basis, ic.Observed = BasisObserved, []lint.Observation{sawComment, sawCacheComment, sawCommentNone}
	// compromised-runners names issue_comment, issues and push among the
	// runs whose secrets and write token an attacker could get
	issues := defaultBranchGrant(workflow.EventNameIssues, branchWithin)
	issues.Basis, issues.Observed = BasisObserved, []lint.Observation{sawIssuesReaders}
	g = append(g, wr, ic, issues, defaultBranchGrant(workflow.EventNamePush, branchWithin, cacheTriggers))
	inferred := []workflow.EventName{workflow.EventNameDiscussion, workflow.EventNameDiscussionComment, workflow.EventNameFork, workflow.EventNameGollum, workflow.EventNameWorkflowDispatch, workflow.EventNameSchedule}
	// the rest of the events that artifact-poisoning takes, whose run is of a
	// commit of the repository (who starts some of them is not documented)
	inferred = append(inferred, workflow.EventNameBranchProtectionRule, workflow.EventNameCheckRun, workflow.EventNameCheckSuite, workflow.EventNameCreate, workflow.EventNameDelete, workflow.EventNameDeployment, workflow.EventNameDeploymentStatus, workflow.EventNameLabel, workflow.EventNameMilestone, workflow.EventNameRegistryPackage, workflow.EventNamePageBuild, workflow.EventNamePublic, workflow.EventNameRelease, workflow.EventNameRepositoryDispatch, workflow.EventNameStatus, workflow.EventNameWatch)
	for _, e := range inferred {
		x := defaultBranchGrant(e)
		if e == workflow.EventNameSchedule {
			x.Quotes = append(x.Quotes, scheduleDefault)
		}
		if e == workflow.EventNameSchedule || e == workflow.EventNameWorkflowDispatch {
			x.Quotes = append(x.Quotes, cacheTriggers) // they save by default
		}
		if e == workflow.EventNameGollum {
			x.Basis, x.Observed = BasisObserved, []lint.Observation{sawWikiNone}
		} else {
			x.Basis, x.Uncertainty = BasisUnverified, unknownInferred
		}
		g = append(g, x)
	}
	mg := defaultBranchGrant(workflow.EventNameMergeGroup)
	mg.Basis, mg.Uncertainty = BasisUnverified, unknownMergeGroup
	g = append(g, mg)
	wc := defaultBranchGrant(workflow.EventNameWorkflowCall)
	wc.Basis, wc.Uncertainty = BasisUnverified, unknownCalled
	g = append(g, wc)
	for _, e := range noRowEvents {
		g = append(g, RunGrant{Event: e, Head: PRHeadNone, Token: AccessWrite, Cache: AccessWrite, Secrets: SecretsAccessAll, Basis: BasisUnverified,
			Quotes: []Quote{forkedSecrets, permissionsAsk, cacheAsk}, Uncertainty: unknownNoRow})
	}
	return g
}

// grantRows are what GitHub gives a run of each event and head.
var grantRows = grantList()

package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// ArtifactPoisoning is the rule artifact-poisoning: a job that no one
// approves, with the repository's secrets and a token that may write,
// downloads the artifact of a run an attacker drives (the run workflow_run
// follows, a fork's run a release of dawidd6/action-download-artifact
// searches, on any event of the job, or the current run, whose earlier job
// checked out the code of a pull request and uploaded the artifact), into
// its workspace or where a step after it runs it. When no step is seen to
// run it, the finding holds if one does (download.executed true).
var ArtifactPoisoning lint.Rule = withExamples(lint.WithView[ir.ArtifactPoisoningReader](artifactPoisoning{}, ir.ArtifactPoisoningView))

// ArtifactPoisoningID is the ID of artifact-poisoning, and RunnerTempPathID
// the kind of its fix.
var (
	ArtifactPoisoningID = lint.MustRuleID("artifact-poisoning")
	RunnerTempPathID    = lint.MustFixKindID(ir.FixRunnerTempPath.String())
)

type artifactPoisoning struct{}

func (artifactPoisoning) Meta() lint.Meta { return artifactPoisoningMeta }

func (artifactPoisoning) Check(_ context.Context, c *lint.RuleContext, v ir.ArtifactPoisoningReader) error {
	for _, s := range v.DownloadSites() {
		refs := s.PRRunRefs()
		// a search of forks' runs takes the newest after any approval
		search := slices.ContainsFunc(refs, func(r ir.PRRunRef) bool {
			return r.Input == analysis.DownloadInputUses || r.Input == analysis.DownloadInputAllowForks || r.Input == analysis.DownloadInputRepo
		})
		same := s.SameRunUploads()
		// before the approval: a run of workflow_dispatch has no label
		if s.DispatchInput() && len(s.DispatchOn()) > 0 {
			c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(s.At()), Related: downloadRelated(c, refs, same, s.CodeRunSteps()),
				Note: "an input of " + s.UsesText() + " that chooses the run refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses; the rule does not determine the run that the value names"})
		}
		if len(s.PRCodeOn()) == 0 {
			continue // only workflow_dispatch: the input is all
		}
		auto := s.AutomaticApproval()
		if s.Approval() == analysis.ApprovalLabel && !search {
			// no reference but a search is on pull_request_target, so a label
			// that is not free leaves nothing to report; an undecided label is
			// inconclusive where a free one gives a finding (a reference or an
			// upload of the same run)
			free := freeLabel(c, auto)
			if !free && (len(refs) > 0 || len(same) > 0) {
				free = automaticLabelFree(c, auto, s.At(), stepRef(s.UsesText()), downloadRelated(c, refs, same, s.CodeRunSteps()))
			}
			if !free {
				continue
			}
		}
		if len(refs) == 0 && len(same) == 0 {
			if len(s.InconclusiveValues()) > 0 {
				c.Inconclusive(lint.InconclusiveDraft{KindID: downloadInputUnknown, Location: c.At(s.At()), Related: downloadEvidence(c, s.CodeRunSteps()),
					Note: fmt.Sprintf("which run this download takes is not known: %s", strings.Join(s.InconclusiveValues(), ", "))})
			}
			continue
		}
		var scope *lint.Condition
		switch s.ActionsRead() {
		case analysis.ActionsReadNo:
			continue // the download fails
		case analysis.ActionsReadUnwritten:
			scope = defaultWrites(c)
		}
		if s.Destination() == analysis.DownloadDestinationInconclusive {
			c.Inconclusive(lint.InconclusiveDraft{KindID: downloadPathUnknown, Location: c.At(s.At()), Related: downloadRelated(c, refs, same, nil),
				Note: fmt.Sprintf("where this download puts the artifact's files is not known: %s", s.DestinationText())})
			continue
		}
		runs := s.CodeRunSteps()
		if s.Destination() == analysis.DownloadDestinationRunnerTemp && len(runs) == 0 {
			continue
		}
		var approval *lint.Condition
		switch {
		case s.Approval() == analysis.ApprovalEnvironment && !search:
			approval = environmentCond(c, analysis.ApprovalEnvironment, s.Environment())
		case s.Approval() == analysis.ApprovalLabel && !search && auto.Environment != (facts.EnvironmentName{}) && !c.Barriers().Passes(analysis.BarrierLabelApproval):
			approval = environmentCond(c, analysis.ApprovalEnvironment, auto.Environment)
		}
		pins := unlessCond(s.MissingCommits())
		ref, at, producers := "", s.At(), sameRunEvidence(c, same)
		if len(refs) > 0 {
			ref, at, producers = refs[0].Text, refs[0].At, nil
		} else {
			// the uploads of the current run: one whose checkout the guard
			// does not decide holds whatever the commit
			u := same[0]
			for _, v := range same {
				if len(v.Unless) == 0 {
					u = v
					break
				}
			}
			ref = u.Text
			pins = allOf(pins, unlessCond(u.Unless))
		}
		f := lint.FindingDraft{Location: c.At(at), Evidence: producers}
		if len(runs) > 0 {
			f.Args = ArtifactPoisoningExecuted{Uses: s.UsesText(), PRRunRef: ref, PRCodeOn: eventsOf(s.PRCodeOn()), Runs: runNames(runs)}
			f.Evidence = append(f.Evidence, downloadEvidence(c, runs)...)
			f.Condition = allOf(approval, scope, pins)
		} else {
			// the fact names a step of the input: a step of a remote called
			// workflow, or of an input whose name no fact can hold, has none
			// to ask, and the finding holds as if download.executed were true
			// (https://github.com/gh-intel/sisakulint/issues/738)
			var executed *lint.Condition
			if file, ok := c.Name().FactArgument(); ok && !c.RemoteCalled() {
				executed = factCond(facts.DownloadExecuted{InputPath: file, Step: s.StepPath()}, true)
			}
			f.Args = ArtifactPoisoningDownload{Uses: s.UsesText(), PRRunRef: ref, PRCodeOn: eventsOf(s.PRCodeOn())}
			f.Condition = allOf(approval, scope, pins, executed)
		}
		f.Fix, f.NoFix = fixOf(s.RunnerTempPath())
		c.Report(f)
	}
	return nil
}

// sameRunEvidence is, for each upload of the current run that a download
// takes, the checkout of the pull request's code and the upload.
func sameRunEvidence(c *lint.RuleContext, ups []ir.SameRunUpload) []lint.Related {
	var out []lint.Related
	for _, u := range ups {
		out = append(out,
			lint.Related{Location: c.At(u.CheckoutAt), Note: "checks out the pull request's code (" + u.Text + ")"},
			lint.Related{Location: c.At(u.UploadAt), Note: "uploads the artifact (" + u.Text + ")"})
	}
	return out
}

// downloadRelated are the places of the finding of artifact-poisoning on
// the download of refs or of the uploads same, after which runs run what it
// puts, other than the step of the download: the first reference, or the
// checkouts and the uploads of same, and the steps of runs.
func downloadRelated(c *lint.RuleContext, refs []ir.PRRunRef, same []ir.SameRunUpload, runs []ir.CodeRunStep) []lint.Related {
	var out []lint.Related
	if len(refs) > 0 {
		out = append(out, lint.Related{Location: c.At(refs[0].At), Note: "names the run of the pull request whose artifact the download takes (" + refs[0].Text + ")"})
	} else {
		out = sameRunEvidence(c, same)
	}
	return append(out, downloadEvidence(c, runs)...)
}

// downloadEvidence is where each step of runs runs what the download puts.
func downloadEvidence(c *lint.RuleContext, runs []ir.CodeRunStep) []lint.Related {
	var out []lint.Related
	for _, e := range runs {
		out = append(out, lint.Related{Location: c.At(e.At), Note: "runs what the download puts (" + e.Cite + ")"})
	}
	return out
}

var (
	downloadInputUnknown = lint.MustInconclusiveKindID(analysis.InconclusiveDownloadInput.String())
	downloadPathUnknown  = lint.MustInconclusiveKindID(analysis.InconclusiveDownloadPath.String())
)

var (
	observedDownload = lint.MustDate("2026-10-04")

	ghsl2024125     = lint.MustCitation("https://securitylab.github.com/advisories/GHSL-2024-124_GHSL-2024-125_quarkus/")
	ghsa5xr6        = lint.MustCitation("https://github.com/advisories/GHSA-5xr6-xhww-33m4")
	workflowRunDocs = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run")
	codeqlArtifact  = lint.MustCitation("https://github.com/github/codeql/blob/f7617abe602d4763cd08c6a57b6a6bc347e7e325/actions/ql/src/Security/CWE-829/ArtifactPoisoningCritical.md")
	legitRust       = lint.MustCitation("https://www.legitsecurity.com/blog/artifact-poisoning-vulnerability-discovered-in-rust")
	downloadAction  = lint.MustCitation("https://github.com/actions/download-artifact/blob/v8.0.1/src/download-artifact.ts")

	attackerRun   = lint.MustPreconditionID("attacker-run")
	downloadEvent = lint.MustPreconditionID("download-event")
	tokenReads    = lint.MustPreconditionID("token-reads")
	intoWorkspace = lint.MustPreconditionID("into-workspace")

	// the day a job of a push run, whose download searched the runs of its
	// workflow, took the artifact of a run of a pull request from a fork
	observedSearch = lint.MustDate("2026-11-05")
	runnerSearch   = lint.MustVersion("2.338.2")
	// the search of runs, which reads of the event of the job only its run
	// (github.context.runId)
	dawidd6Search = lint.MustCitation("https://github.com/dawidd6/action-download-artifact/blob/09f2f74827fd3a8607589e5ad7f9398816f540fe/main.js")
)

// downloadStarters are who starts the run of each event the actor takes: a
// search of runs takes the attacker's on any event of the job, so the
// actor takes them all. The attacker starts the privileged events, gollum
// where anyone may edit the wiki, watch by a star, and pull_request by a
// pull request between two branches of the repository (taken for now, as
// for the review events; owner's answer of 2026-11-06); others start the
// rest.
func downloadStarters() map[workflow.EventName]lint.RunStarter {
	byAttacker := append(job.Privileged(), workflow.EventNameGollum, workflow.EventNameWatch, workflow.EventNamePullRequest)
	all := ir.SearchEvents()
	others := slices.DeleteFunc(slices.Clone(all), func(e workflow.EventName) bool { return slices.Contains(byAttacker, e) })
	return startedBy(all, others...)
}

// downloadBase is the CVSS of artifact-poisoning: the attacker's code runs
// in the job, as untrusted-checkout's does.
var downloadBase = lint.CVSS{
	AV: metric(lint.AttackVectorNetwork, "the attacker opens a pull request from a fork over the network, whose run uploads the artifact"),
	AC: metric(lint.AttackComplexityLow, "a change of the pull request's workflow or build is all it takes to put any file in the artifact"),
	AT: metric(lint.AttackRequirementsNone, "a pull request from a fork can run the workflow workflow_run follows under its name, and its artifact is the one the download takes; a search of forks' runs takes the newest, the attacker's"),
	PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository is needed"),
	UI: metric(lint.UserInteractionNone, "the run of the pull request triggers workflow_run with nobody doing anything"),
	VC: metric(lint.ImpactHigh, "the code reads the job's secrets and GITHUB_TOKEN"),
	VI: metric(lint.ImpactHigh, "with the job's token the code can push, and write releases and packages"),
	VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
	SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
	SI: metric(lint.ImpactHigh, "what the job publishes reaches those who use it"),
	SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
}

var artifactPoisoningMeta = lint.Meta{
	ID:       ArtifactPoisoningID,
	Problem:  "a job that no one approves, and that has the repository's secrets or a token that may write, downloads the artifact of a run that a pull request from a fork drives, either into the workspace of the job or to a directory from which a step after the download runs the files of the artifact",
	Expected: "a job that has the repository's secrets or a token that may write downloads such an artifact outside the workspace, into ${{ runner.temp }}, and reads the files of the artifact as data only",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedCodeExecution}, AttackMeans: []lint.AttackMeans{lint.AttackMeansCode}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textArtifactPoisoningExecuted,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor},
			Preconditions:   []lint.PreconditionID{attackerRun, downloadEvent, noApproval, tokenReads, intoWorkspace, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected, facts.KindRepoDefaultTokenWrite, facts.KindGitCommitContains},
			Fixes:           []lint.FixKindID{RunnerTempPathID},
			CVSS:            downloadBase,
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "GHSL-2024-125: a pull request that changes the workflow of the artifact runs its script in Quarkus's preview workflow, reported with the workflow's steps", ghsl2024125),
		},
		{
			FindingText:     textArtifactPoisoningDownload,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor},
			Preconditions:   []lint.PreconditionID{attackerRun, downloadEvent, noApproval, tokenReads, intoWorkspace, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected, facts.KindRepoDefaultTokenWrite, facts.KindGitCommitContains, facts.KindDownloadExecuted},
			Fixes:           []lint.FixKindID{RunnerTempPathID},
			CVSS:            downloadBase,
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "the same as when a step is seen to run it: whether one does is what the condition asks", ghsl2024125),
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{Attacker: lint.AttackerForkPRAuthor, Via: "opens a pull request from a fork whose run uploads an artifact of their making, which a run of the job downloads",
			Events: ir.SearchEvents(), RunStarters: downloadStarters(), Gains: jobGains}},
		Preconditions: []lint.Precondition{
			callersEventsPre,
			{
				ID:   attackerRun,
				Text: "the download takes the artifact of a run the attacker drives: actions/download-artifact v4 or later with a token and the input run-id github.event.workflow_run.id, or dawidd6/action-download-artifact in one of three forms: with the input run_id github.event.workflow_run.id; with the input repo of the fork; or with no input run_id, or with an input run_id whose ${{ }} is empty on the event of the job, with which dawidd6/action-download-artifact searches the runs of the workflow. The search takes the run of a pull request from a fork when the input allow_forks is true or the version of dawidd6/action-download-artifact is before v4. Whatever the input allow_forks is, the search also takes the run of a review of a pull request from a fork: the run of the review runs the workflow of the merge commit of the pull request, and the head repository of the run of the review is the base repository. Without a token, actions/download-artifact takes the current run's artifacts",
				Observed: []lint.Observation{
					{Date: observedDownload, Runner: runner, What: "a pull request from a fork changed the workflow workflow_run follows, on push alone, to run on pull_request under the same name; its run triggered the base's workflow_run, whose download with a token and run-id github.event.workflow_run.id took the fork's artifact; without the token it found none"},
					{Date: observedSearch, Runner: runnerSearch, What: "a pull request from a fork added pull_request_review to the workflow, and a comment-only review of the pull request started a pull_request_review run of the workflow; the head repository of that run was the base repository, and a job of a later push run, with dawidd6/action-download-artifact v20 and no input allow_forks, did not skip that run and took the artifact of that run"},
				},
				Cites: []lint.Citation{downloadAction, ghsa5xr6, workflowRunDocs, legitRust, dawidd6Search},
			},
			{
				ID:   downloadEvent,
				Text: "the job runs on an event on which the download takes the attacker's artifact, with the repository's secrets or a token that may write: workflow_run, for a run-id or run_id of github.event.workflow_run.id or a repo of github.event.workflow_run.head_repository.full_name; pull_request_target, for a repo of github.event.pull_request.head.repo.full_name; and any event of the job, for a search of runs by dawidd6/action-download-artifact, as the search does not filter the runs by the event of the job: push, schedule and workflow_dispatch, which only those who can write to the repository start, count too. A job on pull_request counts only when the pull request is from a branch of the repository: the run of a pull request from a fork runs the workflow of the pull request, which the author of the pull request can change, with a read-only token and no secrets",
				Observed: []lint.Observation{
					{Date: observedSearch, Runner: runnerSearch, What: "a job of a push run, with dawidd6/action-download-artifact v3.1.4 and no input workflow, run_id or allow_forks, took the artifact of the newest run of its workflow, a pull_request run of a pull request from a fork; v20, whose input allow_forks is false by default, skipped that run, whose head repository was the fork"},
				},
				Cites: []lint.Citation{dawidd6Search},
			},
			{
				ID:   noApproval,
				Text: "no one approves the run: either the job runs on at least one event other than pull_request_target with the activity type labeled, and a run on the other event starts with no label added, or no person adds the label that starts the run, as the label is " + labelerAddedLabel + "; and the job has no environment that has required reviewers (repo.environment-protected false)",
				Observed: []lint.Observation{
					{Date: observedCheckout, Runner: runner, What: "a push after the label ran no labeled run, and ran pull_request_target on synchronize"},
				},
			},
			{
				ID:    tokenReads,
				Text:  "the token may read the artifacts of another run: the scope actions, read-all or write-all for the GITHUB_TOKEN, or the repository's permissive default when no permissions are written (repo.default-token-write true); permissions written without actions set it to none",
				Cites: []lint.Citation{tokenDocs},
			},
			{
				ID:   intoWorkspace,
				Text: "the files go into the workspace, where they replace the files a build reads (no path, a relative one, a literal $RUNNER_TEMP, or a release with the zip-slip of 4.0.0 to 4.1.2), or a step after it names them to run; when none is seen to run, the finding holds if one does (download.executed true)",
				Observed: []lint.Observation{
					{Date: observedDownload, Runner: runner, What: "actions/download-artifact@v4 with no path put the artifact's x.sh over the x.sh a step before had written in the workspace"},
				},
				Cites: []lint.Citation{codeqlArtifact},
			},
		},
	},
	Citations:       []lint.Citation{cvss},
	Targets:         []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append(append(append(slices.Clone(artifactPoisoningLimits), ifLimits...), repositoryDispatchLimit, dispatchRelayLimit, dispatchInputCallLimit, dispatchDerivedLimit, npmAbbreviation(kindArtifactPoisoningExecuted), npmOptionValueCommand(kindArtifactPoisoningExecuted)), automaticLabelForms...)),
	InconclusiveKinds: withRemoteCalleeUnknown(append([]lint.InconclusiveKind{
		{ID: downloadInputUnknown, Text: "a download whose token, run-id, repository, run_id or repo has what a step or a job computes, an input other than one of workflow_dispatch (or an input of workflow_dispatch in a workflow that also has workflow_call, when a workflow on an event of a pull request calls the workflow), an env, a matrix or a variable, or whose with is a whole ${{ }}: which run it takes is not analyzed", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: inputDispatch, Text: "a download whose token, run-id, repository, run_id or repo has a ${{ }} that refers to an input of workflow_dispatch (inputs, github.event.inputs), alone or with other values: " + dispatcherChooses, Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: downloadPathUnknown, Text: "a download whose path is absolute, under ~, a ${{ }} other than runner.temp and github.workspace, a Windows path, or leaves by ..: whether it is in the workspace is not known from the workflow (on a self-hosted runner /tmp and /var can hold the workspace)", Disposition: lint.Todo(lint.NeedSameFile)},
	}, automaticLabelKinds...)),
	FalsePositiveForms: append(withCallee([]lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("approval-if"), Text: "an if of the job that keeps out the runs of forks (github.event.workflow_run.head_repository.full_name == github.repository), when the run before it is of pull_request: a run of pull_request_target or issue_comment before it has the repository as its head too, and which it is is in that workflow", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustFalsePositiveFormID("search-filter"), Text: "a search of the runs of a workflow by dawidd6/action-download-artifact (no input run_id, or an input run_id that is empty on the event of the job) with the input event push, or, in a job on push, with the input commit ${{ github.sha }}: the search then lists only the push runs of the workflow, or only the runs of the commit pushed to the repository, and those runs run the workflow of a commit pushed to the repository. In contrast, with any other input event the finding holds: with pull_request, pull_request_target, pull_request_review or pull_request_review_comment, the list keeps the runs that a pull request from a fork starts, and with issue_comment or workflow_run, the list keeps runs whose artifacts can hold the files of a pull request from a fork (a run that builds the head of the pull request, or a run that uploads again the artifact of a run of a fork)", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("no-exec-bit"), Text: "a file of the artifact run by its path with no chmod (./x.sh, or after a wrapper such as sudo ./x.sh): the files of an artifact lose their mode, so the step fails and runs nothing", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningExecuted}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("written-after-checkout"), Text: "a job that uploads an artifact in the same workflow run as the job that downloads the artifact, checks out the code of the pull request into the root of the workspace (with no input path of actions/checkout), runs no code of the checkout, and uploads only files that a later step of the same job creates or overwrites with > (not appends to with >>), such as a file into which echo writes the number of the pull request: the rule takes every file under the directory of the checkout as code of the pull request, and every file of the workspace is under the root of the workspace, so the rule reads the artifact as holding code of the pull request, though the artifact holds only the files that the job wrote", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("unknown-version"), Text: "a ref of actions/download-artifact whose version is not known (a branch such as releases/v2, which moves), which the rule reads as v4 or later: the worst case, as v4 or later reads the inputs run-id and github-token and can take the artifact of another run", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("not-executed"), Text: "a job that runs nothing it downloaded, such as one that only publishes it", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningDownload}, FactKinds: []facts.Kind{facts.KindDownloadExecuted}},
		{ID: lint.MustFalsePositiveFormID("remote-not-executed"), Text: "a job of a reusable workflow of another repository that runs nothing it downloaded, as in the form not-executed: the fact download.executed names a step of the input and cannot name a step of a reusable workflow of another repository, so no answer of the fact removes the finding", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningDownload}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("environment-protected"), Text: "a job whose environment has required reviewers, who approve it before it runs", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload}, FactKinds: []facts.Kind{facts.KindRepoEnvironmentProtected}},
		{ID: lint.MustFalsePositiveFormID("default-token-read"), Text: "a job that writes no permissions, in a repository whose default token is read: the token reads no artifact of another run", FindingKinds: []lint.FindingKindID{kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload}, FactKinds: []facts.Kind{facts.KindRepoDefaultTokenWrite}},
		npmUnknownCommand(kindArtifactPoisoningExecuted),
		npmOptionValueOperand(kindArtifactPoisoningExecuted),
		cdOutOfTree(kindArtifactPoisoningExecuted),
		ignoredPnpmfile(kindArtifactPoisoningExecuted),
		absolutePathOutOfTree(kindArtifactPoisoningExecuted),
		pytestPathOutOfTree(kindArtifactPoisoningExecuted),
		toolDirectoryOutOfTree(kindArtifactPoisoningExecuted),
	}, kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload), automaticLabelFalsePositives(kindArtifactPoisoningExecuted, kindArtifactPoisoningDownload)...),
	FixKinds: []lint.FixKind{{
		ID:                  RunnerTempPathID,
		Title:               "put the artifact's files out of the workspace: path: ${{ runner.temp }}/artifacts",
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectArtifactPathMoved},
	}},
}

// artifactPoisoningLimits are the forms the rule does not report.
var artifactPoisoningLimits = []lint.UndetectedForm{
	outsideCallerLimit,
	{ID: lint.MustUndetectedFormID("labeler-same-run"), Text: "a job on pull_request_target with the activity type labeled that downloads and runs an artifact that another job of the same run uploads after the other job checks out the code of the pull request, where the if of each job requires a label that actions/labeler adds to the pull request of the attacker. The rule reads an upload of the same run only from a job that no label and no environment approves, and does not read whether actions/labeler adds the label that the job that uploads requires. untrusted-checkout reports the checkout of the job that uploads.", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("run-command"), Text: "an artifact downloaded by a command of a run: gh run download, gh api …/zip, curl", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("github-script"), Text: "an artifact downloaded by github-script (downloadArtifact)", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("other-action"), Text: "an artifact downloaded by an action other than actions/download-artifact and dawidd6/action-download-artifact", Disposition: lint.Todo(lint.NeedFact)},
	{ID: lint.MustUndetectedFormID("local-action"), Text: "a download inside a local action the job uses, whose action.yml is another file of the repository", Disposition: lint.Todo(lint.NeedRepoFile)},
	{ID: lint.MustUndetectedFormID("read-as-data"), Text: "a file of the artifact read as a value: written to $GITHUB_ENV or $GITHUB_OUTPUT, or put in a run, which may run as code", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("same-run-pr-code"), Text: "an artifact of the current run that another job made from a pull request's code that the other job checked out, where the job that downloads does not list the job that uploads in its needs, directly or through other jobs, or where an approval admits the job that uploads; also an upload that the rule does not read as such: an upload in a reusable workflow that a job of the workflow calls, an upload inside a composite action that a step uses, and actions/upload-artifact/merge, which uploads again the artifacts of other jobs under a new name. The rule reads such an upload only when the job of the download lists the job of the upload in needs, directly or through other jobs, no approval admits the job of the upload, and a step of that job uses actions/upload-artifact itself", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("dispatch-ref"), Text: "an artifact of the current run that a job built from a ref that an input of workflow_dispatch names", Disposition: lint.Limitation(lint.DeciderDispatcher)},
	{ID: lint.MustUndetectedFormID("producer-dependency"), Text: "an artifact whose producer took what is bad from a dependency it built with", Disposition: lint.Limitation(lint.DeciderRunTime)},
	{ID: lint.MustUndetectedFormID("runner-temp-indirect"), Text: "a download under runner.temp whose files a step runs without writing the path of the file as a command or as an argument of a command in the run: script of the step, for example by: the source command or its short form, the . (dot) command, a shell that gets the path inside the code of its -c option (bash -c '$RUNNER_TEMP/x.sh'), a path that format() makes (${{ format('{0}/x.sh', runner.temp) }}), a shell variable that holds the path (bash $S, where an earlier line or the env of the step sets S to $RUNNER_TEMP/x.sh), or a ${{ }} in the path whose value goes to a parent directory with .. and so points outside the directory written before the ${{ }} ($RUNNER_TEMP/pr/${{ matrix.f }}, where matrix.f is ../a/x.sh and the download is in runner.temp/a)", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("caller-omitted-input"), Text: "an input of a reusable workflow, which callers in the repository call, used as the input run_id of dawidd6/action-download-artifact, when a caller does not give the input (an input that is not required), or an input of a composite action that the step that uses the action does not give: the value is then empty, and the action searches the runs of the workflow; the rule reads an input that the callers give as a value that is not empty", Disposition: lint.Todo(lint.NeedRepoFile)},
	{ID: lint.MustUndetectedFormID("run-id-condition"), Text: "an input run_id of dawidd6/action-download-artifact whose ${{ }} gives github.run_id on some events and an empty value on others (${{ github.event_name == 'push' && github.run_id || '' }}): the action searches the runs of the workflow when the value is empty; the rule reads a run_id that writes github.run_id as a value that is never empty", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("runtime-token"), Text: "an artifact of the current run replaced by code of the run that has ACTIONS_RUNTIME_TOKEN", Disposition: lint.Limitation(lint.DeciderRunTime)},
}

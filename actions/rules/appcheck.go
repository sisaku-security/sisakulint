package rules

import (
	"maps"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// What the rules share of the runs that an app outside GitHub Actions, such
// as an outside CI, starts by a commit status or a check run for a commit
// whose message an attacker writes (a commit of a pull request from a fork,
// or a commit that merges a pull request): status, check_suite and
// check_run start on the default branch with the SHA of the commit in the
// payload, and status and check_suite with its message and the names of its
// author and committer too (seen on GitHub on 2026-11-05 and 2026-11-06). The three events are
// privileged events (job.Privileged); the engine asks
// repo.fork-pr-app-checks or repo.merge-commit-app-checks for a workflow on
// them alone (package lint).

// appCommitEvents are the events of a commit status or a check run.
var appCommitEvents = []workflow.EventName{workflow.EventNameStatus, workflow.EventNameCheckSuite, workflow.EventNameCheckRun}

var (
	appStatusCheck = lint.MustPreconditionID("app-status-check")

	appStatusCheckPre = lint.Precondition{
		ID:   appStatusCheck,
		Text: "an app outside GitHub Actions, such as an outside CI, makes a commit status or a check run for a commit whose message an attacker writes (a commit of a pull request from a fork, or a commit that merges a pull request; the message of a commit that merges a pull request can have the title of the pull request), and the commit status or the check run starts a run of status, check_suite or check_run, which runs the workflow of the default branch, whatever branch the commit is on. The payload of a run of any of the three events has the SHA of the commit, and the payload of a run of status or check_suite also has the message, the author name and the committer name of the commit. A finding of a workflow whose on has only events among status, check_suite and check_run (one, two or all three) holds only when the fact of the commit is true: repo.fork-pr-app-checks for a commit of a pull request from a fork, and repo.merge-commit-app-checks for a commit that the merge of a pull request puts in a branch of the repository or that a merge queue of the repository makes. A finding kind asks the fact of each kind of commit that its attackers write; the finding of a finding kind that asks both facts holds when at least one of the two facts is true. The rule does not ask these facts of a workflow whose on has another event too, and reports the finding of such a workflow whatever the values of the facts are. The rule assumes each fact to be true unless a file of facts says otherwise",
		Observed: []lint.Observation{
			{Date: lint.MustDate("2026-11-05"), Runner: lint.MustVersion("2.338.2"), What: "a GitHub App made a commit status and a check run for a commit of a pull request from a fork: runs of status, check_suite and check_run started on the default branch, and the message of the commit, with $( ) in it, was in commit.commit.message of status and in check_suite.head_commit.message of check_suite"},
			{Date: lint.MustDate("2026-11-06"), Runner: lint.MustVersion("2.338.2"), What: "the same again: the SHA of the commit of the pull request was in sha and commit.sha of status, check_suite.head_sha and check_suite.head_commit.id of check_suite, and check_run.head_sha and check_run.check_suite.head_sha of check_run; check_suite.after and check_suite.before were null; the author name and the committer name of the commit, with $( ) in each, were in the payloads of status and check_suite"},
		},
		Cites: []lint.Citation{
			lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#status"),
			lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#check_suite"),
			lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#check_run"),
		},
	}
)

var (
	// appWrittenLimit is a value that the app writes into a commit status or
	// a check run, which the table reads as fixed.
	appWrittenLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("app-written"), Text: "a value that an app outside GitHub Actions writes into a field of a commit status or a check run (the fields context, description and target_url of status; the fields name, output, details_url and external_id of check_run): the app may copy a value of a pull request from a fork into the field, such as the name of a job that a configuration file of the pull request gives to an outside CI; the rule reads the field as a field whose value the app chooses", Disposition: lint.Todo(lint.NeedFact)}
	// deploymentStatusLimit is the run of deployment_status, which did not
	// start when a GitHub App made a deployment and its status for a commit
	// of a pull request from a fork (seen on GitHub on 2026-11-05).
	deploymentStatusLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("deployment-status"), Text: "a value of the payload of deployment_status, such as the SHA of the deployment (deployment.sha), when an app outside GitHub Actions makes a deployment and a status of the deployment for a commit of a pull request from a fork: no run of deployment_status started when the authors of the linter tried this, and why the run did not start was not found; the rule does not read deployment_status as an event that an attacker starts", Disposition: lint.Todo(lint.NeedFact)}
)

// appChecksNotAsked are the rules whose findings on status, check_suite
// and check_run do not rest on an app that checks the commits of the pull
// requests from forks: artifact-poisoning, whose search of the runs of
// forks takes the artifact of a run of a pull request from a fork on any
// event of the job, whoever starts the run of the job.
var appChecksNotAsked = []lint.RuleID{ArtifactPoisoningID}

// appChecksUnasked is the false positive form of the runs that
// repo.fork-pr-app-checks and repo.merge-commit-app-checks do not reach:
// the engine asks the facts only of a workflow whose own on has no event
// other than the three.
var appChecksUnasked = lint.MustFalsePositiveFormID("app-checks-unasked")

const appChecksUnaskedText = "a run of status, check_suite or check_run in a repository where no app outside GitHub Actions makes a commit status or a check run for a commit that the attacker of the finding writes: the facts that the finding kind asks are false (repo.fork-pr-app-checks for a commit of a pull request from a fork, repo.merge-commit-app-checks for a commit that the merge of a pull request puts in a branch of the repository). In two cases, the rule does not ask these facts, and reports the finding whatever the values of the facts are. First, a workflow whose on has an event other than status, check_suite and check_run: the rule decides whether to ask the facts from the events of on alone, and does not read the if of the job, so the rule does not ask the facts even when the if of the job lets the job run only on status, check_suite or check_run. Second, a reusable workflow (on workflow_call) or an action (an action has no on) that only workflows on status, check_suite or check_run call: the rule asks the facts only of a workflow whose on has only events among these three, not of the reusable workflow or the action, so the rule reports a finding in the reusable workflow or the action whatever the values of the facts are"

// withAppChecks is m with each kind asking, for each of its attackers
// whose actor starts status, check_suite or check_run, the fact of the
// commits that the attacker writes (lint.AppChecksFact; the engine adds the
// condition, package lint), and the false positive form app-checks-unasked
// of those kinds; m itself when it has no such kind. It panics on an
// attacker whose actor starts one of the three and who has no such fact.
func withAppChecks(m lint.Meta) lint.Meta {
	if slices.Contains(appChecksNotAsked, m.ID) {
		return m
	}
	var ids []lint.FindingKindID
	kinds := slices.Clone(m.FindingKinds)
	for i, k := range kinds {
		var asked []facts.Kind
		for _, a := range m.Threat.Actors {
			if !slices.Contains(k.Attackers, a.Attacker) || !slices.ContainsFunc(a.Events, func(e workflow.EventName) bool { return slices.Contains(appCommitEvents, e) }) {
				continue
			}
			f, ok := lint.AppChecksFact(a.Attacker)
			if !ok {
				panic(m.ID.String() + ": the attacker " + a.Attacker.String() + " starts status, check_suite or check_run, and has no fact of the commits an outside app checks")
			}
			if !slices.Contains(asked, f) {
				asked = append(asked, f)
			}
		}
		if len(asked) == 0 {
			continue
		}
		kinds[i].FactKinds = append(slices.Clip(k.FactKinds), asked...)
		ids = append(ids, k.ID)
	}
	if len(ids) == 0 {
		return m
	}
	m.FindingKinds = kinds
	m.FalsePositiveForms = append(slices.Clip(m.FalsePositiveForms),
		lint.FalsePositiveForm{ID: appChecksUnasked, Text: appChecksUnaskedText, FindingKinds: ids, Disposition: lint.Todo(lint.NeedSameFile, lint.NeedRepoFile)})
	return m
}

// withoutAppCommitEvents are actors without the events of a commit status
// or a check run: for a rule that declares them (app-commit-event).
func withoutAppCommitEvents(actors []lint.Actor) []lint.Actor {
	out := slices.Clone(actors)
	for i, a := range out {
		out[i].Events = slices.DeleteFunc(slices.Clone(a.Events), func(e workflow.EventName) bool { return slices.Contains(appCommitEvents, e) })
		starters := map[workflow.EventName]lint.RunStarter{}
		for e, s := range a.RunStarters {
			if !slices.Contains(appCommitEvents, e) {
				starters[e] = s
			}
		}
		out[i].RunStarters = starters
	}
	return out
}

// withAppCommitEventsAdded are actors with the events of a commit status or
// a check run added to the author of a pull request from a fork, whose via
// says so: for a rule that reads the privileged events (job.Privileged) of
// a job, and whose other actors are shared with rules that do not.
func withAppCommitEventsAdded(actors []lint.Actor) []lint.Actor {
	out := slices.Clone(actors)
	for i, a := range out {
		if a.Attacker != lint.AttackerForkPRAuthor {
			continue
		}
		out[i].Via = a.Via + "; or pushes a commit to the pull request, and an app outside GitHub Actions makes a commit status or a check run for the commit, and the commit status or the check run starts a run of status, check_suite or check_run whose actor is the app"
		out[i].Events = append(slices.Clone(a.Events), appCommitEvents...)
		starters := maps.Clone(a.RunStarters)
		for _, e := range appCommitEvents {
			starters[e] = lint.RunStarterAttacker
		}
		out[i].RunStarters = starters
	}
	return out
}

// withMergedCommitAppEvents are actors with the author of a merged commit
// added, on the events of a commit status or a check run alone, with the
// gains of the author of a pull request from a fork: for a rule that reads
// the privileged events (job.Privileged) of a job, whose kinds of a value
// that an attacker writes (such as a message of a commit in the payload)
// also hold for the commit that the merge of a pull request puts in a
// branch, and whose actors have no author of a merged commit on push. One
// who can write merges the commit, so another person starts each run.
func withMergedCommitAppEvents(actors []lint.Actor) []lint.Actor {
	i := slices.IndexFunc(actors, func(a lint.Actor) bool { return a.Attacker == lint.AttackerForkPRAuthor })
	if i < 0 {
		panic("no author of a pull request from a fork among the actors")
	}
	return append(slices.Clone(actors), lint.Actor{
		Attacker:    lint.AttackerMergedCommitAuthor,
		Via:         "writes the message of a commit that is merged, or put in a merge queue, and an app outside GitHub Actions makes a commit status or a check run for the commit, and the commit status or the check run starts a run of status, check_suite or check_run",
		Events:      slices.Clone(appCommitEvents),
		RunStarters: startedBy(appCommitEvents, appCommitEvents...),
		Gains:       slices.Clone(actors[i].Gains),
	})
}

// mergedCommitPush is the undetected form of the kinds that read the author
// of a merged commit only on status, check_suite and check_run
// (withMergedCommitAppEvents): the same message in a run of push or
// merge_group. kinds are those kinds of the rule, none when they are all of
// its kinds (a form on which the rule reports nothing names no kind).
func mergedCommitPush(kinds ...lint.FindingKindID) lint.UndetectedForm {
	return lint.UndetectedForm{ID: lint.MustUndetectedFormID("merged-commit-push"), Text: "a value that the author of a merged commit writes, such as the message of the head commit of a push (github.event.head_commit.message), in a run of push or merge_group: the message of a commit that merges a pull request can have the title of the pull request, which the author of the pull request writes; the rule reads the author of a merged commit only in a run of status, check_suite or check_run", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

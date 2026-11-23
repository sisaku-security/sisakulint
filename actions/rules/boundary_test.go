package rules

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/boundary"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// prEvents are the events of a pull request, whose head is a fork or a
// branch of the repository.
var prEvents = []workflow.EventName{workflow.EventNamePullRequest, workflow.EventNamePullRequestTarget, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}

func headsOf(e workflow.EventName) []boundary.PRHead {
	if slices.Contains(prEvents, e) {
		return []boundary.PRHead{boundary.PRHeadFork, boundary.PRHeadRepository}
	}
	return []boundary.PRHead{boundary.PRHeadNone}
}

// TestBoundaryCoversActors: every Actor of a rule with events has, for
// each event and head, a run grant, and, for each role, a channel row; an
// Actor with no event and a gain the tables compare has, for each role, a
// pathway row.
func TestBoundaryCoversActors(t *testing.T) {
	grants, channels, pathways := boundary.Grants(), boundary.Channels(), boundary.Pathways()
	for _, r := range All() {
		m := r.Meta()
		for _, a := range m.Threat.Actors {
			for _, e := range a.Events {
				for _, h := range headsOf(e) {
					if !slices.ContainsFunc(grants, func(g boundary.RunGrant) bool { return g.Event == e && g.Head == h }) {
						t.Errorf("%s %s: no run grant of %s %s", m.ID, a.Attacker, e, h)
					}
				}
			}
			if len(a.Events) == 0 {
				if len(boundary.HoldingsOf(a.Gains)) == 0 {
					continue // no gain the tables compare: the viewer says so
				}
				for _, role := range boundary.Roles() {
					if !slices.ContainsFunc(pathways, func(p boundary.Pathway) bool { return p.Attacker == a.Attacker && p.Role == role }) {
						t.Errorf("%s: no pathway of %s %s", m.ID, a.Attacker, role)
					}
				}
				continue
			}
			for _, role := range boundary.Roles() {
				if !slices.ContainsFunc(channels, func(c boundary.Channel) bool { return c.Attacker == a.Attacker && c.Role == role }) {
					t.Errorf("%s: no channel of %s %s", m.ID, a.Attacker, role)
				}
			}
		}
	}
}

// TestAttackerChannelOrPathway: no attacker has both channel rows and
// pathway rows, so that one name is one attacker in the tables.
func TestAttackerChannelOrPathway(t *testing.T) {
	for _, p := range boundary.Pathways() {
		if slices.ContainsFunc(boundary.Channels(), func(c boundary.Channel) bool { return c.Attacker == p.Attacker }) {
			t.Errorf("%s has channel rows and pathway rows", p.Attacker)
		}
	}
}

// publicAnswers answers a public repository whose wiki is not open to
// anyone.
func publicAnswers(q facts.Query) facts.RawAnswer {
	v := map[facts.Kind]bool{facts.KindRepoPublic: true, facts.KindRepoAllowForking: true, facts.KindRepoWikiOpen: false}[q.Kind()]
	b, _ := json.Marshal(v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

// TestBoundaryAgreesWithPrivileged: the privileged events of job give the
// secrets and a token that writes, as the tables say of a public
// repository: a review of a pull request from a branch of the repository,
// a pull_request_target of one from a fork; the pull request events from a
// fork that job leaves out do not.
func TestBoundaryAgreesWithPrivileged(t *testing.T) {
	head := func(e workflow.EventName) boundary.PRHead {
		switch {
		case e == workflow.EventNamePullRequestReview || e == workflow.EventNamePullRequestReviewComment:
			return boundary.PRHeadRepository
		case slices.Contains(prEvents, e):
			return boundary.PRHeadFork
		}
		return boundary.PRHeadNone
	}
	for _, e := range job.Privileged() {
		d, _ := boundary.RunDims(boundary.RunRef{Event: e, Head: head(e)}, publicAnswers)
		if d[lint.GainReadSecrets] != expr.TruthTrue || d[lint.GainWriteWithToken] != expr.TruthTrue {
			t.Errorf("%s is privileged, but the tables say secrets %v, write %v", e, d[lint.GainReadSecrets], d[lint.GainWriteWithToken])
		}
	}
	if slices.Contains(job.Privileged(), workflow.EventNamePullRequest) {
		t.Errorf("pull_request is privileged in job")
	}
	for _, e := range []workflow.EventName{workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment} {
		if !slices.Contains(job.Privileged(), e) {
			t.Errorf("%s of a pull request from a branch of the repository is not privileged in job", e)
		}
	}
	for _, e := range []workflow.EventName{workflow.EventNamePullRequest, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment} {
		d, _ := boundary.RunDims(boundary.RunRef{Event: e, Head: boundary.PRHeadFork}, publicAnswers)
		if d[lint.GainReadSecrets] != expr.TruthFalse || d[lint.GainWriteWithToken] != expr.TruthFalse {
			t.Errorf("%s from a fork: the tables say secrets %v, write %v", e, d[lint.GainReadSecrets], d[lint.GainWriteWithToken])
		}
	}
}

// TestRunStartersOfSpec: the events whose run others start are those the
// table of the permission boundary lists; every other event of an actor is
// started by the attacker.
func TestRunStartersOfSpec(t *testing.T) {
	merged := []workflow.EventName{workflow.EventNamePush, workflow.EventNameMergeGroup, workflow.EventNameStatus, workflow.EventNameCheckSuite, workflow.EventNameCheckRun}
	want := map[string][]workflow.EventName{
		"code-injection merged-commit-author":       merged,
		"envvar-injection merged-commit-author":     merged,
		"output-clobbering merged-commit-author":    merged,
		"envpath-injection merged-commit-author":    merged,
		"argument-injection merged-commit-author":   merged,
		"request-forgery merged-commit-author":      merged,
		"unsecure-commands merged-commit-author":    merged,
		"set-output-injection merged-commit-author": merged,
		// the author of a merged commit on the events of a commit status or
		// a check run alone (withMergedCommitAppEvents)
		"ai-action-unsafe-sandbox merged-commit-author": appCommitEvents,
		"cache-poisoning merged-commit-author":          appCommitEvents,
		// every event but those the attacker starts
		"artifact-poisoning fork-pr-author":        {workflow.EventNameBranchProtectionRule, workflow.EventNameCreate, workflow.EventNameDelete, workflow.EventNameDeployment, workflow.EventNameDeploymentStatus, workflow.EventNameImageVersion, workflow.EventNameInteractiveComponent, workflow.EventNameLabel, workflow.EventNameMember, workflow.EventNameMergeGroup, workflow.EventNameMilestone, workflow.EventNameRegistryPackage, workflow.EventNamePageBuild, workflow.EventNameProjectCard, workflow.EventNameProjectColumn, workflow.EventNameProject, workflow.EventNamePublic, workflow.EventNamePush, workflow.EventNameRelease, workflow.EventNameRepositoryDispatch, workflow.EventNameWorkflowDispatch, workflow.EventNameSchedule, workflow.EventNameDynamic, workflow.EventNameWorkflowCall, workflow.EventNamePullRequestComment},
		"untrusted-checkout-toctou fork-pr-author": {workflow.EventNamePullRequestTarget},
	}
	seen := map[string]bool{}
	for _, r := range All() {
		m := r.Meta()
		for _, a := range m.Threat.Actors {
			key := m.ID.String() + " " + a.Attacker.String()
			var others []workflow.EventName
			for _, e := range a.Events {
				if a.RunStarters[e] == lint.RunStarterOther {
					others = append(others, e)
				}
			}
			if len(others) == 0 {
				continue
			}
			seen[key] = true
			if !slices.Equal(others, want[key]) {
				t.Errorf("%s: others start %v, want %v", key, others, want[key])
			}
		}
	}
	for key := range want {
		if !seen[key] {
			t.Errorf("%s: no event that others start", key)
		}
	}
}

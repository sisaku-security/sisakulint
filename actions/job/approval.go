package job

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// ApprovalOf is what approves a run on the events evs of the job j (nil for
// the steps of an action.yml): a label, when
// every event is pull_request_target labeled, as a push after the label
// runs no labeled run and adding one needs a credential with write access
// to the permission Issues or Pull requests, which the credential premise
// of the terms assumes no attacker holds; else an
// environment whose name is written out, which approves only if it has
// required reviewers (repo.environment-protected, for the rules to ask). A
// name with a ${{ }} is not known, so it approves nothing.
func ApprovalOf(evs []analysis.EventActivity, j *workflow.Job) (analysis.Approval, facts.EnvironmentName) {
	if len(evs) > 0 && !slices.ContainsFunc(evs, func(e analysis.EventActivity) bool {
		return e.Name() != workflow.EventNamePullRequestTarget || e.ActivityType() != workflow.ActivityTypeLabeled
	}) {
		return analysis.ApprovalLabel, facts.EnvironmentName{}
	}
	if j == nil {
		return analysis.ApprovalNone, facts.EnvironmentName{}
	}
	env := j.Environment
	if env.Status != workflow.Present || env.Value.Parts != nil {
		return analysis.ApprovalNone, facts.EnvironmentName{}
	}
	name, err := facts.ParseEnvironmentName(env.Value.AsString())
	if err != nil {
		return analysis.ApprovalNone, facts.EnvironmentName{}
	}
	return analysis.ApprovalEnvironment, name
}

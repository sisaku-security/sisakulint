package boundary

import (
	"reflect"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func TestHoldingsOf(t *testing.T) {
	got := HoldingsOf([]lint.Gain{lint.GainRunCode, lint.GainSetEnv, lint.GainReadSecrets, lint.GainUseRegistryAccount})
	if want := []Holding{HoldingSecrets, HoldingWriteTokenSecretsOrCache}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if got := HoldingsOf([]lint.Gain{lint.GainUseRegistryAccount}); len(got) != 0 {
		t.Errorf("a gain the tables do not compare: %v", got)
	}
}

// groupsOfRules are the sets of holdings the actors of the rules with no
// event need, and the groups of the runs of each, as the rows of
// grants.go make them.
func groupsOfRules() map[string][][]RunRef {
	refs := func(h PRHead, es ...workflow.EventName) []RunRef {
		var out []RunRef
		for _, e := range es {
			out = append(out, RunRef{e, h})
		}
		return out
	}
	prEvents := []workflow.EventName{workflow.EventNamePullRequest, workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment}
	forkPR, branchPR := refs(PRHeadFork, prEvents...), refs(PRHeadRepository, prEvents...)
	rest := append(refs(PRHeadFork, workflow.EventNamePullRequestTarget), refs(PRHeadRepository, workflow.EventNamePullRequestTarget)...)
	rest = append(rest, refs(PRHeadNone, workflow.EventNameWorkflowRun, workflow.EventNameIssueComment, workflow.EventNameIssues, workflow.EventNamePush,
		workflow.EventNameDiscussion, workflow.EventNameDiscussionComment, workflow.EventNameFork, workflow.EventNameGollum,
		workflow.EventNameWorkflowDispatch, workflow.EventNameSchedule,
		workflow.EventNameBranchProtectionRule, workflow.EventNameCheckRun, workflow.EventNameCheckSuite, workflow.EventNameCreate, workflow.EventNameDelete,
		workflow.EventNameDeployment, workflow.EventNameDeploymentStatus, workflow.EventNameLabel, workflow.EventNameMilestone, workflow.EventNameRegistryPackage,
		workflow.EventNamePageBuild, workflow.EventNamePublic, workflow.EventNameRelease, workflow.EventNameRepositoryDispatch, workflow.EventNameStatus, workflow.EventNameWatch,
		workflow.EventNameMergeGroup, workflow.EventNameWorkflowCall,
		workflow.EventNameImageVersion, workflow.EventNameInteractiveComponent, workflow.EventNameMember, workflow.EventNameProject, workflow.EventNameProjectCard,
		workflow.EventNameProjectColumn, workflow.EventNameDynamic, workflow.EventNamePullRequestComment)...)
	two := [][]RunRef{forkPR, append(append([]RunRef{}, branchPR...), rest...)}
	return map[string][][]RunRef{
		"secrets":                     two,
		"write-token":                 two,
		"secrets write-token":         two,
		"secrets write-token cache 4": {forkPR, branchPR, rest},
	}
}

var holdingsOfRules = map[string][]Holding{
	"secrets":                     {HoldingSecrets},
	"write-token":                 {HoldingWriteToken},
	"secrets write-token":         {HoldingSecrets, HoldingWriteToken},
	"secrets write-token cache 4": {HoldingSecrets, HoldingWriteToken, HoldingWriteCache, HoldingWriteTokenSecretsOrCache},
}

func TestRunGroups(t *testing.T) {
	for name, want := range groupsOfRules() {
		if got := RunGroups(holdingsOfRules[name]); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}
}

// TestRunGroupsDiffer: the first runs of two groups differ, for some
// answer, in whether they run or in what they hold of hs.
func TestRunGroupsDiffer(t *testing.T) {
	tb := rows()
	answers := every(tb.allRunQueries())
	for name, hs := range holdingsOfRules {
		gs := RunGroups(hs)
		for i := range gs {
			for j := i + 1; j < len(gs); j++ {
				if tb.runKey(gs[i][0], hs, answers) == tb.runKey(gs[j][0], hs, answers) {
					t.Errorf("%s: %v and %v hold alike", name, gs[i][0], gs[j][0])
				}
			}
		}
	}
}

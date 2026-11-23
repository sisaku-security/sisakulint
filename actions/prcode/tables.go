package prcode

import (
	"time"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// prCodeEvents are the events an attacker triggers whose run has the
// repository's secrets and a token that may write.
var prCodeEvents = []workflow.EventName{
	workflow.EventNameIssueComment,      // a comment on a pull request
	workflow.EventNamePullRequestTarget, // a pull request from a fork
	workflow.EventNameWorkflowRun,       // after a run that a pull request from a fork triggered
	// a commit status or a check run that an app outside GitHub Actions
	// makes for a commit of a pull request from a fork (seen on GitHub on
	// 2026-11-05 and 2026-11-06)
	workflow.EventNameStatus,
	workflow.EventNameCheckSuite,
	workflow.EventNameCheckRun,
}

// notOnPullRequest are the activity types of issue_comment whose comment is
// never on a pull request, so that the issue's number names none: "Comment
// pinning is not supported on Pull Requests" (PinIssueCommentInput of
// src/graphql/data/fpt/schema.docs.graphql, github/docs
// ba6f6f9b9b31c4f0a991fbcb1005080526424804).
var notOnPullRequest = []workflow.ActivityType{workflow.ActivityTypePinned, workflow.ActivityTypeUnpinned}

// refKind is what a reference in a checkout's input names.
type refKind uint8

const (
	refCommit refKind = iota // a commit of the pull request: in ref, the tree on its own
	refBranch                // the name of its branch: the tree only with the fork as the repository
	refFork                  // the fork: in repository
)

// treeRef is a reference whose value names the code of a pull request
// and the events whose payload has it.
type treeRef struct {
	path   []string // * is a star or an index
	kind   refKind
	events []workflow.EventName
	// bypasses: not a value the guard of actions/checkout compares (head.sha
	// and merge_commit_sha on pull_request_target)
	bypasses bool
}

var (
	onPRTarget = []workflow.EventName{workflow.EventNamePullRequestTarget}
	onRun      = []workflow.EventName{workflow.EventNameWorkflowRun}
	onComment  = []workflow.EventName{workflow.EventNameIssueComment}
	onStatus   = []workflow.EventName{workflow.EventNameStatus}
	onSuite    = []workflow.EventName{workflow.EventNameCheckSuite}
	onCheckRun = []workflow.EventName{workflow.EventNameCheckRun}
)

var treeRefs = []treeRef{
	{[]string{"github", "event", "pull_request", "head", "sha"}, refCommit, onPRTarget, false},
	{[]string{"github", "event", "pull_request", "merge_commit_sha"}, refCommit, onPRTarget, false},
	// on synchronize, after is the head's commit and before the head before
	// the push, both the author's
	{[]string{"github", "event", "after"}, refCommit, onPRTarget, false},
	{[]string{"github", "event", "before"}, refCommit, onPRTarget, true},
	{[]string{"github", "event", "workflow_run", "head_sha"}, refCommit, onRun, false},
	{[]string{"github", "event", "workflow_run", "head_commit", "id"}, refCommit, onRun, false},
	// the commit of a commit status or a check run, which held the SHA of the
	// commit of a pull request from a fork (seen on GitHub on 2026-11-06);
	// check_suite.after and check_suite.before were null for that commit
	{[]string{"github", "event", "sha"}, refCommit, onStatus, false},
	{[]string{"github", "event", "commit", "sha"}, refCommit, onStatus, false},
	{[]string{"github", "event", "check_suite", "head_sha"}, refCommit, onSuite, false},
	{[]string{"github", "event", "check_suite", "head_commit", "id"}, refCommit, onSuite, false},
	{[]string{"github", "event", "check_run", "head_sha"}, refCommit, onCheckRun, false},
	{[]string{"github", "event", "check_run", "check_suite", "head_sha"}, refCommit, onCheckRun, false},
	{[]string{"github", "event", "pull_request", "head", "ref"}, refBranch, onPRTarget, false},
	{[]string{"github", "head_ref"}, refBranch, onPRTarget, false},
	{[]string{"github", "event", "workflow_run", "head_branch"}, refBranch, onRun, false},
	{[]string{"github", "event", "pull_request", "head", "repo", "full_name"}, refFork, onPRTarget, false},
	{[]string{"github", "event", "workflow_run", "head_repository", "full_name"}, refFork, onRun, false},
}

// prNumbers are the references whose value is the number of a pull
// request, which refs/pull/<n>/head and refs/pull/<n>/merge name, and the
// events whose payload has it.
var prNumbers = []treeRef{
	{[]string{"github", "event", "pull_request", "number"}, refCommit, onPRTarget, false},
	{[]string{"github", "event", "number"}, refCommit, onPRTarget, false},
	{[]string{"github", "event", "issue", "number"}, refCommit, onComment, false},
	{[]string{"github", "event", "workflow_run", "pull_requests", "*", "number"}, refCommit, onRun, false},
}

// baseRepos are the references a repository input may have that name the
// base repository, not a fork; baseRefs those of a ref that name a commit
// or a branch of the base, which an attacker shapes (taint's table says
// Structured) only by choosing among the base's branches.
var (
	baseRepos = [][]string{
		{"github", "repository"},
		{"github", "event", "repository", "full_name"},
		{"github", "event", "pull_request", "base", "repo", "full_name"},
	}
	baseRefs = [][]string{
		{"github", "ref"},
		{"github", "sha"},
		{"github", "base_ref"},
		{"github", "ref_name"},
		{"github", "event", "pull_request", "base", "ref"},
		{"github", "event", "pull_request", "base", "sha"},
		{"github", "event", "repository", "default_branch"},
	}
)

// unknownRoots are the contexts of a ref whose value the tables cannot
// tell: what a step or a job computes, what a caller gives, what a step may
// set at run time, a repository's variable.
var unknownRoots = []string{"steps", "needs", "inputs", "env", "matrix", "vars"}

// guardedFrom is, for each major version of actions/checkout, the first
// release that refuses a fork's code; a major from
// 7 on is 7.0.0, and major 1 has none.
var guardedFrom = map[int][3]int{2: {2, 8, 0}, 3: {3, 7, 0}, 4: {4, 4, 0}, 5: {5, 1, 0}, 6: {6, 1, 0}, 7: {7, 0, 0}}

// guardCommits are the commits of those releases: a commit of
// actions/checkout refuses a fork's code when it has one of them in its
// history.
var guardCommits = []string{
	"9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0", // v7.0.0
	"d23441a48e516b6c34aea4fa41551a30e30af803", // v6.1.0
	"fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09", // v5.1.0
	"11d5960a326750d5838078e36cf38b85af677262", // v4.4.0
	"a37ce9120846195fa4ece8f58b268e6043cb2f26", // v3.7.0
	"0717577d45739eb3c851188b29f50ed6c0b2194e", // v2.8.0
}

// releaseCommits are the commits the tags of the releases with the guard
// point to (2026-09-28), the major tags included: v7 and v7.0.1 are
// 3d3c42e5, v6 to v2 the backports of guardCommits. commit-sha's fix pins a
// tag to the commit it points to, so a checkout pinned to one of them has
// the guard with no fact asked, and the run again after that fix makes no
// new finding.
var releaseCommits = append([]string{"3d3c42e5aac5ba805825da76410c181273ba90b1"}, guardCommits...) // v7.0.1

// releaseCommitsOn is the day releaseCommits were taken: a release of
// actions/checkout published on it or later must be added
// (upstream.CheckTable).
var releaseCommitsOn = time.Date(2026, 9, 28, 0, 0, 0, 0, time.UTC)

// GuardCommits are the commits of guardCommits.
func GuardCommits() []facts.SHA {
	out := make([]facts.SHA, len(guardCommits))
	for i, c := range guardCommits {
		s, err := facts.ParseSHA(c)
		if err != nil {
			panic(err)
		}
		out[i] = s
	}
	return out
}

// CheckoutRepo is the repository of actions/checkout, which GuardCommits
// are of; actions/artifact and actions/ir refer to it.
var CheckoutRepo = func() facts.Repo {
	r, err := facts.ParseRepo("actions/checkout")
	if err != nil {
		panic(err)
	}
	return r
}()

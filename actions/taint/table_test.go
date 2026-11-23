package taint

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// path is the reference src as a path.
func path(t *testing.T, src string) []expr.PathElem {
	t.Helper()
	n, errs := expr.Parse(src)
	if len(errs) > 0 {
		t.Fatalf("Parse(%q): %v", src, errs)
	}
	p, ok := expr.AccessPath(n)
	if !ok {
		t.Fatalf("%q is not a reference", src)
	}
	return p
}

func TestLookup(t *testing.T) {
	for _, c := range []struct {
		event, action, ref string
		want               Control
	}{
		{"issues", "", "github.event.issue.title", ControlArbitrary},
		{"issues", "", "GitHub.Event.Issue.Title", ControlArbitrary},
		{"issues", "", "github['event']['issue'].body", ControlArbitrary},
		// the payload of push has no issue
		{"push", "", "github.event.issue.title", ControlAbsent},
		{"push", "", "github.event.head_commit.message", ControlArbitrary},
		{"push", "", "github.event.after", ControlFixed},
		// a branch's name: no line break (overrides.tsv)
		{"pull_request_target", "", "github.event.pull_request.head.ref", ControlStructured},
		// a review that an attacker can start is of a pull request from a
		// branch of the repository: its head and its diff are not theirs
		{"pull_request_review", "submitted", "github.event.pull_request.head.ref", ControlFixed},
		{"pull_request_review", "submitted", "github.event.pull_request.head.repo.description", ControlFixed},
		{"pull_request_review", "submitted", "github.event.pull_request.title", ControlArbitrary},
		{"pull_request_review", "submitted", "github.event.review.body", ControlArbitrary},
		{"pull_request_review", "submitted", "github.event.review.commit_id", ControlFixed},
		{"pull_request_review_comment", "created", "github.event.pull_request.head.ref", ControlFixed},
		{"pull_request_review_comment", "created", "github.event.comment.diff_hunk", ControlFixed},
		{"pull_request_review_comment", "created", "github.event.comment.path", ControlFixed},
		{"pull_request_review_comment", "created", "github.event.comment.commit_id", ControlFixed},
		{"pull_request_review_comment", "created", "github.event.comment.original_commit_id", ControlFixed},
		{"pull_request_review_comment", "created", "github.event.comment.body", ControlArbitrary},
		{"workflow_run", "", "github.event.workflow_run.head_branch", ControlStructured},
		// the name of the event of the run that triggered workflow_run, as github.event_name of that run (GHSL-2026-207)
		{"workflow_run", "", "github.event.workflow_run.event", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.base.ref", ControlFixed},
		{"issues", "transferred", "github.event.changes.new_repository.default_branch", ControlStructured},
		{"issues", "opened", "github.event.changes.old_repository.master_branch", ControlStructured},
		{"merge_group", "", "github.event.merge_group.head_ref", ControlFixed},
		// a pull request of the list may be to another repository of the fork network
		{"workflow_run", "", "github.event.workflow_run.pull_requests.*.base.ref", ControlStructured},
		{"pull_request_target", "", "github.event.pull_request.head.sha", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.number", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.html_url", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.labels.*.name", ControlArbitrary},
		{"pull_request_target", "", "github.event.pull_request.labels[0].name", ControlArbitrary},
		// a whole object, which toJSON writes out
		{"pull_request_target", "", "github.event.pull_request", ControlArbitrary},
		{"pull_request_target", "", "github.event", ControlArbitrary},
		{"pull_request_target", "", "github", ControlArbitrary},
		// a field the schema does not have, under a key the payload has: not known
		{"issues", "", "github.event.issue.no_such_field", ControlUnknown},
		// the actions of the event: changes is in edited (and in opened, with old_issue), not in labeled
		{"issues", "edited", "github.event.changes.title.from", ControlArbitrary},
		{"issues", "labeled", "github.event.changes.title.from", ControlAbsent},
		{"issues", "opened", "github.event.changes.title.from", ControlUnknown},
		// an action whose webhook has its action in
		// the branches of a oneOf
		{"pull_request_target", "review_requested", "github.event.pull_request.title", ControlArbitrary},
		// activity types the table has from v12.2.0: their own rows
		{"pull_request_target", "stacked", "github.event.pull_request.title", ControlArbitrary},
		{"issues", "field_added", "github.event.issue.title", ControlArbitrary},
		{"issues", "field_added", "github.event.issue.number", ControlFixed},
		{"issues", "field_added", "github.event.pull_request.title", ControlAbsent},
		// the payload of field_added has no label (unlisted-activity-type, gone)
		{"issues", "field_added", "github.event.label.name", ControlAbsent},
		// a stack holds branches of the repository alone (overrides.tsv)
		{"pull_request_target", "opened", "github.event.pull_request.stack.base.ref", ControlFixed},
		{"pull_request_target", "opened", "github.event.pull_request.stack.size", ControlFixed},
		// a comment pinned or unpinned: the comment, which an outsider may
		// have written (as observed on 2026-10-14); no pull_request in
		// the payload
		{"issue_comment", "pinned", "github.event.comment.body", ControlArbitrary},
		{"issue_comment", "unpinned", "github.event.comment.body", ControlArbitrary},
		{"issue_comment", "pinned", "github.event.comment.pin.pinned_by.login", ControlFixed},
		{"issue_comment", "pinned", "github.event.pull_request.title", ControlAbsent},
		// what the repository's owners set, and a ref pushed to (corpus)
		{"pull_request_target", "", "github.event.repository.name", ControlFixed},
		// a repository's name: no line break (overrides.tsv)
		{"pull_request_target", "", "github.event.pull_request.head.repo.name", ControlStructured},
		{"pull_request_target", "", "github.event.pull_request.head.repo.full_name", ControlStructured},
		{"fork", "", "github.event.forkee.full_name", ControlStructured},
		{"fork", "", "github.event.forkee.name", ControlStructured},
		{"fork", "", "github.event.forkee.description", ControlStructured},
		{"workflow_run", "", "github.event.workflow_run.head_repository.full_name", ControlStructured},
		{"workflow_run", "", "github.event.workflow_run.pull_requests.*.head.repo.name", ControlStructured},
		{"issues", "transferred", "github.event.changes.new_repository.full_name", ControlStructured},
		// the repository the workflow runs in
		{"pull_request_target", "", "github.event.pull_request.base.repo.full_name", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.base.repo.name", ControlFixed},
		{"workflow_run", "", "github.event.workflow_run.repository.full_name", ControlFixed},
		{"workflow_run", "", "github.event.workflow_run.repository.name", ControlFixed},
		// what GitHub makes of an account's login and ID, and sets for it
		// (as observed on 2026-10-22: the sender of the events of the runs)
		{"gollum", "", "github.event.sender.html_url", ControlFixed},
		{"gollum", "", "github.event.sender.avatar_url", ControlFixed},
		{"gollum", "", "github.event.sender.events_url", ControlFixed},
		{"gollum", "", "github.event.sender.starred_url", ControlFixed},
		{"gollum", "", "github.event.sender.gravatar_id", ControlFixed},
		{"gollum", "", "github.event.sender.type", ControlFixed},
		{"gollum", "", "github.event.sender.user_view_type", ControlFixed},
		{"push", "", "github.event.sender.url", ControlFixed},
		{"issues", "", "github.event.issue.user.html_url", ControlFixed},
		{"issues", "", "github.event.issue.assignees[0].type", ControlFixed},
		{"issues", "", "github.event.issue.labels[0].archived_by.url", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.head.repo.owner.html_url", ControlFixed},
		// what the owner of an account writes, and the whole sender with it;
		// the payloads of push, gollum and fork had no name in sender on
		// 2026-10-22, though the account had a profile name
		{"gollum", "", "github.event.sender.name", ControlFixed},
		{"fork", "", "github.event.sender.name", ControlFixed},
		{"push", "", "github.event.sender.name", ControlFixed},
		{"issues", "", "github.event.sender.name", ControlArbitrary},
		{"gollum", "", "github.event.sender.email", ControlArbitrary},
		{"gollum", "", "github.event.sender.starred_at", ControlArbitrary},
		{"gollum", "", "github.event.sender", ControlArbitrary},
		// the pusher and the sender of push, and the account that merged a
		// pull request or enabled auto-merge for it: each holds a credential
		// that can push or merge, which no attacker holds
		{"push", "", "github.event.pusher.name", ControlFixed},
		{"push", "", "github.event.pusher.email", ControlFixed},
		{"push", "", "github.event.pusher.username", ControlFixed},
		{"push", "", "GitHub.Event.Pusher.Email", ControlFixed},
		{"push", "", "github.event.pusher", ControlFixed},
		{"push", "", "github.event.pusher.date", ControlFixed},
		{"push", "", "github.event.sender.email", ControlFixed},
		{"push", "", "github.event.sender.starred_at", ControlFixed},
		{"push", "", "github.event.sender", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.merged_by.email", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.auto_merge.enabled_by.name", ControlFixed},
		{"pull_request_review", "", "github.event.pull_request.auto_merge.enabled_by.email", ControlFixed},
		// the line of merged_by and auto_merge.enabled_by has no events: every
		// event whose payload has the path
		{"pull_request_target", "", "github.event.pull_request.merged_by.name", ControlFixed},
		{"pull_request_review_comment", "", "github.event.pull_request.auto_merge.enabled_by.name", ControlFixed},
		// the line of sender is for push alone
		{"pull_request_target", "", "github.event.sender.email", ControlArbitrary},
		// what the author of a pull request writes stays the attacker's
		{"push", "", "github.event.head_commit.author.name", ControlArbitrary},
		{"push", "", "github.event.commits[0].author.email", ControlStructured},
		// objects that are not an account's alone, or whose values were not seen
		{"pull_request_target", "", "github.event.pull_request.requested_reviewers[0].html_url", ControlStructured},
		{"issue_comment", "", "github.event.comment.performed_via_github_app.owner.html_url", ControlStructured},
		{"push", "", "github.event.organization.url", ControlStructured},
		{"pull_request_target", "", "github.event.pull_request.labels[0].url", ControlArbitrary},
		{"pull_request_target", "", "github.event.pull_request.milestone.html_url", ControlStructured},
		{"gollum", "", "github.event.pages[0].html_url", ControlStructured},
		// a repository's URLs, of owner/name: the repository the workflow
		// runs in, and one an attacker names; mirror_url is not GitHub's
		{"pull_request_target", "", "github.event.pull_request.base.repo.clone_url", ControlFixed},
		{"workflow_run", "", "github.event.workflow_run.repository.html_url", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.head.repo.html_url", ControlStructured},
		{"pull_request_target", "", "github.event.pull_request.head.repo.clone_url", ControlStructured},
		{"fork", "", "github.event.forkee.ssh_url", ControlStructured},
		{"workflow_run", "", "github.event.workflow_run.head_repository.html_url", ControlStructured},
		{"pull_request_target", "", "github.event.pull_request.head.repo.mirror_url", ControlStructured},
		{"fork", "", "github.event.forkee.mirror_url", ControlFixed},
		// the URLs of a push
		{"push", "", "github.event.head_commit.url", ControlFixed},
		{"push", "", "github.event.commits[0].url", ControlFixed},
		{"push", "", "github.event.compare", ControlFixed},
		// the URLs of the objects of the repository the workflow runs in, as
		// the observed payloads had them
		{"issues", "", "github.event.issue.html_url", ControlFixed},
		{"issue_comment", "", "github.event.comment.html_url", ControlFixed},
		{"issue_comment", "", "github.event.issue.pull_request.html_url", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request.statuses_url", ControlFixed},
		{"pull_request_target", "", "github.event.pull_request._links.html.href", ControlFixed},
		{"pull_request_review", "", "github.event.review.html_url", ControlFixed},
		{"discussion", "", "github.event.discussion.html_url", ControlFixed},
		{"discussion", "answered", "github.event.answer.html_url", ControlFixed},
		{"workflow_run", "", "github.event.workflow_run.html_url", ControlFixed},
		{"workflow_run", "", "github.event.workflow_run.artifacts_url", ControlFixed},
		// a pull request of the run may be to another repository of the fork network
		{"workflow_run", "", "github.event.workflow_run.pull_requests[0].url", ControlStructured},
		// objects that the observed payloads did not have, which stay as they
		// were
		{"workflow_run", "", "github.event.workflow_run.previous_attempt_url", ControlStructured},
		{"issues", "", "github.event.issue.pinned_comment.html_url", ControlStructured},
		{"discussion", "", "github.event.old_answer.html_url", ControlArbitrary},
		{"issues", "transferred", "github.event.changes.new_issue.html_url", ControlStructured},
		{"issues", "opened", "github.event.changes.old_issue.html_url", ControlStructured},
		{"discussion", "transferred", "github.event.changes.new_discussion.html_url", ControlArbitrary},
		// an account in those objects is still an account
		{"discussion", "", "github.event.old_answer.user.html_url", ControlFixed},
		{"issues", "transferred", "github.event.changes.new_issue.user.html_url", ControlFixed},
		// the homepage of the fork made is the forked repository's: neither
		// the request nor the form that makes a fork has one (2026-10-22);
		// a homepage elsewhere is still what its administrator writes
		{"fork", "", "github.event.forkee.homepage", ControlFixed},
		{"discussion", "transferred", "github.event.changes.new_repository.homepage", ControlArbitrary},
		{"push", "", "github.event.ref", ControlFixed},
		// names below github, from the overrides
		{"pull_request_target", "", "github.head_ref", ControlStructured},
		// head_ref has a value only for pull requests (the contexts document)
		{"issues", "", "github.head_ref", ControlAbsent},
		{"issues", "", "github.run_id", ControlFixed},
		{"issues", "", "github.repository", ControlFixed},
		{"issues", "", "github.no_such_name", ControlUnknown},
		// not what the table is for
		{"issues", "", "env.TITLE", ControlUnknown},
		{"pull_request", "", "github.event.pull_request.title", ControlUnknown},
	} {
		e, err := workflow.ParseEventName(c.event)
		if err != nil {
			t.Fatal(err)
		}
		a := workflow.ActivityTypeUnset
		if c.action != "" {
			if a, err = workflow.ParseActivityType(c.action); err != nil {
				t.Fatal(err)
			}
		}
		got := Lookup(e, a, path(t, c.ref))
		if got != c.want {
			t.Errorf("Lookup(%s, %q, %s) = %v, want %v", c.event, c.action, c.ref, got, c.want)
		}
	}
}

// TestLookupAppCommitEvents: on status, check_suite and check_run, which an
// app outside GitHub Actions starts for a commit of a pull request from a
// fork, the attacker writes the message and the names of the author and the
// committer of the commit (seen on GitHub on 2026-11-05 and 2026-11-06);
// the SHAs, the values GitHub makes, the names of the branches of the
// repository and the values the app writes are not the attacker's.
func TestLookupAppCommitEvents(t *testing.T) {
	for _, c := range []struct {
		event, action, ref string
		want               Control
	}{
		{"status", "", "github.event.commit.commit.message", ControlArbitrary},
		{"status", "", "github.event.commit.commit.author.name", ControlArbitrary},
		{"status", "", "github.event.commit.commit.committer.name", ControlArbitrary},
		// the account of GitHub that the email of the commit is of: its object
		// had no name and no email (seen on GitHub on 2026-11-06)
		{"status", "", "github.event.commit.author.name", ControlFixed},
		{"status", "", "github.event.commit.committer.email", ControlFixed},
		{"status", "", "github.event.commit.author.login", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.head_commit.message", ControlArbitrary},
		{"check_suite", "completed", "github.event.check_suite.head_commit.author.name", ControlArbitrary},
		{"check_suite", "completed", "github.event.check_suite.head_commit.committer.name", ControlArbitrary},
		{"status", "", "github.event.sha", ControlFixed},
		{"status", "", "github.event.commit.sha", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.head_sha", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.head_commit.id", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.after", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.before", ControlFixed},
		{"check_run", "created", "github.event.check_run.head_sha", ControlFixed},
		{"check_run", "created", "github.event.check_run.check_suite.head_sha", ControlFixed},
		{"status", "", "github.event.context", ControlFixed},
		{"status", "", "github.event.description", ControlFixed},
		{"status", "", "github.event.target_url", ControlFixed},
		{"status", "", "github.event.created_at", ControlFixed},
		{"check_run", "created", "github.event.check_run.name", ControlFixed},
		{"check_run", "created", "github.event.check_run.output.title", ControlFixed},
		{"check_run", "created", "github.event.check_run.details_url", ControlFixed},
		{"check_run", "created", "github.event.check_run.external_id", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.app.name", ControlFixed},
		{"status", "", "github.event.branches[0].name", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.head_branch", ControlFixed},
		{"check_suite", "completed", "github.event.check_suite.pull_requests[0].head.ref", ControlFixed},
	} {
		e, err := workflow.ParseEventName(c.event)
		if err != nil {
			t.Fatal(err)
		}
		a := workflow.ActivityTypeUnset
		if c.action != "" {
			if a, err = workflow.ParseActivityType(c.action); err != nil {
				t.Fatal(err)
			}
		}
		if got := Lookup(e, a, path(t, c.ref)); got != c.want {
			t.Errorf("Lookup(%s, %q, %s) = %v, want %v", c.event, c.action, c.ref, got, c.want)
		}
	}
	email := path(t, "github.event.commit.commit.author.email")
	if got := WorkflowCommand(workflow.EventNameStatus, workflow.ActivityTypeUnset, email); got != CommandWritingWritten {
		t.Errorf("WorkflowCommand(status, commit.commit.author.email) = %v, want CommandWritingWritten", got)
	}
}

// TestAccountParents: overrides.tsv reads the URLs and the values GitHub
// sets of an account below a
// key of these names, anywhere in the payload. Each object below such a
// key has login and gravatar_id, and no slug of a team, so that an object
// a pin of the schema adds under such a name, or one that may be a team,
// fails here instead of being read as an account.
func TestAccountParents(t *testing.T) {
	names := []string{"actor", "answer_chosen_by", "archived_by", "assignee", "creator", "enabled_by", "merged_by", "pinned_by", "requested_reviewer", "sender", "triggering_actor", "user"}
	for e, root := range tries() {
		var walk func(n *node, path []string)
		walk = func(n *node, path []string) {
			l := len(path)
			account := l > 0 && slices.Contains(names, path[l-1]) || l > 1 && path[l-2] == "assignees" && path[l-1] == "*"
			if account && len(n.kids) > 0 && (n.kids["login"] == nil || n.kids["gravatar_id"] == nil || n.kids["slug"] != nil) {
				t.Errorf("%s %s: not an account's keys", e, strings.Join(path, "."))
			}
			for k, kid := range n.kids {
				walk(kid, append(slices.Clone(path), k))
			}
		}
		walk(root, nil)
	}
}

func TestAttackerEvents(t *testing.T) {
	var got []string
	for _, e := range TableEvents() {
		got = append(got, e.String())
	}
	want := []string{"check_run", "check_suite", "discussion", "discussion_comment", "fork", "gollum", "issue_comment", "issues", "merge_group", "pull_request_review", "pull_request_review_comment", "pull_request_target", "push", "status", "workflow_run"}
	if !slices.Equal(got, want) {
		t.Errorf("TableEvents = %v, want %v", got, want)
	}
	if a := ActivityTypes(workflow.EventNameIssueComment); !slices.Equal(a, []workflow.ActivityType{workflow.ActivityTypeCreated, workflow.ActivityTypeDeleted, workflow.ActivityTypeEdited, workflow.ActivityTypePinned, workflow.ActivityTypeUnpinned}) {
		t.Errorf("ActivityTypes(issue_comment) = %v", a)
	}
}

// BenchmarkLookup: a reference looked up on every activity type of every
// attacker's event, as for a reusable workflow.
func BenchmarkLookup(b *testing.B) {
	n, _ := expr.Parse("github.event.pull_request.head.repo.owner.login")
	p, _ := expr.AccessPath(n)
	evs := allActivityTypes()
	b.ResetTimer()
	for range b.N {
		for _, e := range evs {
			Lookup(e.Name(), e.ActivityType(), p)
		}
	}
}

// TestTableActivityTypes: each activity type of the table is one of the
// event's (workflow.ActivityTypesOf), so that its pairs are made.
func TestTableActivityTypes(t *testing.T) {
	for _, e := range TableEvents() {
		as := ActivityTypes(e)
		if as == nil {
			as = []workflow.ActivityType{workflow.ActivityTypeUnset}
		}
		for _, a := range as {
			if _, err := analysis.NewEventActivity(e, a); err != nil {
				t.Error(err)
			}
		}
	}
}

// TestTableCoversActivityTypes: each activity type of an attacker's event
// (workflow.ActivityTypesOf) is one the table has. Lookup reads one it does
// not have as every activity type of the event, and so reads the objects of
// other payloads as the attacker's (the false positive form
// unlisted-activity-type that the pin of v12.2.0 took away). A pin of the
// workflow schema that adds an activity type before GitHub's webhooks have
// it fails here.
func TestTableCoversActivityTypes(t *testing.T) {
	for _, e := range TableEvents() {
		have := ActivityTypes(e)
		for _, a := range workflow.ActivityTypesOf(e) {
			if !slices.Contains(have, a) {
				t.Errorf("%s: the table has no activity type %s (update the pin octokit-webhooks)", e, a)
			}
		}
	}
}

// TestAllOfIsConjunction: allOf is all of its branches, so a path takes the
// least an attacker controls of them: the issue of
// issue_comment has author_association both as the enum and as a string.
func TestAllOfIsConjunction(t *testing.T) {
	p := path(t, "github.event.issue.author_association")
	if got := Lookup(workflow.EventNameIssueComment, workflow.ActivityTypeUnset, p); got != ControlFixed {
		t.Errorf("issue_comment issue.author_association: %v, want fixed", got)
	}
}

// TestRepoName: the name of a repository an attacker names may begin with
// -, and holds only ASCII letters, digits, ., - and _; the name of a
// branch, which may hold = and blanks of ${IFS}, is not one.
func TestRepoName(t *testing.T) {
	for _, c := range []struct {
		event, ref string
		want       bool
	}{
		{"pull_request_target", "github.event.pull_request.head.repo.name", true},
		{"fork", "github.event.forkee.name", true},
		{"workflow_run", "github.event.workflow_run.head_repository.name", true},
		{"pull_request_target", "github.head_ref", false},
		{"pull_request_target", "github.event.pull_request.head.ref", false},
		{"pull_request_target", "github.event.pull_request.title", false},
		{"fork", "github.event.forkee.full_name", false},
		{"pull_request_target", "github.event.pull_request.base.repo.name", false},
	} {
		e, err := workflow.ParseEventName(c.event)
		if err != nil {
			t.Fatal(err)
		}
		if got := RepoName(e, workflow.ActivityTypeUnset, path(t, c.ref)); got != c.want {
			t.Errorf("%s %s: %v", c.event, c.ref, got)
		}
	}
}

// TestLeadingDash: an attacker makes a value they write, and the name of a
// pull request's head branch, begin with -; the other
// structured values are not known to.
func TestLeadingDash(t *testing.T) {
	for _, c := range []struct {
		event, ref string
		want       bool
	}{
		{"pull_request_target", "github.head_ref", true},
		{"pull_request_target", "github.event.pull_request.head.ref", true},
		{"pull_request_review", "github.event.pull_request.head.ref", false},
		{"workflow_run", "github.event.workflow_run.pull_requests.*.head.ref", true},
		{"pull_request_target", "github.event.pull_request.title", true},
		{"issues", "github.event.issue.no_such_field", true},
		{"workflow_run", "github.event.workflow_run.head_branch", false},
		{"pull_request_target", "github.event.pull_request.head.label", false},
		{"pull_request_target", "github.event.pull_request.head.repo.html_url", false},
		{"gollum", "github.event.sender.gravatar_id", false},
		{"pull_request_target", "github.event.pull_request.head.sha", false},
		// an object, whose JSON begins with {
		{"pull_request_target", "github.event.pull_request.head", false},
		{"pull_request_target", "github.event", false},
		{"pull_request_target", "github", false},
		{"pull_request_target", "github.event.pull_request.labels.*.name", true},
		{"push", "github.event.issue.title", false},
		// a repository's name may begin with -, owner/name begins with a login
		{"fork", "github.event.forkee.name", true},
		{"pull_request_target", "github.event.pull_request.head.repo.name", true},
		{"fork", "github.event.forkee.full_name", false},
		{"fork", "github.event.forkee.description", false},
		{"pull_request_target", "github.event.pull_request.base.repo.name", false},
		// the title of a wiki page holds no -; its summary
		// is a value nobody writes (fixed)
		{"gollum", "github.event.pages[0].title", false},
		{"gollum", "github.event.pages[0].summary", false},
	} {
		e, err := workflow.ParseEventName(c.event)
		if err != nil {
			t.Fatal(err)
		}
		if got := LeadingDash(e, workflow.ActivityTypeUnset, path(t, c.ref)); got != c.want {
			t.Errorf("%s %s: %v", c.event, c.ref, got)
		}
	}
	for ref, want := range map[string]bool{"github.event.pages[0].title": true, "github.event.pages[0].summary": false, "github.event.pages[0].page_name": false, "github.event.pages": false} {
		if h := hyphenlessLeaf(workflow.EventNameGollum, workflow.ActivityTypeUnset, path(t, ref)); h != want {
			t.Errorf("hyphenlessLeaf of %s: %v", ref, h)
		}
	}
	if c := Lookup(workflow.EventNameGollum, workflow.ActivityTypeUnset, path(t, "github.event.pages[0].summary")); c != ControlFixed {
		t.Errorf("the summary of a wiki page: %v, want ControlFixed", c)
	}
	// the name of a wiki page made on the web interface may begin with -
	// (GitHub turns a + of the title into a -) and holds add-path, but no
	// command that takes a property; a page pushed by git keeps its name
	if !LeadingDash(workflow.EventNameGollum, workflow.ActivityTypeUnset, path(t, "github.event.pages[0].page_name")) {
		t.Error("LeadingDash of the name of a wiki page: false, want true")
	}
	for ref, want := range map[string]bool{"github.event.pages[0].page_name": true, "github.event.pages[0].title": false, "github.event.pages[0].html_url": false, "github.event.pages": false, "github.event.issue.title": false} {
		e := workflow.EventNameGollum
		if ref == "github.event.issue.title" {
			e = workflow.EventNameIssues
		}
		if got := PathCommand(e, workflow.ActivityTypeUnset, path(t, ref)); got != want {
			t.Errorf("PathCommand of %s: %v, want %v", ref, got, want)
		}
	}
	if Lookup(workflow.EventNamePullRequestTarget, workflow.ActivityTypeUnset, path(t, "github.head_ref")) != ControlStructured {
		t.Error("a branch's name is structured to Lookup")
	}
}

// TestWorkflowCommand: whether an attacker can write a workflow command
// of the runner (##[set-env ...]) in a value: a text
// they write, the email of a git commit; not the name of a
// ref, a repository or a label, which hold no : and no [; the other
// structured values are not known.
func TestWorkflowCommand(t *testing.T) {
	for _, c := range []struct {
		event workflow.EventName
		path  string
		want  CommandWriting
	}{
		{workflow.EventNameIssues, "github.event.issue.title", CommandWritingWritten},
		{workflow.EventNamePush, "github.event.head_commit.author.email", CommandWritingWritten},
		{workflow.EventNamePush, "github.event.head_commit.committer.email", CommandWritingWritten},
		{workflow.EventNamePush, "github.event.commits[0].author.email", CommandWritingWritten},
		{workflow.EventNameWorkflowRun, "github.event.workflow_run.head_commit.author.email", CommandWritingWritten},
		{workflow.EventNamePush, "github.event.pusher.email", CommandWritingNone},
		{workflow.EventNameFork, "github.event.forkee.description", CommandWritingUndecided},
		{workflow.EventNamePullRequestTarget, "github.event.pull_request.head.ref", CommandWritingNone},
		{workflow.EventNamePullRequestTarget, "github.head_ref", CommandWritingNone},
		{workflow.EventNamePullRequestTarget, "github.event.pull_request.head.label", CommandWritingNone},
		{workflow.EventNamePullRequestTarget, "github.event.pull_request.head.repo.full_name", CommandWritingNone},
		{workflow.EventNamePullRequestTarget, "github.event.pull_request.head.repo.html_url", CommandWritingNone},
		{workflow.EventNameGollum, "github.event.sender.type", CommandWritingNone},
		{workflow.EventNameWorkflowRun, "github.event.workflow_run.head_branch", CommandWritingNone},
		{workflow.EventNamePullRequestTarget, "github.event.pull_request.head.sha", CommandWritingNone},
		{workflow.EventNamePush, "github.event.head_commit", CommandWritingWritten},
		{workflow.EventNameGollum, "github.event.pages[0].title", CommandWritingNone},
		{workflow.EventNameGollum, "github.event.pages[0].page_name", CommandWritingUndecided},
		{workflow.EventNameGollum, "github.event.pages[0].summary", CommandWritingNone},
	} {
		if got := WorkflowCommand(c.event, workflow.ActivityTypeUnset, path(t, c.path)); got != c.want {
			t.Errorf("%s %s: got %v, want %v", c.event, c.path, got, c.want)
		}
	}
}

// TestLookupText: the value of a path itself, as a ${{ }} writes it as
// text: an object or an array writes Object or Array.
func TestLookupText(t *testing.T) {
	for _, c := range []struct {
		event, action, ref string
		want               Control
		collection         bool
	}{
		{"push", "", "github", ControlFixed, true},
		{"push", "", "github.event", ControlFixed, true},
		{"push", "", "github.event.head_commit", ControlFixed, true}, // an object, or null
		{"push", "", "github.event.head_commit.message", ControlArbitrary, false},
		{"push", "", "github.event.commits", ControlFixed, true},
		{"push", "", "github.event.commits.*", ControlFixed, true},
		{"push", "", "github.event.commits[0].message", ControlArbitrary, false},
		{"push", "", "github.event.commits.*.message", ControlArbitrary, false},
		{"push", "", "github.event.commits.*.added", ControlFixed, true},
		{"push", "", "github.event.commits.*.added.*", ControlArbitrary, false},
		{"push", "", "github.event.head_commit.id", ControlFixed, false},
		// an item is an object, or null: no text an attacker writes
		{"issues", "", "github.event.issue.labels.*", ControlFixed, true},
		{"issues", "", "github.event.issue.labels[0]", ControlFixed, true},
		{"issues", "", "github.event.issue.labels[0].name", ControlArbitrary, false},
		{"issues", "", "github.event.issue.milestone", ControlFixed, true},
		{"issues", "", "github.event.issue.title", ControlArbitrary, false},
		// below a leaf of a text: null; read as Lookup: a key the schema
		// does not have, a payload without it, names below github
		{"issues", "", "github.event.issue.title.x", ControlFixed, false}, // a part of a text is null
		{"issues", "", "github.event.issue.no_such_field", ControlUnknown, false},
		{"push", "", "github.event.issue.title", ControlAbsent, false},
		{"issues", "labeled", "github.event.changes.title.from", ControlAbsent, false},
		{"issues", "opened", "github.event.changes.title.from", ControlUnknown, false},
		{"issues", "edited", "github.event.changes.title.from", ControlArbitrary, false},
		{"issues", "labeled", "github.event.changes", ControlAbsent, false},
		{"pull_request_target", "", "github.head_ref", ControlStructured, false},
		{"issues", "", "env.TITLE", ControlUnknown, false},
		// a key not known of an object with names: maybe one the schema does not have
		{"issue_comment", "created", "github.event[matrix.k]", ControlUnknown, true},
		{"pull_request_target", "", "github.event.pull_request.head[matrix.k]", ControlUnknown, true},
		// an index not known of an array: its items
		{"push", "", "github.event.commits[matrix.k].message", ControlArbitrary, false},
	} {
		e, err := workflow.ParseEventName(c.event)
		if err != nil {
			t.Fatal(err)
		}
		a := workflow.ActivityTypeUnset
		if c.action != "" {
			if a, err = workflow.ParseActivityType(c.action); err != nil {
				t.Fatal(err)
			}
		}
		got, collection := LookupText(e, a, path(t, c.ref))
		if got != c.want || collection != c.collection {
			t.Errorf("LookupText(%s, %q, %s) = %v, %v; want %v, %v", c.event, c.action, c.ref, got, collection, c.want, c.collection)
		}
	}
}

// TestHasItems: the items of an array, which join writes, and none of an
// object of free keys or of names: join writes nothing of an
// object.
func TestHasItems(t *testing.T) {
	for _, c := range []struct {
		event, ref string
		want       bool
	}{
		{"issue_comment", "github.event.comment.performed_via_github_app.permissions", false},
		{"issues", "github.event.changes.new_repository.custom_properties", false},
		{"push", "github.event.head_commit.author", false},
		{"push", "github.event.head_commit.message", false},
		{"push", "github.event.head_commit.added", true},
		{"push", "github.event.commits", true},
		{"push", "github.event.commits[matrix.k].added", true}, // not one path: may be
		{"push", "github.event.nope", true},                    // not in the table: read as Lookup reads it
	} {
		e, err := workflow.ParseEventName(c.event)
		if err != nil {
			t.Fatal(err)
		}
		if got := hasItems(e, path(t, c.ref)); got != c.want {
			t.Errorf("hasItems(%s, %s) = %v, want %v", c.event, c.ref, got, c.want)
		}
	}
}

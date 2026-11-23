package boundary

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// private answers a private repository that may be forked, with the fork
// pull request settings given.
func private(run, write, secrets *bool) Answer {
	by := map[facts.Kind]bool{facts.KindRepoPublic: false, facts.KindRepoAllowForking: true, facts.KindRepoWikiOpen: false}
	for k, v := range map[facts.Kind]*bool{facts.KindRepoForkPRRunWorkflows: run, facts.KindRepoForkPRWriteTokens: write, facts.KindRepoForkPRSecrets: secrets} {
		if v != nil {
			by[k] = *v
		}
	}
	return answers(by)
}

var yes, no = func() *bool { b := true; return &b }(), func() *bool { b := false; return &b }()

// TestNoRunNoRunner: where fork pull requests do not run, one who reads
// cannot put their run on a self-hosted runner, and the run of a fork
// pull request is on none.
func TestNoRunNoRunner(t *testing.T) {
	r := Cross(lint.AttackerForkPRAuthor, RoleRead, RunRef{workflow.EventNamePullRequest, PRHeadFork}, private(no, no, no))
	if got := r.Crossings[lint.GainPersistOnRunner]; got != CrossingNone {
		t.Errorf("persist-on-runner where fork pull requests do not run: %s, want none", got)
	}
}

// TestPrivateReviewNotFalse: the private rows of the review events follow
// the settings as pull_request does, unverified.
func TestPrivateReviewNotFalse(t *testing.T) {
	for _, e := range []workflow.EventName{workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment} {
		d, b := RunDims(RunRef{e, PRHeadFork}, private(yes, no, yes))
		if d[lint.GainReadSecrets] != expr.TruthTrue || b != BasisUnverified {
			t.Errorf("%s from a fork, private, secrets sent: secrets %v, basis %s", e, d[lint.GainReadSecrets], b)
		}
	}
}

// TestExhaustiveRowsKeepFalse: rows that cover every answer keep what all
// of them say, when the fact that tells them apart is not known.
func TestExhaustiveRowsKeepFalse(t *testing.T) {
	d, _ := RunDims(RunRef{workflow.EventNamePullRequest, PRHeadFork}, private(yes, no, nil))
	if d[lint.GainWriteWithToken] != expr.TruthFalse {
		t.Errorf("write-with-token with secrets unknown: %v, want false", d[lint.GainWriteWithToken])
	}
}

// TestBasisOfRows: the basis of each row of a run: documented, observed
// or unverified.
func TestBasisOfRows(t *testing.T) {
	public := answers(map[facts.Kind]bool{facts.KindRepoPublic: true, facts.KindRepoAllowForking: true, facts.KindRepoWikiOpen: false})
	for _, c := range []struct {
		name string
		ref  RunRef
		a    Answer
		want Basis
	}{
		{"pull_request_target from a branch", RunRef{workflow.EventNamePullRequestTarget, PRHeadRepository}, public, BasisDocumented},
		{"discussion: inferred from the default branch", RunRef{workflow.EventNameDiscussion, PRHeadNone}, public, BasisUnverified},
		{"run, no write, no secrets", RunRef{workflow.EventNamePullRequest, PRHeadFork}, private(yes, no, no), BasisObserved},
		{"write tokens", RunRef{workflow.EventNamePullRequest, PRHeadFork}, private(yes, yes, no), BasisObserved},
		{"secrets", RunRef{workflow.EventNamePullRequest, PRHeadFork}, private(yes, no, yes), BasisObserved},
		{"no run", RunRef{workflow.EventNamePullRequest, PRHeadFork}, private(no, no, no), BasisObserved},
	} {
		if _, b := RunDims(c.ref, c.a); b != c.want {
			t.Errorf("%s: basis %s, want %s", c.name, b, c.want)
		}
	}
	privateAnswers := private(no, no, no)
	for _, a := range []lint.Attacker{lint.AttackerIssueAuthor, lint.AttackerCommenter, lint.AttackerForkPRAuthor} {
		if open, b := ChannelWritable(a, RoleNone, privateAnswers); open != expr.TruthFalse || b != BasisDocumented {
			t.Errorf("%s of no access to a private repository: %v %s, want false documented", a, open, b)
		}
	}
}

// every is each answer of qs, true or false.
func every(qs []facts.Query) []Answer {
	out := []Answer{}
	for n := range 1 << len(qs) {
		by := map[facts.Kind]bool{}
		for i, q := range qs {
			by[q.Kind()] = n&(1<<i) != 0
		}
		out = append(out, answers(by))
	}
	return out
}

// TestRowsExhaustive: for every answer of their facts, some row of each
// run, role, channel and pathway holds, so that what the rows that may hold all
// say is what holds (cross.go reads them so).
func TestRowsExhaustive(t *testing.T) {
	tb := rows()
	refs := map[RunRef]bool{}
	for _, g := range tb.grants {
		refs[RunRef{g.Event, g.Head}] = true
	}
	for ref := range refs {
		for _, a := range every(tb.runQueries(ref)) {
			n := 0
			for _, g := range tb.grants {
				if g.Event == ref.Event && g.Head == ref.Head && holds(g.Condition, a) == truthT {
					n++
				}
			}
			if n == 0 {
				t.Errorf("%s %s: no row holds for an answer", ref.Event, ref.Head)
			}
		}
	}
	for _, r := range Roles() {
		for _, a := range every(queries([]lint.Condition{lint.All(conditionsOf(tb.baselines, r)...)})) {
			if !anyHolds(tb.baselines, r, a) {
				t.Errorf("%s: no baseline holds for an answer", r)
			}
		}
	}
	type pair struct {
		a lint.Attacker
		r Role
	}
	pairs := map[pair]bool{}
	for _, c := range tb.channels {
		pairs[pair{c.Attacker, c.Role}] = true
	}
	for p := range pairs {
		for _, a := range every(tb.channelQueries(p.a, p.r)) {
			n := 0
			for _, c := range tb.channels {
				if c.Attacker == p.a && c.Role == p.r && holds(c.Condition, a) == truthT {
					n++
				}
			}
			if n == 0 {
				t.Errorf("%s %s: no channel row holds for an answer", p.a, p.r)
			}
		}
	}
	ways := map[pair]bool{}
	for _, p := range tb.pathways {
		ways[pair{p.Attacker, p.Role}] = true
	}
	for p := range ways {
		for _, a := range every(tb.pathwayQueries(p.a, p.r)) {
			n := 0
			for _, w := range tb.pathways {
				if w.Attacker == p.a && w.Role == p.r && holds(w.Condition, a) == truthT {
					n++
				}
			}
			if n == 0 {
				t.Errorf("%s %s: no pathway row holds for an answer", p.a, p.r)
			}
		}
	}
}

func conditionsOf(bs []RoleBaseline, r Role) []lint.Condition {
	var cs []lint.Condition
	for _, b := range bs {
		if b.Role == r {
			cs = append(cs, b.Condition)
		}
	}
	return cs
}

func anyHolds(bs []RoleBaseline, r Role, a Answer) bool {
	for _, b := range bs {
		if b.Role == r && holds(b.Condition, a) == truthT {
			return true
		}
	}
	return false
}

// TestForkAuthorReachesNoBranch: the author of a pull request from a fork
// writes no pull request from a branch of the repository.
func TestForkAuthorReachesNoBranch(t *testing.T) {
	public := answers(map[facts.Kind]bool{facts.KindRepoPublic: true, facts.KindRepoAllowForking: true, facts.KindRepoWikiOpen: false})
	if r := Cross(lint.AttackerForkPRAuthor, RoleRead, RunRef{workflow.EventNamePullRequest, PRHeadRepository}, public); r.Channel != expr.TruthFalse {
		t.Errorf("fork-pr-author on pull_request repository: channel %v, want false", r.Channel)
	}
	if r := Cross(lint.AttackerCommenter, RoleRead, RunRef{workflow.EventNamePullRequestReview, PRHeadRepository}, public); r.Channel != expr.TruthTrue {
		t.Errorf("a review on a pull request from a branch: channel %v, want true", r.Channel)
	}
	if ReachesHead(lint.AttackerForkPRAuthor, PRHeadRepository) || !ReachesHead(lint.AttackerForkPRAuthor, PRHeadFork) {
		t.Error("ReachesHead of fork-pr-author")
	}
}

// TestBranchReviewObserved: no sentence names the review events from a
// branch of the repository, and the run of a review by an account with no
// role in a public repository was seen with the secret and a token that
// writes.
func TestBranchReviewObserved(t *testing.T) {
	for _, e := range []workflow.EventName{workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment} {
		if _, b := RunDims(RunRef{e, PRHeadRepository}, answers(nil)); b != BasisObserved {
			t.Errorf("%s from a branch: basis %s, want observed", e, b)
		}
	}
	if _, b := RunDims(RunRef{workflow.EventNamePullRequest, PRHeadRepository}, answers(nil)); b != BasisDocumented {
		t.Errorf("pull_request from a branch: basis %s, want documented", b)
	}
}

// TestPrivateWikiClosedToNone: a private repository's wiki is open to no
// one without access, whatever repo.wiki-open says (repo.wiki-open is true
// only of a public repository).
func TestPrivateWikiClosedToNone(t *testing.T) {
	a := answers(map[facts.Kind]bool{facts.KindRepoPublic: false})
	if w, _ := ChannelWritable(lint.AttackerWikiEditor, RoleNone, a); w != expr.TruthFalse {
		t.Errorf("wiki-editor of no access to a private repository, wiki-open not known: %v, want false", w)
	}
}

// TestAccountObservationBases: the rows whose values were all seen in the
// check with accounts of no role, of the role read and of the role triage
// are observed; the rows with a value not seen keep their basis.
func TestAccountObservationBases(t *testing.T) {
	public := answers(map[facts.Kind]bool{facts.KindRepoPublic: true, facts.KindRepoWikiOpen: true})
	for _, ref := range []RunRef{
		{workflow.EventNameGollum, PRHeadNone},
		{workflow.EventNameIssues, PRHeadNone},
		{workflow.EventNameIssueComment, PRHeadNone},
		{workflow.EventNameWorkflowRun, PRHeadNone},
		{workflow.EventNamePullRequestTarget, PRHeadFork},
		{workflow.EventNamePullRequest, PRHeadFork},
		{workflow.EventNamePullRequestReview, PRHeadFork},
	} {
		if _, b := RunDims(ref, public); b != BasisObserved {
			t.Errorf("%s %s, public: basis %s, want observed", ref.Event, ref.Head, b)
		}
	}
	for _, c := range []struct {
		a     lint.Attacker
		roles []Role
		want  Basis
	}{
		{lint.AttackerIssueAuthor, []Role{RoleNone, RoleRead, RoleTriage}, BasisObserved},
		{lint.AttackerCommenter, []Role{RoleNone, RoleRead, RoleTriage}, BasisObserved},
		{lint.AttackerForkPRAuthor, []Role{RoleNone, RoleRead, RoleTriage}, BasisObserved},
		{lint.AttackerAnyoneWhoForks, []Role{RoleNone}, BasisObserved},
		{lint.AttackerWikiEditor, []Role{RoleNone}, BasisObserved},
		{lint.AttackerAnyoneWhoForks, []Role{RoleRead, RoleTriage}, BasisDocumented},
		{lint.AttackerMergedCommitAuthor, []Role{RoleNone, RoleRead, RoleTriage}, BasisDocumented},
	} {
		for _, r := range c.roles {
			if _, b := ChannelWritable(c.a, r, public); b != c.want {
				t.Errorf("%s %s, public: basis %s, want %s", c.a, r, b, c.want)
			}
		}
	}
	for _, b := range Baselines() {
		if b.Role != RoleNone && b.Role != RoleRead && b.Role != RoleTriage {
			continue
		}
		if b.Basis != BasisDocumented {
			t.Errorf("baseline %s: basis %s, want documented (the self-hosted runner was not seen)", b.Role, b.Basis)
		}
		if holds(b.Condition, public) == truthT && len(b.Observed) == 0 {
			t.Errorf("baseline %s that holds on a public repository: no observation", b.Role)
		}
	}
	// rows observed before keep their observations and get the new ones
	for _, ref := range []RunRef{{workflow.EventNamePullRequestTarget, PRHeadFork}, {workflow.EventNameWorkflowRun, PRHeadNone}, {workflow.EventNameIssueComment, PRHeadNone}} {
		for _, g := range Grants() {
			if g.Event == ref.Event && g.Head == ref.Head && (len(g.Observed) < 2 || !slices.ContainsFunc(g.Observed, func(o lint.Observation) bool { return o.Date == observedAccounts })) {
				t.Errorf("%s %s: observations %v, want the earlier ones and one of the check with accounts", ref.Event, ref.Head, g.Observed)
			}
		}
	}
	// not seen: a review comment on a pull request from a fork, and the
	// wiki of a private repository or one only collaborators may edit
	if _, b := RunDims(RunRef{workflow.EventNamePullRequestReviewComment, PRHeadFork}, public); b != BasisDocumented {
		t.Errorf("pull_request_review_comment from a fork, public: basis %s, want documented", b)
	}
	closed := answers(map[facts.Kind]bool{facts.KindRepoPublic: true, facts.KindRepoWikiOpen: false})
	if w, b := ChannelWritable(lint.AttackerWikiEditor, RoleNone, closed); w != expr.TruthFalse || b != BasisDocumented {
		t.Errorf("wiki-editor none, wiki not open: %v %s, want false documented", w, b)
	}
	for _, c := range Channels() {
		if c.Attacker == lint.AttackerWikiEditor && c.Role == RoleNone && !c.Writable && len(c.Observed) == 0 {
			t.Error("wiki-editor none, not writable: no observation of the wiki turned off")
		}
	}
}

// TestWikiEditorReadersUnverified: one of the role read or triage could not
// edit a wiki with Restrict editing to collaborators only on, and was not
// seen at a wiki turned off; repo.wiki-open cannot tell the two cases
// apart, so the row keeps the worst case, writable, as unverified.
func TestWikiEditorReadersUnverified(t *testing.T) {
	for _, r := range []Role{RoleRead, RoleTriage} {
		for _, by := range []map[facts.Kind]bool{
			{facts.KindRepoPublic: true, facts.KindRepoWikiOpen: true},
			{facts.KindRepoPublic: true, facts.KindRepoWikiOpen: false},
			{facts.KindRepoPublic: true},
		} {
			w, b := ChannelWritable(lint.AttackerWikiEditor, r, answers(by))
			if w != expr.TruthTrue || b != BasisUnverified {
				t.Errorf("wiki-editor %s, %v: %v %s, want true unverified", r, by, w, b)
			}
		}
	}
}

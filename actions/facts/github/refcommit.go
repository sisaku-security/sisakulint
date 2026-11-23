package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// refCommit answers git.ref-commit: the commit the runner runs for
// uses: <repo>@<ref>, and the tag or the branch it is found as. The runner
// takes the tag when a branch and a tag have the same name, while the
// commits API given the bare ref takes the branch (both seen on GitHub,
// 2026-09-24), so it asks
// refs/tags/<ref>, then refs/heads/<ref>, then, for a full SHA, the commit
// itself, found as no ref. A shortened SHA is never resolved: the runner
// refuses it. It is asked once a run of each ref, and
// action.runs-using reads the same answer.
func (r *resolver) refCommit(ctx context.Context, g facts.GitRefCommit) facts.RawAnswer {
	return r.refCommitOf(ctx, g, facts.KindGitRefCommit)
}

// refCommitInfo is the answer of git.ref-commit of one ref, asked once a
// run.
type refCommitInfo struct {
	done     chan struct{}
	raw      facts.RawAnswer
	canceled bool // failed for its asker's ctx, or for the budget of its asker's kind: not kept
}

// refCommitOf is the answer of git.ref-commit of g, whose requests count
// as of the kind k of the fact asked, once a run.
func (r *resolver) refCommitOf(ctx context.Context, g facts.GitRefCommit, k facts.Kind) facts.RawAnswer {
	for {
		r.mu.Lock()
		i, ok := r.refCommits[g]
		if !ok {
			i = &refCommitInfo{done: make(chan struct{})}
			r.refCommits[g] = i
		}
		r.mu.Unlock()
		if !ok {
			i.raw = r.findRefCommit(ctx, g, k)
			i.canceled = i.raw.State == facts.StateUnknown && (ctx.Err() != nil || i.raw.Reason == usesTargetSpent)
			if i.canceled {
				r.mu.Lock()
				delete(r.refCommits, g)
				r.mu.Unlock()
			}
			close(i.done)
			return i.raw
		}
		select {
		case <-i.done:
			if !i.canceled {
				return i.raw
			}
		case <-ctx.Done():
			return unknown("github: not asked: " + ctx.Err().Error())
		}
	}
}

// findRefCommit asks the API for git.ref-commit of g.
func (r *resolver) findRefCommit(ctx context.Context, g facts.GitRefCommit, k facts.Kind) facts.RawAnswer {
	repo, why := r.repoPath(g.Repo)
	switch {
	case why != "":
		return unknown(why)
	case g.Ref == "":
		return unknown("github: the fact names no ref")
	case g.Ref == "." || g.Ref == "..":
		return unknown("github: " + g.Ref + " is not a name GitHub has")
	}
	type try struct {
		path string
		as   string // the ref it is found as; none for a commit
	}
	ref := url.PathEscape(g.Ref)
	tries := []try{{"refs/tags/" + ref, "refs/tags/" + g.Ref}, {"refs/heads/" + ref, "refs/heads/" + g.Ref}}
	if fullSHA.MatchString(g.Ref) {
		tries = append(tries, try{strings.ToLower(ref), ""}) // the API takes either case; one spelling is one request
	}
	for _, t := range tries {
		sha, raw, next := r.commit(ctx, k, repo+"commits/"+t.path)
		switch {
		case next:
			continue
		case raw.State != facts.StateFound:
			return raw
		}
		v := facts.RefCommit{SHA: sha}
		if t.as != "" {
			n, err := facts.ParseRefName(t.as)
			if err != nil {
				return unknown("github: " + t.as + " is not the name of a ref")
			}
			v.Ref = n
		}
		b, _ := json.Marshal(v)
		return facts.RawAnswer{State: facts.StateFound, Value: b}
	}
	return facts.RawAnswer{State: facts.StateAbsent}
}

var fullSHA = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)

// commit asks the commits endpoint at u, for a fact of kind k: the commit, with a found RawAnswer, or
// why there is none. next is whether there was no such commit (422), so
// that the next form of the ref is to be asked.
func (r *resolver) commit(ctx context.Context, k facts.Kind, u string) (sha facts.SHA, raw facts.RawAnswer, next bool) {
	resp, why := r.get(ctx, k, u, "application/vnd.github.sha", 1024)
	if why != "" {
		return sha, unknown(why), false
	}
	switch resp.status {
	case http.StatusOK:
		sha, err := facts.ParseSHA(strings.TrimSpace(string(resp.body)))
		if err != nil || !fullSHA.MatchString(sha.String()) {
			return facts.SHA{}, unknown("github: the answer is not a commit"), false
		}
		return sha, facts.RawAnswer{State: facts.StateFound}, false
	case http.StatusUnprocessableEntity:
		return sha, facts.RawAnswer{}, true
	case http.StatusNotFound:
		return sha, unknown("github: the repository is not there, or the token cannot see it"), false
	}
	return sha, unknown("github: HTTP " + strconv.Itoa(resp.status)), false
}

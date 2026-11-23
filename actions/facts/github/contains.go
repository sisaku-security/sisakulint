package github

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// commitContains answers git.commit-contains by the compare API:
// compare/<commit>...<sha> is identical or ahead when sha has commit in its
// history, behind or diverged, or 404 with no common ancestor, when it does
// not.
// The answer lists the commits and the files between them; per_page=1
// keeps it short, and one cut at maxCompare is not a comparison.
func (r *resolver) commitContains(ctx context.Context, q facts.GitCommitContains) facts.RawAnswer {
	repo, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	if q.SHA.String() == "" || q.Commit.String() == "" {
		return unknown("github: the fact names no commit")
	}
	resp, why := r.get(ctx, facts.KindGitCommitContains, repo+"compare/"+q.Commit.String()+"..."+q.SHA.String()+"?per_page=1", "application/vnd.github+json", maxCompare)
	if why != "" {
		return unknown(why)
	}
	var c struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	switch resp.status {
	case http.StatusOK:
	case http.StatusNotFound:
		// histories with no common ancestor: sha does not have commit
		// (observed 2026-09-28); else the repository or a commit is not there
		if json.Unmarshal(resp.body, &c) == nil && strings.HasPrefix(c.Message, "No common ancestor") {
			return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
		}
		return unknown("github: the repository or a commit is not there, or the token cannot see it")
	default:
		return unknown("github: HTTP " + strconv.Itoa(resp.status))
	}
	if json.Unmarshal(resp.body, &c) != nil {
		return unknown("github: the answer is not a comparison")
	}
	switch c.Status {
	case "identical", "ahead":
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
	case "behind", "diverged":
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
	}
	return unknown("github: the comparison's status is " + c.Status)
}

// maxCompare is the most bytes of a comparison read.
const maxCompare = 1 << 20

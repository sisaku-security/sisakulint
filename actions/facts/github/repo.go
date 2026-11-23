package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// noName is why a fact about a repository of no name is not asked: the API
// needs the name (--repo).
const noName = "github: the fact names no repository (no --repo)"

// repoInfo is what GET /repos/{owner}/{repo} said of a repository, asked
// once a run: repo.public, repo.wiki-open and repo.archived read it, and so
// does repo.environment-protected when an environment is not there.
type repoInfo struct {
	done         chan struct{}
	public       bool // visibility public; private and internal are not
	hasWiki      bool
	allowForking *bool  // allow_forking; nil when the answer has none
	archived     *bool  // archived; nil when the answer has none
	ownerUser    bool   // the owner is a user, not an organization: no organization level of configuration variables
	why          string // why there is no answer
	canceled     bool   // failed for its asker's ctx, or for the budget of its asker's kind: not kept
}

// repo asks GET /repos/{owner}/{repo} for a fact of kind k, once a run. A
// request that failed for its asker's ctx is not kept.
func (r *resolver) repo(ctx context.Context, repo facts.Repo, k facts.Kind) (*repoInfo, string) {
	path, why := r.repoPath(repo)
	if why != "" {
		return nil, why
	}
	for {
		r.mu.Lock()
		i, ok := r.repos[repo]
		if !ok {
			i = &repoInfo{done: make(chan struct{})}
			r.repos[repo] = i
		}
		r.mu.Unlock()
		if !ok {
			r.fetchRepo(ctx, strings.TrimSuffix(path, "/"), k, i)
			if i.canceled {
				r.mu.Lock()
				delete(r.repos, repo)
				r.mu.Unlock()
			}
			close(i.done) // after the delete: a waiter that sees canceled asks again
			return i, i.why
		}
		select {
		case <-i.done:
			if !i.canceled {
				return i, i.why
			}
		case <-ctx.Done():
			return nil, "github: not asked: " + ctx.Err().Error()
		}
	}
}

func (r *resolver) fetchRepo(ctx context.Context, u string, k facts.Kind, i *repoInfo) {
	resp, why := r.get(ctx, k, u, "application/vnd.github+json", 1<<20)
	switch {
	case why != "":
		i.why, i.canceled = why, ctx.Err() != nil || why == usesTargetSpent
	case resp.status == http.StatusOK:
		var v struct {
			Visibility   string `json:"visibility"`
			HasWiki      *bool  `json:"has_wiki"`
			AllowForking *bool  `json:"allow_forking"`
			Archived     *bool  `json:"archived"`
			Owner        struct {
				Type string `json:"type"`
			} `json:"owner"`
		}
		if json.Unmarshal(resp.body, &v) != nil || v.HasWiki == nil || !slices.Contains([]string{"public", "private", "internal"}, v.Visibility) {
			i.why = "github: the answer is not a repository"
			return
		}
		i.public, i.hasWiki = v.Visibility == "public", *v.HasWiki
		i.allowForking, i.archived = v.AllowForking, v.Archived
		i.ownerUser = v.Owner.Type == "User"
	case resp.status == http.StatusNotFound:
		i.why = "github: the repository is not there, or the token cannot see it"
	default:
		i.why = "github: HTTP " + strconv.Itoa(resp.status)
	}
}

func boolean(b bool) facts.RawAnswer {
	return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage(strconv.FormatBool(b))}
}

// repoPublic answers repo.public: visibility public; private and internal
// are not (only an enterprise's members may fork an internal one).
func (r *resolver) repoPublic(ctx context.Context, q facts.RepoPublic) facts.RawAnswer {
	i, why := r.repo(ctx, q.Repo, facts.KindRepoPublic)
	if why != "" {
		return unknown(why)
	}
	return boolean(i.public)
}

// repoArchived answers repo.archived: archived, of any repository.
func (r *resolver) repoArchived(ctx context.Context, q facts.RepoArchived) facts.RawAnswer {
	i, why := r.repo(ctx, q.Repo, facts.KindRepoArchived)
	switch {
	case why != "":
		return unknown(why)
	case i.archived == nil:
		return unknown("github: the answer does not say whether the repository is archived")
	}
	return boolean(*i.archived)
}

// wikiOpen answers repo.wiki-open when it is false: no wiki, or a
// repository that is not public. Whether only collaborators may edit is in
// no API.
func (r *resolver) wikiOpen(ctx context.Context, q facts.RepoWikiOpen) facts.RawAnswer {
	i, why := r.repo(ctx, q.Repo, facts.KindRepoWikiOpen)
	if why != "" {
		return unknown(why)
	}
	if !i.hasWiki || !i.public {
		return boolean(false)
	}
	return unknown("github: whether only collaborators may edit the wiki is a setting no API gives")
}

// defaultTokenWrite answers repo.default-token-write: the repository's
// default workflow permissions, which only a token that may read its
// Actions settings gets (not the GITHUB_TOKEN of a run).
func (r *resolver) defaultTokenWrite(ctx context.Context, q facts.RepoDefaultTokenWrite) facts.RawAnswer {
	path, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	resp, why := r.get(ctx, facts.KindRepoDefaultTokenWrite, path+"actions/permissions/workflow", "application/vnd.github+json", 4096)
	switch {
	case why != "":
		return unknown(why)
	case resp.status == http.StatusOK:
		var v struct {
			Default string `json:"default_workflow_permissions"`
		}
		if json.Unmarshal(resp.body, &v) != nil || v.Default != "read" && v.Default != "write" {
			return unknown("github: the answer is not the default workflow permissions")
		}
		return boolean(v.Default == "write")
	case resp.status == http.StatusUnauthorized, resp.status == http.StatusForbidden, resp.status == http.StatusNotFound:
		return unknown("github: the token cannot read the repository's Actions settings (HTTP " + strconv.Itoa(resp.status) + ")")
	}
	return unknown("github: HTTP " + strconv.Itoa(resp.status))
}

// protectionRule is a protection rule of an environment.
type protectionRule struct {
	Type string `json:"type"`
}

// environmentProtected answers repo.environment-protected: a protection
// rule of the type required_reviewers. An environment that is not there is
// made with no protection rules when a job references it, so 404 is false;
// but 404 is also what a repository that is not seen gives, so only of a
// repository that is seen.
func (r *resolver) environmentProtected(ctx context.Context, q facts.RepoEnvironmentProtected) facts.RawAnswer {
	path, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	resp, why := r.get(ctx, facts.KindRepoEnvironmentProtected, path+"environments/"+url.PathEscape(q.Environment.String()), "application/vnd.github+json", 1<<20)
	switch {
	case why != "":
		return unknown(why)
	case resp.status == http.StatusOK:
		var v struct {
			Rules []protectionRule `json:"protection_rules"`
		}
		if json.Unmarshal(resp.body, &v) != nil {
			return unknown("github: the answer is not an environment")
		}
		return boolean(slices.ContainsFunc(v.Rules, func(p protectionRule) bool { return p.Type == "required_reviewers" }))
	case resp.status == http.StatusNotFound:
		if _, why := r.repo(ctx, q.Repo, facts.KindRepoEnvironmentProtected); why != "" {
			return unknown(why)
		}
		return boolean(false)
	}
	return unknown("github: HTTP " + strconv.Itoa(resp.status))
}

// repoAllowForking answers repo.allow-forking: allow_forking of the
// repository, which an answer without it leaves unknown.
func (r *resolver) repoAllowForking(ctx context.Context, q facts.RepoAllowForking) facts.RawAnswer {
	i, why := r.repo(ctx, q.Repo, facts.KindRepoAllowForking)
	if why != "" {
		return unknown(why)
	}
	if i.allowForking == nil {
		return unknown("github: the answer has no allow_forking")
	}
	return boolean(*i.allowForking)
}

// forkPRInfo is what GET .../actions/permissions/fork-pr-workflows-private-repos
// said of a repository, asked once a run: three kinds read it.
type forkPRInfo struct {
	done                chan struct{}
	public              bool // the repository is public: it has no such setting
	run, write, secrets bool
	why                 string
	canceled            bool
}

// forkPR asks the fork pull request settings of repo, once a run.
func (r *resolver) forkPR(ctx context.Context, repo facts.Repo, k facts.Kind) (*forkPRInfo, string) {
	path, why := r.repoPath(repo)
	if why != "" {
		return nil, why
	}
	for {
		r.mu.Lock()
		i, ok := r.forkPRs[repo]
		if !ok {
			i = &forkPRInfo{done: make(chan struct{})}
			r.forkPRs[repo] = i
		}
		r.mu.Unlock()
		if !ok {
			r.fetchForkPR(ctx, path+"actions/permissions/fork-pr-workflows-private-repos", k, i)
			if i.canceled {
				r.mu.Lock()
				delete(r.forkPRs, repo)
				r.mu.Unlock()
			}
			return i, i.why
		}
		select {
		case <-i.done:
			if !i.canceled {
				return i, i.why
			}
		case <-ctx.Done():
			return nil, "github: not asked: " + ctx.Err().Error()
		}
	}
}

// publicForkPR is what GitHub says of a public repository, which has no
// such setting.
const publicForkPR = "Fork PR workflow settings is not allowed for public repositories."

func (r *resolver) fetchForkPR(ctx context.Context, u string, k facts.Kind, i *forkPRInfo) {
	defer close(i.done)
	resp, why := r.get(ctx, k, u, "application/vnd.github+json", 4096)
	switch {
	case why != "":
		i.why, i.canceled = why, ctx.Err() != nil
	case resp.status == http.StatusOK:
		var v struct {
			Run     *bool `json:"run_workflows_from_fork_pull_requests"`
			Write   *bool `json:"send_write_tokens_to_workflows"`
			Secrets *bool `json:"send_secrets_and_variables"`
		}
		if json.Unmarshal(resp.body, &v) != nil || v.Run == nil || v.Write == nil || v.Secrets == nil {
			i.why = "github: the answer is not the fork pull request settings"
			return
		}
		i.run, i.write, i.secrets = *v.Run, *v.Write, *v.Secrets
	case resp.status == http.StatusUnprocessableEntity:
		var v struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(resp.body, &v) == nil && v.Message == publicForkPR {
			i.public = true
			return
		}
		i.why = "github: HTTP 422"
	case resp.status == http.StatusUnauthorized, resp.status == http.StatusForbidden, resp.status == http.StatusNotFound:
		i.why = "github: the token cannot read the repository's Actions settings (HTTP " + strconv.Itoa(resp.status) + ")"
	default:
		i.why = "github: HTTP " + strconv.Itoa(resp.status)
	}
}

// forkPRSetting answers a kind of the fork pull request settings by pick;
// a public repository has none, so the fact is absent.
func (r *resolver) forkPRSetting(ctx context.Context, repo facts.Repo, k facts.Kind, pick func(*forkPRInfo) bool) facts.RawAnswer {
	i, why := r.forkPR(ctx, repo, k)
	if why != "" {
		return unknown(why)
	}
	if i.public {
		return facts.RawAnswer{State: facts.StateAbsent}
	}
	return boolean(pick(i))
}

// Package github answers facts from the GitHub API. It holds a token
// through actions/internal/githubapi, as actions/remote does, and no other
// package does: a rule asks a facts.Resolver and never sees it.
//
// Where things are:
//
//	github.go     Options, New, and sending a request (the budget, the
//	              token, the rate limit)
//	refcommit.go  git.ref-commit: the commit the runner runs for
//	              uses: <repo>@<ref>
//	commitref.go  git.commit-ref: a branch or a tag of a repository
//	              whose history has a commit
//	contains.go   git.commit-contains: whether a commit's history has another
//	committags.go git.commit-tags: the tags that point to a commit
//	advisories.go package.advisories: the advisories of the GitHub Advisory
//	              Database of a package of the actions ecosystem
//	repo.go       repo.public, repo.wiki-open, repo.default-token-write and
//	              repo.environment-protected of a named repository, and
//	              repo.archived of any repository
//	variables.go  repo.configuration-variables and
//	              repo.environment-configuration-variables of a named
//	              repository: the names of its configuration variables
//	allowedactions.go
//	              repo.allowed-actions of a named repository: its setting of
//	              allowed actions, which includes that of its organization
//	runsusing.go  action.runs-using: the runs.using of the metadata of the
//	              action that uses: <repo>/<path>@<ref> runs
//	definition.go action.definition: the file that defines that action, from
//	              the archive of the commit the runner downloads, and the
//	              archive read once a commit (action.runs-using reads it too)
//	workflowdefinition.go
//	              workflow.definition: the reusable workflow that uses:
//	              <repo>/<path>@<ref> calls, from the commit (its blob)
package github

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/githubapi"
)

// Options says how to reach the API.
type Options struct {
	// Token is sent as a bearer token; empty is no token, which sees public
	// repositories only, 60 requests an hour, and no GraphQL. It is sent
	// to BaseURL whatever its scheme, and never across a redirect to
	// another host.
	Token string
	// BaseURL is the REST API's root; nil is https://api.github.com. Its
	// path is kept (a GitHub Enterprise Server's /api/v3, whose GraphQL is
	// /api/graphql).
	BaseURL *url.URL
	// Client makes the requests; nil is a client that gives up on a request
	// after 30 seconds.
	Client *http.Client
	// MaxRequests is the most requests the Resolver sends, whatever the
	// workflows name; 0 is 1000. A workflow is the attacker's input, and a
	// token's budget (5000 an hour) is shared with its other uses.
	MaxRequests int
	// ReadRunsUsing reads the runs.using of the metadata of an action
	// (action.yml or action.yaml), for action.runs-using; nil leaves that
	// kind unknown. The caller gives it, since this package does not read
	// YAML.
	ReadRunsUsing func(definition []byte) (facts.RunsUsing, error)
}

// New makes the Resolver.
func New(o Options) facts.Resolver {
	requests := o.MaxRequests
	if requests <= 0 {
		requests = 1000
	}
	api := githubapi.New(githubapi.Options{Token: o.Token, BaseURL: o.BaseURL, HTTP: o.Client})
	return &resolver{api: api, base: api.Base(), left: requests, commitRefLeft: requests / 2, usesTargetLeft: requests / 4, queriesLeft: maxQueries,
		lists: map[facts.Repo]*refList{}, tagLists: map[facts.Repo]*tagList{}, repos: map[facts.Repo]*repoInfo{}, forkPRs: map[facts.Repo]*forkPRInfo{},
		refCommits: map[facts.GitRefCommit]*refCommitInfo{}, archives: map[archiveKey]*archiveInfo{}, readRunsUsing: o.ReadRunsUsing, graphql: make(chan struct{}, maxGraphQL)}
}

type resolver struct {
	api  *githubapi.Client
	base string // api.Base()

	mu      sync.Mutex
	left    int  // requests the budget has left
	limited bool // GitHub has said the rate limit of REST is reached
	// requests left for git.commit-ref: half of the budget, so that the
	// decoys of a workflow leave the other kinds the other half (with
	// usesTargetLeft, git.ref-commit is left a quarter at the least)
	commitRefLeft int
	// requests left for repo.archived and action.runs-using: a quarter of
	// the budget, so that the quality rules that ask them, which run before
	// most rules, leave the rules the rest
	usesTargetLeft int
	// GraphQL has a rate limit of its own; reaching it stops only the
	// GraphQL queries, which git.ref-commit does not send
	graphqlLimited bool
	queriesLeft    int // GraphQL queries left in the run
	lists          map[facts.Repo]*refList
	tagLists       map[facts.Repo]*tagList               // GET /repos/{owner}/{repo}/tags, once a repository
	repos          map[facts.Repo]*repoInfo              // GET /repos/{owner}/{repo}, once a repository
	forkPRs        map[facts.Repo]*forkPRInfo            // GET .../fork-pr-workflows-private-repos, once a repository
	refCommits     map[facts.GitRefCommit]*refCommitInfo // git.ref-commit, once a ref: action.runs-using reads it too
	archives       map[archiveKey]*archiveInfo           // GET .../tarball/{sha}, once a commit: action.definition and action.runs-using read it
	archiveKept    int                                   // the bytes the archives keep (maxRunKept)
	readRunsUsing  func([]byte) (facts.RunsUsing, error)

	graphql chan struct{} // the GraphQL queries in flight
}

func unknown(reason string) facts.RawAnswer {
	return facts.RawAnswer{State: facts.StateUnknown, Reason: reason}
}

// otherKinds is why a fact of a kind the source does not ask about has no
// answer (facts.OnlineAnswerOf gives those it asks about).
const otherKinds = "github: answers only the kinds git.*, package.advisories, action.runs-using, action.definition, workflow.definition and, of a named repository, repo.* except repo.pull-request-target-allowed, repo.fork-pr-app-checks and repo.merge-commit-app-checks (the description of each of these kinds in the schema of the facts says why --online does not answer the kind)"

func (r *resolver) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	var raw facts.RawAnswer
	switch q := q.(type) {
	case facts.GitRefCommit:
		raw = r.refCommit(ctx, q)
	case facts.GitCommitRef:
		raw = r.commitRef(ctx, q)
	case facts.GitCommitContains:
		raw = r.commitContains(ctx, q)
	case facts.GitCommitTags:
		raw = r.commitTags(ctx, q)
	case facts.PackageAdvisories:
		raw = r.packageAdvisories(ctx, q)
	case facts.RepoArchived:
		raw = r.repoArchived(ctx, q)
	case facts.ActionRunsUsing:
		raw = r.actionRunsUsing(ctx, q)
	case facts.ActionDefinition:
		raw = r.actionDefinition(ctx, q)
	case facts.WorkflowDefinition:
		raw = r.workflowDefinition(ctx, q)
	case facts.RepoPublic:
		if q.Repo.IsZero() {
			return unknown(noName) // not asked of the API: no source
		}
		raw = r.repoPublic(ctx, q)
	case facts.RepoWikiOpen:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.wikiOpen(ctx, q)
	case facts.RepoDefaultTokenWrite:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.defaultTokenWrite(ctx, q)
	case facts.RepoEnvironmentProtected:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.environmentProtected(ctx, q)
	case facts.RepoAllowForking:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.repoAllowForking(ctx, q)
	case facts.RepoForkPRRunWorkflows:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.forkPRSetting(ctx, q.Repo, facts.KindRepoForkPRRunWorkflows, func(i *forkPRInfo) bool { return i.run })
	case facts.RepoForkPRWriteTokens:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.forkPRSetting(ctx, q.Repo, facts.KindRepoForkPRWriteTokens, func(i *forkPRInfo) bool { return i.write })
	case facts.RepoForkPRSecrets:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.forkPRSetting(ctx, q.Repo, facts.KindRepoForkPRSecrets, func(i *forkPRInfo) bool { return i.secrets })
	case facts.RepoAllowedActions:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.allowedActions(ctx, q)
	case facts.RepoConfigurationVariables:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.configurationVariables(ctx, q)
	case facts.RepoEnvironmentConfigurationVariables:
		if q.Repo.IsZero() {
			return unknown(noName)
		}
		raw = r.environmentConfigurationVariables(ctx, q)
	default:
		return unknown(otherKinds) // not asked of the API: no source
	}
	raw.Source = facts.SourceGitHub
	return raw
}

// repoPath is <base>/repos/<owner>/<name>/, or why there is nothing to
// ask about repo.
func (r *resolver) repoPath(repo facts.Repo) (string, string) {
	owner, name, _ := strings.Cut(repo.String(), "/")
	if owner == "" || name == "" {
		return "", "github: the fact names no repository"
	}
	// A server cleans . and .. away from a path; no GitHub repository has
	// such a name, so there is nothing to ask.
	for _, part := range []string{owner, name} {
		if part == "." || part == ".." {
			return "", "github: " + part + " is not a name GitHub has"
		}
	}
	return r.base + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/", ""
}

// take counts a request for a fact of kind k, a GraphQL query or not, or
// says why none is sent.
func (r *resolver) take(k facts.Kind, graphql bool) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case graphql && r.graphqlLimited, !graphql && r.limited:
		return "github: rate limited", false
	case graphql && r.queriesLeft == 0:
		return "github: the GraphQL queries of this run are spent", false
	case r.left == 0:
		return "github: the requests of this run are spent (MaxRequests)", false
	case k == facts.KindGitCommitRef && r.commitRefLeft == 0:
		return "github: the requests of this run for git.commit-ref are spent (half of MaxRequests)", false
	case usesTargetKind(k) && r.usesTargetLeft == 0:
		return usesTargetSpent, false
	}
	r.left--
	if k == facts.KindGitCommitRef {
		r.commitRefLeft--
	}
	if usesTargetKind(k) {
		r.usesTargetLeft--
	}
	if graphql {
		r.queriesLeft--
	}
	return "", true
}

// usesTargetSpent is why a request of repo.archived or action.runs-using
// is not sent; such an answer is not kept, as the rest of the budget may
// answer the same request of another kind.
const usesTargetSpent = "github: the requests of this run for repo.archived, action.runs-using, action.definition and workflow.definition are spent (a quarter of MaxRequests)"

// usesTargetKind is whether k is of the budget of usesTargetLeft.
func usesTargetKind(k facts.Kind) bool {
	return k == facts.KindRepoArchived || k == facts.KindActionRunsUsing || k == facts.KindActionDefinition || k == facts.KindWorkflowDefinition
}

// setLimited says the rate limit of REST, or of GraphQL, is reached.
func (r *resolver) setLimited(graphql bool) {
	r.mu.Lock()
	if graphql {
		r.graphqlLimited = true
	} else {
		r.limited = true
	}
	r.mu.Unlock()
}

// response is the status and the first bytes of an answer.
type response struct {
	status int
	body   []byte
	next   bool // a Link header says there is a next page
}

// send sends req, for a fact of kind k, within the budget, with the
// headers of the API, and reads at most maxBytes bytes of the answer. When
// there is no answer to read (the budget is spent, the request failed, the
// rate limit is reached), it says why.
func (r *resolver) send(ctx context.Context, k facts.Kind, req *http.Request, maxBytes int64) (response, string) {
	graphql := req.URL.String() == r.graphqlURL()
	if why, ok := r.take(k, graphql); !ok {
		return response{}, why
	}
	resp, err := r.api.Do(req, maxBytes)
	switch {
	case errors.Is(err, githubapi.ErrRateLimited):
		r.setLimited(graphql)
		return response{}, err.Error()
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return response{}, "github: not asked: " + ctx.Err().Error()
	case err != nil:
		return response{}, err.Error()
	}
	return response{status: resp.Status, body: resp.Body, next: resp.Next}, ""
}

// get sends a GET of u with the Accept header accept.
func (r *resolver) get(ctx context.Context, k facts.Kind, u, accept string, maxBytes int64) (response, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return response{}, "github: the request could not be made"
	}
	req.Header.Set("Accept", accept)
	return r.send(ctx, k, req, maxBytes)
}

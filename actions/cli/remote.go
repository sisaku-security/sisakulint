package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/githubapi"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/remote"
)

// remoteTarget is what --remote names: a repository, and a ref or a pull
// request of it.
type remoteTarget struct {
	repo facts.Repo
	ref  string // after @, or after /tree/ of a URL; empty is the default branch
	pull int    // the N of a URL .../pull/N; 0 is none
}

// webHost is the host of the web pages of the GitHub that api serves:
// github.com for none, the host of a GitHub Enterprise Server's /api/v3,
// and the host of api without its api. (api.SUBDOMAIN.ghe.com).
func webHost(api *url.URL) string {
	if api == nil {
		return "github.com"
	}
	if strings.HasPrefix(strings.TrimSuffix(api.Path, "/"), "/api/v3") {
		return api.Host
	}
	if h, ok := strings.CutPrefix(strings.ToLower(api.Host), "api."); ok {
		return h
	}
	return api.Host
}

// parseRemote reads the value of --remote: owner/repo, owner/repo@ref, or
// a URL of the repository (/tree/<ref> and /pull/N too) on the web host of
// api.
func parseRemote(value string, api *url.URL) (remoteTarget, error) {
	bad := func(why string) (remoteTarget, error) {
		return remoteTarget{}, fmt.Errorf("--remote %s: %s", value, why)
	}
	if lower := strings.ToLower(value); !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
		name, ref, hasRef := strings.Cut(value, "@")
		if hasRef && ref == "" {
			return bad("no ref after @")
		}
		repo, err := facts.ParseRepo(name)
		if err != nil {
			return bad("not owner/repo, owner/repo@ref or a URL of a repository: " + err.Error())
		}
		return remoteTarget{repo: repo, ref: ref}, nil
	}
	u, err := url.Parse(value)
	if err != nil {
		return bad("not a URL")
	}
	if want := webHost(api); !strings.EqualFold(u.Host, want) {
		return bad("the host is not " + want + ", the web host of the GitHub API that the run asks (--github-api)")
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 {
		return bad("the URL names no repository")
	}
	repo, err := facts.ParseRepo(segs[0] + "/" + strings.TrimSuffix(segs[1], ".git"))
	if err != nil {
		return bad(err.Error())
	}
	t := remoteTarget{repo: repo}
	switch rest := segs[2:]; {
	case len(rest) == 0:
	case rest[0] == "tree" && len(rest) >= 2:
		t.ref = strings.Join(rest[1:], "/")
	case rest[0] == "pull" && len(rest) >= 2 && (len(rest) == 2 || len(rest) == 3 && slices.Contains([]string{"files", "commits", "checks"}, rest[2])):
		n, err := strconv.Atoi(rest[1])
		if err != nil || n <= 0 {
			return bad("not a number of a pull request: " + rest[1])
		}
		t.pull = n
	default:
		return bad("a URL is https://github.com/owner/repo, https://github.com/owner/repo/tree/<ref> or https://github.com/owner/repo/pull/<number>")
	}
	return t, nil
}

// openRemote reads the tree of the commit t names.
func openRemote(ctx context.Context, c *githubapi.Client, t remoteTarget) (*remote.Tree, error) {
	commit, err := remote.ResolveCommit(ctx, c, t.repo, t.ref)
	if err != nil {
		return nil, remoteError(err)
	}
	tree, err := remote.OpenTree(ctx, c, t.repo, commit, remoteLimits)
	if err != nil {
		return nil, remoteError(err)
	}
	return tree, nil
}

// remoteError is err of reading a repository, with what a reader of it
// does next.
func remoteError(err error) error {
	if errors.Is(err, githubapi.ErrRateLimited) {
		return fmt.Errorf("%w; set GITHUB_TOKEN, or wait until the rate limit resets", err)
	}
	return err
}

// remoteRevision is what the run read of tree.
func remoteRevision(t remoteTarget, tree *remote.Tree) *lint.RemoteRevision {
	rev := &lint.RemoteRevision{Repository: t.repo, Ref: t.ref, Commit: tree.Commit(), Tree: tree.SHA()}
	for _, f := range tree.ReadFiles() {
		rev.ReadFiles = append(rev.ReadFiles, lint.RemoteFile{Path: f.Path, Blob: f.Blob, Mode: f.Mode})
	}
	return rev
}

// unreadOther is an error for a file of tree that is not an input of in
// and that the run could not read: what it would have answered is not
// known (the configuration of actions/labeler, .github/dependabot.yml).
func unreadOther(tree *remote.Tree, in lint.Inputs) error {
	inputs := map[facts.InputPath]bool{}
	for _, i := range in.List {
		inputs[i.Name] = true
		if hops := tree.Hops(i.Name); len(hops) > 0 {
			inputs[hops[len(hops)-1]] = true // the file a symlink input is
		}
	}
	for _, p := range tree.Unread() {
		if !inputs[p] {
			return fmt.Errorf("%s of the repository could not be read, and the run needs it", p)
		}
	}
	return nil
}

// pullRun is what a run of --pull-request read before the inputs: the
// pull request, the entries of the trees of its merge base and of its
// base, and the paths it changes.
type pullRun struct {
	pr        remote.PullRequest
	mergeBase map[facts.InputPath]remote.Entry
	base      map[facts.InputPath]remote.Entry
	changed   []facts.InputPath
	set       remote.ChangedSet
	accepted  int // the accepted inconclusive places in the changed inputs
}

// openPullRequest reads the pull request t names, the tree of its head,
// and the trees of its merge base and base; it reads the changed files of
// the head first, before the requests are spent by the others.
func openPullRequest(ctx context.Context, c *githubapi.Client, t remoteTarget, head facts.SHA, exclude []lint.Exclude) (*remote.Tree, *pullRun, error) {
	pr, err := remote.ReadPullRequest(ctx, c, t.repo, t.pull, head)
	if err != nil {
		return nil, nil, remoteError(err)
	}
	tree, err := remote.OpenTree(ctx, c, t.repo, pr.Head, remoteLimits)
	if err != nil {
		return nil, nil, remoteError(err)
	}
	p := &pullRun{pr: pr}
	if p.mergeBase, err = remote.ListTree(ctx, c, t.repo, pr.MergeBase); err != nil {
		return nil, nil, remoteError(err)
	}
	p.base = p.mergeBase
	if pr.Base != pr.MergeBase {
		if p.base, err = remote.ListTree(ctx, c, t.repo, pr.Base); err != nil {
			return nil, nil, remoteError(err)
		}
	}
	p.changed = remote.ChangedPaths(p.mergeBase, tree.Entries())
	var first []facts.InputPath // not those under --exclude, which the run does not read
	for _, ch := range p.changed {
		if !slices.ContainsFunc(exclude, func(e lint.Exclude) bool { return e.Covers(ch) }) {
			first = append(first, ch)
		}
	}
	tree.Prefetch(first)
	return tree, p, nil
}

// apply sets the reported and the counted inputs of rep, of a run of in
// read from tree: the PATHs, or the changed inputs (every input when the
// pull request changes a file the run read that is not an input), and
// the changed inputs under --exclude counted too. A PATH that is not a
// changed input is a usage error.
func (p *pullRun) apply(rep *lint.Report, in lint.Inputs, tree *remote.Tree, paths []string) error {
	p.set = remote.ChangedInputs(in, tree, p.changed)
	reported := slices.Clone(p.set.Inputs)
	if p.set.ReadNonInput {
		reported = nil
		for _, i := range in.List {
			reported = append(reported, i.Name)
		}
	}
	counted := append(slices.Clone(reported), p.set.Excluded...)
	slices.SortFunc(counted, facts.CompareInputPaths)
	counted = slices.Compact(counted)
	if len(paths) > 0 {
		reported = nil
		for _, s := range paths {
			n := facts.MustCleanInputPath(s)
			if !slices.Contains(p.set.Inputs, n) {
				return fmt.Errorf("%s is not an input that the pull request #%d changes (the changed inputs: %s)", n, p.pr.Number, pathList(p.set.Inputs))
			}
			if !slices.Contains(reported, n) {
				reported = append(reported, n)
			}
		}
		slices.SortFunc(reported, facts.CompareInputPaths)
	}
	if reported == nil {
		reported = []facts.InputPath{}
	}
	rep.Reported, rep.Counted = reported, counted
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if g.Acceptance != nil && g.In(p.set.All()) {
			p.accepted++
		}
	}
	return nil
}

func pathList(ps []facts.InputPath) string {
	if len(ps) == 0 {
		return "none"
	}
	var out []string
	for _, p := range ps {
		out = append(out, p.String())
	}
	return strings.Join(out, ", ")
}

// revision is the pull request of rep, after Narrow.
func (p *pullRun) revision(rep lint.Report, tree *remote.Tree) *lint.PullRequestRevision {
	var read []facts.InputPath
	for _, f := range tree.ReadFiles() {
		read = append(read, f.Path)
	}
	return &lint.PullRequestRevision{Number: p.pr.Number, Base: p.pr.Base, MergeBase: p.pr.MergeBase, BehindBy: p.pr.BehindBy,
		ChangedInputs: p.set.All(), UnreportedCount: rep.Unreported(), BaseChangeCount: remote.BaseChanges(p.mergeBase, p.base, read), AcceptedCount: p.accepted}
}

// remoteLimits are the limits of a remote run; the zero Limits are
// remote's defaults. Tests lower them.
var remoteLimits remote.Limits

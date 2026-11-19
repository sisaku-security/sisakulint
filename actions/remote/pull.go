package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/internal/githubapi"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// ErrHeadMoved is a pull request whose head is not the commit asked for.
var ErrHeadMoved = errors.New("the head of the pull request is not the commit given")

// PullRequest is a pull request as a run reads it: the commit of its head,
// the branch it is to merge into, that branch's commit when the run read
// it, the merge base of the two, and how many commits the base has past
// the merge base (the behind_by of the compare API).
type PullRequest struct {
	Number    int
	Head      facts.SHA
	BaseRef   string
	Base      facts.SHA
	MergeBase facts.SHA
	BehindBy  int
}

// ReadPullRequest reads the pull request number of repo. A head that is
// not zero is the commit the head is to be: another head is ErrHeadMoved.
func ReadPullRequest(ctx context.Context, c *githubapi.Client, repo facts.Repo, number int, head facts.SHA) (PullRequest, error) {
	what := "the pull request " + repo.String() + "#" + strconv.Itoa(number)
	resp, err := get(ctx, c, what, repoURL(c, repo)+"pulls/"+strconv.Itoa(number), "application/vnd.github+json", 4<<20)
	if err != nil {
		return PullRequest{}, err
	}
	var v struct {
		Head struct {
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return PullRequest{}, fmt.Errorf("%s: %w", what, err)
	}
	pr := PullRequest{Number: number, BaseRef: v.Base.Ref}
	if pr.Head, err = facts.ParseSHA(v.Head.SHA); err != nil {
		return PullRequest{}, fmt.Errorf("%s: %w", what, err)
	}
	if head != (facts.SHA{}) && head != pr.Head {
		return PullRequest{}, fmt.Errorf("%w: %s is at %s, not %s", ErrHeadMoved, what, pr.Head, head)
	}
	if pr.Base, err = ResolveCommit(ctx, c, repo, pr.BaseRef); err != nil {
		return PullRequest{}, err
	}
	what = "the compare of " + pr.Base.String() + "..." + pr.Head.String()
	resp, err = get(ctx, c, what, repoURL(c, repo)+"compare/"+pr.Base.String()+"..."+pr.Head.String()+"?per_page=1", "application/vnd.github+json", 64<<20)
	if err != nil {
		return PullRequest{}, err
	}
	var cmp struct {
		MergeBase struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
		BehindBy int `json:"behind_by"`
	}
	if err := json.Unmarshal(resp.Body, &cmp); err != nil {
		return PullRequest{}, fmt.Errorf("%s: %w", what, err)
	}
	if pr.MergeBase, err = facts.ParseSHA(cmp.MergeBase.SHA); err != nil {
		return PullRequest{}, fmt.Errorf("%s: %w", what, err)
	}
	pr.BehindBy = cmp.BehindBy
	return pr, nil
}

// ChangedPaths are the paths whose entry differs between the trees from
// and to (a mode, an object, or one tree only has it), in order: a rename
// is the old path and the new one.
func ChangedPaths(from, to map[facts.InputPath]Entry) []facts.InputPath {
	var out []facts.InputPath
	for p, e := range from {
		if f, ok := to[p]; !ok || f.Mode != e.Mode || f.SHA != e.SHA {
			out = append(out, p)
		}
	}
	for p := range to {
		if _, ok := from[p]; !ok {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, facts.CompareInputPaths)
	return out
}

// ChangedSet is what a pull request changes of what a run reads: the
// changed inputs, those under --exclude among them, and whether it
// changes a file the run read that is not an input.
type ChangedSet struct {
	Inputs       []facts.InputPath // not excluded, in order
	Excluded     []facts.InputPath // in order
	ReadNonInput bool
}

// All are Inputs and Excluded, in order.
func (s ChangedSet) All() []facts.InputPath {
	out := slices.Concat(s.Inputs, s.Excluded)
	slices.SortFunc(out, facts.CompareInputPaths)
	return out
}

// ChangedInputs are the inputs of in, read from head, that the changed
// paths change: an input at a changed path, an input a symlink of which on
// its way is at a changed path, an input that calls by uses: ./ into a
// submodule at a changed path, and an input not read (unreadable), whose
// changes the run cannot tell. A file head read that is not an input, at
// a changed path, is ReadNonInput. Call it after the run, which reads the
// files that are not inputs.
func ChangedInputs(in lint.Inputs, head *Tree, changed []facts.InputPath) ChangedSet {
	isChanged := func(p facts.InputPath) bool { return slices.Contains(changed, p) }
	var subs []string
	for _, p := range changed {
		if e, ok := head.entries[p.String()]; ok && e.Mode == "160000" {
			subs = append(subs, p.String())
		}
	}
	var out ChangedSet
	inputs := map[facts.InputPath]bool{}
	for _, i := range in.List {
		inputs[i.Name] = true
		// an input not read is changed: what it is, what it calls and
		// which symlinks lead to it are not known (a pull request may spend
		// the requests of the run to leave it unread)
		hit := i.State == lint.InputStateUnreadable || isChanged(i.Name) || slices.ContainsFunc(head.Hops(i.Name), isChanged)
		if !hit && i.Tree != nil && len(subs) > 0 {
			f := calls.File{Name: i.Name, Tree: i.Tree, Workflow: i.Workflow, Action: i.ActionMetadata}
			for _, t := range calls.Targets(f, in.Repo) {
				for _, s := range subs {
					if t == s || strings.HasPrefix(t, s+"/") {
						hit = true
					}
				}
			}
		}
		switch {
		case !hit:
		case i.State == lint.InputStateExcluded:
			out.Excluded = append(out.Excluded, i.Name)
		default:
			out.Inputs = append(out.Inputs, i.Name)
		}
	}
	for _, f := range head.ReadFiles() {
		if !inputs[f.Path] && isChanged(f.Path) && !slices.ContainsFunc(in.List, func(i lint.Input) bool { return slices.Contains(head.Hops(i.Name), f.Path) }) {
			out.ReadNonInput = true
		}
	}
	return out
}

// inputPath is whether p is where an input of a run may be: a workflow
// right under .github/workflows, or an action.yml or action.yaml.
func inputPath(p facts.InputPath) bool {
	dir, base := path.Split(p.String())
	if dir == ".github/workflows/" && (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) {
		return true
	}
	return base == "action.yml" || base == "action.yaml"
}

// BaseChanges is how many paths the base changed after the merge base
// (the trees mergeBase and base) that are where an input may be, in
// either tree, or that the run read (read).
func BaseChanges(mergeBase, base map[facts.InputPath]Entry, read []facts.InputPath) int {
	n := 0
	for _, p := range ChangedPaths(mergeBase, base) {
		if inputPath(p) || slices.Contains(read, p) {
			n++
		}
	}
	return n
}

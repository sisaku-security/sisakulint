package github

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// maxTagPages is how many pages of tags, 100 a page, are read of a
// repository: one with more is not answered.
const maxTagPages = 10

// tagList is the tags of a repository and the commits they point to,
// listed once. GET /repos/{owner}/{repo}/tags gives the commit an
// annotated tag points to, not the tag object.
type tagList struct {
	done     chan struct{}
	tags     []tagOf
	why      string // why there is no list
	canceled bool   // no list, for the ctx of its asker was done: the next asker lists again
}

type tagOf struct {
	name string
	sha  facts.SHA
}

// commitTags answers git.commit-tags: the tags of the repository that
// point to the commit, by name.
func (r *resolver) commitTags(ctx context.Context, q facts.GitCommitTags) facts.RawAnswer {
	path, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	if q.SHA.String() == "" {
		return unknown("github: the fact names no commit")
	}
	tags, why := r.tagsOf(ctx, q.Repo, path)
	if why != "" {
		return unknown(why)
	}
	names := []facts.RefName{}
	for _, t := range tags {
		if t.sha != q.SHA {
			continue
		}
		n, err := facts.ParseRefName("refs/tags/" + t.name)
		if err != nil {
			continue // not a name git takes, which the runner cannot run either
		}
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b facts.RefName) int { return strings.Compare(a.String(), b.String()) })
	b, _ := json.Marshal(names)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

// tagsOf lists the tags of repo, whose path is path, once. A list that
// failed is kept for the run, but not one that failed for its asker's ctx.
func (r *resolver) tagsOf(ctx context.Context, repo facts.Repo, path string) ([]tagOf, string) {
	for {
		r.mu.Lock()
		l, ok := r.tagLists[repo]
		if !ok {
			l = &tagList{done: make(chan struct{})}
			r.tagLists[repo] = l
		}
		r.mu.Unlock()
		if !ok {
			return r.listTags(ctx, repo, path, l)
		}
		select {
		case <-l.done:
			if !l.canceled {
				return l.tags, l.why
			}
		case <-ctx.Done():
			return nil, "github: not asked: " + ctx.Err().Error()
		}
	}
}

func (r *resolver) listTags(ctx context.Context, repo facts.Repo, path string, l *tagList) ([]tagOf, string) {
	defer close(l.done)
	tags, why := r.fetchTags(ctx, path)
	switch {
	case why != "" && ctx.Err() != nil:
		l.canceled = true
		r.mu.Lock()
		delete(r.tagLists, repo)
		r.mu.Unlock()
	case why != "":
		l.why = why
	default:
		l.tags = tags
	}
	return tags, why
}

// fetchTags reads the pages of the tags at path.
func (r *resolver) fetchTags(ctx context.Context, path string) ([]tagOf, string) {
	var out []tagOf
	for page := 1; page <= maxTagPages; page++ {
		resp, why := r.get(ctx, facts.KindGitCommitTags, path+"tags?per_page=100&page="+strconv.Itoa(page), "application/vnd.github+json", 1<<20)
		if why != "" {
			return nil, why
		}
		switch resp.status {
		case http.StatusOK:
		case http.StatusNotFound:
			return nil, "github: the repository is not there, or the token cannot see it"
		default:
			return nil, "github: HTTP " + strconv.Itoa(resp.status)
		}
		var tags []struct {
			Name   string `json:"name"`
			Commit struct {
				SHA string `json:"sha"`
			} `json:"commit"`
		}
		if err := json.Unmarshal(resp.body, &tags); err != nil {
			return nil, "github: the list of tags is not one"
		}
		for _, t := range tags {
			sha, err := facts.ParseSHA(t.Commit.SHA)
			if err != nil {
				return nil, "github: a tag points to no commit"
			}
			out = append(out, tagOf{t.Name, sha})
		}
		if !resp.next {
			return out, ""
		}
	}
	return nil, "github: the repository has more than " + strconv.Itoa(maxTagPages*100) + " tags"
}

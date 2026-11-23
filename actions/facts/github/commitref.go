package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// commitRef answers git.commit-ref: a branch or a tag of the repository
// whose history has the commit.
//
//  1. The refs, by matching-refs: every branch and every tag in one request
//     each, once for the repository.
//  2. A ref that points to the SHA (a tip, a lightweight tag, the object of
//     an annotated tag) has it.
//  3. Else GraphQL compares the SHA with every ref, 100 refs to a query,
//     the queries at once. The REST compare takes a second a ref.
//  4. When GraphQL fails as a whole, as it does for a SHA that is nowhere,
//     the commit and the tag object of the SHA are asked by REST.
func (r *resolver) commitRef(ctx context.Context, q facts.GitCommitRef) facts.RawAnswer {
	repo, why := r.repoPath(q.Repo)
	if why != "" {
		return unknown(why)
	}
	sha := q.SHA
	if sha == (facts.SHA{}) {
		return unknown("github: the fact names no commit")
	}
	refs, why := r.refs(ctx, q.Repo, repo)
	if why != "" {
		return unknown(why)
	}
	for _, x := range refs {
		if x.sha == sha {
			return foundRef(x.name)
		}
	}
	switch {
	case !r.api.HasToken():
		return unknown("github: git.commit-ref needs a token past the tips of the refs")
	case len(refs) > maxRefs:
		return unknown("github: the repository has too many refs to compare")
	}
	return r.compare(ctx, q.Repo, repo, sha, refs)
}

const (
	maxRefs      = 1500 // the most refs of a repository compared with a SHA
	refsPerQuery = 100
	maxGraphQL   = 15  // the GraphQL queries at once, for the whole Resolver
	maxQueries   = 100 // the GraphQL queries of the whole Resolver: 7 rounds of 15, about 35 s at worst
)

func foundRef(name string) facts.RawAnswer {
	v, _ := json.Marshal(name)
	return facts.RawAnswer{State: facts.StateFound, Value: v}
}

// namedRef is a ref and the object it points to.
type namedRef struct {
	name string
	sha  facts.SHA
}

// refList is the refs of a repository, listed once.
type refList struct {
	done     chan struct{}
	refs     []namedRef // branches then tags, each by name
	why      string     // why there is no list
	canceled bool       // no list, for the ctx of its asker was done: the next asker lists again
	// more refs than are compared: the list is not kept, for a workflow may
	// name many such repositories; each asker lists again for the tips
	tooMany bool
}

// refs lists the branches and the tags of repo, whose path is path. A list
// that failed is kept for the run, but not one that failed for its asker's
// ctx.
func (r *resolver) refs(ctx context.Context, repo facts.Repo, path string) ([]namedRef, string) {
	for {
		r.mu.Lock()
		l, ok := r.lists[repo]
		if !ok {
			l = &refList{done: make(chan struct{})}
			r.lists[repo] = l
		}
		r.mu.Unlock()
		if !ok {
			return r.list(ctx, repo, path, l)
		}
		select {
		case <-l.done:
			if l.tooMany {
				return r.fetch(ctx, path)
			}
			if !l.canceled {
				return l.refs, l.why
			}
		case <-ctx.Done():
			return nil, "github: not asked: " + ctx.Err().Error()
		}
	}
}

func (r *resolver) list(ctx context.Context, repo facts.Repo, path string, l *refList) ([]namedRef, string) {
	defer close(l.done)
	refs, why := r.fetch(ctx, path)
	switch {
	case why != "" && ctx.Err() != nil:
		l.canceled = true
		r.mu.Lock()
		delete(r.lists, repo)
		r.mu.Unlock()
	case why != "":
		l.why = why
	case len(refs) > maxRefs:
		l.tooMany = true
	default:
		l.refs = refs
	}
	return refs, why
}

// fetch lists the branches and the tags at path.
func (r *resolver) fetch(ctx context.Context, path string) ([]namedRef, string) {
	var all []namedRef
	for _, kind := range []string{"heads", "tags"} {
		refs, why := r.matchingRefs(ctx, path, kind)
		if why != "" {
			return nil, why
		}
		all = append(all, refs...)
	}
	return all, ""
}

// matchingRefs is the refs under refs/<kind>/, by name.
func (r *resolver) matchingRefs(ctx context.Context, path, kind string) ([]namedRef, string) {
	resp, why := r.get(ctx, facts.KindGitCommitRef, path+"git/matching-refs/"+kind, "application/vnd.github+json", 16<<20)
	switch {
	case why != "":
		return nil, why
	case resp.status == http.StatusNotFound:
		return nil, "github: the repository is not there, or the token cannot see it"
	case resp.status != http.StatusOK:
		return nil, "github: HTTP " + strconv.Itoa(resp.status)
	case resp.next:
		return nil, "github: the list of refs has more pages" // matching-refs was seen whole; a part is not the list
	}
	var list []struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	if json.Unmarshal(resp.body, &list) != nil {
		return nil, "github: the answer is not a list of refs"
	}
	prefix := "refs/" + kind + "/"
	var out []namedRef
	for _, x := range list {
		if !strings.HasPrefix(x.Ref, prefix) || len(x.Ref) == len(prefix) {
			continue // matching-refs/tags also has refs/tagsX/…
		}
		if x.Object.Type != "commit" && x.Object.Type != "tag" {
			continue // a tag of a tree or a blob has no commit; GraphQL compares it to null
		}
		sha, err := facts.ParseSHA(x.Object.SHA)
		if err != nil {
			return nil, "github: the answer is not a list of refs"
		}
		out = append(out, namedRef{x.Ref, sha})
	}
	slices.SortFunc(out, func(a, b namedRef) int { return strings.Compare(a.name, b.name) })
	return out, ""
}

// batch is what one GraphQL query said.
type batch struct {
	has     int    // the index in the batch of the first ref that has the SHA, or -1
	unsure  bool   // a ref could not be compared
	failed  string // why the query has no answer
	failAll bool   // the query failed as a whole, with no reason given
}

// compare compares sha with each of refs by GraphQL.
func (r *resolver) compare(ctx context.Context, repo facts.Repo, path string, sha facts.SHA, refs []namedRef) facts.RawAnswer {
	var chunks [][]namedRef
	for c := range slices.Chunk(refs, refsPerQuery) {
		chunks = append(chunks, c)
	}
	out := make([]batch, len(chunks))
	var wg sync.WaitGroup
	for i, c := range chunks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = r.compareBatch(ctx, repo, sha, c)
		}()
	}
	wg.Wait()
	failed, failAll, unsure := "", false, false
	for i, b := range out {
		switch {
		case b.has >= 0:
			return foundRef(chunks[i][b.has].name)
		case b.failed != "" && failed == "":
			failed = b.failed
		}
		failAll = failAll || b.failAll
		unsure = unsure || b.unsure
	}
	switch {
	case failed != "":
		return unknown(failed)
	case failAll:
		return r.nowhere(ctx, path, sha)
	case unsure:
		return unknown("github: a ref could not be compared")
	}
	return facts.RawAnswer{State: facts.StateAbsent}
}

// compareBatch asks GraphQL whether each of refs has sha.
func (r *resolver) compareBatch(ctx context.Context, repo facts.Repo, sha facts.SHA, refs []namedRef) batch {
	select {
	case r.graphql <- struct{}{}:
		defer func() { <-r.graphql }()
	case <-ctx.Done():
		return batch{has: -1, failed: "github: not asked: " + ctx.Err().Error()}
	}
	owner, name, _ := strings.Cut(repo.String(), "/")
	vars := map[string]string{"owner": owner, "name": name, "sha": sha.String()}
	var decl, sel strings.Builder
	decl.WriteString("$owner: String!, $name: String!, $sha: String!")
	for i, x := range refs {
		vars["q"+strconv.Itoa(i)] = x.name
		fmt.Fprintf(&decl, ", $q%d: String!", i)
		fmt.Fprintf(&sel, " r%d: ref(qualifiedName: $q%d) { compare(headRef: $sha) { status } }", i, i)
	}
	body, _ := json.Marshal(map[string]any{
		"query":     "query(" + decl.String() + ") { repository(owner: $owner, name: $name) {" + sel.String() + " } }",
		"variables": vars,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.graphqlURL(), bytes.NewReader(body))
	if err != nil {
		return batch{has: -1, failed: "github: the request could not be made"}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, why := r.send(ctx, facts.KindGitCommitRef, req, 1<<20)
	switch {
	case why != "":
		return batch{has: -1, failed: why}
	case resp.status != http.StatusOK:
		return batch{has: -1, failed: "github: HTTP " + strconv.Itoa(resp.status)}
	}
	var ans struct {
		Data *struct {
			Repository map[string]*struct {
				Compare *struct {
					Status string `json:"status"`
				} `json:"compare"`
			} `json:"repository"`
		} `json:"data"`
		Errors []struct {
			Type string `json:"type"`
		} `json:"errors"`
	}
	if json.Unmarshal(resp.body, &ans) != nil {
		return batch{has: -1, failed: "github: the answer is not a comparison"}
	}
	for _, e := range ans.Errors {
		switch e.Type {
		case "RATE_LIMITED":
			r.setLimited(true)
			return batch{has: -1, failed: "github: rate limited"}
		case "NOT_FOUND":
			if ans.Data != nil && ans.Data.Repository == nil {
				return batch{has: -1, failed: "github: the repository is not there, or the token cannot see it"}
			}
		}
	}
	if ans.Data == nil || ans.Data.Repository == nil {
		return batch{has: -1, failAll: true}
	}
	b := batch{has: -1}
	for i := range refs {
		x := ans.Data.Repository["r"+strconv.Itoa(i)]
		if x == nil || x.Compare == nil {
			b.unsure = true
			continue
		}
		switch x.Compare.Status {
		case "BEHIND", "IDENTICAL":
			if b.has < 0 {
				b.has = i
			}
		case "AHEAD", "DIVERGED":
		default:
			b.unsure = true
		}
	}
	return b
}

// graphqlURL is where GraphQL is: /graphql at api.github.com, and
// /api/graphql on a GitHub Enterprise Server, whose REST is /api/v3.
func (r *resolver) graphqlURL() string {
	if base, ok := strings.CutSuffix(r.base, "/api/v3"); ok {
		return base + "/api/graphql"
	}
	return r.base + "/graphql"
}

// nowhere is whether sha is nowhere in the network: neither a commit nor
// a tag object. GraphQL fails as a whole for such a SHA, and for other
// reasons too.
func (r *resolver) nowhere(ctx context.Context, path string, sha facts.SHA) facts.RawAnswer {
	c, why := r.get(ctx, facts.KindGitCommitRef, path+"commits/"+sha.String(), "application/vnd.github.sha", 1024)
	if why != "" {
		return unknown(why)
	}
	if c.status != http.StatusUnprocessableEntity {
		return unknown("github: the refs could not be compared")
	}
	t, why := r.get(ctx, facts.KindGitCommitRef, path+"git/tags/"+sha.String(), "application/vnd.github+json", 1024)
	if why != "" {
		return unknown(why)
	}
	if t.status != http.StatusNotFound {
		return unknown("github: the refs could not be compared")
	}
	return facts.RawAnswer{State: facts.StateAbsent}
}

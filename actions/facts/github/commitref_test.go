package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// network is a fake of what git.commit-ref asks of GitHub: the
// refs of o/r by matching-refs, the commits and tag objects there are, and
// GraphQL's Ref.compare against a SHA.
type network struct {
	mu       sync.Mutex
	refs     []ref                        // of o/r
	contains map[string]map[string]string // SHA -> ref -> status; a ref not there is DIVERGED
	objects  map[string]string            // the commits and the tag objects in the network: SHA -> commit or tag

	// override the answer of a path (after /api), when it returns true
	answer func(w http.ResponseWriter, path string) bool
	// override the answer to a GraphQL batch, when it returns true
	batch func(w http.ResponseWriter, refs []string) bool

	rest, graphql        []string // what was asked
	inFlight, mostAtOnce int
	tokens               []string
}

type ref struct{ name, sha, typ string }

func (n *network) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/api")
	n.mu.Lock()
	n.tokens = append(n.tokens, r.Header.Get("Authorization"))
	if path == "/graphql" {
		n.inFlight++
		n.mostAtOnce = max(n.mostAtOnce, n.inFlight)
	} else {
		n.rest = append(n.rest, path)
	}
	answer := n.answer
	n.mu.Unlock()
	defer func() {
		if path == "/graphql" {
			n.mu.Lock()
			n.inFlight--
			n.mu.Unlock()
		}
	}()
	if answer != nil && answer(w, path) {
		return
	}
	switch {
	case path == "/graphql":
		n.serveGraphQL(w, r)
	case strings.HasPrefix(path, "/repos/o/r/git/matching-refs/"):
		prefix := "refs/" + strings.TrimPrefix(path, "/repos/o/r/git/matching-refs/")
		out := []any{}
		for _, x := range n.refs {
			if strings.HasPrefix(x.name, prefix) {
				out = append(out, map[string]any{"ref": x.name, "object": map[string]string{"sha": x.sha, "type": x.typ}})
			}
		}
		json.NewEncoder(w).Encode(out)
	case strings.HasPrefix(path, "/repos/o/r/commits/"), strings.HasPrefix(path, "/repos/o/r/git/tags/"):
		// commits/{sha} is 422 but for a commit, git/tags/{sha} is 404 but
		// for a tag object
		sha := path[strings.LastIndex(path, "/")+1:]
		switch {
		case strings.Contains(path, "/commits/") && n.objects[sha] == "commit":
			w.Write([]byte(sha))
		case strings.Contains(path, "/commits/"):
			w.WriteHeader(http.StatusUnprocessableEntity)
		case n.objects[sha] == "tag":
			w.Write([]byte(`{"sha":"` + sha + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	default:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}
}

var alias = regexp.MustCompile(`r(\d+): ref\(qualifiedName: \$q\d+\)`)

func (n *network) serveGraphQL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string            `json:"query"`
		Variables map[string]string `json:"variables"`
	}
	b, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(b, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var refs []string
	for _, m := range alias.FindAllStringSubmatch(req.Query, -1) {
		refs = append(refs, req.Variables["q"+m[1]])
	}
	n.mu.Lock()
	n.graphql = append(n.graphql, strings.Join(refs, " "))
	batch := n.batch
	n.mu.Unlock()
	if batch != nil && batch(w, refs) {
		return
	}
	if req.Variables["owner"] != "o" || req.Variables["name"] != "r" {
		w.Write([]byte(`{"data":{"repository":null},"errors":[{"type":"NOT_FOUND","message":"Could not resolve to a Repository"}]}`))
		return
	}
	sha := req.Variables["sha"]
	if n.objects[sha] == "" {
		w.Write([]byte(`{"data":null,"errors":[{"message":"Something went wrong while executing your query."}]}`))
		return
	}
	// the aliases in the reverse order: the answer is not read by position
	repo := map[string]any{}
	for i := len(refs) - 1; i >= 0; i-- {
		st := n.contains[sha][refs[i]]
		if st == "" {
			st = "DIVERGED"
		}
		repo[fmt.Sprintf("r%d", i)] = map[string]any{"compare": map[string]string{"status": st}}
	}
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": repo}})
}

const (
	tip    = "1eb21b193d10eb7c5b7e85ff355391469f6233c2" // P: under branches, not a tip
	tagged = "860fb3d0de1295b37890acec26add9a411d36583" // T: tags only
	tagObj = "446c8b2d5ea45191c4912da46eb80b184994a3bb" // the annotated tag of T
	fork   = "b3154b9543ce6392fe65a19ce523c4d4adabca7b" // F: in a fork only
	head   = "d93bf9bc538996ee57c1ab573602859be7dbaa4b" // C: the tip of main
	absent = "0123456789abcdef0123456789abcdef01234567" // nowhere
)

// experiment is a network of a repository and its forks like the one
// observed on GitHub.
func experiment() *network {
	return &network{
		refs: []ref{
			{"refs/heads/main", head, "commit"},
			{"refs/heads/exp", head, "commit"},
			{"refs/tags/i-tag", tagged, "commit"},
			{"refs/tags/i-annot", tagObj, "tag"},
		},
		contains: map[string]map[string]string{
			tip:    {"refs/heads/main": "BEHIND", "refs/heads/exp": "BEHIND", "refs/tags/i-tag": "BEHIND", "refs/tags/i-annot": "BEHIND"},
			tagged: {"refs/tags/i-tag": "IDENTICAL", "refs/tags/i-annot": "IDENTICAL"},
			fork:   {"refs/heads/main": "DIVERGED", "refs/tags/i-tag": "AHEAD"},
		},
		objects: map[string]string{tip: "commit", tagged: "commit", tagObj: "tag", fork: "commit", head: "commit"},
	}
}

func serve(t *testing.T, n *network, o Options) facts.Resolver {
	t.Helper()
	srv := httptest.NewServer(n)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/api")
	o.BaseURL, o.Client = u, srv.Client()
	return New(o)
}

func commitRef(t *testing.T, r facts.Resolver, repo, sha string) facts.Answer[facts.RefName] {
	t.Helper()
	rp, err := facts.ParseRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	s, err := facts.ParseSHA(sha)
	if err != nil {
		t.Fatal(err)
	}
	return facts.GitCommitRef{Repo: rp, SHA: s}.Ask(context.Background(), r)
}

func TestCommitRef(t *testing.T) {
	for _, c := range []struct {
		name, sha string
		state     facts.State
		value     string
		graphql   bool
	}{
		{"the tip of a branch", head, facts.StateFound, "refs/heads/exp", false},
		{"a lightweight tag", tagged, facts.StateFound, "refs/tags/i-tag", false},
		{"the object of an annotated tag", tagObj, facts.StateFound, "refs/tags/i-annot", false},
		{"under branches: the first branch by name", tip, facts.StateFound, "refs/heads/exp", true},
		{"a commit only in a fork", fork, facts.StateAbsent, "", true},
		{"a SHA that is nowhere", absent, facts.StateAbsent, "", true},
		{"in upper case", strings.ToUpper(fork), facts.StateAbsent, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := experiment()
			got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", c.sha)
			if got.State != c.state || got.Value.String() != c.value {
				t.Errorf("= %+v, want %v %q", got, c.state, c.value)
			}
			if (len(n.graphql) > 0) != c.graphql {
				t.Errorf("GraphQL asked %v", n.graphql)
			}
		})
	}
}

// TestCommitRefTagsOnly: a commit that only a tag has is in the repository.
func TestCommitRefTagsOnly(t *testing.T) {
	n := experiment()
	n.refs = append(n.refs, ref{"refs/tags/v2", head, "commit"})
	n.contains["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = map[string]string{"refs/tags/i-annot": "BEHIND"}
	n.objects["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = "commit"
	got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if got.State != facts.StateFound || got.Value.String() != "refs/tags/i-annot" {
		t.Errorf("= %+v", got)
	}
}

// TestCommitRefListsOnce: the refs of a repository are listed once for
// every SHA asked about it.
func TestCommitRefListsOnce(t *testing.T) {
	n := experiment()
	r := serve(t, n, Options{Token: "tok"})
	var wg sync.WaitGroup
	for _, sha := range []string{head, tagged, tip, fork} {
		wg.Add(1)
		go func() { defer wg.Done(); commitRef(t, r, "o/r", sha) }()
	}
	wg.Wait()
	slices.Sort(n.rest)
	if want := []string{"/repos/o/r/git/matching-refs/heads", "/repos/o/r/git/matching-refs/tags"}; !slices.Equal(n.rest, want) {
		t.Errorf("REST asked %v, want %v", n.rest, want)
	}
}

// TestCommitRefWithoutAToken: the lists need no token, GraphQL does.
func TestCommitRefWithoutAToken(t *testing.T) {
	n := experiment()
	r := serve(t, n, Options{})
	if got := commitRef(t, r, "o/r", tagged); got.State != facts.StateFound {
		t.Errorf("a tag = %+v", got)
	}
	got := commitRef(t, r, "o/r", fork)
	if got.State != facts.StateUnknown || got.Reason != "github: git.commit-ref needs a token past the tips of the refs" {
		t.Errorf("a fork's commit = %+v", got)
	}
	if len(n.graphql) != 0 {
		t.Errorf("GraphQL asked without a token: %v", n.graphql)
	}
}

// TestCommitRefAnswers: what could not be learned
// is unknown, never absent.
func TestCommitRefAnswers(t *testing.T) {
	status := func(code int, b string) func(http.ResponseWriter) bool {
		return func(w http.ResponseWriter) bool { w.WriteHeader(code); w.Write([]byte(b)); return true }
	}
	lists := func(a func(http.ResponseWriter) bool) func(http.ResponseWriter, string) bool {
		return func(w http.ResponseWriter, path string) bool {
			return strings.Contains(path, "/matching-refs/tags") && a(w)
		}
	}
	gql := func(b string) func(http.ResponseWriter, []string) bool {
		return func(w http.ResponseWriter, _ []string) bool { w.Write([]byte(b)); return true }
	}
	for _, c := range []struct {
		name   string
		answer func(http.ResponseWriter, string) bool
		batch  func(http.ResponseWriter, []string) bool
		sha    string
		state  facts.State
		reason string
	}{
		{"the list is 404", lists(status(404, `{"message":"Not Found"}`)), nil, fork, facts.StateUnknown, "github: the repository is not there, or the token cannot see it"},
		{"the list is 500", lists(status(500, "")), nil, fork, facts.StateUnknown, "github: HTTP 500"},
		{"the list is not a list", lists(status(200, `{"ref":"refs/tags/x"}`)), nil, fork, facts.StateUnknown, "github: the answer is not a list of refs"},
		{"the list has a SHA that is not one", lists(status(200, `[{"ref":"refs/tags/x","object":{"sha":"zz","type":"commit"}}]`)), nil, fork, facts.StateUnknown, "github: the answer is not a list of refs"},
		{"the list is rate limited", lists(status(429, "")), nil, fork, facts.StateUnknown, "github: rate limited"},
		{"the repository is not there for GraphQL", nil, gql(`{"data":{"repository":null},"errors":[{"type":"NOT_FOUND","message":"x"}]}`), fork, facts.StateUnknown, "github: the repository is not there, or the token cannot see it"},
		{"a compare is null", nil, gql(`{"data":{"repository":{"r0":{"compare":null},"r1":{"compare":{"status":"DIVERGED"}},"r2":{"compare":{"status":"DIVERGED"}},"r3":{"compare":{"status":"DIVERGED"}}}}}`), fork, facts.StateUnknown, "github: a ref could not be compared"},
		{"a ref is gone", nil, gql(`{"data":{"repository":{"r0":null,"r1":{"compare":{"status":"DIVERGED"}},"r2":{"compare":{"status":"DIVERGED"}},"r3":{"compare":{"status":"DIVERGED"}}}}}`), fork, facts.StateUnknown, "github: a ref could not be compared"},
		{"an unknown status", nil, gql(`{"data":{"repository":{"r0":{"compare":{"status":"NEW"}},"r1":{"compare":{"status":"DIVERGED"}},"r2":{"compare":{"status":"DIVERGED"}},"r3":{"compare":{"status":"DIVERGED"}}}}}`), fork, facts.StateUnknown, "github: a ref could not be compared"},
		{"GraphQL is rate limited", nil, gql(`{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}`), fork, facts.StateUnknown, "github: rate limited"},
		{"GraphQL is 502", nil, func(w http.ResponseWriter, _ []string) bool { w.WriteHeader(502); return true }, fork, facts.StateUnknown, "github: HTTP 502"},
		{"GraphQL fails for a commit in the network", nil, gql(`{"data":null,"errors":[{"message":"Something went wrong"}]}`), fork, facts.StateUnknown, "github: the refs could not be compared"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := experiment()
			n.answer, n.batch = c.answer, c.batch
			got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", c.sha)
			if got.State != c.state || got.Reason != c.reason {
				t.Errorf("= %+v, want %v %q", got, c.state, c.reason)
			}
		})
	}
}

// manyRefs is o/r with k tags, none of which has fork.
func manyRefs(k int) *network {
	n := experiment()
	n.refs = nil
	for i := range k {
		n.refs = append(n.refs, ref{fmt.Sprintf("refs/tags/v%04d", i), head, "commit"})
	}
	return n
}

// TestCommitRefBatches: the refs are compared 100 at a
// time, 15 queries at once at most, and a repository with more refs than
// the limit is not compared.
func TestCommitRefBatches(t *testing.T) {
	n := manyRefs(maxRefs)
	release := make(chan struct{})
	n.batch = func(w http.ResponseWriter, refs []string) bool {
		<-release
		return false
	}
	r := serve(t, n, Options{Token: "tok"})
	done := make(chan facts.Answer[facts.RefName])
	go func() { done <- commitRef(t, r, "o/r", fork) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		n.mu.Lock()
		k := len(n.graphql)
		n.mu.Unlock()
		if k == maxRefs/refsPerQuery {
			break
		}
		if time.Now().After(deadline) {
			close(release)
			t.Fatalf("%d queries at once, want %d", k, maxRefs/refsPerQuery)
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if got := <-done; got.State != facts.StateAbsent {
		t.Errorf("= %+v", got)
	}
	if n.mostAtOnce > maxGraphQL {
		t.Errorf("%d queries at once, want at most %d", n.mostAtOnce, maxGraphQL)
	}
	var all []string
	for _, q := range n.graphql {
		if k := len(strings.Fields(q)); k > refsPerQuery {
			t.Errorf("a query compares %d refs", k)
		}
		all = append(all, strings.Fields(q)...)
	}
	if slices.Sort(all); len(slices.Compact(all)) != maxRefs {
		t.Errorf("the queries compare %d refs, want each of the %d once", len(all), maxRefs)
	}

	n = manyRefs(maxRefs + 1)
	got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", fork)
	if got.State != facts.StateUnknown || got.Reason != "github: the repository has too many refs to compare" || len(n.graphql) != 0 {
		t.Errorf("past the limit = %+v, asked %d", got, len(n.graphql))
	}
}

// TestCommitRefBudget: the queries count in MaxRequests, with the requests
// of git.ref-commit.
func TestCommitRefBudget(t *testing.T) {
	n := manyRefs(250)
	got := commitRef(t, serve(t, n, Options{Token: "tok", MaxRequests: 3}), "o/r", fork)
	if got.State != facts.StateUnknown || !strings.Contains(got.Reason, "MaxRequests") {
		t.Errorf("= %+v", got)
	}
	if len(n.rest)+len(n.graphql) > 3 {
		t.Errorf("sent %d requests", len(n.rest)+len(n.graphql))
	}
}

// TestCommitRefNames: a ref name from GitHub, which may have a quote, goes
// to GraphQL as a variable, never into the query.
func TestCommitRefNames(t *testing.T) {
	n := experiment()
	odd := `refs/tags/a"){x}#`
	n.refs = append(n.refs, ref{odd, head, "commit"})
	n.contains[fork] = map[string]string{odd: "BEHIND"}
	got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", fork)
	if got.State != facts.StateFound || got.Value.String() != odd {
		t.Errorf("= %+v", got)
	}
}

// TestCommitRefGraphQLPath: GraphQL is /graphql at api.github.com and
// /api/graphql on a GitHub Enterprise Server, whose REST is /api/v3.
func TestCommitRefGraphQLPath(t *testing.T) {
	for base, want := range map[string]string{
		"https://api.github.com":      "https://api.github.com/graphql",
		"https://ghe.example/api/v3":  "https://ghe.example/api/graphql",
		"https://ghe.example/api/v3/": "https://ghe.example/api/graphql",
		"http://127.0.0.1:1/api":      "http://127.0.0.1:1/api/graphql",
	} {
		u, _ := url.Parse(base)
		if got := New(Options{BaseURL: u}).(*resolver).graphqlURL(); got != want {
			t.Errorf("%s: %s, want %s", base, got, want)
		}
	}
}

func TestCommitRefTokenStaysIn(t *testing.T) {
	const token = "tok-secret-7"
	n := experiment()
	n.batch = func(w http.ResponseWriter, _ []string) bool {
		w.WriteHeader(500)
		w.Write([]byte(token))
		return true
	}
	got := commitRef(t, serve(t, n, Options{Token: token}), "o/r", fork)
	if strings.Contains(got.Reason, token) {
		t.Errorf("the reason has the token: %q", got.Reason)
	}
	for _, a := range n.tokens {
		if a != "Bearer "+token {
			t.Errorf("Authorization = %q", a)
		}
	}
}

// TestCommitRefBudgetHalf: git.commit-ref
// sends at most half of MaxRequests, so that decoy SHAs leave
// git.ref-commit its half.
func TestCommitRefBudgetHalf(t *testing.T) {
	n := manyRefs(1000)
	n.answer = func(w http.ResponseWriter, path string) bool {
		if strings.Contains(path, "/commits/refs/tags/v1") {
			w.Write([]byte(head))
			return true
		}
		return false
	}
	r := serve(t, n, Options{Token: "tok", MaxRequests: 10})
	got := commitRef(t, r, "o/r", fork)
	if got.State != facts.StateUnknown || got.Reason != "github: the requests of this run for git.commit-ref are spent (half of MaxRequests)" {
		t.Errorf("= %+v", got)
	}
	if sent := len(n.rest) + len(n.graphql); sent != 5 {
		t.Errorf("git.commit-ref sent %d requests, want 5", sent)
	}
	rp, _ := facts.ParseRepo("o/r")
	if got := (facts.GitRefCommit{Repo: rp, Ref: "v1"}).Ask(context.Background(), r); got.State != facts.StateFound {
		t.Errorf("git.ref-commit after = %+v", got)
	}
}

// TestCommitRefListAfterACancel: a list not
// taken because its asker's ctx was done is taken again by the next.
func TestCommitRefListAfterACancel(t *testing.T) {
	n := experiment()
	r := serve(t, n, Options{Token: "tok"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rp, _ := facts.ParseRepo("o/r")
	s, _ := facts.ParseSHA(tagged)
	if got := (facts.GitCommitRef{Repo: rp, SHA: s}).Ask(ctx, r); got.State != facts.StateUnknown {
		t.Errorf("canceled = %+v", got)
	}
	if got := r.Resolve(ctx, facts.GitCommitRef{Repo: rp, SHA: s}); got.State != facts.StateUnknown {
		t.Errorf("canceled = %+v", got)
	}
	if got := commitRef(t, r, "o/r", tagged); got.State != facts.StateFound {
		t.Errorf("after = %+v, want the list taken again", got)
	}
}

// TestCommitRefListFailureKept: a list that failed is not asked again in
// the run; the same answer, like a Recorder's.
func TestCommitRefListFailureKept(t *testing.T) {
	n := experiment()
	n.answer = func(w http.ResponseWriter, path string) bool {
		if strings.Contains(path, "/matching-refs/") {
			w.WriteHeader(500)
			return true
		}
		return false
	}
	r := serve(t, n, Options{Token: "tok"})
	commitRef(t, r, "o/r", tagged)
	asked := len(n.rest)
	if got := commitRef(t, r, "o/r", fork); got.State != facts.StateUnknown || got.Reason != "github: HTTP 500" || len(n.rest) != asked {
		t.Errorf("= %+v, asked %d more", got, len(n.rest)-asked)
	}
}

// TestCommitRefBatchesAnswer: what the
// batches of one question say together.
func TestCommitRefBatchesAnswer(t *testing.T) {
	failing := func(first string, answer string, code int) func(http.ResponseWriter, []string) bool {
		return func(w http.ResponseWriter, refs []string) bool {
			if refs[0] != first {
				return false
			}
			w.WriteHeader(code)
			w.Write([]byte(answer))
			return true
		}
	}
	for _, c := range []struct {
		name   string
		batch  func(http.ResponseWriter, []string) bool
		has    string // a ref that has fork
		sha    string
		state  facts.State
		value  string
		reason string
	}{
		{"one batch of three fails", failing("refs/tags/v0100", "", 502), "", fork, facts.StateUnknown, "", "github: HTTP 502"},
		{"one fails, another has it", failing("refs/tags/v0100", "", 502), "refs/tags/v0200", fork, facts.StateFound, "refs/tags/v0200", ""},
		{"one fails as a whole, for a commit in the network", failing("refs/tags/v0100", `{"data":null,"errors":[{"message":"x"}]}`, 200), "", fork, facts.StateUnknown, "", "github: the refs could not be compared"},
		{"all fail as a whole, for a SHA nowhere", nil, "", absent, facts.StateAbsent, "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := manyRefs(250)
			n.batch = c.batch
			if c.has != "" {
				n.contains[fork] = map[string]string{c.has: "BEHIND"}
			}
			got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", c.sha)
			if got.State != c.state || got.Value.String() != c.value || got.Reason != c.reason {
				t.Errorf("= %+v, want %v %q %q", got, c.state, c.value, c.reason)
			}
		})
	}
}

// TestCommitRefNowhere is the table of step 4: a SHA is nowhere only when
// it is no commit (422) and no tag object (404).
func TestCommitRefNowhere(t *testing.T) {
	for _, c := range []struct {
		name  string
		code  map[string]int // by commits or tags
		state facts.State
	}{
		{"no commit, no tag object", map[string]int{"commits": 422, "tags": 404}, facts.StateAbsent},
		{"a tag object that no ref has", map[string]int{"commits": 422, "tags": 200}, facts.StateUnknown},
		{"the repository is not seen", map[string]int{"commits": 404}, facts.StateUnknown},
		{"500", map[string]int{"commits": 500}, facts.StateUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := experiment()
			n.answer = func(w http.ResponseWriter, path string) bool {
				for k, code := range c.code {
					if strings.Contains(path, "/"+k+"/") {
						w.WriteHeader(code)
						return true
					}
				}
				return false
			}
			if got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", absent); got.State != c.state {
				t.Errorf("= %+v, want %v", got, c.state)
			}
		})
	}
}

// TestCommitRefSkipsOtherObjects: a tag of
// a tree or a blob is not compared, which GraphQL answers with null.
func TestCommitRefSkipsOtherObjects(t *testing.T) {
	n := experiment()
	n.refs = append(n.refs, ref{"refs/tags/v2.6.11-tree", "5dc01c595e6c6ec9ccda4f6f69c131c0dd945f8c", "tree"})
	got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", fork)
	if got.State != facts.StateAbsent {
		t.Errorf("= %+v", got)
	}
	for _, q := range n.graphql {
		if strings.Contains(q, "tree") {
			t.Errorf("compared %s", q)
		}
	}
}

// TestSecondaryRateLimit: a 403 with
// Retry-After is the secondary rate limit, after which nothing is sent.
func TestSecondaryRateLimit(t *testing.T) {
	n := experiment()
	n.batch = func(w http.ResponseWriter, _ []string) bool {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"message":"You have exceeded a secondary rate limit."}`))
		return true
	}
	r := serve(t, n, Options{Token: "tok"})
	if got := commitRef(t, r, "o/r", fork); got.Reason != "github: rate limited" {
		t.Errorf("= %+v", got)
	}
	asked := len(n.rest) + len(n.graphql)
	commitRef(t, r, "o/r", tip)
	if len(n.rest)+len(n.graphql) != asked {
		t.Error("sent after the secondary rate limit")
	}
}

// TestGraphQLRateLimitKeepsREST: GraphQL has a
// rate limit of its own; reaching it stops git.commit-ref past the tips,
// not git.ref-commit.
func TestGraphQLRateLimitKeepsREST(t *testing.T) {
	for name, batch := range map[string]func(http.ResponseWriter, []string) bool{
		"RATE_LIMITED": func(w http.ResponseWriter, _ []string) bool {
			w.Write([]byte(`{"errors":[{"type":"RATE_LIMITED","message":"x"}]}`))
			return true
		},
		"secondary": func(w http.ResponseWriter, _ []string) bool {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusForbidden)
			return true
		},
	} {
		t.Run(name, func(t *testing.T) {
			n := experiment()
			n.batch = batch
			n.answer = func(w http.ResponseWriter, path string) bool {
				if strings.Contains(path, "/commits/refs/tags/v1") {
					w.Write([]byte(head))
					return true
				}
				return false
			}
			r := serve(t, n, Options{Token: "tok"})
			if got := commitRef(t, r, "o/r", fork); got.Reason != "github: rate limited" {
				t.Errorf("= %+v", got)
			}
			asked := len(n.graphql)
			commitRef(t, r, "o/r", tip)
			if len(n.graphql) != asked {
				t.Error("GraphQL sent after its rate limit")
			}
			if got := commitRef(t, r, "o/r", tagged); got.State != facts.StateFound {
				t.Errorf("a tip after = %+v, want the REST list still used", got)
			}
			rp, _ := facts.ParseRepo("o/r")
			if got := (facts.GitRefCommit{Repo: rp, Ref: "v1"}).Ask(context.Background(), r); got.State != facts.StateFound {
				t.Errorf("git.ref-commit after = %+v", got)
			}
		})
	}
}

// TestGraphQLQueriesOfARun: a run sends at most
// maxQueries GraphQL queries, whatever the workflows name.
func TestGraphQLQueriesOfARun(t *testing.T) {
	n := manyRefs(maxRefs)
	r := serve(t, n, Options{Token: "tok", MaxRequests: 100000})
	var last facts.Answer[facts.RefName]
	for i := range 2 * maxQueries / (maxRefs / refsPerQuery) {
		sha := fmt.Sprintf("%040x", i+1)
		n.mu.Lock()
		n.objects[sha] = "commit"
		n.mu.Unlock()
		last = commitRef(t, r, "o/r", sha)
	}
	if len(n.graphql) > maxQueries {
		t.Errorf("sent %d queries, want at most %d", len(n.graphql), maxQueries)
	}
	if last.State != facts.StateUnknown || last.Reason != "github: the GraphQL queries of this run are spent" {
		t.Errorf("past the limit = %+v", last)
	}
}

// TestCommitRefLongListNotKept: a list longer
// than can be compared is not kept, only that it is too long; the tips are
// matched from it, and a later question lists again.
func TestCommitRefLongListNotKept(t *testing.T) {
	n := manyRefs(maxRefs + 1)
	r := serve(t, n, Options{Token: "tok"}).(*resolver)
	if got := commitRef(t, r, "o/r", head); got.State != facts.StateFound {
		t.Errorf("a tip = %+v", got)
	}
	rp, _ := facts.ParseRepo("o/r")
	if l := r.lists[rp]; l == nil || len(l.refs) != 0 || l.why != "" || !l.tooMany {
		t.Errorf("kept %+v", l)
	}
	if got := commitRef(t, r, "o/r", fork); got.Reason != "github: the repository has too many refs to compare" {
		t.Errorf("= %+v", got)
	}
}

// TestCommitRefPagedList: a list GitHub says has
// a next page is not taken as whole.
func TestCommitRefPagedList(t *testing.T) {
	n := experiment()
	n.answer = func(w http.ResponseWriter, path string) bool {
		if strings.Contains(path, "/matching-refs/tags") {
			w.Header().Set("Link", `<https://api.github.com/x?page=2>; rel="next"`)
		}
		return false
	}
	if got := commitRef(t, serve(t, n, Options{Token: "tok"}), "o/r", fork); got.State != facts.StateUnknown || got.Reason != "github: the list of refs has more pages" {
		t.Errorf("= %+v", got)
	}
}

package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

const (
	shaA = "019216bb322ee2a2b2259739ceacae26020c46bb"
	shaB = "ee770a9615648ecfcf3ca4bf8b549375d3be713e"
)

// fake is a GitHub API that answers the commits endpoint from a table of
// escaped paths, and records what it was asked.
type fake struct {
	mu      sync.Mutex
	answers map[string]func(w http.ResponseWriter) // by the escaped path after /api
	paths   []string
	headers []http.Header
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.EscapedPath())
	f.headers = append(f.headers, r.Header.Clone())
	key := strings.TrimPrefix(r.URL.EscapedPath(), "/api")
	a := f.answers[key]
	if q := r.URL.RawQuery; q != "" && f.answers[key+"?"+q] != nil {
		a = f.answers[key+"?"+q]
	}
	f.mu.Unlock()
	if a == nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message":"No commit found for SHA: x"}`))
		return
	}
	a(w)
}

func body(status int, b string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(status); w.Write([]byte(b)) }
}

// start serves f under /api, so that the tests see BaseURL's path kept.
func start(t *testing.T, f *fake, token string) facts.Resolver {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/api")
	return New(Options{Token: token, BaseURL: u, Client: srv.Client()})
}

func ask(t *testing.T, r facts.Resolver, repo, ref string) facts.Answer[facts.RefCommit] {
	t.Helper()
	rp, err := facts.ParseRepo(repo)
	if err != nil {
		t.Fatal(err)
	}
	return facts.GitRefCommit{Repo: rp, Ref: ref}.Ask(context.Background(), r)
}

// TestRunnerOrder: the runner runs the tag when a branch and
// a tag have the same name, so the tag is asked first.
func TestRunnerOrder(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/both":  body(200, shaB),
		"/repos/o/r/commits/refs/heads/both": body(200, shaA),
		"/repos/o/r/commits/refs/heads/main": body(200, shaA),
		"/repos/o/r/commits/" + shaA:         body(200, shaA),
	}}
	r := start(t, f, "")
	if got := ask(t, r, "o/r", "both"); got.State != facts.StateFound || got.Value.SHA.String() != shaB || got.Value.Ref.String() != "refs/tags/both" {
		t.Errorf("both = %+v, want the tag's %s", got, shaB)
	}
	if got := ask(t, r, "o/r", "main"); got.State != facts.StateFound || got.Value.SHA.String() != shaA || got.Value.Ref.String() != "refs/heads/main" {
		t.Errorf("main = %+v", got)
	}
	if got := ask(t, r, "o/r", strings.ToUpper(shaA)); got.State != facts.StateFound || got.Value.SHA.String() != shaA || !got.Value.Ref.IsZero() {
		t.Errorf("a full SHA = %+v, want no ref: it is found as a commit", got)
	}
	f.paths = nil
	if got := ask(t, r, "o/r", shaA[:7]); got.State != facts.StateAbsent {
		t.Errorf("a shortened SHA = %+v, want absent: the runner refuses it", got)
	}
	if want := []string{"/api/repos/o/r/commits/refs/tags/019216b", "/api/repos/o/r/commits/refs/heads/019216b"}; strings.Join(f.paths, " ") != strings.Join(want, " ") {
		t.Errorf("a shortened SHA asked %v, want %v", f.paths, want)
	}
	if got := ask(t, r, "o/r", "nope"); got.State != facts.StateAbsent {
		t.Errorf("nope = %+v, want absent", got)
	}
}

func TestAnswers(t *testing.T) {
	limited := func(w http.ResponseWriter) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", "1790000000")
		w.WriteHeader(http.StatusForbidden)
	}
	for _, c := range []struct {
		name   string
		answer func(http.ResponseWriter)
		state  facts.State
		reason string
	}{
		{"a SHA with a line break", body(200, shaA+"\n"), facts.StateFound, ""},
		{"not a SHA", body(200, `{"sha": "x"}`), facts.StateUnknown, "github: the answer is not a commit"},
		{"404", body(404, `{"message":"Not Found"}`), facts.StateUnknown, "github: the repository is not there, or the token cannot see it"},
		{"403 rate limited", limited, facts.StateUnknown, "github: rate limited"},
		{"429", body(429, ""), facts.StateUnknown, "github: rate limited"},
		{"403", body(403, ""), facts.StateUnknown, "github: HTTP 403"},
		{"500", body(500, "oops"), facts.StateUnknown, "github: HTTP 500"},
		{"a redirect to itself is followed", nil, facts.StateFound, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fake{answers: map[string]func(http.ResponseWriter){"/repos/o/r/commits/refs/tags/v1": c.answer}}
			if c.answer == nil {
				f.answers["/repos/o/r/commits/refs/tags/v1"] = func(w http.ResponseWriter) {
					w.Header().Set("Location", "/api/repos/o/moved/commits/refs/tags/v1")
					w.WriteHeader(http.StatusMovedPermanently)
				}
				f.answers["/repos/o/moved/commits/refs/tags/v1"] = body(200, shaA)
			}
			got := ask(t, start(t, f, ""), "o/r", "v1")
			if got.State != c.state || got.Reason != c.reason {
				t.Errorf("= %+v, want %v %q", got, c.state, c.reason)
			}
		})
	}
}

func TestOtherKinds(t *testing.T) {
	r := New(Options{})
	if got := r.Resolve(context.Background(), facts.TestFlag{Name: "x"}); got.State != facts.StateUnknown || got.Reason == "" {
		t.Errorf("= %+v", got)
	}
}

func TestCanceled(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	r := start(t, f, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rp, _ := facts.ParseRepo("o/r")
	if got := r.Resolve(ctx, facts.GitRefCommit{Repo: rp, Ref: "v1"}); got.State != facts.StateUnknown {
		t.Errorf("= %+v", got)
	}
}

func TestHeaders(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){"/repos/o/r/commits/refs/tags/v1": body(200, shaA)}}
	ask(t, start(t, f, "tok-123"), "o/r", "v1")
	h := f.headers[0]
	if h.Get("Accept") != "application/vnd.github.sha" || h.Get("Authorization") != "Bearer tok-123" || h.Get("X-GitHub-Api-Version") == "" {
		t.Errorf("headers = %v", h)
	}
	f.headers = nil
	ask(t, start(t, f, ""), "o/r", "v1")
	if _, ok := f.headers[0]["Authorization"]; ok {
		t.Error("an Authorization header without a token")
	}
}

// TestEscape: a ref from an untrusted workflow stays one
// part of the path of the commits endpoint.
func TestEscape(t *testing.T) {
	for ref, want := range map[string]string{
		"feature/x":             "/api/repos/o/r/commits/refs/tags/feature%2Fx",
		"../../../orgs/x/repos": "/api/repos/o/r/commits/refs/tags/..%2F..%2F..%2Forgs%2Fx%2Frepos",
		"v1?per_page=1":         "/api/repos/o/r/commits/refs/tags/v1%3Fper_page=1",
		"v1#x":                  "/api/repos/o/r/commits/refs/tags/v1%23x",
		"%2e%2e":                "/api/repos/o/r/commits/refs/tags/%252e%252e",
		"a b":                   "/api/repos/o/r/commits/refs/tags/a%20b",
		"é":                     "/api/repos/o/r/commits/refs/tags/%C3%A9",
	} {
		f := &fake{answers: map[string]func(http.ResponseWriter){}}
		ask(t, start(t, f, ""), "o/r", ref)
		if len(f.paths) == 0 || f.paths[0] != want {
			t.Errorf("%q asked %v, want %s first", ref, f.paths, want)
		}
	}
	// . and .. as a whole part would be cleaned away by a server: no git ref
	// or GitHub repository has such a name, so nothing is asked.
	for _, c := range [][2]string{{"o/r", ".."}, {"o/r", "."}, {"../r", "v1"}, {"o/..", "v1"}, {"./r", "v1"}} {
		f := &fake{answers: map[string]func(http.ResponseWriter){}}
		got := ask(t, start(t, f, ""), c[0], c[1])
		if len(f.paths) != 0 || got.State != facts.StateUnknown {
			t.Errorf("%v: asked %v, answer %+v", c, f.paths, got)
		}
	}
}

// TestTokenStaysIn: a redirect to another host does not carry the token.
func TestTokenStaysIn(t *testing.T) {
	const token = "tok-secret-9"
	other := &fake{answers: map[string]func(http.ResponseWriter){"/repos/o/r/commits/refs/tags/v1": body(200, shaA)}}
	otherSrv := httptest.NewServer(other)
	defer otherSrv.Close()
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": func(w http.ResponseWriter) {
			w.Header().Set("Location", otherSrv.URL+"/api/repos/o/r/commits/refs/tags/v1")
			w.WriteHeader(http.StatusFound)
		},
		"/repos/o/r/commits/refs/tags/v2": body(500, "echo "+token),
	}}
	r := start(t, f, token)
	got := ask(t, r, "o/r", "v1")
	for _, h := range other.headers {
		if strings.Contains(h.Get("Authorization"), token) {
			t.Error("the token went to another host on a redirect")
		}
	}
	if got.State == facts.StateFound {
		t.Error("a redirect to another host was followed")
	}
	for _, ref := range []string{"v1", "v2"} {
		if got := ask(t, r, "o/r", ref); strings.Contains(got.Reason, token) {
			t.Errorf("%s: the reason has the token: %q", ref, got.Reason)
		}
	}
}

// TestRateLimitStops: once GitHub says the rate
// limit is reached, nothing more is asked; every later fact is unknown.
func TestRateLimitStops(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	for i := range 50 {
		f.answers["/repos/o/r/commits/refs/tags/v"+strconv.Itoa(i)] = body(429, "")
	}
	r := start(t, f, "")
	for i := range 50 {
		if got := ask(t, r, "o/r", "v"+strconv.Itoa(i)); got.State != facts.StateUnknown || got.Reason != "github: rate limited" {
			t.Fatalf("v%d = %+v", i, got)
		}
	}
	if len(f.paths) != 1 {
		t.Errorf("asked %d times after a rate limit, want 1", len(f.paths))
	}
}

// TestRequestBudget: a workflow may name any
// number of refs; one Resolver sends at most MaxRequests requests.
func TestRequestBudget(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := New(Options{BaseURL: u, Client: srv.Client(), MaxRequests: 10})
	var last facts.Answer[facts.RefCommit]
	for i := range 50 {
		last = ask(t, r, "o/r", "v"+strconv.Itoa(i))
	}
	if len(f.paths) != 10 {
		t.Errorf("sent %d requests, want MaxRequests, 10", len(f.paths))
	}
	if last.State != facts.StateUnknown || !strings.Contains(last.Reason, "requests") {
		t.Errorf("past the budget = %+v", last)
	}
}

// TestNothingToAsk: a query that names no
// repository or no ref sends nothing.
func TestNothingToAsk(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	r := start(t, f, "")
	rp, _ := facts.ParseRepo("o/r")
	for _, q := range []facts.GitRefCommit{{Ref: "v1"}, {Repo: rp}} {
		if got := r.Resolve(context.Background(), q); got.State != facts.StateUnknown {
			t.Errorf("%+v = %+v", q, got)
		}
	}
	if len(f.paths) != 0 {
		t.Errorf("asked %v", f.paths)
	}
}

// TestRedirectKeepsTheScheme: a redirect to the
// same host by another scheme (https to http would carry the token in the
// clear) is not followed.
func TestRedirectKeepsTheScheme(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	f.answers["/repos/o/r/commits/refs/tags/v1"] = func(w http.ResponseWriter) {
		w.Header().Set("Location", strings.Replace(srv.URL, "http://", "https://", 1)+"/api/repos/o/r/commits/refs/tags/v2")
		w.WriteHeader(http.StatusFound)
	}
	u, _ := url.Parse(srv.URL + "/api")
	got := ask(t, New(Options{Token: "tok", BaseURL: u, Client: srv.Client()}), "o/r", "v1")
	if got.State != facts.StateUnknown || got.Reason != "github: HTTP 302" {
		t.Errorf("= %+v, want the redirect not followed", got)
	}
}

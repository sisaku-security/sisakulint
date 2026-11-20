// Package githubtest is a fake of GitHub for tests. It answers the way
// GitHub did:
//
//   - the commits API: a commit for the paths it knows, 500 for a broken repository,
//     and 422 for anything else;
//   - the refs of a repository by matching-refs, and GraphQL's
//     Ref.compare of a SHA with them, for
//     the repositories given to Network: a SHA that the repository has
//     somewhere but no ref has is DIVERGED from each; for a SHA it has
//     nowhere, GraphQL fails as a whole, and git/tags/{sha} is 404 but for a
//     tag object.
//   - the tags of a repository given to Network (GET /repos/{o}/{r}/tags),
//     each with the commit it points to, an annotated tag by its commit, in
//     one page;
//   - the advisories of the GitHub Advisory Database (GET /advisories) given
//     to Advisories, for type reviewed; [] for any other affects or type.
package githubtest

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/facts/github"
)

// Server is the fake. Refs maps an escaped path, such as
// /repos/actions/checkout/commits/refs/tags/v4, to the SHA it answers.
type Server struct {
	URL string

	srv  *httptest.Server
	mu   sync.Mutex
	auth []string // the Authorization of each request, in order
	nets map[string]Repo
	advs map[string]string // affects -> the body of GET /advisories
}

// Repo is what a repository has.
type Repo struct {
	Refs map[string]string   // a full name such as refs/tags/v1 -> the object it points to
	Tags map[string]string   // an annotated tag's object -> its commit
	Has  map[string][]string // a commit -> the refs whose history has it
}

// knows is whether sha is somewhere in the repository's network.
func (n Repo) knows(sha string) bool {
	if _, ok := n.Tags[sha]; ok {
		return true
	}
	if _, ok := n.Has[sha]; ok {
		return true
	}
	for _, v := range n.Refs {
		if v == sha {
			return true
		}
	}
	return false
}

// New starts the fake; it stops when the test ends. A request for a
// repository in broken (owner/repo) gets 500.
func New(t testing.TB, refs map[string]string, broken ...string) *Server {
	t.Helper()
	s := &Server{nets: map[string]Repo{}, advs: map[string]string{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.auth = append(s.auth, r.Header.Get("Authorization"))
		s.mu.Unlock()
		for _, b := range broken {
			if strings.HasPrefix(r.URL.Path, "/repos/"+b+"/") {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		if r.URL.Path == "/graphql" {
			s.compare(w, r)
			return
		}
		if m := matchingRefs.FindStringSubmatch(r.URL.Path); m != nil {
			s.matchingRefs(w, m[1], m[2])
			return
		}
		if m := repoTags.FindStringSubmatch(r.URL.Path); m != nil {
			s.tags(w, m[1])
			return
		}
		if r.URL.Path == "/advisories" {
			s.mu.Lock()
			body, ok := s.advs[r.URL.Query().Get("affects")]
			s.mu.Unlock()
			if !ok || r.URL.Query().Get("type") != "reviewed" {
				body = "[]"
			}
			w.Write([]byte(body))
			return
		}
		if m := gitTags.FindStringSubmatch(r.URL.Path); m != nil {
			s.mu.Lock()
			_, ok := s.nets[m[1]].Tags[m[2]]
			s.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write([]byte(`{"sha":"` + m[2] + `"}`))
			return
		}
		if sha, ok := refs[r.URL.EscapedPath()]; ok {
			w.Write([]byte(sha))
			return
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	t.Cleanup(s.srv.Close)
	s.URL = s.srv.URL
	return s
}

// Network gives the fake the refs of the repository repo (owner/name).
func (s *Server) Network(repo string, r Repo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nets[repo] = r
}

// Advisories gives the fake the body of GET /advisories of type reviewed
// for affects=affects (a package, or package@version), as GitHub writes
// it.
func (s *Server) Advisories(affects, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.advs[affects] = body
}

// tags answers GET /repos/{o}/{r}/tags of the repository repo.
func (s *Server) tags(w http.ResponseWriter, repo string) {
	s.mu.Lock()
	n, ok := s.nets[repo]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	out := []any{}
	for name, sha := range n.Refs {
		tag, ok := strings.CutPrefix(name, "refs/tags/")
		if !ok {
			continue
		}
		if c, ok := n.Tags[sha]; ok {
			sha = c
		}
		out = append(out, map[string]any{"name": tag, "commit": map[string]string{"sha": sha}})
	}
	json.NewEncoder(w).Encode(out)
}

var (
	repoTags     = regexp.MustCompile(`^/repos/([^/]+/[^/]+)/tags$`)
	matchingRefs = regexp.MustCompile(`^/repos/([^/]+/[^/]+)/git/matching-refs/(heads|tags)$`)
	gitTags      = regexp.MustCompile(`^/repos/([^/]+/[^/]+)/git/tags/([0-9a-f]+)$`)
)

func (s *Server) matchingRefs(w http.ResponseWriter, repo, kind string) {
	s.mu.Lock()
	n, ok := s.nets[repo]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	out := []any{}
	for name, sha := range n.Refs {
		if strings.HasPrefix(name, "refs/"+kind+"/") {
			typ := "commit"
			if _, ok := n.Tags[sha]; ok {
				typ = "tag"
			}
			out = append(out, map[string]any{"ref": name, "object": map[string]string{"sha": sha, "type": typ}})
		}
	}
	json.NewEncoder(w).Encode(out)
}

var alias = regexp.MustCompile(`r(\d+): ref\(qualifiedName: \$q\d+\)`)

func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Query     string            `json:"query"`
		Variables map[string]string `json:"variables"`
	}
	b, _ := io.ReadAll(r.Body)
	if json.Unmarshal(b, &req) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	n, ok := s.nets[req.Variables["owner"]+"/"+req.Variables["name"]]
	s.mu.Unlock()
	if !ok {
		w.Write([]byte(`{"data":{"repository":null},"errors":[{"type":"NOT_FOUND"}]}`))
		return
	}
	sha := req.Variables["sha"]
	if !n.knows(sha) {
		w.Write([]byte(`{"data":null,"errors":[{"message":"Something went wrong while executing your query."}]}`))
		return
	}
	has := n.Has[sha]
	repo := map[string]any{}
	for _, m := range alias.FindAllStringSubmatch(req.Query, -1) {
		status := "DIVERGED"
		for _, h := range has {
			if h == req.Variables["q"+m[1]] {
				status = "BEHIND"
			}
		}
		repo["r"+m[1]] = map[string]any{"compare": map[string]string{"status": status}}
	}
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"repository": repo}})
}

// Resolver is a Resolver of package github that asks the fake, with a
// token, which GraphQL needs.
func (s *Server) Resolver() facts.Resolver {
	u, _ := url.Parse(s.URL)
	return github.New(github.Options{Token: "githubtest", BaseURL: u, Client: s.srv.Client()})
}

// Authorizations are the Authorization headers the fake got, one a request.
func (s *Server) Authorizations() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth...)
}

package githubtest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// File is a file of a commit of Git: a blob (Mode 100644 or 100755, Data
// its bytes), a symlink (Mode 120000, Data its target) or a submodule
// (Mode 160000, Data the commit it points to).
type File struct {
	Mode string
	Data string
}

// Blob is a file of mode 100644.
func Blob(data string) File { return File{Mode: "100644", Data: data} }

// Symlink is a file of mode 120000.
func Symlink(target string) File { return File{Mode: "120000", Data: target} }

// Submodule is a file of mode 160000.
func Submodule(commit string) File { return File{Mode: "160000", Data: commit} }

// PullRequest is a pull request of a repository of Git.
type PullRequest struct {
	Head    string // the commit of the head
	BaseRef string // the base branch
}

type gitRepo struct {
	defaultBranch string
	refs          map[string]string          // a branch, a tag or a SHA -> a commit
	commits       map[string]map[string]File // a commit -> its files
	parents       map[string][]string        // a commit -> the commits before it, the nearest first
	pulls         map[int]PullRequest
}

// Git is a fake of the git trees, blobs, commits, pulls and compare APIs
// of GitHub, for repositories given to Commit.
type Git struct {
	t   testing.TB
	srv *httptest.Server

	mu        sync.Mutex
	repos     map[string]*gitRepo
	blobs     map[string]string // a blob's SHA -> its bytes
	truncated map[string]bool   // a commit whose tree is truncated
	failBlob  map[string]int    // a blob's SHA -> the status to answer
	requests  []string
	auth      []string
}

// NewGit starts the fake; it stops when the test ends.
func NewGit(t testing.TB) *Git {
	g := &Git{t: t, repos: map[string]*gitRepo{}, blobs: map[string]string{}, truncated: map[string]bool{}, failBlob: map[string]int{}}
	g.srv = httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(g.srv.Close)
	return g
}

// URL is the root of the fake's REST API.
func (g *Git) URL() *url.URL {
	u, _ := url.Parse(g.srv.URL)
	return u
}

// Client is an HTTP client for the fake.
func (g *Git) Client() *http.Client { return g.srv.Client() }

func blobSHA(data string) string {
	h := sha1.Sum([]byte("blob " + strconv.Itoa(len(data)) + "\x00" + data))
	return hex.EncodeToString(h[:])
}

func (g *Git) repo(name string) *gitRepo {
	r := g.repos[strings.ToLower(name)]
	if r == nil {
		r = &gitRepo{defaultBranch: "main", refs: map[string]string{}, commits: map[string]map[string]File{}, parents: map[string][]string{}, pulls: map[int]PullRequest{}}
		g.repos[strings.ToLower(name)] = r
	}
	return r
}

// Commit adds a commit of repo whose files are files, after the commits
// parents (the nearest first), and points the branch ref to it when ref is
// not empty. It returns the commit's SHA.
func (g *Git) Commit(repo, ref string, files map[string]File, parents ...string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	r := g.repo(repo)
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha1.New()
	fmt.Fprintf(h, "%s %v", repo, parents)
	for _, k := range keys {
		fmt.Fprintf(h, "%s %s %s\n", k, files[k].Mode, files[k].Data)
		if files[k].Mode != "160000" {
			g.blobs[blobSHA(files[k].Data)] = files[k].Data
		}
	}
	sha := hex.EncodeToString(h.Sum(nil))
	r.commits[sha] = files
	var chain []string
	for _, p := range parents {
		chain = append(chain, p)
		chain = append(chain, r.parents[p]...)
	}
	r.parents[sha] = chain
	r.refs[sha] = sha
	if ref != "" {
		r.refs[ref] = sha
	}
	return sha
}

// Pull adds the pull request number of repo.
func (g *Git) Pull(repo string, number int, p PullRequest) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.repo(repo).pulls[number] = p
}

// Truncate makes the tree of commit truncated.
func (g *Git) Truncate(commit string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.truncated[commit] = true
}

// FailBlob makes the blob of data answer status.
func (g *Git) FailBlob(data string, status int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failBlob[blobSHA(data)] = status
}

// Requests are the paths of the requests the fake got, in order.
func (g *Git) Requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.requests)
}

// Authorizations are the Authorization headers of the requests.
func (g *Git) Authorizations() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.auth)
}

func (g *Git) serve(w http.ResponseWriter, req *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, req.URL.Path)
	g.auth = append(g.auth, req.Header.Get("Authorization"))
	p := strings.TrimPrefix(req.URL.Path, "/api/v3") // a GitHub Enterprise Server's root
	parts := strings.Split(strings.TrimPrefix(p, "/repos/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, req)
		return
	}
	r, ok := g.repos[strings.ToLower(parts[0]+"/"+parts[1])]
	if !ok {
		http.NotFound(w, req)
		return
	}
	rest := parts[2:]
	switch {
	case len(rest) == 0:
		json.NewEncoder(w).Encode(map[string]any{"default_branch": r.defaultBranch})
	case rest[0] == "commits" && len(rest) >= 2:
		sha, ok := r.refs[strings.Join(rest[1:], "/")]
		if !ok {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		fmt.Fprint(w, sha)
	case rest[0] == "git" && len(rest) == 3 && rest[1] == "trees":
		g.tree(w, req, r, rest[2])
	case rest[0] == "git" && len(rest) == 3 && rest[1] == "blobs":
		if s, ok := g.failBlob[rest[2]]; ok {
			w.WriteHeader(s)
			return
		}
		data, ok := g.blobs[rest[2]]
		if !ok {
			http.NotFound(w, req)
			return
		}
		fmt.Fprint(w, data)
	case rest[0] == "pulls" && len(rest) == 2:
		n, _ := strconv.Atoi(rest[1])
		p, ok := r.pulls[n]
		if !ok {
			http.NotFound(w, req)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"number": n, "head": map[string]any{"sha": p.Head}, "base": map[string]any{"ref": p.BaseRef}})
	case rest[0] == "compare" && len(rest) >= 2:
		base, head, ok := strings.Cut(strings.Join(rest[1:], "/"), "...")
		if !ok {
			http.NotFound(w, req)
			return
		}
		mb, behind := mergeBase(r, base, head)
		json.NewEncoder(w).Encode(map[string]any{"merge_base_commit": map[string]any{"sha": mb}, "behind_by": behind})
	default:
		http.NotFound(w, req)
	}
}

// mergeBase is the nearest commit of head's history that base's history
// has, and how many commits base has past it.
func mergeBase(r *gitRepo, base, head string) (string, int) {
	ofBase := append([]string{base}, r.parents[base]...)
	for _, c := range append([]string{head}, r.parents[head]...) {
		if i := slices.Index(ofBase, c); i >= 0 {
			return c, i
		}
	}
	return "", len(ofBase)
}

func (g *Git) tree(w http.ResponseWriter, req *http.Request, r *gitRepo, commit string) {
	files, ok := r.commits[commit]
	if !ok {
		http.NotFound(w, req)
		return
	}
	type entry struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
		Size int    `json:"size,omitempty"`
	}
	dirs := map[string]bool{}
	var tree []entry
	for p, f := range files {
		for d := p; strings.Contains(d, "/"); {
			d = d[:strings.LastIndex(d, "/")]
			dirs[d] = true
		}
		switch f.Mode {
		case "160000":
			tree = append(tree, entry{p, f.Mode, "commit", f.Data, 0})
		default:
			tree = append(tree, entry{p, f.Mode, "blob", blobSHA(f.Data), len(f.Data)})
		}
	}
	for d := range dirs {
		h := sha1.Sum([]byte("tree " + d))
		tree = append(tree, entry{d, "040000", "tree", hex.EncodeToString(h[:]), 0})
	}
	slices.SortFunc(tree, func(a, b entry) int { return strings.Compare(a.Path, b.Path) })
	h := sha1.Sum([]byte("tree of " + commit))
	json.NewEncoder(w).Encode(map[string]any{"sha": hex.EncodeToString(h[:]), "tree": tree, "truncated": g.truncated[commit]})
}

// Tarball is the archive GitHub serves of a commit (GET .../tarball/{sha}),
// of files (a path and its text) under one top directory, as a string a
// Server answers with.
func Tarball(files map[string]string) string {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "top/", Typeflag: tar.TypeDir, Mode: 0o755})
	for _, p := range slices.Sorted(maps.Keys(files)) {
		tw.WriteHeader(&tar.Header{Name: "top/" + p, Typeflag: tar.TypeReg, Size: int64(len(files[p])), Mode: 0o644})
		tw.Write([]byte(files[p]))
	}
	tw.Close()
	gz.Close()
	return buf.String()
}

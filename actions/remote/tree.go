package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/internal/githubapi"
)

// Limits bound what a run reads of a repository: the files and the
// requests are those of the repository read, which its writers decide.
type Limits struct {
	MaxRequests  int   // the requests of the run, the tree's included; 0 is 1000
	MaxBlobBytes int64 // the largest file read; 0 is 1 MiB, above the 500 KB of a workflow GitHub runs
}

func (l Limits) orDefault() Limits {
	if l.MaxRequests <= 0 {
		l.MaxRequests = 1000
	}
	if l.MaxBlobBytes <= 0 {
		l.MaxBlobBytes = 1 << 20
	}
	return l
}

var (
	// ErrTruncated is a tree of more entries than GitHub lists.
	ErrTruncated = errors.New("the tree of the commit is truncated: GitHub lists at most 100,000 entries or 7 MB of it")
	// ErrBlobTooLarge is a file above Limits.MaxBlobBytes.
	ErrBlobTooLarge = errors.New("larger than the limit of a file read")
	// ErrRequestsSpent is a file not read, the requests of Limits being spent.
	ErrRequestsSpent = errors.New("not read: the run has used up the requests it may send to the GitHub API")
	errEscapes       = errors.New("a symlink out of the repository")
	errLoop          = errors.New("too many symlinks")
)

// NotFoundError is a repository, a ref, a commit or a pull request GitHub
// answers 404 (or 422) for: it is not there, or the token cannot see it.
type NotFoundError struct{ What string }

func (e *NotFoundError) Error() string {
	return e.What + " is not there, or the token cannot see it"
}

// StatusError is another status GitHub answered.
type StatusError struct {
	What   string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.What, e.Status) }

// Entry is an entry of a tree: its mode (100644, 100755, 120000, 160000,
// 040000) and its object.
type Entry struct {
	Mode string
	SHA  facts.SHA
	size int64
}

// ReadFile is a file whose contents a run read or tried to read: its path,
// its blob and its mode (Report's remote_revision.read_files).
type ReadFile struct {
	Path facts.InputPath
	Blob facts.SHA
	Mode string
}

// Tree is the files of one commit of a repository, as an fs.FS: the
// paths from the tree, the contents read one blob at a time when a file is
// opened. A symlink is a symlink (Open and Stat follow it within the
// repository), a submodule an empty directory.
type Tree struct {
	ctx    context.Context
	c      *githubapi.Client
	repo   facts.Repo
	commit facts.SHA
	sha    facts.SHA
	limits Limits

	entries map[string]Entry
	dirs    map[string][]string // a directory -> the names in it

	mu     sync.Mutex
	left   int
	blobs  map[string][]byte // by path
	failed map[string]error  // by path
	read   map[string]bool   // the paths whose contents were asked
	hops   map[string][]string
}

func get(ctx context.Context, c *githubapi.Client, what, u, accept string, max int64) (githubapi.Response, error) {
	resp, err := c.Get(ctx, u, accept, max)
	if err != nil {
		return resp, fmt.Errorf("%s: %w", what, err)
	}
	switch resp.Status {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound, http.StatusUnprocessableEntity:
		return resp, &NotFoundError{What: what}
	}
	return resp, &StatusError{What: what, Status: resp.Status}
}

func repoURL(c *githubapi.Client, repo facts.Repo) string {
	return c.Base() + "/repos/" + repo.String() + "/"
}

// ResolveCommit is the commit ref names in repo: a branch, a tag or a
// SHA, or the head of the default branch when ref is empty.
func ResolveCommit(ctx context.Context, c *githubapi.Client, repo facts.Repo, ref string) (facts.SHA, error) {
	what := "the repository " + repo.String()
	if ref == "" {
		resp, err := get(ctx, c, what, strings.TrimSuffix(repoURL(c, repo), "/"), "application/vnd.github+json", 1<<20)
		if err != nil {
			return facts.SHA{}, err
		}
		var v struct {
			DefaultBranch string `json:"default_branch"`
		}
		if err := json.Unmarshal(resp.Body, &v); err != nil || v.DefaultBranch == "" {
			return facts.SHA{}, fmt.Errorf("%s: no default branch in the answer", what)
		}
		ref = v.DefaultBranch
	} else {
		what = "the ref " + ref + " of " + repo.String()
	}
	resp, err := get(ctx, c, what, repoURL(c, repo)+"commits/"+escapeRef(ref), "application/vnd.github.sha", 1024)
	if err != nil {
		return facts.SHA{}, err
	}
	sha, err := facts.ParseSHA(strings.TrimSpace(string(resp.Body)))
	if err != nil {
		return facts.SHA{}, fmt.Errorf("%s: %w", what, err)
	}
	return sha, nil
}

// escapeRef escapes ref for a path, keeping its slashes.
func escapeRef(ref string) string {
	parts := strings.Split(ref, "/")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(p, "%", "%25"), "?", "%3F")
		parts[i] = strings.ReplaceAll(parts[i], "#", "%23")
	}
	return strings.Join(parts, "/")
}

type treeJSON struct {
	SHA  string `json:"sha"`
	Tree []struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
		Size int64  `json:"size"`
	} `json:"tree"`
	Truncated bool `json:"truncated"`
}

// listTree reads the tree of commit: its SHA and its entries, of the paths
// facts.CleanInputPath keeps as they are.
func listTree(ctx context.Context, c *githubapi.Client, repo facts.Repo, commit facts.SHA) (facts.SHA, map[string]Entry, error) {
	what := "the tree of " + repo.String() + "@" + commit.String()
	resp, err := get(ctx, c, what, repoURL(c, repo)+"git/trees/"+commit.String()+"?recursive=1", "application/vnd.github+json", 64<<20)
	if err != nil {
		return facts.SHA{}, nil, err
	}
	var v treeJSON
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return facts.SHA{}, nil, fmt.Errorf("%s: %w", what, err)
	}
	if v.Truncated {
		return facts.SHA{}, nil, ErrTruncated
	}
	sha, err := facts.ParseSHA(v.SHA)
	if err != nil {
		return facts.SHA{}, nil, fmt.Errorf("%s: %w", what, err)
	}
	entries := map[string]Entry{}
	for _, e := range v.Tree {
		if n, err := facts.CleanInputPath(e.Path); err != nil || n.String() != e.Path {
			continue // a path no input can have
		}
		s, err := facts.ParseSHA(e.SHA)
		if err != nil {
			continue
		}
		entries[e.Path] = Entry{Mode: e.Mode, SHA: s, size: e.Size}
	}
	return sha, entries, nil
}

// ListTree is the entries of the tree of commit, by path, without reading
// a file: a merge base and a base are compared by them.
func ListTree(ctx context.Context, c *githubapi.Client, repo facts.Repo, commit facts.SHA) (map[facts.InputPath]Entry, error) {
	_, entries, err := listTree(ctx, c, repo, commit)
	if err != nil {
		return nil, err
	}
	return byInputPath(entries), nil
}

func byInputPath(entries map[string]Entry) map[facts.InputPath]Entry {
	out := map[facts.InputPath]Entry{}
	for p, e := range entries {
		if e.Mode == "040000" {
			continue
		}
		out[facts.MustCleanInputPath(p)] = e
	}
	return out
}

// OpenTree reads the tree of commit of repo. The context is the one of the
// files' reads too.
func OpenTree(ctx context.Context, c *githubapi.Client, repo facts.Repo, commit facts.SHA, l Limits) (*Tree, error) {
	l = l.orDefault()
	sha, entries, err := listTree(ctx, c, repo, commit)
	if err != nil {
		return nil, err
	}
	t := &Tree{ctx: ctx, c: c, repo: repo, commit: commit, sha: sha, limits: l, entries: entries, dirs: map[string][]string{},
		left: l.MaxRequests - 1, blobs: map[string][]byte{}, failed: map[string]error{}, read: map[string]bool{}, hops: map[string][]string{}}
	for p := range entries {
		dir, name := path.Split(p)
		dir = strings.TrimSuffix(dir, "/")
		if dir == "" {
			dir = "."
		}
		t.dirs[dir] = append(t.dirs[dir], name)
	}
	for d := range t.dirs {
		slices.Sort(t.dirs[d])
	}
	return t, nil
}

// SHA is the tree's.
func (t *Tree) SHA() facts.SHA { return t.sha }

// Commit is the commit the tree is of.
func (t *Tree) Commit() facts.SHA { return t.commit }

// Entries are the entries of the tree but its directories, by path.
func (t *Tree) Entries() map[facts.InputPath]Entry { return byInputPath(t.entries) }

// Submodules are the paths of the submodules (mode 160000), in order.
func (t *Tree) Submodules() []facts.InputPath {
	var out []facts.InputPath
	for p, e := range t.entries {
		if e.Mode == "160000" {
			out = append(out, facts.MustCleanInputPath(p))
		}
	}
	slices.SortFunc(out, facts.CompareInputPaths)
	return out
}

// Prefetch reads the files of paths now, before the requests are spent by
// others: those where an input may be (a workflow right under
// .github/workflows, an action.yml or action.yaml); the others the run
// reads only if it needs them.
func (t *Tree) Prefetch(paths []facts.InputPath) {
	for _, p := range paths {
		if !inputPath(p) {
			continue
		}
		if real, _, err := t.resolve(p.String()); err == nil {
			t.fetch(real, false)
		}
	}
}

// ReadFiles are the files whose contents the run read or tried to read,
// the symlinks it followed to them included, in the order of their paths.
func (t *Tree) ReadFiles() []ReadFile {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []ReadFile
	for p := range t.read {
		e := t.entries[p]
		out = append(out, ReadFile{Path: facts.MustCleanInputPath(p), Blob: e.SHA, Mode: e.Mode})
	}
	slices.SortFunc(out, func(a, b ReadFile) int { return facts.CompareInputPaths(a.Path, b.Path) })
	return out
}

// Unread are the files whose contents the run could not read, in order.
func (t *Tree) Unread() []facts.InputPath {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []facts.InputPath
	for p := range t.failed {
		out = append(out, facts.MustCleanInputPath(p))
	}
	slices.SortFunc(out, facts.CompareInputPaths)
	return out
}

// Hops are the entries the run went through to open p: each symlink it
// followed, then the file; nil when p was not opened through a symlink.
func (t *Tree) Hops(p facts.InputPath) []facts.InputPath {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []facts.InputPath
	for _, h := range t.hops[p.String()] {
		out = append(out, facts.MustCleanInputPath(h))
	}
	return out
}

// Blob is the contents of the file at p (a file, not a symlink), read or
// asked for already.
func (t *Tree) Blob(p facts.InputPath) ([]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.blobs[p.String()]
	return b, ok
}

// Mode is the mode of the entry at p, without following a symlink.
func (t *Tree) Mode(p facts.InputPath) (string, bool) {
	e, ok := t.entries[p.String()]
	return e.Mode, ok
}

// resolve follows the symlinks of name (fs.ValidPath) within the tree. It
// gives the path of what name is and the symlinks it went through.
func (t *Tree) resolve(name string) (string, []string, error) {
	if name == "." {
		return ".", nil, nil
	}
	var hops []string
	parts := strings.Split(name, "/")
	for n := 0; n < 40; n++ {
		done := true
		for i := range parts {
			prefix := strings.Join(parts[:i+1], "/")
			e, ok := t.entries[prefix]
			if !ok || e.Mode != "120000" {
				continue
			}
			target, err := t.contents(prefix)
			if err != nil {
				return "", hops, err
			}
			hops = append(hops, prefix)
			joined := path.Join(path.Dir(prefix), string(target))
			if path.IsAbs(string(target)) || joined == ".." || strings.HasPrefix(joined, "../") {
				return "", hops, errEscapes
			}
			rest := parts[i+1:]
			parts = append(strings.Split(joined, "/"), rest...)
			if joined == "." {
				parts = rest
			}
			done = false
			break
		}
		if done {
			p := strings.Join(parts, "/")
			if p == "" {
				p = "."
			}
			return p, hops, nil
		}
	}
	return "", hops, errLoop
}

// contents is the blob of the entry at p (a file or a symlink), read once;
// the run reads it (ReadFiles).
func (t *Tree) contents(p string) ([]byte, error) { return t.fetch(p, true) }

// fetch is the blob of the entry at p, read once; read is whether the run
// reads it (Prefetch fetches what the run may read). An entry that is not
// a file or a symlink is not there to read.
func (t *Tree) fetch(p string, read bool) ([]byte, error) {
	if e, ok := t.entries[p]; !ok || e.Mode != "100644" && e.Mode != "100755" && e.Mode != "120000" {
		return nil, fs.ErrNotExist
	}
	t.mu.Lock()
	if read {
		t.read[p] = true
	}
	if b, ok := t.blobs[p]; ok {
		t.mu.Unlock()
		return b, nil
	}
	if err, ok := t.failed[p]; ok {
		t.mu.Unlock()
		return nil, err
	}
	e := t.entries[p]
	var err error
	switch {
	case e.size > t.limits.MaxBlobBytes:
		err = ErrBlobTooLarge
	case t.left <= 0:
		err = ErrRequestsSpent
	}
	if err != nil {
		t.failed[p] = err
		t.mu.Unlock()
		return nil, err
	}
	t.left--
	t.mu.Unlock()
	resp, err := get(t.ctx, t.c, p, repoURL(t.c, t.repo)+"git/blobs/"+e.SHA.String(), "application/vnd.github.raw+json", t.limits.MaxBlobBytes+1)
	if err == nil && int64(len(resp.Body)) > t.limits.MaxBlobBytes {
		err = ErrBlobTooLarge
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.failed[p] = err
		return nil, err
	}
	t.blobs[p] = resp.Body
	return resp.Body, nil
}

func (t *Tree) isDir(p string) bool {
	if p == "." {
		return true
	}
	e, ok := t.entries[p]
	return ok && (e.Mode == "040000" || e.Mode == "160000")
}

// Open opens name, following its symlinks.
func (t *Tree) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	real, hops, err := t.resolve(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	if len(hops) > 0 {
		t.mu.Lock()
		t.hops[name] = append(slices.Clone(hops), real)
		t.mu.Unlock()
	}
	if t.isDir(real) {
		return &dir{t: t, name: name, real: real}, nil
	}
	e, ok := t.entries[real]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	b, err := t.contents(real)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &file{info: info{name: path.Base(name), entry: e, size: int64(len(b))}, r: bytes.NewReader(b)}, nil
}

// ReadFile is the contents of the file name, following its symlinks.
func (t *Tree) ReadFile(name string) ([]byte, error) {
	f, err := t.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Stat is the file name is, following its symlinks.
func (t *Tree) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	real, _, err := t.resolve(name)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: err}
	}
	if t.isDir(real) {
		return info{name: path.Base(name), entry: Entry{Mode: "040000"}}, nil
	}
	e, ok := t.entries[real]
	if !ok {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return info{name: path.Base(name), entry: e, size: e.size}, nil
}

// Lstat is the entry at name, without following a symlink at its end.
func (t *Tree) Lstat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrInvalid}
	}
	dirPart, base := path.Split(name)
	real := "."
	if dirPart != "" {
		var err error
		if real, _, err = t.resolve(strings.TrimSuffix(dirPart, "/")); err != nil {
			return nil, &fs.PathError{Op: "lstat", Path: name, Err: err}
		}
	}
	p := path.Join(real, base)
	if t.isDir(p) {
		return info{name: base, entry: Entry{Mode: "040000"}}, nil
	}
	e, ok := t.entries[p]
	if !ok {
		return nil, &fs.PathError{Op: "lstat", Path: name, Err: fs.ErrNotExist}
	}
	return info{name: base, entry: e, size: e.size}, nil
}

// ReadLink is the target of the symlink name.
func (t *Tree) ReadLink(name string) (string, error) {
	st, err := t.Lstat(name)
	if err != nil {
		return "", err
	}
	if st.Mode()&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	dirPart, base := path.Split(name)
	real := "."
	if dirPart != "" {
		real, _, _ = t.resolve(strings.TrimSuffix(dirPart, "/"))
	}
	b, err := t.contents(path.Join(real, base))
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return string(b), nil
}

// ReadDir lists the directory name, following its symlinks.
func (t *Tree) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	real, _, err := t.resolve(name)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	if !t.isDir(real) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}
	var out []fs.DirEntry
	for _, n := range t.dirs[real] {
		p := path.Join(real, n)
		e := t.entries[p]
		out = append(out, fs.FileInfoToDirEntry(info{name: n, entry: e, size: e.size}))
	}
	return out, nil
}

type info struct {
	name  string
	entry Entry
	size  int64
}

func (i info) Name() string { return i.name }
func (i info) Size() int64  { return i.size }
func (i info) Mode() fs.FileMode {
	switch i.entry.Mode {
	case "040000", "160000":
		return fs.ModeDir | 0o755
	case "120000":
		return fs.ModeSymlink | 0o777
	case "100755":
		return 0o755
	}
	return 0o644
}
func (i info) ModTime() time.Time { return time.Time{} }
func (i info) IsDir() bool        { return i.Mode().IsDir() }
func (i info) Sys() any           { return nil }

type file struct {
	info info
	r    *bytes.Reader
}

func (f *file) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *file) Read(b []byte) (int, error) { return f.r.Read(b) }
func (f *file) Close() error               { return nil }

type dir struct {
	t          *Tree
	name, real string
	off        int
}

func (d *dir) Stat() (fs.FileInfo, error) {
	return info{name: path.Base(d.name), entry: Entry{Mode: "040000"}}, nil
}
func (d *dir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: errors.New("is a directory")}
}
func (d *dir) Close() error { return nil }

func (d *dir) ReadDir(n int) ([]fs.DirEntry, error) {
	all, err := d.t.ReadDir(d.name)
	if err != nil {
		return nil, err
	}
	all = all[d.off:]
	if n > 0 && len(all) > n {
		all = all[:n]
	}
	d.off += len(all)
	if n > 0 && len(all) == 0 {
		return nil, io.EOF
	}
	return all, nil
}

var (
	_ fs.ReadDirFS  = (*Tree)(nil)
	_ fs.StatFS     = (*Tree)(nil)
	_ fs.ReadLinkFS = (*Tree)(nil)
)

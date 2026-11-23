package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// startWith serves f under /api, as start does, with o's other options.
func startWith(t *testing.T, f *fake, o Options) facts.Resolver {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/api")
	o.BaseURL, o.Client = u, srv.Client()
	return New(o)
}

// readUsing reads a definition written as "using: <value>" alone.
func readUsing(b []byte) (facts.RunsUsing, error) {
	v, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "using: ")
	if !ok {
		return facts.RunsUsingUnset, errors.New("no using")
	}
	return facts.ParseRunsUsing(strings.ToLower(v))
}

// entry is a file of a tarball: its text, or the target of a symlink, or a
// directory.
type entry struct {
	data, link string
	dir        bool
}

// tarball serves the archive of entries, as GitHub's tarball has them under
// one top directory.
func tarball(entries map[string]entry) func(http.ResponseWriter) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "o-r-x/", Typeflag: tar.TypeDir, Mode: 0o755})
	for _, n := range slices.Sorted(maps.Keys(entries)) {
		e := entries[n]
		switch {
		case e.dir:
			tw.WriteHeader(&tar.Header{Name: "o-r-x/" + n + "/", Typeflag: tar.TypeDir, Mode: 0o755})
		case e.link != "":
			tw.WriteHeader(&tar.Header{Name: "o-r-x/" + n, Typeflag: tar.TypeSymlink, Linkname: e.link, Mode: 0o777})
		default:
			tw.WriteHeader(&tar.Header{Name: "o-r-x/" + n, Typeflag: tar.TypeReg, Size: int64(len(e.data)), Mode: 0o644})
			tw.Write([]byte(e.data))
		}
	}
	tw.Close()
	gz.Close()
	b := buf.Bytes()
	return func(w http.ResponseWriter) { w.WriteHeader(200); w.Write(b) }
}

func file(s string) entry { return entry{data: s} }

func countPaths(f *fake, suffix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, p := range f.paths {
		if strings.HasSuffix(p, suffix) {
			n++
		}
	}
	return n
}

func TestRepoArchived(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/old":  body(200, `{"visibility":"public","private":false,"has_wiki":true,"archived":true}`),
		"/repos/o/new":  body(200, `{"visibility":"public","private":false,"has_wiki":true,"archived":false}`),
		"/repos/o/none": body(200, `{"visibility":"public","private":false,"has_wiki":true}`),
		"/repos/o/gone": body(404, notFoundBody),
		"/repos/o/err":  body(500, `{}`),
	}}
	r := start(t, f, "t")
	ctx := context.Background()
	for _, c := range []struct {
		repo  string
		state facts.State
		value bool
	}{
		{"o/old", facts.StateFound, true},
		{"o/new", facts.StateFound, false},
		{"o/none", facts.StateUnknown, false},
		{"o/gone", facts.StateUnknown, false},
		{"o/err", facts.StateUnknown, false},
	} {
		got := facts.RepoArchived{Repo: mustRepo(t, c.repo)}.Ask(ctx, r)
		if got.State != c.state || got.State == facts.StateFound && got.Value != c.value || got.State == facts.StateUnknown && got.Reason == "" {
			t.Errorf("%s: %+v", c.repo, got)
		}
	}
	// repo.public reads the same answer
	if got := (facts.RepoPublic{Repo: mustRepo(t, "o/old")}.Ask(ctx, r)); got.State != facts.StateFound || !got.Value {
		t.Errorf("repo.public: %+v", got)
	}
	if n := countPaths(f, "/repos/o/old"); n != 1 {
		t.Errorf("GET /repos/o/old was sent %d times, want once", n)
	}
}

// A refusal of the budget of repo.archived is not kept as the answer of
// GET /repos: repo.public asks again within the rest of the budget.
func TestRepoArchivedBudgetDoesNotPoisonPublic(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/a": body(200, repoPublicBody),
		"/repos/o/b": body(200, repoPublicBody),
	}}
	r := startWith(t, f, Options{Token: "t", MaxRequests: 4}) // a quarter: 1
	ctx := context.Background()
	if got := (facts.RepoArchived{Repo: mustRepo(t, "o/a")}.Ask(ctx, r)); got.State != facts.StateUnknown {
		t.Errorf("o/a: %+v (no archived in the answer)", got)
	}
	got := facts.RepoArchived{Repo: mustRepo(t, "o/b")}.Ask(ctx, r)
	if got.State != facts.StateUnknown || !strings.Contains(got.Reason, "a quarter of MaxRequests") {
		t.Errorf("o/b: %+v, want the budget spent", got)
	}
	if got := (facts.RepoPublic{Repo: mustRepo(t, "o/b")}.Ask(ctx, r)); got.State != facts.StateFound || !got.Value {
		t.Errorf("repo.public of o/b: %+v", got)
	}
}

func TestActionRunsUsing(t *testing.T) {
	tag := func(sha string) func(http.ResponseWriter) { return body(200, sha) }
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": tag(shaA),
		"/repos/o/r/tarball/" + shaA: tarball(map[string]entry{
			"action.yml":          file("using: node20"),
			"sub/dir/action.yaml": file("using: Node12"),
			"docker/Dockerfile":   file("FROM alpine"),
			"none/README.md":      file("x"),
			"bad/action.yml":      file("runs: {}"),
		}),
		"/repos/o/gone/commits/refs/tags/v1":                           body(404, notFoundBody),
		"/repos/o/r/commits/refs/heads/" + url.PathEscape("feature/x"): tag(shaB),
		"/repos/o/r/tarball/" + shaB:                                   tarball(map[string]entry{"action.yml": file("using: node24")}),
		"/repos/o/r/commits/refs/tags/" + url.PathEscape("feature/x"):  body(422, `{"message":"No commit found"}`),
		"/repos/o/r/commits/refs/heads/" + url.PathEscape("nothing"):   body(422, `{"message":"No commit found"}`),
		"/repos/o/r/commits/refs/tags/" + url.PathEscape("nothing"):    body(422, `{"message":"No commit found"}`),
		"/repos/o/r/commits/refs/tags/err":                             tag("c0ffee0000000000000000000000000000000000"),
		"/repos/o/r/tarball/c0ffee0000000000000000000000000000000000":  body(500, `{}`),
	}}
	r := startWith(t, f, Options{Token: "t", ReadRunsUsing: readUsing})
	ctx := context.Background()
	path := func(s string) facts.UsesPath {
		p, err := facts.ParseUsesPath(s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct {
		q     facts.ActionRunsUsing
		state facts.State
		value facts.RunsUsing
	}{
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "v1"}, facts.StateFound, facts.RunsUsingNode20},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Path: path("sub/dir"), Ref: "v1"}, facts.StateFound, facts.RunsUsingNode12},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Path: path("docker"), Ref: "v1"}, facts.StateFound, facts.RunsUsingDocker},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Path: path("none"), Ref: "v1"}, facts.StateAbsent, facts.RunsUsingUnset},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Path: path("bad"), Ref: "v1"}, facts.StateUnknown, facts.RunsUsingUnset},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "err"}, facts.StateUnknown, facts.RunsUsingUnset},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "feature/x"}, facts.StateFound, facts.RunsUsingNode24},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "nothing"}, facts.StateAbsent, facts.RunsUsingUnset},
		{facts.ActionRunsUsing{Repo: mustRepo(t, "o/gone"), Ref: "v1"}, facts.StateUnknown, facts.RunsUsingUnset},
	} {
		got := c.q.Ask(ctx, r)
		if got.State != c.state || got.Value != c.value || got.State == facts.StateUnknown && got.Reason == "" {
			t.Errorf("%#v = %+v", c.q, got)
		}
	}
	if n := countPaths(f, "/tarball/"+shaA); n != 1 {
		t.Errorf("the archive of v1 was read %d times, want once", n)
	}
}

func TestActionRunsUsingWithoutReader(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){}}
	r := start(t, f, "t")
	got := facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "v1"}.Ask(context.Background(), r)
	if got.State != facts.StateUnknown || got.Reason == "" {
		t.Errorf("%+v", got)
	}
	if len(f.paths) != 0 {
		t.Errorf("asked %v", f.paths)
	}
}

// The runner runs the tag when a branch and a tag have one name, and so
// the definition is read at the tag's commit.
func TestActionRunsUsingTagFirst(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1":  body(200, shaA),
		"/repos/o/r/commits/refs/heads/v1": body(200, shaB),
		"/repos/o/r/tarball/" + shaA:       tarball(map[string]entry{"action.yml": file("using: node20")}),
		"/repos/o/r/tarball/" + shaB:       tarball(map[string]entry{"action.yml": file("using: node24")}),
	}}
	r := startWith(t, f, Options{Token: "t", ReadRunsUsing: readUsing})
	got := facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "v1"}.Ask(context.Background(), r)
	if got.State != facts.StateFound || got.Value != facts.RunsUsingNode20 {
		t.Errorf("%+v, want node20 of the tag", got)
	}
}

// git.ref-commit and action.runs-using of one ref ask the commit once.
func TestRefCommitShared(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": body(200, shaA),
		"/repos/o/r/tarball/" + shaA:      tarball(map[string]entry{"action.yml": file("using: node20")}),
	}}
	r := startWith(t, f, Options{Token: "t", ReadRunsUsing: readUsing})
	ctx := context.Background()
	if got := (facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "v1"}.Ask(ctx, r)); got.State != facts.StateFound {
		t.Fatalf("%+v", got)
	}
	if got := ask(t, r, "o/r", "v1"); got.State != facts.StateFound || got.Value.SHA.String() != shaA {
		t.Errorf("git.ref-commit: %+v", got)
	}
	if n := countPaths(f, "/commits/refs/tags/v1"); n != 1 {
		t.Errorf("the commit of v1 was asked %d times, want once", n)
	}
}

// repo.archived and action.runs-using send at most a quarter of
// MaxRequests, and git.ref-commit answers with the rest.
func TestQualityBudget(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": body(200, shaA),
		"/repos/o/r/commits/refs/tags/v2": body(200, shaB),
		"/repos/o/r/tarball/" + shaA:      tarball(map[string]entry{"action.yml": file("using: node20")}),
		"/repos/o/q":                      body(200, repoPublicBody),
	}}
	r := startWith(t, f, Options{Token: "t", MaxRequests: 8, ReadRunsUsing: readUsing}) // a quarter: 2
	ctx := context.Background()
	if got := (facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "v1"}.Ask(ctx, r)); got.State != facts.StateFound {
		t.Fatalf("%+v", got)
	}
	if got := (facts.RepoArchived{Repo: mustRepo(t, "o/q")}.Ask(ctx, r)); got.State != facts.StateUnknown || !strings.Contains(got.Reason, "a quarter of MaxRequests") {
		t.Errorf("repo.archived: %+v, want the budget spent", got)
	}
	if got := ask(t, r, "o/r", "v2"); got.State != facts.StateFound || got.Value.SHA.String() != shaB {
		t.Errorf("git.ref-commit: %+v", got)
	}
}

// A refusal of the budget of action.runs-using in resolving a ref is not
// kept as the answer of git.ref-commit of that ref.
func TestRefCommitBudgetDoesNotPoison(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": body(200, shaA),
		"/repos/o/r/commits/refs/tags/v2": body(200, shaB),
	}}
	r := startWith(t, f, Options{Token: "t", MaxRequests: 4, ReadRunsUsing: readUsing}) // a quarter: 1
	ctx := context.Background()
	if got := (facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "v1"}.Ask(ctx, r)); got.State != facts.StateUnknown || !strings.Contains(got.Reason, "a quarter of MaxRequests") {
		t.Errorf("v1: %+v, want the budget spent at action.yml", got)
	}
	if got := (facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Ref: "v2"}.Ask(ctx, r)); got.State != facts.StateUnknown || !strings.Contains(got.Reason, "a quarter of MaxRequests") {
		t.Errorf("v2: %+v, want the budget spent at the ref", got)
	}
	if got := ask(t, r, "o/r", "v2"); got.State != facts.StateFound || got.Value.SHA.String() != shaB {
		t.Errorf("git.ref-commit of v2: %+v", got)
	}
}

// The contents API answers a directory with a list of its entries: a
// directory named action.yml or Dockerfile is not the file the runner
// reads; and each
// part of the path is escaped.
func TestActionRunsUsingDirectoriesAndEscapes(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": body(200, shaA),
		"/repos/o/r/tarball/" + shaA: tarball(map[string]entry{
			"d/action.yml":       {dir: true},
			"d/action.yml/keep":  file("x"),
			"d/action.yaml":      file("using: node16"),
			"e/Dockerfile":       {dir: true},
			"e/Dockerfile/keep":  file("x"),
			"a#b/c?d/action.yml": file("using: node20"),
			"l/action.yml":       {link: "../shared/real.yml"},
			"l/action.yaml":      file("using: node12"),
			"shared/real.yml":    file("using: node24"),
			"out/action.yml":     {link: "../../x.yml"},
			"out/action.yaml":    file("using: node16"),
		}),
	}}
	r := startWith(t, f, Options{Token: "t", ReadRunsUsing: readUsing})
	ctx := context.Background()
	for p, want := range map[string]facts.RunsUsing{"d": facts.RunsUsingNode16, "a#b/c?d": facts.RunsUsingNode20, "l": facts.RunsUsingNode24, "out": facts.RunsUsingNode16} {
		path, err := facts.ParseUsesPath(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := (facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Path: path, Ref: "v1"}.Ask(ctx, r)); got.State != facts.StateFound || got.Value != want {
			t.Errorf("%s: %+v, want %v", p, got, want)
		}
	}
	e, _ := facts.ParseUsesPath("e")
	if got := (facts.ActionRunsUsing{Repo: mustRepo(t, "o/r"), Path: e, Ref: "v1"}.Ask(ctx, r)); got.State != facts.StateAbsent {
		t.Errorf("e: %+v, want absent (a directory named Dockerfile)", got)
	}
}

// TestActionDefinition: the file that defines the action, from the archive;
// archive_substituted when the archive's metadata is not the blob
// (export-subst), and unknown when the archive cannot be read.
func TestActionDefinition(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": body(200, shaA),
		"/repos/o/r/tarball/" + shaA: tarball(map[string]entry{
			"action.yml":        file("runs: {using: composite}"),
			"subst/action.yml":  file("run: echo 'E6-DECORATE[ (tag: v1)]'"),
			"docker/Dockerfile": file("FROM alpine"),
		}),
		"/repos/o/r/contents/action.yml?ref=" + shaA:       body(200, "runs: {using: composite}"),
		"/repos/o/r/contents/subst/action.yml?ref=" + shaA: body(200, "run: echo 'E6-DECORATE[$Format:%d$]'"),
		"/repos/o/private/commits/refs/tags/v1":            body(200, shaB),
		"/repos/o/private/tarball/" + shaB:                 body(404, notFoundBody),
	}}
	r := startWith(t, f, Options{Token: "t", ReadRunsUsing: readUsing})
	ctx := context.Background()
	at := func(repo, p string) facts.ActionDefinition {
		q := facts.ActionDefinition{Repo: mustRepo(t, repo), Ref: "v1"}
		if p != "" {
			q.Path, _ = facts.ParseUsesPath(p)
		}
		return q
	}
	if got := at("o/r", "").Ask(ctx, r); got.State != facts.StateFound || got.Value.File != facts.ActionFileYML || got.Value.Content != "runs: {using: composite}" || got.Value.ArchiveSubstituted || got.Value.Commit.String() != shaA {
		t.Errorf("root: %+v", got)
	}
	if got := at("o/r", "subst").Ask(ctx, r); got.State != facts.StateFound || !got.Value.ArchiveSubstituted {
		t.Errorf("export-subst: %+v, want archive_substituted", got)
	}
	if got := at("o/r", "docker").Ask(ctx, r); got.State != facts.StateFound || got.Value.File != facts.ActionFileDockerfile || got.Value.Content != "" {
		t.Errorf("docker: %+v", got)
	}
	if got := at("o/r", "none").Ask(ctx, r); got.State != facts.StateAbsent {
		t.Errorf("none: %+v, want absent", got)
	}
	if got := at("o/private", "").Ask(ctx, r); got.State != facts.StateUnknown || !strings.Contains(got.Reason, "not there, or the token cannot read it") {
		t.Errorf("an archive the token cannot read: %+v, want unknown", got)
	}
}

// TestActionDefinitionArchiveEdges: a directory on the path that is a
// symlink is followed (the runner reads the extracted archive); an archive
// whose file differs from the blob only by a conversion of git archive
// (eol) is not substituted; an action.yml that is a symlink to a file the
// archive does not keep is unknown, not absent.
func TestActionDefinitionArchiveEdges(t *testing.T) {
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1": body(200, shaA),
		"/repos/o/r/tarball/" + shaA: tarball(map[string]entry{
			"sub":             {link: "real"},
			"real/action.yml": file("runs: {using: composite}"),
			"eol/action.yml":  file("runs: {using: composite}\r\n"),
			"txt/action.yml":  {link: "action.txt"},
			"txt/action.txt":  file("runs: {using: composite}"),
		}),
		"/repos/o/r/contents/real/action.yml?ref=" + shaA: body(200, "runs: {using: composite}"),
		"/repos/o/r/contents/eol/action.yml?ref=" + shaA:  body(200, "runs: {using: composite}\n"),
	}}
	r := startWith(t, f, Options{Token: "t", ReadRunsUsing: readUsing})
	ctx := context.Background()
	at := func(p string) facts.Answer[facts.ActionFile] {
		q := facts.ActionDefinition{Repo: mustRepo(t, "o/r"), Ref: "v1"}
		q.Path, _ = facts.ParseUsesPath(p)
		return q.Ask(ctx, r)
	}
	if got := at("sub"); got.State != facts.StateFound || got.Value.Content != "runs: {using: composite}" {
		t.Errorf("a symlinked directory: %+v, want the action.yml of real", got)
	}
	if got := at("eol"); got.State != facts.StateFound || got.Value.ArchiveSubstituted {
		t.Errorf("an eol conversion: %+v, want not substituted", got)
	}
	if got := at("txt"); got.State != facts.StateUnknown {
		t.Errorf("a symlink to a file not kept: %+v, want unknown", got)
	}
}

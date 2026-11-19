package lint

import (
	"context"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

const okWorkflow = "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
const okAction = "runs:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n"

func names(in Inputs) string {
	var out []string
	for _, i := range in.List {
		out = append(out, i.Name.String()+"="+i.InputKind.String()+"/"+i.State.String())
	}
	return strings.Join(out, " ")
}

func TestEnumerate(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/a.yml":          {Data: []byte(okWorkflow)},
		".github/workflows/b.yaml":         {Data: []byte(okWorkflow)},
		".github/workflows/action.yml":     {Data: []byte(okWorkflow)},
		".github/workflows/upper.YML":      {Data: []byte(okWorkflow)}, // i2: GitHub does not run it
		".github/workflows/mixed.Yaml":     {Data: []byte(okWorkflow)},
		".github/workflows/sub/x.yml":      {Data: []byte(okWorkflow)}, // i1
		".github/workflows/notes.md":       {Data: []byte("# x")},
		".github/actions/both/action.yml":  {Data: []byte(okAction)},
		".github/actions/both/action.yaml": {Data: []byte(okAction)}, // i4: action.yml wins
		".github/actions/yaml/action.yaml": {Data: []byte(okAction)},
		".github/actions/upper/Action.yml": {Data: []byte(okAction)},
		"action.yml":                       {Data: []byte(okAction)},
		"docker/Dockerfile":                {Data: []byte("FROM x")},
		".git/action.yml":                  {Data: []byte(okAction)},
		".git/.github/workflows/c.yml":     {Data: []byte(okWorkflow)},
		"src/.github/workflows/nested.yml": {Data: []byte(okWorkflow)},
		"testdata/deep/action.yml":         {Data: []byte(okAction)},
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := ".github/actions/both/action.yml=action-metadata/read .github/actions/yaml/action.yaml=action-metadata/read " +
		".github/workflows/a.yml=workflow/read .github/workflows/action.yml=workflow/read .github/workflows/b.yaml=workflow/read " +
		"action.yml=action-metadata/read testdata/deep/action.yml=action-metadata/read"
	if got := names(in); got != want {
		t.Errorf("Enumerate =\n%s\nwant\n%s", got, want)
	}
	if !in.Complete {
		t.Error("Enumerate must be complete")
	}
	if in.List[0].ActionMetadata == nil || in.List[2].Workflow == nil || in.List[2].Tree == nil {
		t.Error("the inputs must carry their trees and models")
	}
}

func TestEnumerateOrderDoesNotMatter(t *testing.T) {
	a := fstest.MapFS{"b/action.yml": {Data: []byte(okAction)}, "a/action.yml": {Data: []byte(okAction)}}
	b := fstest.MapFS{"a/action.yml": {Data: []byte(okAction)}, "b/action.yml": {Data: []byte(okAction)}}
	x, _ := Enumerate(a)
	y, _ := Enumerate(b)
	if names(x) != names(y) || names(x) != "a/action.yml=action-metadata/read b/action.yml=action-metadata/read" {
		t.Errorf("%s / %s", names(x), names(y))
	}
}

func TestEnumerateBrokenInputs(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/empty.yml":  {Data: nil},
		".github/workflows/bom.yml":    {Data: append([]byte("\xef\xbb\xbf"), okWorkflow...)},
		".github/workflows/latin1.yml": {Data: []byte("on: push\nname: caf\xe9\n")},
		".github/workflows/bad.yml":    {Data: []byte("on: [push\n")},
		"x/action.yml":                 {Data: []byte("name: no runs\n")},
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Input{}
	for _, i := range in.List {
		got[i.Name.String()] = i
	}
	for name, want := range map[string]InputState{
		".github/workflows/empty.yml":  InputStateInvalid,
		".github/workflows/latin1.yml": InputStateUnreadable,
		".github/workflows/bad.yml":    InputStateInvalid,
		"x/action.yml":                 InputStateInvalid,
	} {
		i, ok := got[name]
		if !ok || i.State != want {
			t.Errorf("%s: %+v, want %v", name, i.State, want)
		}
		if i.State == InputStateInvalid && len(i.Diagnostics) == 0 && i.Reason == "" {
			t.Errorf("%s: invalid without a reason", name)
		}
		if i.State == InputStateUnreadable && (i.Reason == "" || i.Tree != nil) {
			t.Errorf("%s: unreadable must have a reason and no tree", name)
		}
	}
	if _, ok := got[".github/workflows/bom.yml"]; !ok {
		t.Error("a file with a byte order mark is not listed")
	}
}

func TestEnumerateWorkflowsIsAFile(t *testing.T) {
	in, err := Enumerate(fstest.MapFS{".github/workflows": {Data: []byte("x")}})
	if err != nil || len(in.List) != 0 {
		t.Errorf("%s, %v", names(in), err)
	}
}

func TestEnumerateSymlinks(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, p string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(dir, p)); err != nil {
			t.Skipf("symlink: %v", err)
		}
	}
	write(".github/workflows/real.yml", okWorkflow)
	link("real.yml", ".github/workflows/link.yml") // i3: GitHub fails it
	write("elsewhere/target.yml", okWorkflow)
	link("../../elsewhere/target.yml", ".github/workflows/out.yml")
	write("act/real/action.yml", okAction)
	link("real/action.yml", "act/action.yml") // followed, as the runner's File.Exists does
	link("..", "act/loop")                    // a loop: not followed; listed as unreadable
	in, err := Enumerate(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	want := ".github/workflows/link.yml=workflow/invalid .github/workflows/out.yml=workflow/invalid .github/workflows/real.yml=workflow/read " +
		"act/action.yml=action-metadata/read act/loop=action-metadata/unreadable act/real/action.yml=action-metadata/read"
	if got := names(in); got != want {
		t.Errorf("Enumerate =\n%s\nwant\n%s", got, want)
	}
	for _, i := range in.List {
		if i.State == InputStateInvalid && (i.Reason == "" || i.Tree != nil) {
			t.Errorf("%s: a symlink workflow must say why and have no tree", i.Name)
		}
	}
}

// TestEnumerateUnderRoot: through an os.Root, a symlink out of the root
// cannot be looked at. It may be a directory, so the inputs are not
// complete, and what it points to is not read.
func TestEnumerateUnderRoot(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "action.yml"), []byte(okAction), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "ext")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	in, err := Enumerate(root.FS())
	if err != nil {
		t.Fatal(err)
	}
	if got := names(in); got != "ext=action-metadata/unreadable" || in.Complete {
		t.Errorf("Enumerate = %s, complete %v; want ext=action-metadata/unreadable, not complete", got, in.Complete)
	}
}

func TestFilesAndSingle(t *testing.T) {
	fsys := fstest.MapFS{
		"w.yml":                       {Data: []byte(okWorkflow)},
		"sub/action.yaml":             {Data: []byte(okAction)},
		".github/workflows/sub/x.yml": {Data: []byte(okWorkflow)},
	}
	in, err := Files(fsys, []string{"./w.yml", "sub//action.yaml", ".github/workflows/sub/x.yml"})
	if err != nil {
		t.Fatal(err)
	}
	want := ".github/workflows/sub/x.yml=workflow/read sub/action.yaml=action-metadata/read w.yml=workflow/read"
	if got := names(in); got != want || in.Complete {
		t.Errorf("Files = %s, complete %v", got, in.Complete)
	}
	for _, bad := range [][]string{{"../w.yml"}, {"/w.yml"}, {""}, {"a/../w.yml"}, {"w.yml", "./w.yml"}, {"missing.yml"}} {
		if in, err := Files(fsys, bad); err == nil {
			t.Errorf("Files(%q) = %s, want an error", bad, names(in))
		}
	}
	s, err := Single(InputBytes{Name: facts.MustCleanInputPath("./x/action.yml"), Bytes: []byte(okAction)})
	if err != nil || names(s) != "x/action.yml=action-metadata/read" || s.Complete {
		t.Errorf("Single(an action by its basename) = %s, %v", names(s), err)
	}
	s, err = Single(InputBytes{Name: facts.MustCleanInputPath("buffer.txt"), InputKind: InputKindWorkflow, Bytes: []byte(okWorkflow)})
	if err != nil || names(s) != "buffer.txt=workflow/read" {
		t.Errorf("Single(explicit) = %s, %v", names(s), err)
	}
	s, err = Single(InputBytes{Name: facts.MustCleanInputPath("action.yml"), InputKind: InputKindWorkflow, Bytes: []byte(okWorkflow)})
	if err != nil || names(s) != "action.yml=workflow/read" {
		t.Errorf("Single(explicit over the basename) = %s, %v", names(s), err)
	}
	if _, err := Single(InputBytes{Bytes: []byte(okWorkflow)}); err == nil {
		t.Error("Single without a Name: no error")
	}
}

func TestLookup(t *testing.T) {
	fsys := fstest.MapFS{".github/workflows/a.yml": {Data: []byte(okWorkflow)}}
	full, _ := Enumerate(fsys)
	part, _ := Files(fsys, []string{".github/workflows/a.yml"})
	for _, c := range []struct {
		in   Inputs
		name string
		want LookupState
	}{
		{full, ".github/workflows/a.yml", LookupFound},
		{full, "./.github/workflows/a.yml", LookupFound},
		{full, ".github/workflows/b.yml", LookupAbsent},
		{part, ".github/workflows/a.yml", LookupFound},
		{part, ".github/workflows/b.yml", LookupUnknown},
		{full, "../x", LookupUnknown},
	} {
		n, _ := facts.CleanInputPath(c.name) // the zero Name when it is not one
		if _, got := c.in.Lookup(n); got != c.want {
			t.Errorf("Lookup(%s) in complete=%v = %v, want %v", c.name, c.in.Complete, got, c.want)
		}
	}
	var _ InputSet = full
	var _ fs.FS = fsys
}

// TestSameBasenameInTwoDirectories: a Name is the whole path, so two
// action.yml in two directories are two inputs, and a finding at the same
// place of each has its own fingerprint.
func TestSameBasenameInTwoDirectories(t *testing.T) {
	fsys := fstest.MapFS{"a/action.yml": {Data: []byte(okAction)}, "b/action.yml": {Data: []byte(okAction)}}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if got := names(in); got != "a/action.yml=action-metadata/read b/action.yml=action-metadata/read" {
		t.Fatalf("inputs = %s", got)
	}
	m := meta("root")
	m.Targets = []InputKind{InputKindActionMetadata}
	m = examplesTargeting(m)
	reg, err := newRegistry([]Rule{testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		c.Report(FindingDraft{Args: said("x"), Location: At(c.input, c.action.Base)})
		return nil
	}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	rep := Run(context.Background(), in, reg, mapResolver{})
	if len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)) != 2 || rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[0].Fingerprint == rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)[1].Fingerprint || len(rep.Errors) != 0 {
		t.Errorf("findings %+v, errors %+v", rep.FindingsWith(CertaintyConfirmed, CertaintyConditional), rep.Errors)
	}
}

// badNamesFS is an fs.FS whose root lists a file named ../action.yml, which
// fs.WalkDir passes on as it is.
type badNamesFS struct{ fstest.MapFS }

type fakeInfo struct{ name string }

func (i fakeInfo) Name() string       { return i.name }
func (i fakeInfo) Size() int64        { return 0 }
func (i fakeInfo) Mode() fs.FileMode  { return 0o644 }
func (i fakeInfo) ModTime() time.Time { return time.Time{} }
func (i fakeInfo) IsDir() bool        { return false }
func (i fakeInfo) Sys() any           { return nil }

func (f badNamesFS) ReadDir(name string) ([]fs.DirEntry, error) {
	es, err := f.MapFS.ReadDir(name)
	if name == "." {
		es = append(es, fs.FileInfoToDirEntry(fakeInfo{"../action.yml"}))
	}
	return es, err
}

// TestEnumerateKeepsNamesNormal: Enumerate makes every InputPath as facts.CleanInputPath does,
// so a name from an fs.FS that is not a path in the repository is not an
// input, and the inputs are not complete.
func TestEnumerateKeepsNamesNormal(t *testing.T) {
	in, err := Enumerate(badNamesFS{fstest.MapFS{"action.yml": {Data: []byte(okAction)}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range in.List {
		if _, err := facts.CleanInputPath(i.Name.String()); err != nil || i.Name.String() != mustNormal(t, i.Name.String()) {
			t.Errorf("an input named %q", i.Name)
		}
	}
	if in.Complete {
		t.Error("complete, with a name left out")
	}
}

func mustNormal(t *testing.T, s string) string {
	t.Helper()
	n, err := facts.CleanInputPath(s)
	if err != nil {
		return "(" + err.Error() + ")"
	}
	return n.String()
}

// TestEnumerateSkippedDirectories: a directory Enumerate does not follow or
// cannot read is in the report, and the inputs are not complete.
func TestEnumerateSkippedDirectories(t *testing.T) {
	dir := t.TempDir()
	mk := func(p, s string) {
		t.Helper()
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("real/action.yml", okAction)
	mk("wf/w.yml", okWorkflow)
	os.MkdirAll(filepath.Join(dir, ".github"), 0o755)
	if err := os.Symlink("real", filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	os.Symlink("../wf", filepath.Join(dir, ".github/workflows"))
	in, err := Enumerate(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	if in.Complete {
		t.Error("complete, with directories not followed")
	}
	want := ".github/workflows=workflow/unreadable link=action-metadata/unreadable real/action.yml=action-metadata/read"
	if got := names(in); got != want {
		t.Errorf("Enumerate =\n%s\nwant\n%s", got, want)
	}
	reg, _ := newRegistry(nil, true)
	if Classify(Run(context.Background(), in, reg, mapResolver{}), SeverityInfo)&UnreadBit == 0 {
		t.Error("no unread bit")
	}
	if _, st := in.Lookup(facts.MustCleanInputPath("link/action.yml")); st != LookupUnknown {
		t.Errorf("Lookup(link/action.yml) = %v, want unknown", st)
	}
	var _ = fstest.MapFS{}
}

func sym(target string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(target), Mode: fs.ModeSymlink}
}

func TestRealPath(t *testing.T) {
	fsys := fstest.MapFS{
		"suite/V55R/in.yaml": {Data: []byte("a: 1\n")},
		"suite/name/a":       sym("../V55R"),
		"suite/name/hop":     sym("../V55R"),
		"suite/name/chain":   sym("hop"),
		"suite/name/up":      sym("hop/../name"), // as the OS reads it: hop is suite/V55R, so .. is suite (fstest.MapFS itself reads it by the letters, as suite/name/name)
		"out":                sym("../x"),
		"abs":                sym("/etc"),
		"loop1":              sym("loop2"),
		"loop2":              sym("loop1"),
		"suite/file":         {Data: []byte("x")},
		"tofile":             sym("suite/file"),
	}
	for _, c := range []struct {
		name, p, want string
		ok            bool
	}{
		{"sibling", "suite/name/a", "suite/V55R", true},
		{"chain", "suite/name/chain", "suite/V55R", true},
		{"chain-dotdot", "suite/name/up", "suite/name", true},
		{"out of the root", "out", "", false},
		{"absolute", "abs", "", false},
		{"loop", "loop1", "", false},
		{"no link", "suite/V55R", "suite/V55R", true},
		{"a file", "tofile", "", false},
	} {
		got, ok := realPath(fsys, c.p)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: realPath(%s) = %q, %v; want %q, %v", c.name, c.p, got, ok, c.want, c.ok)
		}
	}
	if _, ok := realPath(struct{ fs.FS }{fsys}, "suite/name/a"); ok {
		t.Error("an fs.FS without ReadLink: followed")
	}
}

func TestEnumerateDirectoryLinks(t *testing.T) {
	fsys := fstest.MapFS{
		"suite/V55R/in.yaml":  {Data: []byte("a: 1\n")},
		"suite/name/aliases":  sym("../V55R"), // known, and nothing to read: not an input
		"suite/name/hop":      sym("../V55R"),
		"suite/name/chain":    sym("hop"),
		"act/real/action.yml": {Data: []byte(okAction)},
		"act/link":            sym("real"),   // inputs under it
		"up":                  sym("act/.."), // the root: inputs under it
		".git/HEAD":           {Data: []byte("x")},
		"gitlink":             sym(".git"),
		"has/x":               sym("../suite/V55R"),
		"tohas":               sym("has"), // a link under it
	}
	in, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	want := "act/link=action-metadata/unreadable act/real/action.yml=action-metadata/read gitlink=action-metadata/unreadable tohas=action-metadata/unreadable up=action-metadata/unreadable"
	if got := names(in); got != want {
		t.Errorf("Enumerate =\n%s\nwant\n%s", got, want)
	}
	for _, i := range in.List {
		if i.State == InputStateUnreadable && i.Reason == "" {
			t.Errorf("%s: unreadable without a reason", i.Name)
		}
	}
	quiet, err := Enumerate(fstest.MapFS{
		"suite/V55R/in.yaml": {Data: []byte("a: 1\n")},
		"suite/name/aliases": sym("../V55R"),
		"a/action.yml":       {Data: []byte(okAction)},
	})
	if err != nil || names(quiet) != "a/action.yml=action-metadata/read" || !quiet.Complete {
		t.Errorf("links to what is known: %s, complete %v, %v; want a/action.yml only, complete", names(quiet), quiet.Complete, err)
	}
}

// TestEnumerateLinksUnderRoot: through an os.Root, a link to a sibling
// directory is known, and one out of the root is not.
func TestEnumerateLinksUnderRoot(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "suite/V55R"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "suite/name"), 0o755)
	if err := os.Symlink("../V55R", filepath.Join(dir, "suite/name/aliases")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	os.Symlink(outside, filepath.Join(dir, "ext"))
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	in, err := Enumerate(root.FS())
	if err != nil {
		t.Fatal(err)
	}
	if got := names(in); got != "ext=action-metadata/unreadable" || in.Complete {
		t.Errorf("Enumerate = %s, complete %v; want ext=action-metadata/unreadable, not complete", got, in.Complete)
	}
}

// TestEnumerateLinkIntoUnreadable: a link into a directory that cannot be
// read leads to what is not known.
func TestEnumerateLinkIntoUnreadable(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "locked/sub"), 0o755)
	if err := os.Symlink("locked/sub", filepath.Join(dir, "link")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "locked"), 0o311); err != nil { // no read: WalkDir fails, Lstat works
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(dir, "locked"), 0o755)
	if _, err := os.ReadDir(filepath.Join(dir, "locked")); err == nil {
		t.Skip("the directory can be read (root)")
	}
	in, err := Enumerate(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(in); got != "link=action-metadata/unreadable locked=action-metadata/unreadable" {
		t.Errorf("Enumerate = %s", got)
	}
}

// TestEnumerateLinksInWorkflows: a symlink to a directory right under
// .github/workflows is not a workflow, but uses: ./.github/workflows/x
// reaches what is in it, so it is judged as any other; and a link to
// .github counts the links in it.
func TestEnumerateLinksInWorkflows(t *testing.T) {
	dir := t.TempDir()
	mk := func(p, s string) {
		t.Helper()
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("act/action.yml", okAction)
	mk("empty/in.yaml", "a: 1\n")
	mk(".github/workflows/w.yml", okWorkflow)
	if err := os.Symlink("../../act", filepath.Join(dir, ".github/workflows/sub")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	os.Symlink("../../empty", filepath.Join(dir, ".github/workflows/none"))
	os.Symlink(".github", filepath.Join(dir, "L"))
	in, err := Enumerate(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	want := ".github/workflows/sub=action-metadata/unreadable .github/workflows/w.yml=workflow/read L=action-metadata/unreadable act/action.yml=action-metadata/read"
	if got := names(in); got != want || in.Complete {
		t.Errorf("Enumerate = %s, complete %v; want\n%s, not complete", got, in.Complete, want)
	}
	dir2 := t.TempDir() // the layout of the review: nothing but the link in .github
	os.MkdirAll(filepath.Join(dir2, "act"), 0o755)
	os.MkdirAll(filepath.Join(dir2, ".github/workflows"), 0o755)
	os.WriteFile(filepath.Join(dir2, "act/action.yml"), []byte(okAction), 0o644)
	os.WriteFile(filepath.Join(dir2, ".github/README"), []byte("x"), 0o644)
	os.Symlink("../../act", filepath.Join(dir2, ".github/workflows/sub"))
	os.Symlink(".github", filepath.Join(dir2, "L"))
	in, err = Enumerate(os.DirFS(dir2))
	if err != nil {
		t.Fatal(err)
	}
	want = ".github/workflows/sub=action-metadata/unreadable L=action-metadata/unreadable act/action.yml=action-metadata/read"
	if got := names(in); got != want || in.Complete {
		t.Errorf("Enumerate = %s, complete %v; want\n%s, not complete", got, in.Complete, want)
	}
}

func TestParseExclude(t *testing.T) {
	for s, want := range map[string]string{"yaml/corpus": "yaml/corpus", "yaml/corpus/": "yaml/corpus", "./.github/actions": ".github/actions", "x.yml": "x.yml"} {
		e, err := ParseExclude(s)
		if err != nil || e.String() != want {
			t.Errorf("ParseExclude(%q) = %q, %v; want %q", s, e, err, want)
		}
	}
	for _, s := range []string{".github", ".github/workflows", ".github/workflows/", ".github/workflows/x.yml", "..", "a/../b", "/x", "", "."} {
		if e, err := ParseExclude(s); err == nil {
			t.Errorf("ParseExclude(%q) = %q, want an error", s, e)
		}
	}
}

func excludes(t *testing.T, ss ...string) []Exclude {
	t.Helper()
	var out []Exclude
	for _, s := range ss {
		e, err := ParseExclude(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func TestEnumerateExcept(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/a.yml":   {Data: []byte(okWorkflow)},
		"yaml/corpus/x/action.yml":  {Data: []byte("not: [valid\n")},
		"yaml/corpus/y/action.yml":  {Data: []byte(okAction)},
		"yaml/corpus/y/action.yaml": {Data: []byte(okAction)}, // action.yml wins, as in Enumerate
		"yaml/corpus/z/action.yaml": {Data: []byte(okAction)},
		"yaml/corpus/l":             sym("x"), // not judged
		"yaml/corpus2/action.yml":   {Data: []byte(okAction)},
		"testdata/action.yml":       {Data: []byte(okAction)},
	}
	in, err := EnumerateExcept(fsys, excludes(t, "yaml/corpus", "testdata/action.yml", "yaml/corpus", "nowhere"))
	if err != nil {
		t.Fatal(err)
	}
	want := ".github/workflows/a.yml=workflow/read testdata/action.yml=action-metadata/excluded yaml/corpus/x/action.yml=action-metadata/excluded " +
		"yaml/corpus/y/action.yml=action-metadata/excluded yaml/corpus/z/action.yaml=action-metadata/excluded yaml/corpus2/action.yml=action-metadata/read"
	if got := names(in); got != want {
		t.Errorf("EnumerateExcept =\n%s\nwant\n%s", got, want)
	}
	if !in.Complete {
		t.Error("not complete: what is excluded is listed")
	}
	var ex []string
	for _, e := range in.Excluded {
		ex = append(ex, e.String())
	}
	if got := strings.Join(ex, " "); got != "nowhere testdata/action.yml yaml/corpus" {
		t.Errorf("Excluded = %s", got)
	}
	reasons := map[string]string{
		"testdata/action.yml": "--exclude testdata/action.yml", "yaml/corpus/x/action.yml": "--exclude yaml/corpus",
		"yaml/corpus/y/action.yml": "--exclude yaml/corpus", "yaml/corpus/z/action.yaml": "--exclude yaml/corpus",
	}
	for _, i := range in.List {
		if i.State == InputStateExcluded && (i.Tree != nil || i.Reason != reasons[i.Name.String()]) {
			t.Errorf("%s: tree %v, reason %q", i.Name, i.Tree != nil, i.Reason)
		}
	}
	for n, want := range map[string]LookupState{"yaml/corpus/y/action.yml": LookupUnknown, "yaml/corpus/none/action.yml": LookupUnknown, "yaml/corpus2/action.yml": LookupFound, "b/action.yml": LookupAbsent} {
		if _, got := in.Lookup(facts.MustCleanInputPath(n)); got != want {
			t.Errorf("Lookup(%s) = %v, want %v", n, got, want)
		}
	}
}

// TestEnumerateExceptLinks: a link out of what is excluded that leads into
// it is judged by what is there, links in it too.
func TestEnumerateExceptLinks(t *testing.T) {
	fsys := fstest.MapFS{
		"ex/real/action.yml":   {Data: []byte(okAction)},
		"ex/empty/in.yaml":     {Data: []byte("a: 1\n")},
		"ex/empty/l":           sym("../../elsewhere"),
		"elsewhere/action.yml": {Data: []byte(okAction)},
		"toreal":               sym("ex/real"),  // an excluded input under it
		"toempty":              sym("ex/empty"), // a link in what is excluded under it
	}
	in, err := EnumerateExcept(fsys, excludes(t, "ex"))
	if err != nil {
		t.Fatal(err)
	}
	want := "elsewhere/action.yml=action-metadata/read ex/real/action.yml=action-metadata/excluded toempty=action-metadata/unreadable toreal=action-metadata/unreadable"
	if got := names(in); got != want {
		t.Errorf("EnumerateExcept =\n%s\nwant\n%s", got, want)
	}
}

// TestInputsCopiesKeepExcluded: the inputs Run and ApplyFixes check a fix
// with are copies of in; a copy that lost Excluded would answer an excluded
// name as absent.
func TestInputsCopiesKeepExcluded(t *testing.T) {
	for _, f := range []string{"run.go", "apply.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "Inputs{List: slices.Clone(") {
			t.Errorf("%s makes Inputs from List and Complete only: copy the Inputs, then its List", f)
		}
	}
}

// TestEnumerateExceptLinkIntoUnreadable: a directory not read in what is
// excluded is not an input, but a link out of the range that leads there
// leads to what is not known.
func TestEnumerateExceptLinkIntoUnreadable(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "x/sub"), 0o755)
	os.WriteFile(filepath.Join(dir, "x/sub/action.yml"), []byte(okAction), 0o644)
	if err := os.Symlink("x", filepath.Join(dir, "L")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, "x/sub"), 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(filepath.Join(dir, "x/sub"), 0o755)
	if _, err := os.ReadDir(filepath.Join(dir, "x/sub")); err == nil {
		t.Skip("the directory can be read (root)")
	}
	in, err := EnumerateExcept(os.DirFS(dir), excludes(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if got := names(in); got != "L=action-metadata/unreadable" || in.Complete {
		t.Errorf("EnumerateExcept = %s, complete %v; want L=action-metadata/unreadable, not complete", got, in.Complete)
	}
}

// TestEnumerateNameNotUTF8: a file whose name is not UTF-8 is an
// unreadable input, with why
// (here, the fs.FS does not read it), as before the name became a
// facts.InputPath, and Enumerate does not panic.
func TestEnumerateNameNotUTF8(t *testing.T) {
	name := ".github/workflows/a\xff.yml"
	in, err := Enumerate(fstest.MapFS{name: {Data: []byte("on: push\njobs: {}\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(in.List) != 1 || in.List[0].Name.String() != name || in.List[0].State != InputStateUnreadable || in.List[0].Reason == "" {
		t.Errorf("got %+v", in.List)
	}
}

// TestEnumerateActionYAMLBesideNonFile: the runner reads action.yml only
// when File.Exists is true for it (false for a directory), and action.yaml
// otherwise (seen on 2026-10-31 with runner 2.338.2: action.yml a
// directory ran action.yaml; action.yml a symlink to a file ran the file).
func TestEnumerateActionYAMLBesideNonFile(t *testing.T) {
	for _, c := range []struct {
		name string
		fsys fstest.MapFS
		want string
	}{
		{"directory", fstest.MapFS{"x/action.yml/keep": {Data: []byte("k")}, "x/action.yaml": {Data: []byte(okAction)}},
			"x/action.yaml=action-metadata/read"},
		{"symlink to a directory", fstest.MapFS{"x/real/keep": {Data: []byte("k")}, "x/action.yml": sym("real"), "x/action.yaml": {Data: []byte(okAction)}},
			"x/action.yaml=action-metadata/read"},
		{"broken symlink", fstest.MapFS{"x/action.yml": sym("gone.yml"), "x/action.yaml": {Data: []byte(okAction)}},
			"x/action.yaml=action-metadata/read"},
		{"symlink to a file", fstest.MapFS{"x/real.yml": {Data: []byte(okAction)}, "x/action.yml": sym("real.yml"), "x/action.yaml": {Data: []byte(okAction)}},
			"x/action.yml=action-metadata/read"},
		{"file", fstest.MapFS{"x/action.yml": {Data: []byte(okAction)}, "x/action.yaml": {Data: []byte(okAction)}},
			"x/action.yml=action-metadata/read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			in, err := Enumerate(c.fsys)
			if err != nil {
				t.Fatal(err)
			}
			if got := names(in); got != c.want {
				t.Errorf("Enumerate = %s, want %s", got, c.want)
			}
		})
	}
}

func TestLookupUnderSubmodule(t *testing.T) {
	in := Inputs{Complete: true, Submodules: []facts.InputPath{facts.MustCleanInputPath("sub")}}
	if _, st := in.Lookup(facts.MustCleanInputPath("sub/act/action.yml")); st != LookupUnknown {
		t.Errorf("under a submodule: %v, want unknown", st)
	}
	if _, st := in.Lookup(facts.MustCleanInputPath("subway/action.yml")); st != LookupAbsent {
		t.Errorf("beside a submodule: %v, want absent", st)
	}
}

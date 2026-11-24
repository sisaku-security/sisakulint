package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/githubtest"
	"github.com/gh-intel/sisakulint/actions/lint"
)

const (
	shaCheckout = "11bd71901bbe5b1630ceea73d27597364c9af683"
	shaInner    = "ee770a9615648ecfcf3ca4bf8b549375d3be713e"
)

// fakeGitHub knows the refs of testdata/repo but the ref of gone/repo, which
// is not there; and of the repositories whether they are archived, and the
// action.yml of the actions, in the archive and as the blob
// (archived-uses, deprecated-node-runtime, action.definition), so
// that every fact a run asks has a found or absent answer, which a file of
// facts replays without asking again.
func fakeGitHub(t *testing.T) *githubtest.Server {
	t.Helper()
	const repo = `{"visibility":"public","private":false,"has_wiki":true,"archived":false}`
	return githubtest.New(t, map[string]string{
		"/repos/actions/checkout/commits/refs/tags/v4": shaCheckout,
		"/repos/inner/action/commits/refs/tags/v2":     shaInner,
		// the commits themselves: the run that checks the fix of commit-sha
		// reads the action at the full SHA the fix writes
		"/repos/actions/checkout/commits/" + shaCheckout: shaCheckout,
		"/repos/inner/action/commits/" + shaInner:        shaInner,
		"/repos/actions/checkout":                        repo,
		"/repos/inner/action":                            repo,
		"/repos/gone/repo":                               repo,
		"/repos/actions/checkout/tarball/" + shaCheckout: githubtest.Tarball(map[string]string{"action.yml": "runs:\n  using: node24\n  main: index.js\n"}),
		"/repos/inner/action/tarball/" + shaInner:        githubtest.Tarball(map[string]string{"action.yml": "runs:\n  using: node20\n  main: index.js\n"}),
		// the blobs action.definition compares the archives with
		"/repos/actions/checkout/contents/action.yml": "runs:\n  using: node24\n  main: index.js\n",
		"/repos/inner/action/contents/action.yml":     "runs:\n  using: node20\n  main: index.js\n",
	})
}

func withToken(token string) func(string) string {
	return func(k string) string {
		if k == "GITHUB_TOKEN" {
			return token
		}
		return ""
	}
}

func TestFactsReplay(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	file := filepath.Join(t.TempDir(), "facts.json")
	online := run(t, args("--root", dir, "--online", "--github-api", gh.URL, "--write-facts", file))
	if online.code > 7 || !strings.Contains(online.stdout, shaCheckout) {
		t.Fatalf("online: exit %d, stderr %s\n%s", online.code, online.stderr, online.stdout)
	}
	asked := len(gh.Authorizations())
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := facts.LoadStore(b); err != nil {
		t.Fatalf("the facts written cannot be read: %v\n%s", err, b)
	}
	offline := run(t, args("--root", dir, "--facts", file))
	// the same answers; where they come from differs, the API and then the file
	if !strings.Contains(online.stdout, `"source":"github"`) || !strings.Contains(offline.stdout, `"source":"file"`) || strings.Contains(offline.stdout, `"source":"github"`) {
		t.Errorf("the sources: online\n%s\noffline\n%s", online.stdout, offline.stdout)
	}
	if withoutSource(offline.stdout) != withoutSource(online.stdout) || offline.code != online.code {
		t.Errorf("the replay differs: exit %d, not %d\n%s\n%s", offline.code, online.code, offline.stdout, online.stdout)
	}
	if n := len(gh.Authorizations()); n != asked {
		t.Errorf("the replay asked GitHub %d times", n-asked)
	}
	// the same file read and written: the cache of a CI
	again := run(t, args("--root", dir, "--facts", file, "--write-facts", file, "--online", "--github-api", gh.URL))
	if withoutSource(again.stdout) != withoutSource(online.stdout) || len(gh.Authorizations()) != asked {
		t.Errorf("reading and writing one file: exit %d, stderr %s, %d more requests", again.code, again.stderr, len(gh.Authorizations())-asked)
	}
	if b2, _ := os.ReadFile(file); string(b2) != string(b) {
		t.Errorf("the file written again differs:\n%s\n%s", b2, b)
	}
	// the file is replaced by what this run asked: a run of one PATH keeps
	// only its facts, and those it did not ask are asked again later: of its
	// one uses, the commit of its ref (commit-sha), the advisories of its
	// package (known-vulnerable-actions), whether its repository is archived
	// (archived-uses), its runs.using (deprecated-node-runtime) and the
	// file that defines it (action.definition, for the steps of a composite
	// action), and of its file, whether Dependabot and Renovate update it
	// (dependabot-github-actions), answered from the files under --root,
	// and the file that defines the action at the full SHA the fix of
	// commit-sha writes, which the run that checks the fix reads
	one := run(t, args("--root", dir, "--facts", file, "--write-facts", file, ".github/actions/build/action.yml"))
	if one.code > 7 {
		t.Fatalf("one PATH: exit %d, %s", one.code, one.stderr)
	}
	b3, _ := os.ReadFile(file)
	if strings.Count(string(b3), `"query"`) != 8 || strings.Contains(string(b3), `"state":"absent"`) || !strings.Contains(string(b3), `"git.ref-commit"`) || !strings.Contains(string(b3), `"package.advisories"`) || !strings.Contains(string(b3), `"repo.archived"`) || !strings.Contains(string(b3), `"action.runs-using"`) || !strings.Contains(string(b3), `"action.definition"`) {
		t.Errorf("after a run of one PATH, the file of facts is not its eight facts:\n%s", b3)
	}
	for _, k := range []string{`"dependabot.version-updates"`, `"renovate.manager-enabled"`} {
		if !strings.Contains(string(b3), `{"query":{"kind":`+k) || !strings.Contains(one.stdout, `"kind":`+k) {
			t.Errorf("%s is not written, or not in the report:\n%s", k, b3)
		}
	}
	if !strings.Contains(one.stdout, `"source":"repo-file"`) {
		t.Errorf("no answer from the files of the repository in the report:\n%s", one.stdout)
	}
}

func TestWriteFactsThroughSymlink(t *testing.T) {
	dir, tmp := repo(t), t.TempDir()
	real, link := filepath.Join(tmp, "cache/real.json"), filepath.Join(tmp, "link.json")
	if err := os.MkdirAll(filepath.Dir(real), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("cache/real.json", link); err != nil { // real.json is not there yet
		t.Fatal(err)
	}
	for range 2 { // made through the link, then replaced through it
		if got := run(t, args("--root", dir, "--write-facts", link)); got.code > 7 {
			t.Fatalf("exit %d, %s", got.code, got.stderr)
		}
		if st, err := os.Lstat(link); err != nil || st.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("link.json is no longer a symlink: %v", err)
		}
		if b, err := os.ReadFile(real); err != nil || !strings.Contains(string(b), `"query"`) {
			t.Errorf("the facts are not in the file the link points to: %v %s", err, b)
		}
	}
}

func TestToken(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	var keys []string
	getenv := func(k string) string { keys = append(keys, k); return withToken("secret-token")(k) }
	run(t, Env{Args: []string{"--root", dir}, Getenv: getenv})
	if len(gh.Authorizations()) != 0 || slices.Contains(keys, "GITHUB_TOKEN") {
		t.Errorf("offline: %d requests, read %v", len(gh.Authorizations()), keys)
	}
	online := run(t, Env{Args: []string{"--root", dir, "--online", "--github-api", gh.URL}, Getenv: getenv})
	auth := gh.Authorizations()
	if len(auth) == 0 || slices.ContainsFunc(auth, func(a string) bool { return a != "Bearer secret-token" }) {
		t.Errorf("online with a token: Authorization %q", auth)
	}
	if strings.Contains(online.stdout+online.stderr, "secret-token") {
		t.Errorf("the token is written:\n%s\n%s", online.stdout, online.stderr)
	}
	gh2 := fakeGitHub(t)
	none := run(t, args("--root", dir, "--online", "--github-api", gh2.URL))
	if !strings.Contains(none.stderr, "GITHUB_TOKEN") || slices.ContainsFunc(gh2.Authorizations(), func(a string) bool { return a != "" }) {
		t.Errorf("online without a token: stderr %q, Authorization %q", none.stderr, gh2.Authorizations())
	}
}

func TestFactsUsage(t *testing.T) {
	dir := repo(t)
	for _, c := range []struct {
		name string
		env  Env
	}{
		{"--github-api without --online", args("--root", dir, "--github-api", "https://ghe.example/api/v3")},
		{"--github-api of ftp", args("--root", dir, "--online", "--github-api", "ftp://x")},
		{"an empty --github-api", args("--root", dir, "--online", "--github-api", "")},
		{"--github-api without a host", args("--root", dir, "--online", "--github-api", "https://")},
		{"an empty --facts", args("--root", dir, "--facts", "")},
		{"an empty --write-facts", args("--root", dir, "--write-facts", "")},
	} {
		if got := run(t, c.env); got.code != ExitUsage || got.stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d and nothing", c.name, got.code, got.stdout, ExitUsage)
		}
	}
}

func TestFactsNoInput(t *testing.T) {
	dir := repo(t)
	report := run(t, args("--root", dir)).stdout
	tmp := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(tmp, name)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct{ name, path string }{
		{"no such file", filepath.Join(tmp, "nope.json")},
		{"not JSON", write("bad.json", "{")},
		{"a report, not a file of facts", write("report.json", report)},
	} {
		if got := run(t, args("--root", dir, "--facts", c.path)); got.code != ExitNoInput || got.stdout != "" || got.stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d", c.name, got.code, got.stdout, got.stderr, ExitNoInput)
		}
	}
}

func TestWriteFactsFails(t *testing.T) {
	got := run(t, args("--root", repo(t), "--write-facts", filepath.Join(t.TempDir(), "no/such/dir/facts.json")))
	if got.code != ExitIO || !strings.HasPrefix(got.stdout, `{"schema":"sisakulint/report/v0"`) || got.stderr == "" {
		t.Errorf("exit %d, stdout %q, stderr %q; want %d, the report, and why", got.code, got.stdout, got.stderr, ExitIO)
	}
}

func TestAtomicLeavesNoTemporary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory without the permission to")
	}
	dir := t.TempDir()
	if err := writeFileAtomic(filepath.Join(dir, "facts.json"), []byte("{}")); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(locked, "facts.json"), []byte("{}")); err == nil {
		t.Error("a file written in a directory that cannot be written")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if tmp, err := stage(root, facts.MustCleanInputPath("a.yml"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	} else if err := root.Rename(tmp, "a.yml"); err != nil {
		t.Fatal(err)
	}
	if _, err := stage(root, facts.MustCleanInputPath("locked/action.yml"), []byte("y"), 0o644); err == nil {
		t.Error("a file staged in a directory that cannot be written")
	}
	// a rename that fails, over a directory that is not empty: the file made is removed
	if err := os.MkdirAll(filepath.Join(dir, "full/x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "full"), []byte("{}")); err == nil {
		t.Error("a file renamed over a directory")
	}
	for _, d := range []string{dir, locked} {
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if n := e.Name(); n != "facts.json" && n != "a.yml" && n != "locked" && n != "full" {
				t.Errorf("left in %s: %s", d, n)
			}
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.yml")); string(b) != "y" {
		t.Errorf("a.yml = %q", b)
	}
}

func TestTemporaryNames(t *testing.T) {
	n := tempName()
	if strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") || !strings.HasPrefix(n, ".") || len(n) > 64 {
		t.Errorf("tempName() = %q: read as an input, not hidden, or long", n)
	}
	if tempName() == n {
		t.Errorf("tempName() gives %q twice", n)
	}
}

// selfHostedReport is what TestUnknownFactsConditional reads of a report:
// the certainty of each finding of self-hosted-runner by its kind, and
// the state of the answer to repo.public, and whether an answer has the
// source assumption.
type selfHostedReport struct {
	certainty     map[string]string
	public        string
	assumedSource bool
}

func readSelfHosted(t *testing.T, stdout string) selfHostedReport {
	t.Helper()
	var rep struct {
		Findings []struct {
			Rule      string `json:"rule"`
			Certainty string `json:"certainty"`
			Args      struct {
				KindID string `json:"kind_id"`
			} `json:"args"`
		} `json:"findings"`
		Facts []struct {
			Query struct {
				Kind string `json:"kind"`
			} `json:"query"`
			State  string `json:"state"`
			Source string `json:"source"`
		} `json:"facts"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("the report: %v\n%s", err, stdout)
	}
	out := selfHostedReport{certainty: map[string]string{}}
	for _, f := range rep.Findings {
		if f.Rule == "self-hosted-runner" {
			out.certainty[f.Args.KindID] = f.Certainty
		}
	}
	for _, e := range rep.Facts {
		if e.Source == "assumption" {
			out.assumedSource = true
		}
		if e.Query.Kind == "repo.public" {
			out.public = e.State
		}
	}
	return out
}

// TestUnknownFactsConditional: a fact that no source answers is not known,
// so a finding whose condition depends on the fact is conditional, and
// both kinds whose conditions take the two answers of repo.public are
// reported; an answer of --fact or a file of facts decides the condition.
func TestUnknownFactsConditional(t *testing.T) {
	dir := selfHostedRepo(t)
	with := func(a ...string) Env {
		return args(append([]string{"--root", dir, "--rule", "self-hosted-runner"}, a...)...)
	}
	def := run(t, with())
	got := readSelfHosted(t, def.stdout)
	if def.code != int(lint.UndecidedBit) || got.assumedSource || got.public != "unknown" {
		t.Fatalf("default: exit %d, repo.public %s, stderr %s\n%s", def.code, got.public, def.stderr, def.stdout)
	}
	for _, k := range []string{"self-hosted-runner.public", "self-hosted-runner.private"} {
		if got.certainty[k] != "conditional" {
			t.Errorf("default: %s is %q, want conditional\n%s", k, got.certainty[k], def.stdout)
		}
	}
	// an answer of --fact decides the condition
	priv := run(t, with("--fact", "repo.public=false", "--fact", "repo.allow-forking=false"))
	if got := readSelfHosted(t, priv.stdout); len(got.certainty) != 0 || priv.code != 0 {
		t.Errorf("--fact repo.public=false: exit %d, findings %v\n%s", priv.code, got.certainty, priv.stdout)
	}
	// so does a file of facts
	public := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(public, []byte(`{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"repo.public"},"state":"found","value":true}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	fc := run(t, with("--facts", public))
	if got := readSelfHosted(t, fc.stdout); fc.code != int(lint.ConfirmedBit) || got.certainty["self-hosted-runner.public"] != "confirmed" || got.certainty["self-hosted-runner.private"] != "" {
		t.Errorf("--facts with true: exit %d, findings %v\n%s", fc.code, got.certainty, fc.stdout)
	}
	// the cache of a CI: the unknown answer is written, and a run on the
	// file gives the same report, but where its answers come from
	cache := filepath.Join(t.TempDir(), "facts.json")
	first := run(t, with("--write-facts", cache))
	b, err := os.ReadFile(cache)
	if err != nil || !strings.Contains(string(b), `{"query":{"kind":"repo.public"},"state":"unknown"`) {
		t.Errorf("--write-facts does not write repo.public unknown: %s %v", b, err)
	}
	second := run(t, with("--facts", cache, "--write-facts", cache))
	if withoutSource(second.stdout) != withoutSource(first.stdout) || second.code != first.code {
		t.Errorf("the run on the cache differs: exit %d, not %d\n%s\n%s", second.code, first.code, second.stdout, first.stdout)
	}
}

// withoutSource is the report r without where its answers come from.
func withoutSource(r string) string {
	return regexp.MustCompile(`,"source":"[a-z]+"`).ReplaceAllString(r, "")
}

// TestGitHubAPIHTTPOffLoopback: an http --github-api that is not a loopback
// address is a usage error, so that GITHUB_TOKEN is not sent in the clear.
func TestGitHubAPIHTTPOffLoopback(t *testing.T) {
	dir := t.TempDir()
	if got := run(t, args("--root", dir, "--online", "--github-api", "http://ghe.example/api/v3")); got.code != ExitUsage || !strings.Contains(got.stderr, "http") {
		t.Errorf("exit %d, stderr %q; want %d", got.code, got.stderr, ExitUsage)
	}
	if got := run(t, args("--remote", "o/r", "--github-api", "HTTP://ghe.example")); got.code != ExitUsage {
		t.Errorf("--remote: exit %d, want %d", got.code, ExitUsage)
	}
}

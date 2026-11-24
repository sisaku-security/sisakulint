package cli

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

func TestParseFact(t *testing.T) {
	or, _ := facts.ParseRepo("o/r")
	for _, c := range []struct {
		in    string
		repo  facts.Repo
		query string
		value string
	}{
		{"repo.public=false", facts.Repo{}, `{"kind":"repo.public"}`, "false"},
		{"repo.public=false", or, `{"kind":"repo.public","repo":"o/r"}`, "false"},
		{"repo.environment-protected[environment=prod]=true", or, `{"kind":"repo.environment-protected","repo":"o/r","environment":"prod"}`, "true"},
		{"repo.public[repo=O/R]=true", or, `{"kind":"repo.public","repo":"o/r"}`, "true"},
		// a value with brackets
		{"checkout.executed[input_path=.github/workflows/ci.yml,step=jobs.build.steps[2]]=false", or,
			`{"kind":"checkout.executed","input_path":".github/workflows/ci.yml","step":"jobs.build.steps[2]"}`, "false"},
		{"request.destination-trusted[secret=T,destination=api.example.com]=true", facts.Repo{},
			`{"kind":"request.destination-trusted","secret":"T","destination":"api.example.com"}`, "true"},
		{"request.destination-trusted[secret=upload_token,destination=${{ secrets.UPLOAD_API }}]=true", facts.Repo{},
			`{"kind":"request.destination-trusted","secret":"UPLOAD_TOKEN","destination":"${{ secrets.upload_api }}"}`, "true"},
		{`git.ref-commit[repo=actions/checkout,ref=v4]={"sha":"11bd71901bbe5b1630ceea73d27597364c9af683","ref":"refs/tags/v4"}`, facts.Repo{},
			`{"kind":"git.ref-commit","repo":"actions/checkout","ref":"v4"}`, `{"sha":"11bd71901bbe5b1630ceea73d27597364c9af683","ref":"refs/tags/v4"}`},
	} {
		e, err := parseFact(c.in, c.repo)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		q, _ := facts.EncodeQuery(e.Query)
		if string(q) != c.query || string(e.RawAnswer.Value) != c.value || e.RawAnswer.State != facts.StateFound {
			t.Errorf("%s = %s %s", c.in, q, e.RawAnswer.Value)
		}
	}
	for _, c := range []struct {
		in   string
		repo facts.Repo
	}{
		{"repo.public", facts.Repo{}},
		{"repo.public=", facts.Repo{}},
		{"repo.public=yes", facts.Repo{}},
		{"no.such-kind=true", facts.Repo{}},
		{"repo.environment-protected[environment=prod=true", facts.Repo{}},
		{"repo.environment-protected[environment]=true", facts.Repo{}},
		{"repo.environment-protected[kind=x]=true", facts.Repo{}},
		{"repo.environment-protected[environment=a,environment=b]=true", facts.Repo{}},
		{"repo.public[repo=x/y]=true", or},
		{"repo.public[repo=x/y]=true", facts.Repo{}},
		{"repo.public[name=x]=true", facts.Repo{}},
	} {
		if _, err := parseFact(c.in, c.repo); err == nil {
			t.Errorf("%s (--repo %q): no error", c.in, c.repo)
		}
	}
}

// selfHostedRepo is a repository whose job runs on a self-hosted runner.
func selfHostedRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wf, "w.yml"), []byte("on: push\njobs:\n  a:\n    runs-on: self-hosted\n    steps:\n      - run: echo hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fakeRepoAPI says that o/r is private, and nothing else.
func fakeRepoAPI(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/o/r" {
			w.Write([]byte(`{"visibility":"private","private":true,"has_wiki":false}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func writeFile(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRepoAndFact(t *testing.T) {
	dir := selfHostedRepo(t)
	with := func(a ...string) Env {
		return args(append([]string{"--root", dir, "--rule", "self-hosted-runner"}, a...)...)
	}
	const finding = `"kind_id":"self-hosted-runner.public"`
	// on repo.public false, the finding of one who may read the repository
	// is conditional: no fact says whether they fork it and whether the
	// workflows of pull requests from forks run
	const private = `"kind_id":"self-hosted-runner.private"`
	readers := func(got result) bool {
		return got.code == int(lint.UndecidedBit) && strings.Contains(got.stdout, private) && strings.Contains(got.stdout, `"certainty":"conditional"`)
	}
	// the API says o/r is private
	online := run(t, with("--online", "--github-api", fakeRepoAPI(t), "--repo", "o/r"))
	if !readers(online) || strings.Contains(online.stdout, finding) ||
		!strings.Contains(online.stdout, `{"query":{"kind":"repo.public","repo":"o/r"},"state":"found","value":false,"source":"github"}`) {
		t.Errorf("--online --repo: exit %d, stderr %s\n%s", online.code, online.stderr, online.stdout)
	}
	// entries of another repository and of no name do not answer o/r
	mixed := run(t, with("--repo", "o/r", "--facts", writeFile(t, `{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"repo.public","repo":"x/y"},"state":"found","value":false},{"query":{"kind":"repo.public"},"state":"found","value":false}]}`)))
	if mixed.code != int(lint.UndecidedBit) || !strings.Contains(mixed.stdout, finding) || !strings.Contains(mixed.stdout, `{"query":{"kind":"repo.public","repo":"o/r"},"state":"unknown"`) {
		t.Errorf("--facts of x/y and of no name, --repo o/r: exit %d\n%s", mixed.code, mixed.stdout)
	}
	// --fact, with and without --repo
	for _, a := range [][]string{{"--fact", "repo.public=false"}, {"--fact", "repo.public=false", "--repo", "o/r"}, {"--repo", "o/r", "--fact", "repo.public[repo=o/r]=false"}} {
		got := run(t, with(a...))
		if !readers(got) || strings.Contains(got.stdout, finding) || !strings.Contains(got.stdout, `"value":false,"source":"argument"`) {
			t.Errorf("%v: exit %d, stderr %s\n%s", a, got.code, got.stderr, got.stdout)
		}
	}
	// --fact wins over the file of facts
	over := run(t, with("--facts", writeFile(t, `{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"repo.public"},"state":"found","value":true}]}`), "--fact", "repo.public=false"))
	if !readers(over) || strings.Contains(over.stdout, finding) {
		t.Errorf("--fact over --facts: exit %d\n%s", over.code, over.stdout)
	}
	// --write-facts writes what --fact gave, as a file's answer
	cache := filepath.Join(t.TempDir(), "facts.json")
	run(t, with("--fact", "repo.public=false", "--write-facts", cache))
	b, err := os.ReadFile(cache)
	if err != nil || !strings.Contains(string(b), `{"query":{"kind":"repo.public"},"state":"found","value":false}`) {
		t.Errorf("--write-facts: %s %v", b, err)
	}
	// a fact --fact does not give keeps the offline reason
	only := run(t, args("--root", repo(t), "--fact", "repo.public=false"))
	var rep struct {
		Facts []struct {
			Query  json.RawMessage `json:"query"`
			Reason string          `json:"reason"`
		} `json:"facts"`
	}
	if err := json.Unmarshal([]byte(only.stdout), &rep); err != nil {
		t.Fatalf("%v: %s", err, only.stdout)
	}
	if len(rep.Facts) == 0 {
		t.Error("no facts asked")
	}
	for _, f := range rep.Facts {
		if f.Reason != "" && !slices.Contains(slices.Collect(maps.Values(offlineReasons)), f.Reason) {
			t.Errorf("%s: reason %q", f.Query, f.Reason)
		}
	}
}

func TestRepoAndFactUsage(t *testing.T) {
	dir := repo(t)
	for _, c := range []struct {
		name string
		env  Env
	}{
		{"--repo not owner/name", args("--root", dir, "--repo", "o")},
		{"an empty --repo", args("--root", dir, "--repo", "")},
		{"--fact not KIND=VALUE", args("--root", dir, "--fact", "repo.public")},
		{"--fact twice", args("--root", dir, "--fact", "repo.public=true", "--fact", "repo.public=false")},
		{"--fact of another repository", args("--root", dir, "--repo", "o/r", "--fact", "repo.public[repo=x/y]=false")},
		{"--fact of a value that does not fit", args("--root", dir, "--fact", `repo.public="no"`)},
	} {
		if got := run(t, c.env); got.code != ExitUsage || got.stdout != "" || got.stderr == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d", c.name, got.code, got.stdout, got.stderr, ExitUsage)
		}
	}
}

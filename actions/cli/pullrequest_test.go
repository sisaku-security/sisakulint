package cli

import (
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/internal/githubtest"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// prFiles is the repository of the pull request tests: caller.yml gives
// called.yml a title, other.yml echoes a title, x is a composite action.
func prFiles(t *testing.T) map[string]githubtest.File {
	t.Helper()
	return filesOf(t, readAllRepo(t))
}

const injectAction = "runs:\n  using: composite\n  steps:\n    - run: echo \"${{ github.event.issue.title }}\"\n      shell: bash\n"

type prReport struct {
	Reported []string `json:"reported_inputs"`
	Findings []struct {
		Rule     string `json:"rule"`
		Location struct {
			File struct{ Input string } `json:"file"`
		} `json:"location"`
	} `json:"findings"`
	Remote struct {
		Commit      string `json:"commit"`
		PullRequest struct {
			Number          int      `json:"number"`
			ChangedInputs   []string `json:"changed_inputs"`
			BehindBy        int      `json:"behind_by"`
			BaseChangeCount int      `json:"base_change_count"`
			UnreportedCount struct {
				Findings int `json:"findings"`
			} `json:"unreported_count"`
		} `json:"pull_request"`
	} `json:"remote_revision"`
}

// prRepo is a repository whose pull request 1 changes base's files to
// head's, branched from base.
func prRepo(t *testing.T, base, head map[string]githubtest.File) (*githubtest.Git, string, string) {
	t.Helper()
	g := githubtest.NewGit(t)
	b := g.Commit("o/r", "main", base)
	h := g.Commit("o/r", "feature", head, b)
	g.Pull("o/r", 1, githubtest.PullRequest{Head: h, BaseRef: "main"})
	return g, b, h
}

func prRun(t *testing.T, g *githubtest.Git, a ...string) (prReport, result) {
	t.Helper()
	got := run(t, args(append([]string{"--remote", "o/r", "--github-api", g.URL().String()}, a...)...))
	var rep prReport
	if got.code < ExitUsage {
		if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
			t.Fatalf("%v: %v\n%s", a, err, got.stdout)
		}
	}
	return rep, got
}

func findingInputs(rep prReport) []string {
	var out []string
	for _, f := range rep.Findings {
		if !slices.Contains(out, f.Location.File.Input) {
			out = append(out, f.Location.File.Input)
		}
	}
	slices.Sort(out)
	return out
}

func TestPullRequestReportsTheChangedInputs(t *testing.T) {
	base := prFiles(t)
	head := maps.Clone(base)
	head[".github/workflows/other.yml"] = githubtest.Blob(base[".github/workflows/other.yml"].Data + "# changed\n")
	head["x/action.yml"] = githubtest.Blob(injectAction)
	g, _, h := prRepo(t, base, head)
	all, got := prRun(t, g, "--pull-request", "1", "--rule", "code-injection")
	if want := []string{".github/workflows/other.yml", "x/action.yml"}; !slices.Equal(all.Reported, want) || !slices.Equal(all.Remote.PullRequest.ChangedInputs, want) || all.Remote.Commit != h {
		t.Errorf("reported %v, changed %v, commit %s; want %v and the head", all.Reported, all.Remote.PullRequest.ChangedInputs, all.Remote.Commit, want)
	}
	if !slices.Equal(findingInputs(all), []string{".github/workflows/other.yml", "x/action.yml"}) {
		t.Errorf("findings in %v", findingInputs(all))
	}
	some, gotSome := prRun(t, g, "--pull-request", "1", "--rule", "code-injection", ".github/workflows/other.yml")
	if !slices.Equal(some.Reported, []string{".github/workflows/other.yml"}) || !slices.Equal(findingInputs(some), []string{".github/workflows/other.yml"}) {
		t.Errorf("with a PATH: reported %v, findings in %v", some.Reported, findingInputs(some))
	}
	if some.Remote.PullRequest.UnreportedCount.Findings == 0 || gotSome.code != got.code {
		t.Errorf("with a PATH: unreported %+v, exit %d; want the finding of x counted and exit %d", some.Remote.PullRequest.UnreportedCount, gotSome.code, got.code)
	}
	text := run(t, raw("--remote", "o/r", "--github-api", g.URL().String(), "--pull-request", "1", "--rule", "code-injection", ".github/workflows/other.yml"))
	if !strings.Contains(text.stdout, "pull request #1: head "+h) || !strings.Contains(text.stdout, "the PATHs leave out") {
		t.Errorf("the text does not say the pull request and the places left out:\n%s", text.stdout)
	}
}

func TestPullRequestCallerOnly(t *testing.T) {
	base := prFiles(t)
	base[".github/workflows/caller.yml"] = githubtest.Blob("on: issues\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: fixed\n")
	head := maps.Clone(base)
	head[".github/workflows/caller.yml"] = prFiles(t)[".github/workflows/caller.yml"]
	g, _, _ := prRepo(t, base, head)
	rep, _ := prRun(t, g, "--pull-request", "1", "--rule", "code-injection")
	if !slices.Contains(findingInputs(rep), ".github/workflows/called.yml") {
		t.Errorf("the pull request gives called.yml a title; findings in %v", findingInputs(rep))
	}
}

func TestPullRequestChangesNoInput(t *testing.T) {
	base := prFiles(t)
	head := maps.Clone(base)
	head["README.md"] = githubtest.Blob("changed\n")
	g, _, _ := prRepo(t, base, head)
	rep, got := prRun(t, g, "--pull-request", "1")
	if got.code != 0 || rep.Reported == nil || len(rep.Reported) != 0 {
		t.Errorf("exit %d, reported %v; want 0 and []", got.code, rep.Reported)
	}
}

func TestPullRequestUnreadBit(t *testing.T) {
	base := prFiles(t)
	for name, change := range map[string]func(map[string]githubtest.File){
		"a UTF-16 workflow": func(m map[string]githubtest.File) {
			m[".github/workflows/u16.yml"] = githubtest.Blob("\xff\xfeo\x00n\x00:\x00")
		},
		"an action under --exclude": func(m map[string]githubtest.File) { m["x/action.yml"] = githubtest.Blob(injectAction) },
	} {
		head := maps.Clone(base)
		change(head)
		g, _, _ := prRepo(t, base, head)
		_, got := prRun(t, g, "--pull-request", "1", "--exclude", "x")
		if got.code&16 == 0 {
			t.Errorf("%s: exit %d, want bit 16 (%s)", name, got.code, got.stderr)
		}
	}
}

func TestPullRequestBaseChanged(t *testing.T) {
	g := githubtest.NewGit(t)
	files := prFiles(t)
	root := g.Commit("o/r", "", files)
	head := maps.Clone(files)
	head["README.md"] = githubtest.Blob("changed\n")
	h := g.Commit("o/r", "feature", head, root)
	moved := maps.Clone(files)
	moved[".github/workflows/target.yml"] = githubtest.Blob("on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
	g.Commit("o/r", "main", moved, root)
	g.Pull("o/r", 1, githubtest.PullRequest{Head: h, BaseRef: "main"})
	rep, got := prRun(t, g, "--pull-request", "1")
	if got.code&16 == 0 || rep.Remote.PullRequest.BaseChangeCount != 1 || rep.Remote.PullRequest.BehindBy != 1 {
		t.Errorf("exit %d, base_change_count %d, behind_by %d; want bit 16, 1 and 1", got.code, rep.Remote.PullRequest.BaseChangeCount, rep.Remote.PullRequest.BehindBy)
	}
}

func TestPullRequestReadNonInput(t *testing.T) {
	base := prFiles(t)
	base[".github/dependabot.yml"] = githubtest.Blob("version: 2\nupdates: []\n")
	base[".github/workflows/co.yml"] = githubtest.Blob("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n") // the run reads .github/dependabot.yml for it
	head := maps.Clone(base)
	head[".github/dependabot.yml"] = githubtest.Blob("version: 2\nupdates:\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n")
	g, _, _ := prRepo(t, base, head)
	rep, _ := prRun(t, g, "--pull-request", "1")
	if len(rep.Reported) != 5 {
		t.Errorf("a pull request that changes .github/dependabot.yml reports %v, want every input", rep.Reported)
	}
}

func TestPullRequestHead(t *testing.T) {
	base := prFiles(t)
	head := maps.Clone(base)
	head["README.md"] = githubtest.Blob("changed\n")
	g, b, h := prRepo(t, base, head)
	if _, got := prRun(t, g, "--pull-request", "1", "--pull-request-head", b); got.code != ExitTempFail || got.stdout != "" {
		t.Errorf("another head: exit %d, %d bytes on stdout; want %d and nothing", got.code, len(got.stdout), ExitTempFail)
	}
	if _, got := prRun(t, g, "--pull-request", "1", "--pull-request-head", h); got.code != 0 {
		t.Errorf("the head: exit %d (%s)", got.code, got.stderr)
	}
	if _, got := prRun(t, g, "--pull-request", "2"); got.code != ExitNoInput || got.stdout != "" {
		t.Errorf("no pull request: exit %d", got.code)
	}
	url := "http://" + g.URL().Host + "/o/r/pull/1/files"
	if got := run(t, args("--remote", url, "--github-api", g.URL().String())); got.code != 0 {
		t.Errorf("%s: exit %d (%s)", url, got.code, got.stderr)
	}
}

func TestPullRequestUsage(t *testing.T) {
	base := prFiles(t)
	head := maps.Clone(base)
	head["x/action.yml"] = githubtest.Blob(injectAction)
	g, _, _ := prRepo(t, base, head)
	api := g.URL().String()
	url := "http://" + g.URL().Host + "/o/r/pull/1"
	for _, a := range [][]string{
		{"--pull-request", "1"},
		{"--remote", "o/r", "--github-api", api, "--pull-request-head", strings.Repeat("a", 40)},
		{"--remote", "o/r@main", "--github-api", api, "--pull-request", "1"},
		{"--remote", url, "--github-api", api, "--pull-request", "1"},
		{"--remote", "o/r", "--github-api", api, "--pull-request", "1", "--read-all", "x/action.yml"},
		{"--remote", "o/r", "--github-api", api, "--pull-request", "x"},
		{"--remote", "o/r", "--github-api", api, "--pull-request", "1", "../x"},
		{"--remote", "o/r", "--github-api", api, "--pull-request", "1", ".github/workflows/other.yml"},
		{"--remote", "o/r", "--github-api", api, "--pull-request", "1", "--pull-request-head", "nope"},
	} {
		got := run(t, raw(a...))
		if got.code != ExitUsage || got.stdout != "" {
			t.Errorf("%v: exit %d, %d bytes on stdout; want %d and nothing (%s)", a, got.code, len(got.stdout), ExitUsage, got.stderr)
		}
	}
	_ = strconv.Itoa
}

// TestPullRequestDeletesAndRenames: a pull request that deletes or renames
// an input, or makes an action.yml a symlink to a directory, is read.
func TestPullRequestDeletesAndRenames(t *testing.T) {
	for name, change := range map[string]func(map[string]githubtest.File){
		"delete": func(m map[string]githubtest.File) { delete(m, ".github/workflows/other.yml") },
		"rename": func(m map[string]githubtest.File) {
			m[".github/workflows/renamed.yml"] = m[".github/workflows/other.yml"]
			delete(m, ".github/workflows/other.yml")
		},
		"a symlink to a directory": func(m map[string]githubtest.File) {
			m["y/real/x.txt"] = githubtest.Blob("x")
			m["y/action.yml"] = githubtest.Symlink("real")
		},
	} {
		base := prFiles(t)
		head := maps.Clone(base)
		change(head)
		g, _, _ := prRepo(t, base, head)
		if _, got := prRun(t, g, "--pull-request", "1"); got.code >= ExitUsage {
			t.Errorf("%s: exit %d (%s)", name, got.code, got.stderr)
		}
	}
}

// TestPullRequestSpentBudget: a pull request that spends the requests of
// the run on files it adds cannot hide a changed input: the inputs not
// read are changed inputs, and bit 16
// is set.
func TestPullRequestSpentBudget(t *testing.T) {
	old := remoteLimits
	remoteLimits.MaxRequests = 8
	t.Cleanup(func() { remoteLimits = old })
	// unchanged actions read first, in the order of their paths, spend the requests
	pad := func(m map[string]githubtest.File) {
		for i := range 10 {
			m[".github/actions/b"+strconv.Itoa(100+i)+"/action.yml"] = githubtest.Blob("runs:\n  using: composite\n  steps:\n    - run: echo " + strconv.Itoa(i) + "\n      shell: bash\n")
		}
	}
	for name, c := range map[string]struct {
		base, head func(map[string]githubtest.File)
	}{
		"the target of a symlink": {
			func(m map[string]githubtest.File) {
				pad(m)
				m["x/action.yml"] = githubtest.Symlink("../shared/real.yml")
				m["shared/real.yml"] = githubtest.Blob("runs:\n  using: composite\n  steps:\n    - run: echo hi\n      shell: bash\n")
			},
			func(m map[string]githubtest.File) { m["shared/real.yml"] = githubtest.Blob(injectAction) },
		},
		"a caller not read": {
			func(m map[string]githubtest.File) { pad(m) },
			func(m map[string]githubtest.File) { m["x/action.yml"] = githubtest.Blob(injectAction) },
		},
	} {
		base := prFiles(t)
		c.base(base)
		head := maps.Clone(base)
		c.head(head)
		g, _, _ := prRepo(t, base, head)
		_, got := prRun(t, g, "--pull-request", "1", "--rule", "code-injection")
		if got.code&(int(lint.ConfirmedBit)|int(lint.UnreadBit)) == 0 {
			t.Errorf("%s: exit %d, want bit 1 or 16 (%s)", name, got.code, got.stderr)
		}
	}
}

// TestPullRequestActionYAMLBesideFile: a changed action.yaml beside a file
// action.yml is not an input, and the run does not read it.
func TestPullRequestActionYAMLBesideFile(t *testing.T) {
	base := prFiles(t)
	base["x/action.yaml"] = githubtest.Blob("runs:\n  using: composite\n  steps: []\n")
	head := maps.Clone(base)
	head["x/action.yaml"] = githubtest.Blob(injectAction)
	g, _, _ := prRepo(t, base, head)
	rep, _ := prRun(t, g, "--pull-request", "1")
	if len(rep.Reported) != 0 {
		t.Errorf("reported %v, want none", rep.Reported)
	}
}

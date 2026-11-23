package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/rules"
)

// fakeRunner answers a command by the longest key its words start with,
// fails it by a key in fail, and records the commands. "git worktree add"
// writes the approved documents origin/main has (approved, by their paths
// from the root); "git rm" removes a file; "git commit" records the
// approved documents then (committed).
type fakeRunner struct {
	approved  map[string]string
	out       map[string]string
	fail      map[string]bool
	calls     []string
	committed map[string]string // path from the root → text, at the commit
	wt        string
}

func newFake() *fakeRunner {
	return &fakeRunner{approved: map[string]string{}, out: map[string]string{
		"git rev-parse HEAD":        "abc\n",
		"git rev-parse origin/main": "abc\n",
		"gh pr list":                "[]",
		"gh pr create":              "https://github.com/o/r/pull/9\n",
	}, fail: map[string]bool{}}
}

func (f *fakeRunner) run(dir, name string, args ...string) (string, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, c)
	for k := range f.fail {
		if strings.HasPrefix(c, k) {
			return "", errors.New("fails: " + c)
		}
	}
	switch {
	case strings.HasPrefix(c, "git worktree add"):
		f.wt = args[3]
		for p, text := range f.approved {
			full := filepath.Join(f.wt, filepath.FromSlash(p))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return "", err
			}
			if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
				return "", err
			}
		}
	case strings.HasPrefix(c, "git rm"):
		if err := os.Remove(filepath.Join(f.wt, filepath.FromSlash(args[len(args)-1]))); err != nil {
			return "", err
		}
	case strings.HasPrefix(c, "git commit"):
		f.committed = map[string]string{}
		root := filepath.Join(f.wt, "actions/rules/approved")
		filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err == nil && !e.IsDir() {
				b, _ := os.ReadFile(p)
				rel, _ := filepath.Rel(f.wt, p)
				f.committed[filepath.ToSlash(rel)] = string(b)
			}
			return nil
		})
	}
	key := ""
	for k := range f.out {
		if strings.HasPrefix(c, k) && len(k) > len(key) {
			key = k
		}
	}
	return f.out[key], nil
}

func (f *fakeRunner) ran(prefix string) []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

const approvedDir = "actions/rules/approved/"

func TestOpensOneBatch(t *testing.T) {
	f := newFake()
	var log strings.Builder
	if err := runReview(f, options{batch: 10, maxOpen: 1}, []rules.RuleReview{changed("a", true, 12), changed("b", true, 1)}, nil, &log); err != nil {
		t.Fatal(err)
	}
	if n := len(f.ran("gh pr create")); n != 1 {
		t.Fatalf("%d PRs opened, want 1: %q", n, f.calls)
	}
	if len(f.committed) != 11 || f.committed[approvedDir+"a/meta.md"] != "# a meta.md\n" || f.committed[approvedDir+"a/false-positive/10.md"] == "" {
		t.Errorf("committed %v", f.committed)
	}
	if len(f.ran("git push origin HEAD:refs/heads/review/a/1")) != 1 {
		t.Errorf("no push of review/a/1: %q", f.calls)
	}
	if len(f.ran("git commit -m docs: a の approved document を書き換える（11 file）")) != 1 {
		t.Errorf("commit message: %q", f.ran("git commit"))
	}
	if len(f.ran("gh pr create --base main --head review/a/1 --title [bot] review batch: a (11 files)")) != 1 {
		t.Errorf("PR: %q", f.ran("gh pr create"))
	}
	if len(f.ran("git worktree remove")) != 1 {
		t.Error("the worktree stays")
	}
	if !strings.Contains(log.String(), "https://github.com/o/r/pull/9") {
		t.Errorf("log %q", log.String())
	}
}

func TestDeletesStale(t *testing.T) {
	f := newFake()
	f.approved[approvedDir+"a/meta.md"] = "# a meta.md\n"
	f.approved[approvedDir+"a/undetected/old.md"] = "old\n"
	f.approved[approvedDir+"a/true-positive/gone.md"] = "gone\n"
	if err := runReview(f, options{batch: 1, maxOpen: 1}, []rules.RuleReview{changed("a", false, 2, "undetected/old.md", "true-positive/gone.md")}, nil, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if len(f.ran("git rm -q -- "+approvedDir+"a/undetected/old.md")) != 1 || len(f.ran("git rm -q -- "+approvedDir+"a/true-positive/gone.md")) != 1 {
		t.Errorf("rm: %q", f.ran("git rm"))
	}
	if _, ok := f.committed[approvedDir+"a/undetected/old.md"]; ok || len(f.committed) != 2 {
		t.Errorf("committed %v (meta.md and one example, the stale ones gone)", f.committed)
	}
	if len(f.ran("gh pr create --base main --head review/a/1 --title [bot] review batch: a (3 files)")) != 1 {
		t.Errorf("PR: %q", f.ran("gh pr create"))
	}
}

func TestSkipsReviewedAndOpen(t *testing.T) {
	f := newFake()
	f.out["gh pr list"] = `[{"number":1,"headRefName":"review/b/1","files":[{"path":"` + approvedDir + `b/meta.md"}]}]`
	if err := runReview(f, options{batch: 10, maxOpen: 2}, []rules.RuleReview{changed("a", false, 0), changed("b", true, 1), changed("c", true, 0)}, nil, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if c := f.ran("gh pr create"); len(c) != 1 || !strings.Contains(c[0], "--head review/c/1") {
		t.Errorf("opened %q, want c only (a is reviewed, b is open)", c)
	}
}

func TestMaxOpen(t *testing.T) {
	f := newFake()
	f.out["gh pr list"] = `[{"number":1,"headRefName":"review/x/1","files":[{"path":"` + approvedDir + `x/meta.md"}]}]`
	var log strings.Builder
	if err := runReview(f, options{batch: 10, maxOpen: 1}, []rules.RuleReview{changed("a", true, 1), changed("x", true, 0)}, nil, &log); err != nil {
		t.Fatal(err)
	}
	if c := f.ran("gh pr create"); len(c) != 0 || !strings.Contains(log.String(), "nothing to open") {
		t.Errorf("opened %q, log %q", c, log.String())
	}
}

func TestClosesUnknownRule(t *testing.T) {
	list := `[{"number":5,"headRefName":"review/gone/1","files":[{"path":"` + approvedDir + `gone/meta.md"}]}]`
	f := newFake()
	f.out["gh pr list"] = list
	var log strings.Builder
	if err := runReview(f, options{batch: 10, maxOpen: 1, dryRun: true}, []rules.RuleReview{changed("a", true, 0)}, []lint.RuleID{lint.MustRuleID("gone")}, &log); err != nil {
		t.Fatal(err)
	}
	if len(f.ran("gh pr close")) != 0 || !strings.Contains(log.String(), "would close #5") || !strings.Contains(log.String(), "unknown gone") {
		t.Errorf("dry run: %q %q", f.ran("gh pr close"), log.String())
	}
	f = newFake()
	f.out["gh pr list"] = list
	if err := runReview(f, options{batch: 10, maxOpen: 1}, []rules.RuleReview{changed("a", true, 0)}, []lint.RuleID{lint.MustRuleID("gone")}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if c := f.ran("gh pr close 5 --delete-branch --comment"); len(c) != 1 {
		t.Errorf("closed %q", f.ran("gh pr close"))
	}
	if c := f.ran("gh pr create"); len(c) != 1 || !strings.Contains(c[0], "--head review/a/1") {
		t.Errorf("the closed PR still counts: %q", c)
	}
}

func TestDryRunWritesNothing(t *testing.T) {
	f := newFake()
	var log strings.Builder
	rv := changed("a", true, 2, "undetected/old.md")
	if err := runReview(f, options{batch: 10, maxOpen: 2, dryRun: true}, []rules.RuleReview{rv, changed("b", true, 0)}, nil, &log); err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"git worktree", "git commit", "git push", "git rm", "gh pr create", "gh pr close"} {
		if c := f.ran(w); len(c) != 0 {
			t.Errorf("--dry-run ran %q", c)
		}
	}
	write, remove := batchOf(rv, 10)
	for _, want := range []string{
		"would open review/a/1: meta.md, false-positive/01.md, false-positive/02.md; remove undetected/old.md\n",
		"would open review/b/1: meta.md\n",
		"----- title -----\n[bot] review batch: a (4 files)\n----- body -----\n" + body(rv.Rule, write, remove, len(write)+len(remove)) + "----- end -----\n",
		"----- title -----\n[bot] review batch: b (1 file)\n",
	} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("no\n%s\nin the log\n%s", want, log.String())
		}
	}
}

func TestRefusesOffMain(t *testing.T) {
	rs := []rules.RuleReview{changed("a", true, 0)}
	f := newFake()
	f.out["git rev-parse origin/main"] = "def\n"
	if err := runReview(f, options{batch: 10, maxOpen: 1}, rs, nil, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "run it on origin/main (def)") {
		t.Errorf("off main: %v", err)
	}
	f = newFake()
	f.out["git rev-parse origin/main"] = "def\n"
	var log strings.Builder
	if err := runReview(f, options{batch: 10, maxOpen: 1, dryRun: true}, rs, nil, &log); err != nil || !strings.Contains(log.String(), "not origin/main's") || !strings.Contains(log.String(), "would open") {
		t.Errorf("a dry run off main: %v %q", err, log.String())
	}
	for _, p := range []string{"actions/rules/examples/x.yml", approvedDir + "a/meta.md"} {
		f = newFake()
		f.out["git status --porcelain"] = " M " + p + "\n"
		if err := runReview(f, options{batch: 10, maxOpen: 1}, rs, nil, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "changes not on it") {
			t.Errorf("changed %s: %v", p, err)
		}
	}
	if c := f.ran("git status --porcelain --untracked-files=no"); len(c) == 0 {
		t.Errorf("status: %q", f.ran("git status"))
	}
}

func TestFailures(t *testing.T) {
	rs := []rules.RuleReview{changed("a", true, 0)}
	f := newFake()
	f.fail["git push origin HEAD:"] = true
	if err := runReview(f, options{batch: 10, maxOpen: 1}, rs, nil, &strings.Builder{}); err == nil || len(f.ran("gh pr create")) != 0 {
		t.Errorf("a failed push: %v %q", err, f.ran("gh pr create"))
	}
	if len(f.ran("git worktree remove")) != 1 {
		t.Error("the worktree stays after a failure")
	}
	f = newFake()
	f.fail["gh pr create"] = true
	if err := runReview(f, options{batch: 10, maxOpen: 1}, rs, nil, &strings.Builder{}); err == nil || len(f.ran("git push origin --delete review/a/1")) != 1 {
		t.Errorf("a failed PR leaves its branch: %v %q", err, f.calls)
	}
}

func TestBranchNameTaken(t *testing.T) {
	f := newFake()
	f.out["git ls-remote --heads origin refs/heads/review/a/1"] = "abc\trefs/heads/review/a/1\n"
	f.out["git ls-remote --heads origin refs/heads/review/a/2"] = ""
	got, err := branchName(f, lint.MustRuleID("a"))
	if err != nil || got != "review/a/2" {
		t.Errorf("%q %v", got, err)
	}
}

func TestBody(t *testing.T) {
	rv := changed("a", true, 2, "undetected/old.md")
	write, remove := batchOf(rv, 0)
	s := body(lint.MustRuleID("a"), write, remove, len(write)+len(remove))
	for _, want := range []string{"review batch", "Files changed", "Viewed", "squash", "PR 番号", "comment", "Delete file", "main で直",
		"go run ./cmd/sisakulint --examples=a --serve", "`meta.md`", "`false-positive/01.md`", "`undetected/old.md`"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in\n%s", want, s)
		}
	}
	for _, no := range []string{write[0].Text, "のうち", "認めたことになります", "記録に残ります"} {
		if strings.Contains(s, no) {
			t.Errorf("the body has %q:\n%s", no, s)
		}
	}
	// a part of the rule says how much is left
	write, remove = batchOf(rv, 1)
	if s := body(lint.MustRuleID("a"), write, remove, 4); !strings.Contains(s, "4 file のうち 3 file") {
		t.Errorf("no place in the rule:\n%s", s)
	}
}

// TestWholeRuleByDefault: --batch 0, the default, puts every changed
// document of the rule in one review batch.
func TestWholeRuleByDefault(t *testing.T) {
	f := newFake()
	if err := runReview(f, options{maxOpen: 1}, []rules.RuleReview{changed("a", true, 43)}, nil, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if len(f.committed) != 44 || len(f.ran("gh pr create --base main --head review/a/1 --title [bot] review batch: a (44 files)")) != 1 {
		t.Errorf("committed %d, PR %q", len(f.committed), f.ran("gh pr create"))
	}
}

// TestCountsEveryOpenPR: two open review/ PRs of no approved document take
// two places of --max-open.
func TestCountsEveryOpenPR(t *testing.T) {
	f := newFake()
	f.out["gh pr list"] = `[{"number":1,"headRefName":"review/x","files":[]},{"number":2,"headRefName":"review/y","files":[]}]`
	if err := runReview(f, options{batch: 10, maxOpen: 2}, []rules.RuleReview{changed("a", true, 0)}, nil, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if c := f.ran("gh pr create"); len(c) != 0 {
		t.Errorf("opened %q with two open of --max-open 2", c)
	}
}

// TestClosesRuleNotInRegistry: an open review batch of a rule that is not
// among the rules is closed even when main has no directory of it (the
// rule's first review batch).
func TestClosesRuleNotInRegistry(t *testing.T) {
	f := newFake()
	f.out["gh pr list"] = `[{"number":7,"headRefName":"review/gone/1","files":[{"path":"` + approvedDir + `gone/meta.md"}]}]`
	if err := runReview(f, options{batch: 10, maxOpen: 1}, []rules.RuleReview{changed("a", true, 0)}, nil, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if c := f.ran("gh pr close 7 --delete-branch --comment"); len(c) != 1 {
		t.Errorf("closed %q", f.ran("gh pr close"))
	}
	if c := f.ran("gh pr create"); len(c) != 1 || !strings.Contains(c[0], "--head review/a/1") {
		t.Errorf("opened %q", c)
	}
}

// TestRefusesChangedCode: a change to the code the review documents are
// made of, not committed, stops it as a change to the examples does.
func TestRefusesChangedCode(t *testing.T) {
	f := newFake()
	f.out["git status --porcelain --untracked-files=no"] = " M actions/rules/commitsha.go\n"
	if err := runReview(f, options{batch: 10, maxOpen: 1}, []rules.RuleReview{changed("a", true, 0)}, nil, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "changes not on it") {
		t.Errorf("changed code: %v", err)
	}
	f = newFake()
	f.out["git status --porcelain -- actions cmd internal yaml go.mod go.sum"] = "?? actions/rules/new.go\n"
	if err := runReview(f, options{batch: 10, maxOpen: 1}, []rules.RuleReview{changed("a", true, 0)}, nil, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "changes not on it") {
		t.Errorf("a new file in the code tree: %v", err)
	}
}

// TestOpensNamedRulesOnly: with rules named, only their review batches
// open, and the open review batch of a rule not named stays open.
func TestOpensNamedRulesOnly(t *testing.T) {
	f := newFake()
	f.out["gh pr list"] = `[{"number":3,"headRefName":"review/a/1","files":[{"path":"` + approvedDir + `a/meta.md"}]}]`
	rs := []rules.RuleReview{changed("a", true, 0), changed("b", true, 0), changed("c", true, 0), changed("d", true, 0)}
	o := options{maxOpen: 3, rules: []lint.RuleID{lint.MustRuleID("d"), lint.MustRuleID("b")}}
	if err := runReview(f, o, rs, nil, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	c := f.ran("gh pr create")
	if len(c) != 2 || !strings.Contains(c[0], "--head review/b/1") || !strings.Contains(c[1], "--head review/d/1") {
		t.Errorf("opened %q, want b and d", c)
	}
	if len(f.ran("gh pr close")) != 0 {
		t.Errorf("closed %q", f.ran("gh pr close"))
	}
}

func TestParseRules(t *testing.T) {
	known := []rules.RuleReview{changed("a", true, 0), changed("b", true, 0)}
	if got, err := parseRules("b, a", known); err != nil || len(got) != 2 || got[0] != lint.MustRuleID("b") {
		t.Errorf("parseRules = %v, %v", got, err)
	}
	for _, bad := range []string{"a,zz", "a,,b", "Not_A_Rule"} {
		if _, err := parseRules(bad, known); err == nil {
			t.Errorf("parseRules(%q) is no error", bad)
		}
	}
	if got, err := parseRules("", known); err != nil || got != nil {
		t.Errorf("parseRules(\"\") = %v, %v", got, err)
	}
}

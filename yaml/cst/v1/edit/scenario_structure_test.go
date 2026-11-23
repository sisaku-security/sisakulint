package edit

import (
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// must is the edit an operation made, or the test stops.
func must(t *testing.T) func(Edit, error) Edit {
	return func(ed Edit, err error) Edit {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return ed
	}
}

// The structural autofixes of sisakulint (b8f20dc, pkg/core), each made
// on a small workflow and compared with the whole result.
func TestScenarioStructure(t *testing.T) {
	sha := strings.Repeat("0123456789", 4)
	title := "${{ github.event.issue.title }}"
	cases := []struct {
		name, src string
		edits     func(t *testing.T, tr *cst.Tree) []Edit
		want      string
	}{
		{"code-injection, a new env",
			"steps:\n  - name: greet\n    run: |\n      echo \"" + title + "\"\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				step, _ := walk(t, tr, "steps", 0)
				return []Edit{
					must(t)(new(Editor).Insert(step, Last(), Map{{Key: "env", Value: Map{{Key: "ISSUE_TITLE", Value: Str(title)}}}})),
					replaceIn(t, tr, "echo \""+title+"\"\n", title, "$ISSUE_TITLE"),
				}
			},
			"steps:\n  - name: greet\n    run: |\n      echo \"$ISSUE_TITLE\"\n    env:\n      ISSUE_TITLE: " + title + "\n"},
		{"code-injection, the env there",
			"steps:\n  - run: echo \"" + title + "\"\n    env:\n      A: 1\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				env, _ := walk(t, tr, "steps", 0, "env")
				return []Edit{
					must(t)(new(Editor).Insert(env, Last(), Map{{Key: "ISSUE_TITLE", Value: Str(title)}})),
					replaceIn(t, tr, "echo \""+title+"\"", title, "$ISSUE_TITLE"),
				}
			},
			"steps:\n  - run: echo \"$ISSUE_TITLE\"\n    env:\n      A: 1\n      ISSUE_TITLE: " + title + "\n"},
		{"artipacked, with there",
			"steps:\n  - uses: actions/checkout@v4\n    with:\n      fetch-depth: 0\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				with, _ := walk(t, tr, "steps", 0, "with")
				return []Edit{must(t)(new(Editor).Insert(with, First(), Map{{Key: "persist-credentials", Value: Bool(false)}}))}
			},
			"steps:\n  - uses: actions/checkout@v4\n    with:\n      persist-credentials: false\n      fetch-depth: 0\n"},
		{"artipacked, no with",
			"steps:\n  - uses: actions/checkout@v4\n    name: checkout\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				step, _ := walk(t, tr, "steps", 0)
				return []Edit{must(t)(new(Editor).Insert(step, After("uses"), Map{{Key: "with", Value: Map{{Key: "persist-credentials", Value: Bool(false)}}}}))}
			},
			"steps:\n  - uses: actions/checkout@v4\n    with:\n      persist-credentials: false\n    name: checkout\n"},
		{"timeout-minutes",
			"steps:\n  - name: build\n    run: make\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				step, _ := walk(t, tr, "steps", 0)
				return []Edit{must(t)(new(Editor).Insert(step, Before("run"), Map{{Key: "timeout-minutes", Value: Int(5)}}))}
			},
			"steps:\n  - name: build\n    timeout-minutes: 5\n    run: make\n"},
		{"permissions",
			"on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				return []Edit{must(t)(new(Editor).Insert(docContent(tr), After("on"), Map{{Key: "permissions", Value: Map{},
					Comment: "TODO: Review and add required permissions."}}))}
			},
			"on: push\n# TODO: Review and add required permissions.\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n"},
		{"credentials",
			"container:\n  image: x\n  credentials:\n    username: u\n    password: ${{ secrets.P }}\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				_, password := walk(t, tr, "container", "credentials", "password")
				return []Edit{must(t)(new(Editor).Delete(password))}
			},
			"container:\n  image: x\n  credentials:\n    username: u\n"},
		{"cache-poisoning, with.ref and more",
			"steps:\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.head_ref }}\n      path: x\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				_, ref := walk(t, tr, "steps", 0, "with", "ref")
				return []Edit{must(t)(new(Editor).Delete(ref))}
			},
			"steps:\n  - uses: actions/checkout@v4\n    with:\n      path: x\n"},
		{"cache-poisoning, with.ref alone",
			"steps:\n  - uses: actions/checkout@v4\n    with:\n      ref: ${{ github.head_ref }}\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				_, ref := walk(t, tr, "steps", 0, "with", "ref")
				if _, err := new(Editor).Delete(ref); err == nil {
					t.Error("Delete of the only entry of with, want an error")
				}
				_, with := walk(t, tr, "steps", 0, "with")
				return []Edit{must(t)(new(Editor).Delete(with))}
			},
			"steps:\n  - uses: actions/checkout@v4\n"},
		{"commit-sha",
			"steps:\n  - uses: actions/checkout@v4\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				uses, _ := walk(t, tr, "steps", 0, "uses")
				return []Edit{replaceIn(t, tr, "actions/checkout@v4", "v4", sha), must(t)(new(Editor).LineComment(uses, "v4"))}
			},
			"steps:\n  - uses: actions/checkout@" + sha + " # v4\n"},
		{"known-vulnerable-actions",
			"steps:\n  - uses: actions/checkout@abc  # v3\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				uses, _ := walk(t, tr, "steps", 0, "uses")
				return []Edit{replaceIn(t, tr, "actions/checkout@abc", "abc", "v4.2.0"), must(t)(new(Editor).LineComment(uses, ""))}
			},
			"steps:\n  - uses: actions/checkout@v4.2.0\n"},
		{"secrets-inherit",
			"jobs:\n  call:\n    uses: ./.github/workflows/w.yml\n    secrets: inherit\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				secrets, _ := walk(t, tr, "jobs", "call", "secrets")
				return []Edit{must(t)(new(Editor).SetValue(secrets, Map{{Key: "TOKEN", Value: Str("${{ secrets.TOKEN }}")}}))}
			},
			"jobs:\n  call:\n    uses: ./.github/workflows/w.yml\n    secrets:\n      TOKEN: ${{ secrets.TOKEN }}\n"},
		{"dependabot",
			"version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n",
			func(t *testing.T, tr *cst.Tree) []Edit {
				updates, _ := walk(t, tr, "updates")
				return []Edit{must(t)(new(Editor).InsertItem(updates, 1, Map{
					{Key: "package-ecosystem", Value: Str("github-actions")},
					{Key: "directory", Value: Str("/")},
					{Key: "schedule", Value: Map{{Key: "interval", Value: Str("weekly")}}},
				}))}
			},
			"version: 2\nupdates:\n  - package-ecosystem: npm\n    directory: /\n  - package-ecosystem: github-actions\n    directory: /\n    schedule:\n      interval: weekly\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := cst.Parse([]byte(c.src))
			res := mustApply(t, tr, c.edits(t, tr)...)
			if got := string(res.Tree.Bytes()); got != c.want {
				t.Errorf("got\n%s\nwant\n%s", got, c.want)
			}
		})
	}
}

// output-clobbering after code-injection: the second fix finds the run
// script the first one rewrote through Follow.
func TestScenarioChain(t *testing.T) {
	title := "${{ github.event.issue.title }}"
	src := "steps:\n  - run: |\n      echo \"title=" + title + "\" >> \"$GITHUB_OUTPUT\"\n"
	tr := cst.Parse([]byte(src))
	run, _ := walk(t, tr, "steps", 0, "run")
	step, _ := walk(t, tr, "steps", 0)
	res := mustApply(t, tr,
		must(t)(new(Editor).Insert(step, Last(), Map{{Key: "env", Value: Map{{Key: "TITLE", Value: Str(title)}}}})),
		replaceIn(t, tr, "echo \"title="+title+"\" >> \"$GITHUB_OUTPUT\"\n", title, "$TITLE"),
	)
	runNew, ok := res.Follow(run)
	if !ok {
		t.Fatal("the run script does not follow")
	}
	v, _ := scalar.Decode(runNew)
	heredoc := "{\n  echo \"title<<EOF_SISAKULINT\"\n  echo \"$TITLE\"\n  echo \"EOF_SISAKULINT\"\n} >> \"$GITHUB_OUTPUT\""
	ed, err := Replace(v, 0, len(v.String())-1, heredoc)
	if err != nil {
		t.Fatal(err)
	}
	res2 := mustApply(t, res.Tree, ed)
	want := "steps:\n  - run: |\n      {\n        echo \"title<<EOF_SISAKULINT\"\n        echo \"$TITLE\"\n        echo \"EOF_SISAKULINT\"\n      } >> \"$GITHUB_OUTPUT\"\n    env:\n      TITLE: " + title + "\n"
	if got := string(res2.Tree.Bytes()); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// improper-access-control: labeled goes in, then synchronize comes out,
// found in the new tree through Follow.
func TestScenarioTypes(t *testing.T) {
	tr := cst.Parse([]byte("on:\n  pull_request_target:\n    types: [opened, synchronize]\n"))
	types, _ := walk(t, tr, "on", "pull_request_target", "types")
	sync, _ := walk(t, tr, "on", "pull_request_target", "types", 1)
	res := mustApply(t, tr, must(t)(new(Editor).InsertItem(types, 2, Str("labeled"))))
	syncNew, ok := res.Follow(sync)
	if !ok {
		t.Fatal("synchronize does not follow")
	}
	res2 := mustApply(t, res.Tree, must(t)(new(Editor).Delete(syncNew)))
	if got := string(res2.Tree.Bytes()); got != "on:\n  pull_request_target:\n    types: [opened, labeled]\n" {
		t.Errorf("%q", got)
	}
}

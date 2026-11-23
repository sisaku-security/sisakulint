package edit

import (
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

const workflow = `on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          echo start
          echo "${{ github.event.issue.title }}"
          echo "${{ github.event.issue.body }}"
          echo end
      - name: "a multi
          line title"
        run: >
          folded one
          folded two
`

// replaceIn is the edit that replaces the first sub in the value old.
func replaceIn(t *testing.T, tr *cst.Tree, old, sub, text string) Edit {
	t.Helper()
	v := valueOf(t, tr, old)
	s := strings.Index(v.String(), sub)
	ed, err := Replace(v, s, s+len(sub), text)
	if err != nil {
		t.Fatalf("Replace %q in %q: %v", sub, old, err)
	}
	return ed
}

func TestScenario(t *testing.T) {
	tr := cst.Parse([]byte(workflow))
	run := "echo start\necho \"${{ github.event.issue.title }}\"\necho \"${{ github.event.issue.body }}\"\necho end\n"
	sha := strings.Repeat("0123456789", 4)
	res := mustApply(t, tr,
		replaceIn(t, tr, "actions/checkout@v4", "v4", sha),
		replaceIn(t, tr, run, "${{ github.event.issue.title }}", "$ISSUE_TITLE"),
		replaceIn(t, tr, run, "${{ github.event.issue.body }}", "$ISSUE_BODY"),
		replaceIn(t, tr, "a multi line title", "line", "LINE"),
		replaceIn(t, tr, "folded one folded two\n", "two", "2"),
	)
	want := strings.NewReplacer(
		"@v4", "@"+sha,
		"${{ github.event.issue.title }}", "$ISSUE_TITLE",
		"${{ github.event.issue.body }}", "$ISSUE_BODY",
		"line title", "LINE title",
		"folded two", "folded 2",
	).Replace(workflow)
	if got := string(res.Tree.Bytes()); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}

	// deleting a line of the script, and quoting a value, in a second Apply
	tr2 := res.Tree
	run2 := "echo start\necho \"$ISSUE_TITLE\"\necho \"$ISSUE_BODY\"\necho end\n"
	v := valueOf(t, tr2, run2)
	s := strings.Index(run2, "echo end\n")
	del, err := Replace(v, s-len("echo \"$ISSUE_BODY\"\n"), s, "")
	if err != nil {
		t.Fatal(err)
	}
	q, err := Rewrite(valueOf(t, tr2, "ubuntu-latest"), cst.DoubleQuoted, "ubuntu-latest")
	if err != nil {
		t.Fatal(err)
	}
	res2 := mustApply(t, tr2, del, q)
	got := string(res2.Tree.Bytes())
	if strings.Contains(got, "ISSUE_BODY") || !strings.Contains(got, "          echo end\n") || !strings.Contains(got, `runs-on: "ubuntu-latest"`) {
		t.Errorf("second Apply gives\n%s", got)
	}
}

// Replacing text by itself changes no byte, whatever the style's layout.
func TestReplaceSame(t *testing.T) {
	for _, src := range []string{"a: \"x\n  y\"\n", "a: >\n  x\n  y\n", "a: |\n  x\n  \n  y\n"} {
		tr := cst.Parse([]byte(src))
		for n := range allScalars(tr) {
			v, _ := decode(n)
			ed, err := Replace(v, 0, len(v.String()), v.String())
			if err != nil {
				t.Errorf("%q: %v", src, err)
				continue
			}
			if res := mustApply(t, tr, ed); string(res.Tree.Bytes()) != src {
				t.Errorf("%q became %q", src, res.Tree.Bytes())
			}
		}
	}
}

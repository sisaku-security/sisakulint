package edit

import (
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

func TestLineComment(t *testing.T) {
	cases := []struct {
		name, src string
		path      []any
		text      string
		want      string
	}{
		{"add", "steps:\n  - uses: actions/checkout@v4\n", []any{"steps", 0, "uses"}, "v4.1.1",
			"steps:\n  - uses: actions/checkout@v4 # v4.1.1\n"},
		{"add as the document does", "a: 1  # x\nb: 2\n", []any{"b"}, "y", "a: 1  # x\nb: 2  # y\n"},
		{"change", "uses: a@abc  # v3\n", []any{"uses"}, "v4", "uses: a@abc  # v4\n"},
		{"remove", "uses: a@abc  # v3\nb: 1\n", []any{"uses"}, "", "uses: a@abc\nb: 1\n"},
		{"an item", "- a\n- b\n", []any{0}, "c", "- a # c\n- b\n"},
		{"quoted", "k: \"v\"\n", []any{"k"}, "c", "k: \"v\" # c\n"},
		{"no final line break", "k: v", []any{"k"}, "c", "k: v # c"},
		{"a mapping's last line", "a:\n  b: 1\nc: 2\n", []any{"a"}, "c", "a:\n  b: 1 # c\nc: 2\n"},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		n, _ := walk(t, tr, c.path...)
		ed, err := new(Editor).LineComment(n, c.text)
		if err != nil {
			t.Errorf("%s: LineComment: %v", c.name, err)
			continue
		}
		res, ok := applied(t, tr, ed)
		if !ok {
			continue
		}
		if got := string(res.Tree.Bytes()); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if len(res.Diff) > 0 {
			t.Errorf("%s: Diff = %v, want none", c.name, changes(res.Diff))
		}
	}
}

// commit-sha: the SHA and the comment naming the tag, in one Apply.
func TestLineCommentWithReplace(t *testing.T) {
	src := "uses: actions/checkout@v4\n"
	tr := cst.Parse([]byte(src))
	v := valueOf(t, tr, "actions/checkout@v4")
	rep, err := Replace(v, len("actions/checkout@"), len(v.String()), "0123abcd")
	if err != nil {
		t.Fatal(err)
	}
	com, err := new(Editor).LineComment(v.Node(), "v4")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Apply(tr, []Edit{rep, com})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res.Tree.Bytes()); got != "uses: actions/checkout@0123abcd # v4\n" {
		t.Errorf("%q", got)
	}
}

func TestLineCommentRefused(t *testing.T) {
	cases := []struct {
		name, src string
		path      []any
		text      string
	}{
		{"a line break", "k: v\n", []any{"k"}, "a\nb"},
		{"a carriage return", "k: v\n", []any{"k"}, "a\rb"},
		{"not the end of its line", "k: [a, b]\n", []any{"k", 0}, "c"},
		{"a block scalar", "run: |\n  x\n", []any{"run"}, "c"},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		n, _ := walk(t, tr, c.path...)
		if ed, err := new(Editor).LineComment(n, c.text); err == nil {
			t.Errorf("%s: LineComment = %q, want an error", c.name, ed.New)
		}
	}
}

// A LineComment whose bytes were changed after it was made is refused:
// without the '#', the text is the plain scalar's.
func TestLineCommentPromise(t *testing.T) {
	tr := cst.Parse([]byte("uses: a@abc\n"))
	n, _ := walk(t, tr, "uses")
	ed, err := new(Editor).LineComment(n, "v4")
	if err != nil {
		t.Fatal(err)
	}
	ed.New = []byte("  v4")
	if res, err := Apply(tr, []Edit{ed}); err == nil {
		t.Errorf("Apply = %q, want an error", res.Tree.Bytes())
	}
}

// White space at the end of the line.
func TestLineCommentAfterTrailingSpace(t *testing.T) {
	tr := cst.Parse([]byte("steps:\n  - uses: actions/checkout@v4 \n"))
	uses, _ := walk(t, tr, "steps", 0, "uses")
	res := mustApply(t, tr, must(t)(new(Editor).LineComment(uses, "v4")))
	if got := string(res.Tree.Bytes()); got != "steps:\n  - uses: actions/checkout@v4 # v4\n" {
		t.Errorf("%q", got)
	}
}

// Found when the corpus test got LineComment (suite 2XXW): an empty value
// has no line of its own.
func TestLineCommentOnEmpty(t *testing.T) {
	tr := cst.Parse([]byte("? a\n? b\n"))
	a := entriesOf(docContent(tr))[1].Value
	if ed, err := new(Editor).LineComment(a, "c"); err == nil {
		t.Errorf("LineComment on an empty value = %q, want an error", ed.New)
	}
}

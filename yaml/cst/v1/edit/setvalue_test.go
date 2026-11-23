package edit

import (
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func TestSetValue(t *testing.T) {
	ab := Map{{Key: "a", Value: Int(1)}, {Key: "b", Value: Int(2)}}
	cases := []struct {
		name, src string
		path      []any
		v         Value
		want      string
	}{
		{"scalar to mapping, comment kept", "key: x  # c\nz: 1\n", []any{"key"}, ab, "key:  # c\n  a: 1\n  b: 2\nz: 1\n"},
		{"an item to a mapping", "- x\n", []any{0}, ab, "- a: 1\n  b: 2\n"},
		{"in flow", "f: {key: x}\n", []any{"f", "key"}, ab, "f: {key: {a: 1, b: 2}}\n"},
		{"to an empty mapping", "permissions: write-all\n", []any{"permissions"}, Map{}, "permissions: {}\n"},
		{"mapping to scalar", "a:\n  x: 1\n  y: 2\nb: 3\n", []any{"a"}, Str("v"), "a: v\nb: 3\n"},
		{"an empty value", "- uses: x\n  with:\n", []any{0, "with"}, Map{{Key: "k", Value: Bool(false)}},
			"- uses: x\n  with:\n    k: false\n"},
		{"to a literal", "run: echo a\n", []any{"run"}, Str("echo a\necho b\n").In(cst.Literal), "run: |\n  echo a\n  echo b\n"},
		{"anchor and tag go", "a: &x !!str v\n", []any{"a"}, Str("w"), "a: w\n"},
		{"secrets", "uses: ./w.yml\nsecrets: inherit\n", []any{"secrets"}, Map{{Key: "TOKEN", Value: Str("${{ secrets.TOKEN }}")}},
			"uses: ./w.yml\nsecrets:\n  TOKEN: ${{ secrets.TOKEN }}\n"},
		{"block to scalar, key comment kept", "a: # c\n  x: 1\n", []any{"a"}, Int(5), "a: 5 # c\n"},
		{"an empty value with a comment", "k:  # c\n", []any{"k"}, Str("v"), "k: v  # c\n"},
		{"literal with a comment", "k: x  # c\n", []any{"k"}, Str("a\n").In(cst.Literal), "k: |  # c\n  a\n"},
		{"crlf", "a: x\r\n", []any{"a"}, ab, "a:\r\n  a: 1\r\n  b: 2\r\n"},
		// Found in the corpus (suite 8KB6): a flow entry without ':'.
		{"a flow key alone", "- { single, a: b}\n", []any{0, "single"}, Map{{Key: "k", Value: Int(1)}}, "- { single: {k: 1}, a: b}\n"},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		n, _ := walk(t, tr, c.path...)
		ed, err := new(Editor).SetValue(n, c.v)
		if err != nil {
			t.Errorf("%s: SetValue: %v", c.name, err)
			continue
		}
		res, ok := applied(t, tr, ed)
		if !ok {
			continue
		}
		if got := string(res.Tree.Bytes()); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if len(res.Diff) != 1 || res.Diff[0].Kind != Changed {
			t.Errorf("%s: Diff = %v", c.name, changes(res.Diff))
		}
	}
}

func TestSetValueRefused(t *testing.T) {
	tr := cst.Parse([]byte("x: &a 1\ny: *a\nm:\n  k: &b 2\nz: *b\n"))
	x, _ := walk(t, tr, "x")
	m, _ := walk(t, tr, "m")
	_, entry := walk(t, tr, "y")
	key := pairOf(entry).Key
	for name, n := range map[string]cst.Node{"an anchor an alias uses": x, "an anchor below": m, "a key": key, "the document": docContent(tr)} {
		if ed, err := new(Editor).SetValue(n, Str("v")); err == nil {
			t.Errorf("%s: SetValue = %q, want an error", name, ed.New)
		}
	}
}

// A literal as the last value of an input with
// no line break at its end.
func TestSetValueLiteralAtTheEnd(t *testing.T) {
	tr := cst.Parse([]byte("steps:\n  - run: echo hi"))
	run, _ := walk(t, tr, "steps", 0, "run")
	res := mustApply(t, tr, must(t)(new(Editor).SetValue(run, Str("echo hi\n").In(cst.Literal))))
	if got := string(res.Tree.Bytes()); got != "steps:\n  - run: |\n      echo hi\n" {
		t.Errorf("%q", got)
	}
}

// Found when the corpus test got a literal SetValue (suite XW4D): the
// comment on the old value's last line would be the literal's content.
func TestSetValueLiteralMovesLastComment(t *testing.T) {
	tr := cst.Parse([]byte("b: plain\n value  # lala\nc: 1\n"))
	b, _ := walk(t, tr, "b")
	res := mustApply(t, tr, must(t)(new(Editor).SetValue(b, Str("x\n").In(cst.Literal))))
	if got := string(res.Tree.Bytes()); got != "b: |  # lala\n  x\nc: 1\n" {
		t.Errorf("%q", got)
	}
}

// Found in the corpus of sisakuintel (Dicklesworthstone/destructive_command_guard,
// FufuLauncher/FufuLauncher) and before it in the suite (H2RW): a line
// after the value that the literal
// would read as its content, a comment at its indentation or more or a
// line of more spaces, refuses the literal; a comment less indented
// follows it.
func TestSetValueLiteralBeforeLinesItWouldTake(t *testing.T) {
	lit := Str("x\n").In(cst.Literal)
	for _, src := range []string{
		"on:\n  workflow_dispatch:\n    # note\nenv: 1\n",
		"on:\n  workflow_dispatch:\n      # note\nenv: 1\n",
		"k: v\n    \nz: 1\n",
		"k: v\n\n  # note\nz: 1\n",
	} {
		tr := cst.Parse([]byte(src))
		var n cst.Node
		if src[0] == 'o' {
			n, _ = walk(t, tr, "on", "workflow_dispatch")
		} else {
			n, _ = walk(t, tr, "k")
		}
		if ed, err := new(Editor).SetValue(n, lit); err == nil {
			t.Errorf("%q: SetValue = %q, want an error", src, ed.New)
		}
	}
	tr := cst.Parse([]byte("k: v\n# top\nz: 1\n"))
	k, _ := walk(t, tr, "k")
	res := mustApply(t, tr, must(t)(new(Editor).SetValue(k, lit)))
	if got := string(res.Tree.Bytes()); got != "k: |\n  x\n# top\nz: 1\n" {
		t.Errorf("%q", got)
	}
}

// A literal whose first line starts with a space has an indentation
// indicator, and its content is indented by that from the collection; an
// empty literal takes in only what is indented more than the collection.
func TestSetValueLiteralIndentOfItsHeader(t *testing.T) {
	for _, src := range []string{"k: v\n  # c\nz: 1\n", "k: v\n   \nz: 1\n"} {
		tr := cst.Parse([]byte(src))
		k, _ := walk(t, tr, "k")
		if ed, err := new(Editor).SetValue(k, Str(" x\n").In(cst.Literal)); err == nil {
			t.Errorf("%q: SetValue = %q, want an error", src, ed.New)
		}
	}
	tr := cst.Parse([]byte("k: v\n# top\nz: 1\n"))
	k, _ := walk(t, tr, "k")
	res := mustApply(t, tr, must(t)(new(Editor).SetValue(k, Str("").In(cst.Literal))))
	if got := string(res.Tree.Bytes()); !strings.HasSuffix(got, "\n# top\nz: 1\n") {
		t.Errorf("%q", got)
	}
}

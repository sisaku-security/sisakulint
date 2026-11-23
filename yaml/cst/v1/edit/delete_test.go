package edit

import (
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func TestDelete(t *testing.T) {
	cases := []struct {
		name, src string
		path      []any
		value     bool // delete the value node rather than the element
		want      string
	}{
		{"with its comment", "a: 1\n# about b\nb: 2\nc: 3\n", []any{"b"}, false, "a: 1\nc: 3\n"},
		{"keeping the next comment", "a:\n  x: 1\n  y: 2\n# top\nc: 3\n", []any{"a", "y"}, false, "a:\n  x: 1\n# top\nc: 3\n"},
		{"compact first", "- run: a\n  name: x\n", []any{0, "run"}, false, "- name: x\n"},
		{"compact first, a comment next", "- run: a\n  # about name\n  name: x\n", []any{0, "run"}, false,
			"- # about name\n  name: x\n"},
		{"a step", "steps:\n  - run: a\n  - run: b\n", []any{"steps", 0}, false, "steps:\n  - run: b\n"},
		{"an item by its value", "- a\n- b\n", []any{1}, true, "- a\n"},
		{"flow middle", "t: [a, b, c]\n", []any{"t", 1}, false, "t: [a, c]\n"},
		{"flow first", "t: [a, b, c]\n", []any{"t", 0}, false, "t: [b, c]\n"},
		{"flow last", "t: [a, b, c]\n", []any{"t", 2}, false, "t: [a, b]\n"},
		{"flow only", "t: [a]\n", []any{"t", 0}, false, "t: []\n"},
		{"flow trailing comma", "t: [a, b,]\n", []any{"t", 1}, false, "t: [a,]\n"},
		{"flow mapping", "w: {a: 1, b: 2}\n", []any{"w", "b"}, false, "w: {a: 1}\n"},
		{"no final line break", "a: 1\nb: 2", []any{"b"}, false, "a: 1"},
		{"an alias inside", "x:\n  k: &a 1\n  j: *a\ny: 2\n", []any{"x"}, false, "y: 2\n"},
		// Found in the corpus: the empty lines after b would be the kept
		// scalar's.
		{"after a kept scalar", "- |+\n  a\n\n- b\n\n\n- c\n", []any{1}, false, "- |+\n  a\n\n- c\n"},
		// Found in the corpus of sisakuintel: what is left after the
		// element would be the clipped scalar's content, a line of more
		// spaces than its indentation (aaif-goose/goose) and a comment at
		// its indentation (langflow-ai/openrag).
		{"after a clipped scalar, a line of more spaces", "- |\n  a\n- |\n    b\n    \n- c\n", []any{1}, false, "- |\n  a\n- c\n"},
		{"after a clipped scalar, a comment of its indentation", "- |\n  a\n- x: 1\n  # note\n- c\n", []any{1}, false, "- |\n  a\n- c\n"},
		{"after a clipped scalar, a comment less indented", "- |\n  a\n- b\n# top\n- c\n", []any{1}, false, "- |\n  a\n# top\n- c\n"},
		// lightningpixel/modly: the line break before the last element, at
		// the end of an input with no final line break, is the scalar's.
		{"no final line break, after a clipped scalar", "a: |\n  x\nb: 1", []any{"b"}, false, "a: |\n  x\n"},
		{"no final line break, after a stripped scalar", "a: |-\n  x\nb: 1", []any{"b"}, false, "a: |-\n  x"},
		// The byte order mark before the first line stays: it is the
		// stream's, no element's.
		{"the first after a byte order mark", "\xef\xbb\xbfa: 1\nb: 2\n", []any{"a"}, false, "\xef\xbb\xbfb: 2\n"},
		// its comment above it goes with it, as without the mark.
		{"the first after a byte order mark, with its comment", "\xef\xbb\xbf# c\na: 1\nb: 2\n", []any{"a"}, false, "\xef\xbb\xbfb: 2\n"},
		// a scalar with no content line takes in only what is
		// indented more than its parent (8.1.1.1).
		{"after an empty scalar, a comment of the parent's indentation", "- |\n- b\n\n# c\n- c\n", []any{1}, false, "- |\n\n# c\n- c\n"},
		{"after a nested empty scalar, a comment of the parent's indentation", "a:\n  - |\n  - b\n\n  # c\n  - c\n", []any{"a", 1}, false,
			"a:\n  - |\n\n  # c\n  - c\n"},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		v, el := walk(t, tr, c.path...)
		target := el
		if c.value {
			target = v
		}
		ed, err := new(Editor).Delete(target)
		if err != nil {
			t.Errorf("%s: Delete: %v", c.name, err)
			continue
		}
		res, ok := applied(t, tr, ed)
		if !ok {
			continue
		}
		if got := string(res.Tree.Bytes()); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if len(res.Diff) != 1 || res.Diff[0].Kind != Removed {
			t.Errorf("%s: Diff = %v", c.name, changes(res.Diff))
		}
	}
}

func TestDeleteRefused(t *testing.T) {
	cases := []struct {
		name, src string
		path      []any
		says      string
	}{
		{"the only entry", "a:\n  b: 1\nc: 2\n", []any{"a", "b"}, "SetValue"},
		{"an anchor an alias uses", "x: &a 1\ny: *a\n", []any{"x"}, "alias"},
		{"an anchor below", "x:\n  k: &a 1\ny: *a\n", []any{"x"}, "alias"},
		{"a document", "a: 1\n", nil, ""},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		_, el := walk(t, tr, c.path...)
		ed, err := new(Editor).Delete(el)
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("%s: Delete = %q, %v; want an error saying %q", c.name, ed.New, err, c.says)
		}
	}
}

// Deleting a key and inserting it again in one mapping cannot be asked
// for: Insert refuses a key the mapping has, and names SetValue, which
// does that. The same key deleted from one mapping and inserted into
// another is two changes, and Apply takes them.
func TestDeleteAndInsertOneKey(t *testing.T) {
	tr := cst.Parse([]byte("m:\n  a: 1\n  b: 2\nn: {}\n"))
	_, a := walk(t, tr, "m", "a")
	if ins, err := new(Editor).Insert(docContent(tr), Last(), Map{{Key: "m", Value: Int(3)}}); err == nil || !strings.Contains(err.Error(), "SetValue") {
		t.Errorf("Insert of a key the mapping has = %q, %v; want an error naming SetValue", ins.New, err)
	}
	del, err := new(Editor).Delete(a)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := walk(t, tr, "n")
	ins, err := new(Editor).Insert(n, Last(), Map{{Key: "a", Value: Int(3)}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Apply(tr, []Edit{del, ins})
	if err != nil {
		t.Fatalf("Delete and Insert of a key in two mappings: %v", err)
	}
	if got := string(res.Tree.Bytes()); got != "m:\n  b: 2\nn: {a: 3}\n" {
		t.Errorf("%q", got)
	}
}

// Deleting the first entry on
// the "- " line keeps a comment line between it and the next entry, which
// is no entry's.
func TestDeleteCompactKeepsForeignComment(t *testing.T) {
	tr := cst.Parse([]byte("- run: a\n# note\n  name: b\n"))
	_, run := walk(t, tr, 0, "run")
	res := mustApply(t, tr, must(t)(new(Editor).Delete(run)))
	if got := string(res.Tree.Bytes()); got != "-\n# note\n  name: b\n" {
		t.Errorf("%q", got)
	}
}

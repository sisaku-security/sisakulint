package edit

import (
	"bytes"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// applied applies edit to tr and checks that its inverse gives tr back.
func applied(t *testing.T, tr *cst.Tree, edit Edit) (Result, bool) {
	t.Helper()
	res, err := Apply(tr, []Edit{edit})
	if err != nil {
		t.Errorf("%q: Apply: %v", tr.Bytes(), err)
		return res, false
	}
	back, err := Apply(res.Tree, res.Inverse)
	if err != nil || !bytes.Equal(back.Tree.Bytes(), tr.Bytes()) {
		t.Errorf("%q: the inverse does not give it back: %v", tr.Bytes(), err)
	}
	return res, true
}

func TestInsert(t *testing.T) {
	z := Map{{Key: "z", Value: Int(0)}}
	cases := []struct {
		name, src string
		path      []any // to the mapping
		at        Place
		pairs     Map
		want      string
	}{
		{"first", "a: 1\nb: 2\n", nil, First(), z, "z: 0\na: 1\nb: 2\n"},
		{"last", "a: 1\nb: 2\n", nil, Last(), z, "a: 1\nb: 2\nz: 0\n"},
		{"before", "a: 1\nb: 2\n", nil, Before("b"), z, "a: 1\nz: 0\nb: 2\n"},
		{"after", "a: 1\nb: 2\n", nil, After("a"), z, "a: 1\nz: 0\nb: 2\n"},
		{"above a comment", "a: 1\n# about b\nb: 2\n", nil, Before("b"), z, "a: 1\nz: 0\n# about b\nb: 2\n"},
		{"before the next comment", "a:\n  x: 1\n# top\nc: 2\n", []any{"a"}, Last(), Map{{Key: "y", Value: Int(2)}},
			"a:\n  x: 1\n  y: 2\n# top\nc: 2\n"},
		{"compact first", "steps:\n  - run: a\n    name: x\n", []any{"steps", 0}, First(), Map{{Key: "id", Value: Str("s")}},
			"steps:\n  - id: s\n    run: a\n    name: x\n"},
		{"nested", "steps:\n  - run: a\n", []any{"steps", 0}, Last(),
			Map{{Key: "env", Value: Map{{Key: "A", Value: Str("${{ x }}")}, {Key: "B", Value: Int(1)}}}},
			"steps:\n  - run: a\n    env:\n      A: ${{ x }}\n      B: 1\n"},
		{"comment", "on: push\njobs: {}\n", nil, After("on"), Map{{Key: "permissions", Value: Map{}, Comment: "TODO"}},
			"on: push\n# TODO\npermissions: {}\njobs: {}\n"},
		{"in order", "a: 1\n", nil, Last(), Map{{Key: "c", Value: Int(3)}, {Key: "b", Value: Int(2)}}, "a: 1\nc: 3\nb: 2\n"},
		{"flow last", "a: {x: 1}\n", []any{"a"}, Last(), Map{{Key: "y", Value: Int(2)}}, "a: {x: 1, y: 2}\n"},
		{"flow first", "a: {x: 1}\n", []any{"a"}, First(), Map{{Key: "y", Value: Int(2)}}, "a: {y: 2, x: 1}\n"},
		{"flow empty", "a: {}\n", []any{"a"}, Last(), Map{{Key: "y", Value: Int(2)}}, "a: {y: 2}\n"},
		{"crlf", "a:\r\n  x: 1\r\n", []any{"a"}, Last(), Map{{Key: "y", Value: Int(2)}}, "a:\r\n  x: 1\r\n  y: 2\r\n"},
		{"indent 4", "a:\n    x: 1\n", []any{"a"}, Last(), Map{{Key: "y", Value: Map{{Key: "k", Value: Int(1)}}}},
			"a:\n    x: 1\n    y:\n        k: 1\n"},
		// the empty lines are x's value.
		{"after kept lines", "a:\n  x: |+\n    t\n\n\nb: 1\n", []any{"a"}, Last(), Map{{Key: "y", Value: Int(2)}},
			"a:\n  x: |+\n    t\n\n\n  y: 2\nb: 1\n"},
		{"no final line break", "a: 1", nil, Last(), Map{{Key: "b", Value: Int(2)}}, "a: 1\nb: 2"},
		{"after the key's comment", "env: # vars\n  A: 1\n", []any{"env"}, First(), Map{{Key: "Z", Value: Int(0)}},
			"env: # vars\n  Z: 0\n  A: 1\n"},
		{"before the next document", "a: 1\n---\nb: 2\n", nil, Last(), Map{{Key: "c", Value: Int(3)}}, "a: 1\nc: 3\n---\nb: 2\n"},
		// Found in the corpus (suite UGM3): the anchor is on the key's line.
		{"a mapping with properties", "bill-to: &id\n    given: x\n", []any{"bill-to"}, Last(), z, "bill-to: &id\n    given: x\n    z: 0\n"},
		// Found in the corpus (suite DFF7): "?," would be no indicator.
		{"after an empty key in flow", "{\n? explicit: entry,\nimplicit: entry,\n?\n}\n", nil, Last(), z,
			"{\n? explicit: entry,\nimplicit: entry,\n? , z: 0\n}\n"},
		// Found in the corpus of sisakuintel (daokimluc/X-Router): the byte
		// order mark before the first line is no indentation.
		{"after a byte order mark", "\xef\xbb\xbfa: 1\n", nil, Last(), z, "\xef\xbb\xbfa: 1\nz: 0\n"},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		m, _ := walk(t, tr, c.path...)
		ed, err := new(Editor).Insert(m, c.at, c.pairs)
		if err != nil {
			t.Errorf("%s: Insert: %v", c.name, err)
			continue
		}
		res, ok := applied(t, tr, ed)
		if !ok {
			continue
		}
		if got := string(res.Tree.Bytes()); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		var added []string
		for _, ch := range res.Diff {
			if ch.Kind != Added {
				t.Errorf("%s: %v %s in the diff", c.name, ch.Kind, ch.Path)
			}
			added = append(added, ch.Path[len(ch.Path)-1].Key)
		}
		if len(added) != len(c.pairs) {
			t.Errorf("%s: added %v", c.name, added)
		}
	}
}

func TestInsertItem(t *testing.T) {
	z := Str("z")
	cases := []struct {
		name, src string
		path      []any // to the sequence
		i         int
		v         Value
		want      string
	}{
		{"first", "- a\n- b\n", nil, 0, z, "- z\n- a\n- b\n"},
		{"middle", "- a\n- b\n", nil, 1, z, "- a\n- z\n- b\n"},
		{"last", "- a\n- b\n", nil, 2, z, "- a\n- b\n- z\n"},
		{"a mapping", "steps:\n  - run: a\n", []any{"steps"}, 1,
			Map{{Key: "uses", Value: Str("x")}, {Key: "with", Value: Map{{Key: "k", Value: Int(1)}}}},
			"steps:\n  - run: a\n  - uses: x\n    with:\n      k: 1\n"},
		{"flow last", "types: [opened]\n", []any{"types"}, 1, Str("labeled"), "types: [opened, labeled]\n"},
		{"flow first", "types: [opened]\n", []any{"types"}, 0, Str("labeled"), "types: [labeled, opened]\n"},
		{"flow empty", "types: []\n", []any{"types"}, 0, Str("labeled"), "types: [labeled]\n"},
		{"indentless", "s:\n- a\n", []any{"s"}, 1, z, "s:\n- a\n- z\n"},
		{"compact first", "- - a\n  - b\n", []any{0}, 0, z, "- - z\n  - a\n  - b\n"},
		{"multi-line flow", "a: [\n  x,\n  y\n]\n", []any{"a"}, 2, z, "a: [\n  x,\n  y, z\n]\n"},
		{"trailing comma", "a: [x, y,]\n", []any{"a"}, 2, z, "a: [x, y, z,]\n"},
		// Found in the corpus (suite 57H4): the tag is on the key's line.
		{"a sequence with a tag", "s: !!seq\n- a\n", []any{"s"}, 1, z, "s: !!seq\n- a\n- z\n"},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		s, _ := walk(t, tr, c.path...)
		ed, err := new(Editor).InsertItem(s, c.i, c.v)
		if err != nil {
			t.Errorf("%s: InsertItem: %v", c.name, err)
			continue
		}
		res, ok := applied(t, tr, ed)
		if !ok {
			continue
		}
		if got := string(res.Tree.Bytes()); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if len(res.Diff) != 1 || res.Diff[0].Kind != Added || res.Diff[0].Path[len(res.Diff[0].Path)-1].Index != c.i {
			t.Errorf("%s: Diff = %v", c.name, changes(res.Diff))
		}
	}
}

// Found in the corpus (suite RZP5): an item added to a key that is a
// sequence goes past the key's content; the entry is still paired.
func TestInsertItemIntoKey(t *testing.T) {
	tr := cst.Parse([]byte("? - a\n: 1\n"))
	key := entriesOf(docContent(tr))[0].Key
	ed, err := new(Editor).InsertItem(key, 1, Str("z"))
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := applied(t, tr, ed); ok && string(res.Tree.Bytes()) != "? - a\n  - z\n: 1\n" {
		t.Errorf("%q", res.Tree.Bytes())
	}
}

// Found in the corpus (suite L24T/01): the last line of the block scalar
// has no line break, and the one a new line needs would be its value's.
func TestInsertAfterUnterminatedBlockScalar(t *testing.T) {
	tr := cst.Parse([]byte("foo: |\n  x\n   "))
	if ed, err := new(Editor).Insert(docContent(tr), Last(), Map{{Key: "z", Value: Int(0)}}); err == nil {
		t.Errorf("Insert = %q, want an error", ed.New)
	}
}

func TestInsertRefused(t *testing.T) {
	tr := cst.Parse([]byte("a: 1\ns: [x]\nf: [k: v]\nw: {k: v}\n"))
	root := docContent(tr)
	s, _ := walk(t, tr, "s")
	f, _ := walk(t, tr, "f", 0)
	w, _ := walk(t, tr, "w")
	one := Map{{Key: "z", Value: Int(0)}}
	for name, try := range map[string]func() (Edit, error){
		"no such key":   func() (Edit, error) { return new(Editor).Insert(root, Before("nope"), one) },
		"not a mapping": func() (Edit, error) { return new(Editor).Insert(s, Last(), one) },
		"a flow pair":   func() (Edit, error) { return new(Editor).Insert(f, Last(), one) },
		"a key it has":  func() (Edit, error) { return new(Editor).Insert(root, Last(), Map{{Key: "a", Value: Int(2)}}) },
		"a key twice": func() (Edit, error) {
			return new(Editor).Insert(root, Last(), Map{{Key: "y", Value: Int(1)}, {Key: "y", Value: Int(2)}})
		},
		"a comment in flow": func() (Edit, error) {
			return new(Editor).Insert(w, Last(), Map{{Key: "z", Value: Int(0), Comment: "c"}})
		},
		"index out of range": func() (Edit, error) { return new(Editor).InsertItem(s, 2, Str("z")) },
		"not a sequence":     func() (Edit, error) { return new(Editor).InsertItem(root, 0, Str("z")) },
	} {
		if ed, err := try(); err == nil {
			t.Errorf("%s: Insert = %q, want an error", name, ed.New)
		}
	}
}

// An Insert whose bytes were changed after it was made is refused: what
// reads back is not what it promises.
func TestInsertPromise(t *testing.T) {
	tr := cst.Parse([]byte("a: 1\n"))
	ed, err := new(Editor).Insert(docContent(tr), Last(), Map{{Key: "b", Value: Int(2)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"c: 2\n", "b: 3\n", "b: 2\nc: 3\n"} {
		ed.New = []byte(text)
		if res, err := Apply(tr, []Edit{ed}); err == nil {
			t.Errorf("%q: Apply = %q, want an error", text, res.Tree.Bytes())
		}
	}
}

// A block scalar with an anchor or a tag.
func TestBlockScalarWithProperties(t *testing.T) {
	for _, src := range []string{"a:\n  x: &k |+\n    t\n\n\nb: 1\n", "a:\n  x: !!str |+\n    t\n\n\nb: 1\n"} {
		tr := cst.Parse([]byte(src))
		a, _ := walk(t, tr, "a")
		res := mustApply(t, tr, must(t)(new(Editor).Insert(a, Last(), Map{{Key: "y", Value: Int(2)}})))
		want := src[:len(src)-len("b: 1\n")] + "  y: 2\nb: 1\n"
		if got := string(res.Tree.Bytes()); got != want {
			t.Errorf("%q: %q, want %q", src, got, want)
		}
	}
	tr := cst.Parse([]byte("run: &r |\n  echo a\n"))
	run, _ := walk(t, tr, "run")
	if ed, err := new(Editor).LineComment(run, "note"); err == nil {
		t.Errorf("LineComment on a block scalar with an anchor = %q, want an error", ed.New)
	}
}

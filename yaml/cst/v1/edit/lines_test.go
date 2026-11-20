package edit

import (
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// walk goes from the document's content: a string step goes to the value
// of that key, an int step to that item. It returns the last node reached
// and the element holding it: the entry, the "- " entry, or the item of a
// flow sequence itself.
func walk(t *testing.T, tr *cst.Tree, path ...any) (value, element cst.Node) {
	t.Helper()
	n := docContent(tr)
	element = n
	for _, step := range path {
		found := false
		switch s := step.(type) {
		case string:
			m, ok := n.Mapping()
			if !ok {
				t.Fatalf("%v is not a mapping at %q", n.Kind(), s)
			}
			for e := range m.Entries() {
				if string(e.Key.Bytes()) == s {
					n, element, found = e.Value, e.Node, true
					break
				}
			}
		case int:
			q, ok := n.Sequence()
			if !ok {
				t.Fatalf("%v is not a sequence at %d", n.Kind(), s)
			}
			i := 0
			for x := range q.Items() {
				if i == s {
					n, element, found = x, x, true
					if p, _ := x.Parent(); p.Kind() == cst.NodeBlockSequenceEntry {
						element = p
					}
					break
				}
				i++
			}
		}
		if !found {
			t.Fatalf("no %v in %q", step, tr.Bytes())
		}
	}
	return n, element
}

func TestOwned(t *testing.T) {
	cases := []struct {
		src  string
		path []any
		want string
	}{
		{"a:\n  # lead\n  b: 1\n", []any{"a", "b"}, "  # lead\n  b: 1\n"},
		{"- run: a\n  # above\n- uses: x\n", []any{1}, "- uses: x\n"},
		{"- run: a\n  # above\n- uses: x\n", []any{0}, "- run: a\n"},
		{"uses: x\n# top\nx: 1\n", []any{"x"}, "# top\nx: 1\n"},
		{"# c\n\nkey: 1\n", []any{"key"}, "key: 1\n"},
		{"a: 1  # c\nb: 2\n", []any{"a"}, "a: 1  # c\n"},
		{"a:\n  b: 1\n# top\nc: 2\n", []any{"a", "b"}, "  b: 1\n"},
		{"a: 1\nb: 2", []any{"b"}, "b: 2"},
		{"a:\n  x: |+\n    t\n\n\nb: 1\n", []any{"a", "x"}, "  x: |+\n    t\n\n\n"},
		{"a:\n  x: |\n    t\n\n\nb: 1\n", []any{"a", "x"}, "  x: |\n    t\n"},
		{"a:\n  x: |\n    t\n      \nb: 1\n", []any{"a", "x"}, "  x: |\n    t\n      \n"}, // a line of spaces past the indentation is content
		{"a:\n  x: |\n    t\n# c\nb: 1\n", []any{"a", "x"}, "  x: |\n    t\n"},
		{"a:\r\n  # c\r\n  b: 1\r\nd: 2\r\n", []any{"a", "b"}, "  # c\r\n  b: 1\r\n"},
		{"- run: a\n  name: x\n", []any{0, "run"}, "run: a\n"},
		{"- run: a\n  name: x\n", []any{0, "name"}, "  name: x\n"},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		_, el := walk(t, tr, c.path...)
		sp := owned(el)
		if got := c.src[sp.Start:sp.End]; got != c.want {
			t.Errorf("owned %v in %q = %q, want %q", c.path, c.src, got, c.want)
		}
	}
}

func TestSharesLine(t *testing.T) {
	cases := []struct {
		src  string
		path []any
		want bool
	}{
		{"- run: a\n  name: x\n", []any{0, "run"}, true},
		{"- run: a\n  name: x\n", []any{0, "name"}, false},
		{"- run: a\n  name: x\n", []any{0}, false},
		{"- - a\n  - b\n", []any{0, 0}, true},
		{"- - a\n  - b\n", []any{0, 1}, false},
		{"key:\n  a: 1\n", []any{"key", "a"}, false},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		_, el := walk(t, tr, c.path...)
		if got := sharesLine(el); got != c.want {
			t.Errorf("sharesLine %v in %q = %v, want %v", c.path, c.src, got, c.want)
		}
	}
}

// pairOf gives what Mapping.Entries gives for every entry of a block
// mapping in the suite and the corpus, errors included, and firstElement
// the first of elementNodes for every collection.
func TestPairOfAsEntries(t *testing.T) {
	for name, src := range inputs(t) {
		var visit func(n cst.Node)
		visit = func(n cst.Node) {
			if n.Kind() == cst.NodeBlockMapping {
				m, _ := n.Mapping()
				for e := range m.Entries() {
					if got := pairOf(e.Node); got != e {
						t.Errorf("%s: pairOf %v = %+v, Entries gives %+v", name, e.Node.Span(), got, e)
					}
				}
			}
			_, isMap := n.Mapping()
			if _, isSeq := n.Sequence(); isMap || isSeq {
				es := elementNodes(n)
				got, ok := firstElement(n)
				if ok != (len(es) > 0) || ok && got != es[0] {
					t.Errorf("%s: firstElement %v = %v %v, elementNodes gives %v", name, n.Span(), got.Span(), ok, len(es))
				}
			}
			for c := range n.Children() {
				if x, ok := c.Node(); ok {
					visit(x)
				}
			}
		}
		visit(cst.Parse(src).Root())
		visit(cst.ParseMode(src, cst.ModeGitHub).Root())
	}
}

func TestLayoutAt(t *testing.T) {
	cases := []struct {
		src  string
		path []any // to the collection
		want layout
	}{
		{"a:\n  b: 1\n", []any{"a"}, layout{col: 2, unit: 2, seqUnder: true, nl: "\n"}},
		{"a:\n    b: 1\n", []any{"a"}, layout{col: 4, unit: 4, seqUnder: true, nl: "\n"}},
		{"a: 1\n", nil, layout{col: 0, unit: 2, seqUnder: true, nl: "\n"}},
		{"a:\n    b: 1\nc: 2\n", nil, layout{col: 0, unit: 4, seqUnder: true, nl: "\n"}},
		{"s:\n- a\nm:\n  k: 1\n", []any{"s"}, layout{col: 0, unit: 2, seqUnder: false, nl: "\n"}},
		{"s:\n  - a\n", []any{"s"}, layout{col: 2, unit: 2, seqUnder: true, nl: "\n"}},
		{"a:\r\n  b: 1\r\n", []any{"a"}, layout{col: 2, unit: 2, seqUnder: true, nl: "\r\n"}},
		{"a: {b: 1}\n", []any{"a"}, layout{flow: true, col: 3, unit: 2, seqUnder: true, nl: "\n"}},
		{"steps:\n  - run: a\n    name: x\n", []any{"steps", 0}, layout{col: 4, unit: 2, seqUnder: true, nl: "\n"}},
		{"jobs:\n    b:\n        steps:\n        - run: a\n", []any{"jobs", "b", "steps", 0}, layout{col: 10, unit: 4, seqUnder: false, nl: "\n"}},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		n, _ := walk(t, tr, c.path...)
		if got := new(Editor).layoutAt(n); got != c.want {
			t.Errorf("layoutAt %v in %q = %+v, want %+v", c.path, c.src, got, c.want)
		}
	}
}

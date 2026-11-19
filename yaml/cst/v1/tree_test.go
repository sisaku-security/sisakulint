package cst

import (
	"strings"
	"testing"
)

// handBuilt builds "a: b" as Stream > Document > BlockMapping > BlockMappingEntry > Scalar, ':', ' ', Scalar.
func handBuilt(t *testing.T, src string) *Tree {
	t.Helper()
	p := newParser([]byte(src))
	doc := p.open(NodeDocument)
	m := p.open(NodeBlockMapping)
	e := p.open(NodeBlockMappingEntry)
	k := p.open(NodeScalar)
	p.emit(TokPlain, 1)
	p.close(k)
	p.emit(TokMapValue, 2)
	if len(src) > 2 {
		p.emit(TokSpace, 3)
	}
	v := p.open(NodeScalar)
	p.emit(TokPlain, len(src))
	p.close(v)
	p.close(e)
	p.close(m)
	p.close(doc)
	return p.finish()
}

func TestHandBuiltTree(t *testing.T) {
	tr := handBuilt(t, "a: b")
	if err := validate(tr); err != nil {
		t.Fatal(err)
	}
	var entry Node
	for n := tr.Root(); ; {
		var next Node
		found := false
		for e := range n.Children() {
			if c, ok := e.Node(); ok {
				next, found = c, true
				break
			}
		}
		if !found {
			t.Fatal("no BlockMappingEntry")
		}
		n = next
		if n.Kind() == NodeBlockMappingEntry {
			entry = n
			break
		}
	}
	var got []string
	for e := range entry.Children() {
		if c, ok := e.Node(); ok {
			got = append(got, "node:"+string(c.Bytes()))
		} else {
			k, _ := e.Token()
			got = append(got, "tok:"+string(k.Bytes()))
		}
	}
	if want := "node:a tok:: tok:  node:b"; strings.Join(got, " ") != want {
		t.Errorf("entry children = %q, want %q", strings.Join(got, " "), want)
	}
	b := entry.Bytes()
	if string(b) != "a: b" || cap(b) != len(b) {
		t.Errorf("entry Bytes = %q cap %d", b, cap(b))
	}
	if s := entry.Span(); s != (Span{0, 4}) {
		t.Errorf("entry Span = %v", s)
	}
	if p, ok := entry.Parent(); !ok || p.Kind() != NodeBlockMapping {
		t.Errorf("entry Parent = %v %v", p.Kind(), ok)
	}
	if _, ok := tr.Root().Parent(); ok {
		t.Error("root has a parent")
	}
	n := 0
	for range tr.Root().Tokens() {
		n++
	}
	if n != 4 {
		t.Errorf("root Tokens = %d, want 4", n)
	}
}

func TestEmptyNodeSpan(t *testing.T) {
	// "a:" with an empty value scalar at the end of input
	p := newParser([]byte("a:"))
	e := p.open(NodeBlockMappingEntry)
	k := p.open(NodeScalar)
	p.emit(TokPlain, 1)
	p.close(k)
	p.emit(TokMapValue, 2)
	v := p.open(NodeScalar)
	p.close(v)
	p.close(e)
	tr := p.finish()
	if err := validate(tr); err != nil {
		t.Fatal(err)
	}
	empty := Node{tr, v}
	if s := empty.Span(); s != (Span{2, 2}) {
		t.Errorf("empty Span = %v, want {2 2}", s)
	}
	if len(empty.Bytes()) != 0 {
		t.Errorf("empty Bytes = %q", empty.Bytes())
	}

	// empty key before ':' — span is the start of the next token
	p = newParser([]byte(": b"))
	e = p.open(NodeBlockMappingEntry)
	k = p.open(NodeScalar)
	p.close(k)
	p.emit(TokMapValue, 1)
	p.emit(TokSpace, 2)
	v = p.open(NodeScalar)
	p.emit(TokPlain, 3)
	p.close(v)
	p.close(e)
	tr = p.finish()
	if err := validate(tr); err != nil {
		t.Fatal(err)
	}
	if s := (Node{tr, k}).Span(); s != (Span{0, 0}) {
		t.Errorf("empty key Span = %v, want {0 0}", s)
	}
}

func TestEmptyInput(t *testing.T) {
	tr := newParser(nil).finish()
	if err := validate(tr); err != nil {
		t.Fatal(err)
	}
	if tr.Root().Kind() != NodeStream || len(tr.Bytes()) != 0 {
		t.Errorf("root = %v, bytes %q", tr.Root().Kind(), tr.Bytes())
	}
}

func TestValidateDetectsCorruption(t *testing.T) {
	cases := []struct {
		name    string
		corrupt func(*Tree)
	}{
		{"token start shifted", func(tr *Tree) { tr.tokens[1].start = tr.tokens[0].start }},
		{"first token not at 0", func(tr *Tree) { tr.tokens[0].start = 1 }},
		{"subtreeEnd broken", func(tr *Tree) { tr.nodes[2].subtreeEnd = 2 }},
		{"child outside parent", func(tr *Tree) { tr.nodes[4].tokEnd = tr.nodes[3].tokEnd + 1 }},
		{"sibling overlap", func(tr *Tree) { tr.nodes[5].tokStart = 0 }},
		{"token dropped from tree", func(tr *Tree) {
			tr.nodes[0].tokEnd--
			tr.nodes[1].tokEnd--
			tr.nodes[2].tokEnd--
			tr.nodes[3].tokEnd--
			tr.nodes[5].tokEnd--
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := handBuilt(t, "a: b")
			c.corrupt(tr)
			if err := validate(tr); err == nil {
				t.Error("validate accepted a corrupted tree")
			}
		})
	}
}

func TestResetTruncates(t *testing.T) {
	p := newParser([]byte("a: b"))
	doc := p.open(NodeDocument)
	m := p.mark()
	p.open(NodeBlockMapping) // left open: reset must drop it from the stack
	p.emit(TokPlain, 1)
	p.errorAt(0, Span{0, 1}, "x")
	p.reset(m)
	if p.pos != 0 || len(p.t.tokens) != 0 || len(p.t.nodes) != 2 || len(p.t.errs) != 0 || len(p.stack) != 2 {
		t.Fatalf("after reset: pos %d tokens %d nodes %d errs %d stack %d", p.pos, len(p.t.tokens), len(p.t.nodes), len(p.t.errs), len(p.stack))
	}
	p.emit(TokPlain, 4)
	p.close(doc)
	if err := validate(p.finish()); err != nil {
		t.Fatal(err)
	}
}

// ContentSpan leaves out the white space, line breaks and comment lines the
// grammar attaches to the ends of a node.
func TestContentSpan(t *testing.T) {
	src := "a:\n  b: c\n\n# trailing\nd: e\n"
	tr := Parse([]byte(src))
	m, _ := firstNode(tr.Root(), NodeBlockMapping).Mapping()
	var got []string
	for e := range m.Entries() {
		s := e.Node.ContentSpan()
		got = append(got, src[s.Start:s.End])
		v := e.Value.ContentSpan()
		got = append(got, src[v.Start:v.End])
	}
	want := []string{"a:\n  b: c", "b: c", "d: e", "e"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("content spans %q, want %q", got, want)
	}
	lit := "|\n  echo\n\n"
	s := firstNode(Parse([]byte(lit)).Root(), NodeScalar).ContentSpan()
	if lit[s.Start:s.End] != "|\n  echo" {
		t.Errorf("block scalar content span %q", lit[s.Start:s.End])
	}
	empty := "a:\n"
	m2, _ := firstNode(Parse([]byte(empty)).Root(), NodeBlockMapping).Mapping()
	for e := range m2.Entries() {
		if s := e.Value.ContentSpan(); s != (Span{2, 2}) {
			t.Errorf("empty value content span %v", s)
		}
	}
}

func TestReparse(t *testing.T) {
	a := Parse([]byte("a: [b\n"))
	src := []byte("x: {y: z}\n- ]\n")
	b, c := a.Reparse(src), Parse(src)
	if tokens(b) != tokens(c) || len(b.nodes) != len(c.nodes) || len(b.Errors()) != len(c.Errors()) {
		t.Fatalf("Reparse differs from Parse:\n%s\n%s", tokens(b), tokens(c))
	}
	for i := range b.nodes {
		if b.nodes[i] != c.nodes[i] {
			t.Errorf("node %d: %+v, Parse %+v", i, b.nodes[i], c.nodes[i])
		}
	}
}

package edit

import (
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

var (
	block  = layout{unit: 2, seqUnder: true, nl: "\n"}
	flowed = layout{flow: true, unit: 2, nl: "\n"}
)

func TestWriteScalar(t *testing.T) {
	cases := []struct {
		v        Value
		l        layout
		afterKey bool
		want     string
	}{
		{Str("x"), block, true, "x"},
		{Str("true"), block, true, `"true"`},
		{Str("3.10"), block, true, `"3.10"`},
		{Str(""), block, true, `""`},
		{Str("a: b"), block, true, `"a: b"`},
		{Str("a #b"), block, true, `"a #b"`},
		{Str("a:"), block, true, `"a:"`},
		{Str(" a"), block, true, `" a"`},
		{Str("- x"), block, true, `"- x"`},
		{Str("-x"), block, true, "-x"},
		{Str("---"), block, true, `"---"`},
		{Str("#x"), block, true, `"#x"`},
		{Str("a\nb"), block, true, `"a\nb"`},
		{Str("${{ a }}"), block, true, "${{ a }}"},
		{Str("${{ a }}"), flowed, true, `"${{ a }}"`},
		{Str("a,b"), flowed, true, `"a,b"`},
		{Int(5), block, true, "5"},
		{Int(-3), block, true, "-3"},
		{Bool(false), block, true, "false"},
		{Null(), block, true, ""},
		{Null(), block, false, "null"},
		{Null(), flowed, true, "null"},
		{Str("x").In(cst.SingleQuoted), block, true, "'x'"},
		{Str("it's").In(cst.SingleQuoted), block, true, "'it''s'"},
		{Str("x").In(cst.DoubleQuoted), block, true, `"x"`},
		{Str("x").In(cst.Plain), block, true, "x"},
		{Str("a b").In(cst.Folded), block, true, ">-\n  a b"},
	}
	for _, c := range cases {
		got, err := writeValue(c.v, c.l, c.afterKey)
		if err != nil || string(got) != c.want {
			t.Errorf("writeValue(%#v, flow=%v, afterKey=%v) = %q, %v; want %q", c.v, c.l.flow, c.afterKey, got, err, c.want)
		}
	}
}

func TestWriteScalarRefused(t *testing.T) {
	cases := []struct {
		v Value
		l layout
	}{
		{Str("123").In(cst.Plain), block},
		{Str("a: b").In(cst.Plain), block},
		{Str("a\nb").In(cst.SingleQuoted), block},
		{Str("a\nb").In(cst.Folded), block},
		{Int(5).In(cst.DoubleQuoted), block},
		{Null().In(cst.SingleQuoted), block},
		{Str("a\n").In(cst.Literal), flowed},
		{Str("a").In(cst.Folded), flowed},
		{Str("\xff"), block},
	}
	for _, c := range cases {
		if got, err := writeValue(c.v, c.l, true); err == nil {
			t.Errorf("writeValue(%#v, flow=%v) = %q, want an error", c.v, c.l.flow, got)
		}
	}
}

func TestWriteLiteral(t *testing.T) {
	crlf := block
	crlf.nl = "\r\n"
	nested := block
	nested.col = 2
	cases := []struct {
		value string
		l     layout
		want  string
	}{
		{"a\n", block, "|\n  a"},
		{"a", block, "|-\n  a"},
		{"a\n\n", block, "|+\n  a\n"},
		{"\n", block, "|+\n"},
		{"", block, "|-"},
		{"a\n\nb\n", block, "|\n  a\n\n  b"},
		{" a\n", block, "|2\n   a"},
		{"a\nb\n", crlf, "|\r\n  a\r\n  b"},
		{"a\n", nested, "|\n    a"},
	}
	for _, c := range cases {
		got, err := writeValue(Str(c.value).In(cst.Literal), c.l, true)
		if err != nil || string(got) != c.want {
			t.Errorf("literal %q = %q, %v; want %q", c.value, got, err, c.want)
		}
	}
}

func TestWriteKey(t *testing.T) {
	cases := []struct{ key, want string }{
		{"a.b", "a.b: 1\n"},
		{"on", "on: 1\n"},
		{"a: b", "\"a: b\": 1\n"},
		{"true", "\"true\": 1\n"},
		{"", "\"\": 1\n"},
	}
	for _, c := range cases {
		got, err := writePairs(Map{{Key: c.key, Value: Int(1)}}, block)
		if err != nil || string(got) != c.want {
			t.Errorf("key %q = %q, %v; want %q", c.key, got, err, c.want)
		}
	}
	for _, key := range []string{"a\nb", strings.Repeat("x", 1025)} {
		if got, err := writePairs(Map{{Key: key, Value: Int(1)}}, block); err == nil {
			t.Errorf("key %q = %q, want an error", key, got)
		}
	}
}

func TestWritePairs(t *testing.T) {
	indented := layout{col: 2, unit: 4, seqUnder: true, nl: "\n"}
	flat := block
	flat.seqUnder = false
	crlf := block
	crlf.nl = "\r\n"
	nested := Map{{Key: "a", Value: Int(1)}, {Key: "b", Value: Map{{Key: "c", Value: Str("x")}}}}
	cases := []struct {
		m    Map
		l    layout
		want string
	}{
		{nested, block, "a: 1\nb:\n  c: x\n"},
		{nested, indented, "  a: 1\n  b:\n      c: x\n"},
		{nested, crlf, "a: 1\r\nb:\r\n  c: x\r\n"},
		{Map{{Key: "s", Value: Seq{Str("a"), Str("b")}}}, block, "s:\n  - a\n  - b\n"},
		{Map{{Key: "s", Value: Seq{Str("a"), Str("b")}}}, flat, "s:\n- a\n- b\n"},
		{Map{{Key: "p", Value: Map{}}, {Key: "q", Value: Seq{}}}, block, "p: {}\nq: []\n"},
		{Map{{Key: "n", Value: Null()}}, block, "n:\n"},
		{Map{{Key: "run", Value: Str("echo a\necho b\n").In(cst.Literal)}}, block, "run: |\n  echo a\n  echo b\n"},
		{Map{{Key: "permissions", Value: Map{}, Comment: "TODO: review\nsecond"}}, block, "# TODO: review\n# second\npermissions: {}\n"},
		{Map{{Key: "k", Value: Int(1), Comment: "a\n\nb"}}, block, "# a\n#\n# b\nk: 1\n"},
		{Map{{Key: "a", Value: Int(1)}, {Key: "b", Value: Str("x y")}}, flowed, "a: 1, b: x y"},
		{Map{{Key: "a", Value: Map{{Key: "b", Value: Seq{Int(1), Str("x,y")}}}}}, flowed, `a: {b: [1, "x,y"]}`},
	}
	for _, c := range cases {
		got, err := writePairs(c.m, c.l)
		if err != nil || string(got) != c.want {
			t.Errorf("writePairs(%#v) = %q, %v; want %q", c.m, got, err, c.want)
		}
	}
	for _, c := range []struct {
		m Map
		l layout
	}{
		{Map{{Key: "k", Value: Int(1), Comment: "a\rb"}}, block},
		{Map{{Key: "k", Value: Int(1), Comment: "c"}}, flowed},
		{Map{{Key: "k", Value: Str("a\n").In(cst.Literal)}}, flowed},
	} {
		if got, err := writePairs(c.m, c.l); err == nil {
			t.Errorf("writePairs(%#v) = %q, want an error", c.m, got)
		}
	}
}

func TestWriteItem(t *testing.T) {
	cases := []struct {
		v    Value
		l    layout
		want string
	}{
		{Str("a"), block, "- a\n"},
		{Null(), block, "- null\n"},
		{Map{{Key: "a", Value: Int(1)}, {Key: "b", Value: Int(2)}}, block, "- a: 1\n  b: 2\n"},
		{Seq{Str("a"), Str("b")}, block, "- - a\n  - b\n"},
		{Map{}, block, "- {}\n"},
		{Str("a\n").In(cst.Literal), block, "- |\n  a\n"},
		{Map{{Key: "a", Value: Int(1), Comment: "c"}}, block, "-\n  # c\n  a: 1\n"},
		{Map{{Key: "with", Value: Map{{Key: "x", Value: Int(1)}}}}, block, "- with:\n    x: 1\n"},
		{Map{{Key: "a", Value: Seq{Int(1)}}}, flowed, "{a: [1]}"},
		{Str("a,b"), flowed, `"a,b"`},
	}
	for _, c := range cases {
		got, err := writeItem(c.v, c.l)
		if err != nil || string(got) != c.want {
			t.Errorf("writeItem(%#v) = %q, %v; want %q", c.v, got, err, c.want)
		}
	}
}

// roundTripValues are written in every place they can go, read back and
// compared with sameValue.
var roundTripValues = []Value{
	Str("x"), Str("true"), Str(""), Str("a: b"), Str("${{ a }}"), Str("a\nb"),
	Str("  lead"), Str("#x"), Str("a,b"), Int(7), Bool(true), Null(),
	Str("x").In(cst.SingleQuoted),
	Str("echo a\n\n  b\n").In(cst.Literal), Str(" a\n").In(cst.Literal),
	Str("\n").In(cst.Literal), Str("x\n\n").In(cst.Literal), Str("").In(cst.Literal),
	Str(" a b").In(cst.Folded),
	Map{{Key: "a", Value: Int(1)}, {Key: "b", Value: Seq{Str("x"), Map{{Key: "c", Value: Null()}}}}},
	Seq{Seq{Str("a")}, Map{}},
	Map{{Key: "k", Value: Str("v"), Comment: "note"}},
	Map{{Key: "true", Value: Seq{}}, {Key: "a b", Value: Str("run\n").In(cst.Literal)}},
}

func TestWriteRoundTrip(t *testing.T) {
	for _, v := range roundTripValues {
		roundTrip(t, v, true)
	}
}

// roundTrip writes v as a mapping value, as a sequence item, nested one
// level deeper, and in a flow collection, and checks that what is written
// reads back as v. With must, every block place has to take v.
func roundTrip(t *testing.T, v Value, must bool) {
	t.Helper()
	deep := block
	deep.col = 2
	check := func(where string, src []byte, pick func(cst.Node) cst.Node) {
		t.Helper()
		tr := cst.Parse(src)
		if len(tr.Errors()) > 0 {
			t.Errorf("%s: %q has errors: %v", where, src, tr.Errors())
			return
		}
		if err := sameValue(pick(docContent(tr)), v); err != nil {
			t.Errorf("%s: %q: %v", where, src, err)
		}
	}
	if text, err := writeValue(v, block, true); err == nil {
		check("value", []byte("k:"+afterIndicator(string(text))+"\n"), func(n cst.Node) cst.Node { return entryValue(n, 0) })
	} else if must {
		t.Errorf("value %#v: %v", v, err)
	}
	if text, err := writeItem(v, block); err == nil {
		check("item", text, func(n cst.Node) cst.Node { return item(n, 0) })
	} else if must {
		t.Errorf("item %#v: %v", v, err)
	}
	if text, err := writePairs(Map{{Key: "k", Value: v}}, deep); err == nil {
		check("nested", []byte("a:\n"+string(text)), func(n cst.Node) cst.Node { return entryValue(entryValue(n, 0), 0) })
	} else if must {
		t.Errorf("nested %#v: %v", v, err)
	}
	if text, err := writeItem(v, flowed); err == nil {
		check("flow item", []byte("["+string(text)+"]"), func(n cst.Node) cst.Node { return item(n, 0) })
	} else if must && flowable(v) {
		t.Errorf("flow item %#v: %v", v, err)
	}
}

// flowable is whether v has nothing a flow collection cannot hold.
func flowable(v Value) bool {
	switch v := v.(type) {
	case Scalar:
		return v.style != cst.Literal && v.style != cst.Folded || !v.styled
	case Map:
		for _, p := range v {
			if p.Comment != "" || !flowable(p.Value) {
				return false
			}
		}
	case Seq:
		for _, x := range v {
			if !flowable(x) {
				return false
			}
		}
	}
	return true
}

// docContent is the content node of the tree's first document.
func docContent(tr *cst.Tree) cst.Node {
	for e := range tr.Root().Children() {
		doc, ok := e.Node()
		if !ok || doc.Kind() != cst.NodeDocument {
			continue
		}
		for e := range doc.Children() {
			if n, ok := e.Node(); ok && n.Kind() != cst.NodeDirective {
				return n
			}
		}
	}
	return tr.Root()
}

func entryValue(n cst.Node, i int) cst.Node {
	m, _ := n.Mapping()
	for e := range m.Entries() {
		if i == 0 {
			return e.Value
		}
		i--
	}
	return n
}

func item(n cst.Node, i int) cst.Node {
	s, _ := n.Sequence()
	for x := range s.Items() {
		if i == 0 {
			return x
		}
		i--
	}
	return n
}

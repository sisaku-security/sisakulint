package edit

import (
	"bytes"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// FuzzApply checks, on any input, a raw edit, a Replace of the first
// scalar, and a structural operation on a node chosen by s: Apply either
// refuses or returns a result whose inverse gives the input back, and
// nothing panics. The seeds are the suite and the corpus.
func FuzzApply(f *testing.F) {
	for _, src := range inputs(f) {
		f.Add(src, uint16(0), uint16(1), []byte("x"))
	}
	f.Fuzz(func(t *testing.T, src []byte, s, e uint16, text []byte) {
		tr := cst.Parse(src)
		a, b := min(int(s), len(src)), min(int(e), len(src))
		if a > b {
			a, b = b, a
		}
		inverse(t, tr, []Edit{{Span: cst.Span{Start: a, End: b}, New: text}})
		for n := range allScalars(tr) {
			v, _ := decode(n)
			l := len(v.String())
			vs, ve := int(s)%(l+1), int(e)%(l+1)
			if vs > ve {
				vs, ve = ve, vs
			}
			if ed, err := Replace(v, vs, ve, string(text)); err == nil {
				inverse(t, tr, []Edit{ed})
			}
			break
		}
		var nodes []cst.Node
		var visit func(n cst.Node)
		visit = func(n cst.Node) {
			nodes = append(nodes, n)
			for e := range n.Children() {
				if c, ok := e.Node(); ok {
					visit(c)
				}
			}
		}
		visit(tr.Root())
		n := nodes[int(s)%len(nodes)]
		value := Value(Str(string(text)))
		if e%2 == 1 {
			value = Map{{Key: string(text), Value: Seq{Int(int64(e)), Null()}}}
		}
		var ed Edit
		var err error
		switch e % 5 {
		case 0:
			ed, err = new(Editor).Insert(n, []Place{First(), Last()}[s%2], Map{{Key: "zz", Value: value}})
		case 1:
			ed, err = new(Editor).InsertItem(n, int(s)%3, value)
		case 2:
			ed, err = new(Editor).Delete(n)
		case 3:
			ed, err = new(Editor).SetValue(n, value)
		case 4:
			ed, err = new(Editor).LineComment(n, string(text))
		}
		if err == nil {
			inverse(t, tr, []Edit{ed})
		}
	})
}

func inverse(t *testing.T, tr *cst.Tree, edits []Edit) {
	res, err := Apply(tr, edits)
	if err != nil {
		return
	}
	back, err := Apply(res.Tree, res.Inverse)
	if err != nil || !bytes.Equal(back.Tree.Bytes(), tr.Bytes()) {
		t.Fatalf("the inverse of %q on %q does not give it back: %v", edits[0].New, tr.Bytes(), err)
	}
}

// FuzzWrite checks, on any value tree, that every place that takes it
// writes it so that it reads back as the same value (roundTrip).
func FuzzWrite(f *testing.F) {
	f.Add([]byte("m\x02s\x01a\x00s\x03x: y\x00l\x02a\n\n\x00"))
	f.Add([]byte("q\x02i\x05b\x01n\x00f\x03 a b\x00"))
	f.Add([]byte("m\x01c\x04note\x00k\x00S\x02d\x02\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, _ := genValue(data, 0)
		roundTrip(t, v, false)
	})
}

// genValue reads a value tree from data: a kind byte, then for a string
// its bytes up to a 0, for a collection a count byte and its children.
func genValue(data []byte, depth int) (Value, []byte) {
	if len(data) == 0 {
		return Str(""), data
	}
	k, data := data[0], data[1:]
	str := func() string {
		i := bytes.IndexByte(data, 0)
		if i < 0 {
			i = len(data)
		}
		s := string(data[:i])
		data = data[min(i+1, len(data)):]
		return s
	}
	count := func() int {
		if len(data) == 0 {
			return 0
		}
		n := int(data[0] % 4)
		data = data[1:]
		return n
	}
	switch {
	case k == 'm' && depth < 3:
		var m Map
		for range count() {
			p := Pair{Key: str()}
			if len(data) > 0 && data[0] == 'c' {
				data = data[1:]
				p.Comment = str()
			}
			p.Value, data = genValue(data, depth+1)
			m = append(m, p)
		}
		return m, data
	case k == 'q' && depth < 3:
		var q Seq
		for range count() {
			var x Value
			x, data = genValue(data, depth+1)
			q = append(q, x)
		}
		return q, data
	case k == 'i':
		return Int(int64(len(str()))), data
	case k == 'b':
		return Bool(len(str())%2 == 0), data
	case k == 'n':
		return Null(), data
	case k == 'l':
		return Str(str()).In(cst.Literal), data
	case k == 'f':
		return Str(str()).In(cst.Folded), data
	case k == 'd':
		return Str(str()).In(cst.DoubleQuoted), data
	}
	return Str(str()), data
}

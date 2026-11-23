package scalar

import (
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// sample is "abc" copied from [10,13), a line break made from [13,19) and
// "é" copied from [19,21): "abc\né".
func sample() Value {
	var b builder
	b.verbatim(cst.Span{Start: 10, End: 13}, []byte("abc"))
	b.made(cst.Span{Start: 13, End: 19}, "\n")
	b.verbatim(cst.Span{Start: 19, End: 21}, []byte("\xc3\xa9"))
	return b.value()
}

type sourceCase struct {
	s, e  int
	want  cst.Span
	exact bool
}

func checkSource(t *testing.T, v Value, cases []sourceCase) {
	t.Helper()
	for _, c := range cases {
		got, exact := v.Source(c.s, c.e)
		if got != c.want || exact != c.exact {
			t.Errorf("Source(%d,%d) = %v %v, want %v %v", c.s, c.e, got, exact, c.want, c.exact)
		}
	}
}

func TestSource(t *testing.T) {
	v := sample()
	if v.String() != "abc\n\xc3\xa9" {
		t.Fatalf("String = %q", v.String())
	}
	checkSource(t, v, []sourceCase{
		{0, 3, cst.Span{Start: 10, End: 13}, true},
		{1, 2, cst.Span{Start: 11, End: 12}, true},
		{3, 4, cst.Span{Start: 13, End: 19}, true},
		{2, 5, cst.Span{Start: 12, End: 20}, true},
		{0, 6, cst.Span{Start: 10, End: 21}, true},
		// the first byte of a copied "é" is exact.
		{4, 5, cst.Span{Start: 19, End: 20}, true},
	})
}

func TestSourceZeroWidth(t *testing.T) {
	checkSource(t, sample(), []sourceCase{
		{1, 1, cst.Span{Start: 11, End: 11}, true},
		{3, 3, cst.Span{Start: 13, End: 13}, true},
		{4, 4, cst.Span{Start: 19, End: 19}, true},
		{6, 6, cst.Span{Start: 21, End: 21}, true},
	})
	var b builder
	b.made(cst.Span{Start: 30, End: 34}, "\n\n") // two blank lines
	checkSource(t, b.value(), []sourceCase{
		{1, 1, cst.Span{Start: 30, End: 30}, false},
	})
}

func TestSourceInsideMade(t *testing.T) {
	var b builder
	b.verbatim(cst.Span{Start: 1, End: 2}, []byte("a"))
	b.made(cst.Span{Start: 2, End: 6}, "\xc3\xa9") // the escape \xe9
	b.made(cst.Span{Start: 6, End: 10}, "\n\n")    // two blank lines
	v := b.value()
	checkSource(t, v, []sourceCase{
		{1, 2, cst.Span{Start: 2, End: 6}, false},
		{2, 3, cst.Span{Start: 2, End: 6}, false},
		{0, 2, cst.Span{Start: 1, End: 6}, false},
		{3, 4, cst.Span{Start: 6, End: 10}, false},
		{1, 3, cst.Span{Start: 2, End: 6}, true},
		{1, 5, cst.Span{Start: 2, End: 10}, true},
	})
}

func TestSourceOutOfRange(t *testing.T) {
	checkSource(t, sample(), []sourceCase{
		{-1, 2, cst.Span{Start: 10, End: 12}, false},
		{4, 99, cst.Span{Start: 19, End: 21}, false},
		{5, 2, cst.Span{Start: 20, End: 20}, false},
		{-3, -1, cst.Span{Start: 10, End: 10}, false},
	})
}

func TestPosition(t *testing.T) {
	v := sample()
	cases := []struct {
		i    int
		want cst.Span
	}{
		{0, cst.Span{Start: 10, End: 11}},
		{2, cst.Span{Start: 12, End: 13}},
		{3, cst.Span{Start: 13, End: 19}},
		{4, cst.Span{Start: 19, End: 20}},
		{-1, cst.Span{Start: 10, End: 10}},
		{6, cst.Span{Start: 21, End: 21}},
		{100, cst.Span{Start: 21, End: 21}},
	}
	for _, c := range cases {
		if got := v.Position(c.i); got != c.want {
			t.Errorf("Position(%d) = %v, want %v", c.i, got, c.want)
		}
	}
}

func TestEmptyValue(t *testing.T) {
	b := builder{origin: 7}
	v := b.value()
	if v.String() != "" || len(v.segs) != 0 {
		t.Fatalf("empty value = %q with %d segments", v.String(), len(v.segs))
	}
	checkSource(t, v, []sourceCase{
		{0, 0, cst.Span{Start: 7, End: 7}, true},
		{0, 1, cst.Span{Start: 7, End: 7}, false},
	})
	if got := v.Position(0); got != (cst.Span{Start: 7, End: 7}) {
		t.Errorf("Position(0) = %v", got)
	}
}

func TestMerge(t *testing.T) {
	var b builder
	b.verbatim(cst.Span{Start: 0, End: 2}, []byte("ab"))
	b.verbatim(cst.Span{Start: 2, End: 4}, []byte("cd"))
	b.verbatim(cst.Span{Start: 5, End: 6}, []byte("e"))
	b.made(cst.Span{Start: 6, End: 7}, " ")
	b.made(cst.Span{Start: 7, End: 8}, " ")
	b.verbatim(cst.Span{Start: 8, End: 8}, nil)
	v := b.value()
	if len(v.segs) != 4 {
		t.Errorf("segments = %+v, want ab+cd merged, e, and two made", v.segs)
	}
	if v.String() != "abcde  " {
		t.Errorf("String = %q", v.String())
	}
}

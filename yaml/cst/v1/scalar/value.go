package scalar

import (
	"sort"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Value is a scalar's value with the input range each part of it comes from.
type Value struct {
	s      string
	segs   []segment
	origin int  // where an empty value is
	loose  bool // origin is no exact place for content (a block scalar)

	// Kept for rewriting the value later.
	style  cst.ScalarStyle
	indent int // block scalar content indentation
	chomp  Chomping
	node   cst.Node
}

// segment is a part of the value starting at at. A verbatim segment is src
// copied unchanged; any other segment was made from src (an escape, a line
// folding, a line break) and maps to src only as a whole. Segments cover
// the value without gaps, in order.
type segment struct {
	at       int32
	src      cst.Span
	verbatim bool
}

func (v Value) String() string { return v.s }

// Style, Indent and Node are what rewriting the value needs: the style,
// a block scalar's content indentation (0 without content lines), and the
// Scalar node.
func (v Value) Style() cst.ScalarStyle { return v.style }
func (v Value) Indent() int            { return v.indent }
func (v Value) Node() cst.Node         { return v.node }

// Source returns the smallest input range that contains the value's bytes
// [s,e). exact reports that the range corresponds to [s,e) byte for byte:
// it is false when [s,e) cuts a made segment or lies outside the value, in
// which case the range is that of the clamped [s,e) widened to whole
// segments, and for the empty value of a block scalar.
//
// exact is not that replacing the range keeps the rest of the value: in a
// block scalar the next line's indentation is in no segment, so removing a
// range that ends in a line feed indents the following line further.
func (v Value) Source(s, e int) (span cst.Span, exact bool) {
	exact = true
	n := len(v.s)
	if s < 0 {
		s, exact = 0, false
	}
	if s > n {
		s, exact = n, false
	}
	if e > n {
		e, exact = n, false
	}
	if e < s {
		e, exact = s, false
	}
	if s == e {
		p, ok := v.point(s)
		return cst.Span{Start: p, End: p}, exact && ok
	}
	start, ok1 := v.point(s)
	end, ok2 := v.end(e)
	return cst.Span{Start: start, End: end}, exact && ok1 && ok2
}

// Position returns the input range the value's byte i comes from: one byte
// of a verbatim segment, or all of a made one. Outside the value it is the
// empty range at the clamped position, as Source(i, i).
func (v Value) Position(i int) cst.Span {
	if i < 0 || i >= len(v.s) {
		sp, _ := v.Source(i, i)
		return sp
	}
	g := v.segs[v.find(i)]
	if !g.verbatim {
		return g.src
	}
	p := g.src.Start + i - int(g.at)
	return cst.Span{Start: p, End: p + 1}
}

// find is the index of the segment containing byte i, for 0 <= i < len.
func (v Value) find(i int) int {
	return sort.Search(len(v.segs), func(k int) bool { return int(v.segs[k].at) > i }) - 1
}

func (v Value) segEnd(k int) int {
	if k+1 < len(v.segs) {
		return int(v.segs[k+1].at)
	}
	return len(v.s)
}

// point maps the position before byte i; ok is false inside a made segment.
func (v Value) point(i int) (int, bool) {
	if len(v.segs) == 0 {
		return v.origin, !v.loose
	}
	if i == len(v.s) {
		return v.segs[len(v.segs)-1].src.End, true
	}
	g := v.segs[v.find(i)]
	if g.verbatim {
		return g.src.Start + i - int(g.at), true
	}
	return g.src.Start, i == int(g.at)
}

// end maps the position after byte e-1; ok is false inside a made segment.
func (v Value) end(e int) (int, bool) {
	k := v.find(e - 1)
	g := v.segs[k]
	if g.verbatim {
		return g.src.Start + e - int(g.at), true
	}
	return g.src.End, e == v.segEnd(k)
}

// builder makes a Value segment by segment. It is internal so that the
// segment layout can change; exporting it later does not break callers.
type builder struct {
	buf    []byte
	segs   []segment
	origin int
	loose  bool
}

// verbatim appends text, which is the input src unchanged. A segment that
// continues the previous verbatim one in the input extends it.
func (b *builder) verbatim(src cst.Span, text []byte) {
	if len(text) == 0 {
		return
	}
	if k := len(b.segs) - 1; k >= 0 && b.segs[k].verbatim && b.segs[k].src.End == src.Start {
		b.segs[k].src.End = src.End
	} else {
		b.segs = append(b.segs, segment{at: int32(len(b.buf)), src: src, verbatim: true})
	}
	b.buf = append(b.buf, text...)
}

// made appends text made from the input src.
func (b *builder) made(src cst.Span, text string) {
	if text == "" {
		return
	}
	b.segs = append(b.segs, segment{at: int32(len(b.buf)), src: src})
	b.buf = append(b.buf, text...)
}

func (b *builder) value() Value {
	return Value{s: string(b.buf), segs: b.segs, origin: b.origin, loose: b.loose}
}

package shell

import (
	"strconv"
	"strings"
)

// Read is a script tokenized once with the places at: its tree, as Parse
// makes it, and how bash reads each place, as Places tells it.
type Read struct {
	Script *Script
	Places []Place // nil when at is empty
}

// ReadAt reads script once for its tree and the places at. The tree does
// not depend on at (FuzzReadAtTree).
func ReadAt(script string, at []int) Read {
	return readAt(script, at, nil)
}

// readAt is ReadAt, whose places read the NameVisibility of the tree from m
// (Memo.Visibility).
func readAt(script string, at []int, m *Memo) Read {
	lx := tokenize(script, at)
	sc := parse(script, lx)
	r := Read{Script: sc}
	if len(at) > 0 {
		r.Places, _ = classifyWith(script, lx, sc, at, func() *NameVisibility { return m.functions(script, sc) })
	}
	return r
}

// Memo keeps the Read of each script and places, so that the analyses of
// an input read a script once. A nil Memo reads each time.
type Memo struct {
	reads map[memoKey]Read
	n     int // how many times it read, for the tests
	vis   map[*Script]*NameVisibility
	funcs map[*Script]*NameVisibility // readings of the definitions alone (functions)
}

type memoKey struct{ script, at string }

func NewMemo() *Memo {
	return &Memo{reads: map[memoKey]Read{}, vis: map[*Script]*NameVisibility{}, funcs: map[*Script]*NameVisibility{}}
}

// functions is a NameVisibility of the tree sc whose Functions answer
// (readFlowOf without the variables), read once for m: the whole reading
// when m has one.
func (m *Memo) functions(script string, sc *Script) *NameVisibility {
	if m == nil {
		return readFlowOf(script, sc, false)
	}
	if v, ok := m.vis[sc]; ok {
		return v
	}
	if v, ok := m.funcs[sc]; ok {
		return v
	}
	v := readFlowOf(script, sc, false)
	m.funcs[sc] = v
	return v
}

// Visibility is NewNameVisibility(script, sc), read once for m and the
// tree sc (the readings hold the nodes of the tree they read).
func (m *Memo) Visibility(script string, sc *Script) *NameVisibility {
	if m == nil {
		return NewNameVisibility(script, sc)
	}
	if v, ok := m.vis[sc]; ok {
		return v
	}
	v := NewNameVisibility(script, sc)
	m.vis[sc] = v
	return v
}

// Read is ReadAt(script, at), read once for m.
func (m *Memo) Read(script string, at []int) Read {
	if m == nil {
		return ReadAt(script, at)
	}
	var b strings.Builder
	for _, a := range at {
		b.WriteString(strconv.Itoa(a))
		b.WriteByte(',')
	}
	k := memoKey{script, b.String()}
	if r, ok := m.reads[k]; ok {
		return r
	}
	r := readAt(script, at, m)
	m.reads[k] = r
	m.n++
	return r
}

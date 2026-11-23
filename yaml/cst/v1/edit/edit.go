package edit

import (
	"bytes"
	"fmt"
	"sort"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// Edit replaces the range Span of a tree's bytes with New. When Old is not
// nil, Apply refuses the edit unless the range holds Old, which catches an
// edit made from another version of the bytes.
type Edit struct {
	Span   cst.Span
	Old    []byte
	New    []byte
	want   *expect
	origin *cst.Tree // for an edit of Result.Inverse, the tree it gives back
}

// expect is the change an edit promises in the diff (check.go): a kind
// of change of node, a node of the old tree. For Replace and Rewrite, the
// scalar's value reads back as scalar says.
type expect struct {
	kind    ChangeKind
	node    cst.Node
	scalar  *scalarWant
	added   *addedWant
	set     Value   // SetValue: the node reads back as this
	comment *string // LineComment: the comment after the node, without "# "; "" for none
}

// addedWant is that the collection gets values, with keys for a mapping,
// in order between the elements before and after, nodes of the old tree
// (none at the start or the end).
type addedWant struct {
	keys          []string
	values        []Value
	before, after cst.Node
}

// scalarWant is that the scalar, whose value was old, reads back with its
// value's bytes [s,e) replaced by text. Edits of one scalar are checked
// together.
type scalarWant struct {
	old  string
	s, e int
	text string
}

// Result is the tree read back after Apply, the edits of its bytes that
// give back the original bytes, and the logical difference of the trees
// (diff.go). Apply does not check the syntax of what gives back exactly
// the bytes of the tree an Inverse was made from: they were read before,
// errors and all, which may be errors the edits had removed.
type Result struct {
	Tree    *cst.Tree
	Inverse []Edit
	Diff    []Change
	d       *differ
}

// Error is why Apply refused the edits. Edit is the index of the edit it
// concerns in the list given to Apply, or -1.
type Error struct {
	Edit   int
	Reason string
}

func (e *Error) Error() string {
	if e.Edit < 0 {
		return "edit: " + e.Reason
	}
	return fmt.Sprintf("edit %d: %s", e.Edit, e.Reason)
}

// placed is an edit in position order, with its index in the given list,
// where its replacement starts in the new bytes, and how far it and the
// edits before it move what follows.
type placed struct {
	Edit
	index int
	at    int
	delta int
}

// Apply applies edits, whose ranges are all in t's bytes, to a copy of
// them, and reads the copy back with t.Reparse. It refuses the whole list,
// leaving t as it is, when an edit is out of range or does not hold its
// Old, when two edits overlap or insert at the same place, or when the
// result fails a check (check.go).
func Apply(t *cst.Tree, edits []Edit) (Result, error) {
	src := t.Bytes()
	var ps []placed
	for i, e := range edits {
		if e.Span.Start < 0 || e.Span.Start > e.Span.End || e.Span.End > len(src) {
			return Result{}, &Error{i, fmt.Sprintf("range %v is outside the %d bytes", e.Span, len(src))}
		}
		if e.Old != nil && !bytes.Equal(src[e.Span.Start:e.Span.End], e.Old) {
			return Result{}, &Error{i, fmt.Sprintf("range %v holds %q, not %q", e.Span, src[e.Span.Start:e.Span.End], e.Old)}
		}
		if bytes.Equal(src[e.Span.Start:e.Span.End], e.New) {
			continue // it changes nothing, so it cannot conflict or break anything
		}
		ps = append(ps, placed{Edit: e, index: i})
	}
	// An insertion sorts before a replacement that starts at the same place.
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i].Span, ps[j].Span
		return a.Start < b.Start || a.Start == b.Start && a.End < b.End
	})
	for k := 1; k < len(ps); k++ {
		a, b := ps[k-1].Span, ps[k].Span
		if a.End > b.Start || a == b && a.Start == a.End {
			return Result{}, &Error{ps[k].index, fmt.Sprintf("range %v overlaps edit %d's %v", b, ps[k-1].index, a)}
		}
	}
	var buf []byte
	prev := 0
	for k := range ps {
		buf = append(buf, src[prev:ps[k].Span.Start]...)
		ps[k].at = len(buf)
		buf = append(buf, ps[k].New...)
		prev = ps[k].Span.End
		ps[k].delta = len(buf) - prev
	}
	buf = append(buf, src[prev:]...)
	nt := t.Reparse(buf)
	d, err := check(t, nt, ps)
	if err != nil {
		return Result{}, err
	}
	inv := make([]Edit, len(ps))
	for k, p := range ps {
		inv[k] = Edit{
			Span:   cst.Span{Start: p.at, End: p.at + len(p.New)},
			Old:    bytes.Clone(p.New),
			New:    bytes.Clone(src[p.Span.Start:p.Span.End]),
			origin: t,
		}
	}
	return Result{Tree: nt, Inverse: inv, Diff: d.changes, d: d}, nil
}

// shift maps pos, a position in the old bytes outside every edit's range,
// to the new bytes; ps is in position order, so the ends are too.
func shift(ps []placed, pos int) int {
	k := sort.Search(len(ps), func(k int) bool { return ps[k].Span.End > pos })
	if k == 0 {
		return pos
	}
	return pos + ps[k-1].delta
}

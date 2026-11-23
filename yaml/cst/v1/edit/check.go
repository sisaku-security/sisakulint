package edit

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// check is what Apply requires of the tree read back: no new syntax error,
// the values that the edits of Replace and Rewrite promise, and no change
// in the diff that neither an edit's promise nor a raw edit's range
// explains. It returns the diff.
func check(old, nt *cst.Tree, ps []placed) (*differ, error) {
	if !restores(nt, ps) {
		if err := checkSyntax(old, nt, ps); err != nil {
			return nil, err
		}
	}
	wants, err := scalarWants(ps)
	if err != nil {
		return nil, err
	}
	renamed := map[cst.Node]string{}
	for _, w := range wants {
		renamed[w.node] = w.value
	}
	d := diff(old, nt, ps, renamed)
	promised := map[cst.Node]bool{}
	for _, w := range wants {
		n, ok := d.pairs[w.node]
		if !ok || n.n.Kind() != cst.NodeScalar {
			return nil, &Error{w.index, "the scalar is no scalar after reading back"}
		}
		if v, _ := scalar.Decode(n.n); v.String() != w.value {
			return nil, &Error{w.index, fmt.Sprintf("the value reads back as %q, not %q", v.String(), w.value)}
		}
		promised[w.node] = true
	}
	explained := make([]bool, len(d.changes))
	raw := rawEdits(ps)
	for _, p := range ps {
		var err error
		switch w := p.want; {
		case w == nil:
		case w.added != nil:
			err = d.checkAdded(p, explained)
		case w.kind == Removed:
			err = d.checkRemoved(p, explained)
		case w.set != nil:
			err = d.checkSet(p, explained)
		case w.comment != nil:
			err = d.checkComment(p)
		}
		if err != nil {
			return nil, err
		}
	}
	for k, c := range d.changes {
		if explained[k] || c.Kind == Changed && promised[c.Old] || rawReach(raw, c) {
			continue
		}
		at := -1
		if c.New != (cst.Node{}) {
			at = editAt(ps, c.New.Span().Start)
		}
		return nil, &Error{at, fmt.Sprintf("the result changes %s (%v), which no edit promises", c.Path, c.Kind)}
	}
	return d, nil
}

// scalarGroup groups the edits of one scalar: the value they promise
// together, and the first of them in the list given to Apply.
type scalarGroup struct {
	node  cst.Node
	value string
	index int
}

// scalarWants applies the replacements of the edits of each scalar to its
// old value.
func scalarWants(ps []placed) ([]scalarGroup, error) {
	groups := map[cst.Node][]placed{}
	var order []cst.Node
	for _, p := range ps {
		if p.want == nil || p.want.scalar == nil {
			continue
		}
		if _, ok := groups[p.want.node]; !ok {
			order = append(order, p.want.node)
		}
		groups[p.want.node] = append(groups[p.want.node], p)
	}
	var out []scalarGroup
	for _, node := range order {
		g := groups[node]
		sort.SliceStable(g, func(i, j int) bool { return g[i].want.scalar.s < g[j].want.scalar.s })
		old := g[0].want.scalar.old
		var b strings.Builder
		prev := 0
		first := g[0].index
		for _, p := range g {
			w := p.want.scalar
			if w.s < prev { // their ranges in the bytes overlap too, which Apply refused
				return nil, &Error{p.index, "two edits of one scalar overlap in its value"}
			}
			b.WriteString(old[prev:w.s])
			b.WriteString(w.text)
			prev = w.e
			first = min(first, p.index)
		}
		b.WriteString(old[prev:])
		out = append(out, scalarGroup{node, b.String(), first})
	}
	return out, nil
}

// rawReach is whether c touches the range of an edit of raw, the edits
// that promise nothing: in the old bytes for its old node, in the new for
// its new one.
func rawReach(raw []placed, c Change) bool {
	return c.Old != (cst.Node{}) && touched(raw, c.Old.Span()) ||
		c.New != (cst.Node{}) && touchedNew(raw, c.New.Span())
}

// rawEdits are the edits of ps that promise nothing, in position order.
func rawEdits(ps []placed) []placed {
	var raw []placed
	for _, p := range ps {
		if p.want == nil {
			raw = append(raw, p)
		}
	}
	return raw
}

// overlaps is whether a and b share a byte or a boundary.
func overlaps(a, b cst.Span) bool { return a.Start <= b.End && b.Start <= a.End }

type errorKey struct {
	code         cst.ErrorCode
	start, width int
}

// checkSyntax requires every error of nt to be an error of old moved by
// the edits. An error that an edit touches, even at its ends, is not
// expected to stay: the edit may have changed it.
func checkSyntax(old, nt *cst.Tree, ps []placed) error {
	want := map[errorKey]int{}
	for _, e := range old.Errors() {
		if touched(ps, e.Span) {
			continue
		}
		want[errorKey{e.Code, shift(ps, e.Span.Start), e.Span.End - e.Span.Start}]++
	}
	for _, e := range nt.Errors() {
		k := errorKey{e.Code, e.Span.Start, e.Span.End - e.Span.Start}
		if want[k] > 0 {
			want[k]--
			continue
		}
		return &Error{editAt(ps, e.Span.Start), fmt.Sprintf("the result has a new error at offset %d: %s", e.Span.Start, e.Msg)}
	}
	return nil
}

// touched is whether the range of an edit of ps overlaps sp in the old
// bytes. The edits are in position order and do not overlap, so their
// ends are in order too: the first that ends at or after sp starts is the
// only one to look at.
func touched(ps []placed, sp cst.Span) bool {
	k := sort.Search(len(ps), func(k int) bool { return ps[k].Span.End >= sp.Start })
	return k < len(ps) && overlaps(ps[k].Span, sp)
}

// touchedNew is touched for the replacements of ps in the new bytes.
func touchedNew(ps []placed, sp cst.Span) bool {
	k := sort.Search(len(ps), func(k int) bool { return ps[k].at+len(ps[k].New) >= sp.Start })
	return k < len(ps) && overlaps(cst.Span{Start: ps[k].at, End: ps[k].at + len(ps[k].New)}, sp)
}

// editAt is the index of the edit whose replacement contains pos in the
// new bytes, or -1.
func editAt(ps []placed, pos int) int {
	for _, p := range ps {
		if p.at <= pos && pos <= p.at+len(p.New) {
			return p.index
		}
	}
	return -1
}

// restores reports that ps are edits of one Inverse and give back exactly
// the bytes of the tree it was made from.
func restores(nt *cst.Tree, ps []placed) bool {
	if len(ps) == 0 || ps[0].origin == nil {
		return false
	}
	for _, p := range ps {
		if p.origin != ps[0].origin {
			return false
		}
	}
	return bytes.Equal(nt.Bytes(), ps[0].origin.Bytes())
}

// checkAdded finds the elements an Insert or an InsertItem promises in the
// new collection, right after the element that followed from before (or
// first), and right before the one that followed from after (or last),
// and marks their Added changes explained.
func (d *differ) checkAdded(p placed, explained []bool) error {
	w := p.want.added
	nc, ok := d.pairs[p.want.node]
	if !ok {
		return &Error{p.index, "the collection is gone after reading back"}
	}
	elems, at := d.elements(nc.n)
	j := 0
	if w.before != (cst.Node{}) {
		nb, ok := d.follow(w.before)
		k, found := at[nb]
		if !ok || !found {
			return &Error{p.index, "the element before the new ones is gone after reading back"}
		}
		j = k + 1
	}
	if j+len(w.values) > len(elems) {
		return &Error{p.index, fmt.Sprintf("%d elements, not the %d promised after the one before", len(elems)-j, len(w.values))}
	}
	for n, v := range w.values {
		e := elems[j+n]
		k := d.changeOf(Added, e)
		if k < 0 || explained[k] {
			return &Error{p.index, fmt.Sprintf("element %d is not a new one after reading back", j+n)}
		}
		value := e
		if w.keys != nil {
			entry := pairOfEntry(e)
			if got := keyText(entry.Key); got != w.keys[n] {
				return &Error{p.index, fmt.Sprintf("the new key reads back as %q, not %q", got, w.keys[n])}
			}
			value = entry.Value
		}
		if err := sameValue(value, v); err != nil {
			return &Error{p.index, fmt.Sprintf("the new element %d reads back otherwise: %v", j+n, err)}
		}
		explained[k] = true
	}
	next := j + len(w.values)
	if w.after == (cst.Node{}) {
		if next != len(elems) {
			return &Error{p.index, "the new elements are not the last after reading back"}
		}
		return nil
	}
	if na, ok := d.follow(w.after); !ok || next >= len(elems) || elems[next] != na {
		return &Error{p.index, "the element after the new ones is not where it was after reading back"}
	}
	return nil
}

// elements is elementsOf(c) and the index of each, found once for each c.
func (d *differ) elements(c cst.Node) ([]cst.Node, map[cst.Node]int) {
	if x, ok := d.colls[c]; ok {
		return x.elems, x.at
	}
	x := elementIndex{elems: elementsOf(c), at: map[cst.Node]int{}}
	for i, n := range x.elems {
		if _, dup := x.at[n]; !dup {
			x.at[n] = i
		}
	}
	if d.colls == nil {
		d.colls = map[cst.Node]elementIndex{}
	}
	d.colls[c] = x
	return x.elems, x.at
}

type elementIndex struct {
	elems []cst.Node
	at    map[cst.Node]int
}

// elementsOf is the entries of a mapping or the items of a sequence.
func elementsOf(c cst.Node) []cst.Node {
	if _, ok := c.Mapping(); ok {
		var out []cst.Node
		for _, e := range entriesOf(c) {
			out = append(out, e.Node)
		}
		return out
	}
	return itemsOf(c)
}

// changeOf is the first change of kind k whose old or new node is n, or -1.
func (d *differ) changeOf(k ChangeKind, n cst.Node) int {
	if d.byNode == nil {
		d.byNode = map[nodeChange]int{}
		for i, c := range d.changes {
			for _, x := range [2]cst.Node{c.Old, c.New} {
				if _, ok := d.byNode[nodeChange{c.Kind, x}]; !ok && x != (cst.Node{}) {
					d.byNode[nodeChange{c.Kind, x}] = i
				}
			}
		}
	}
	if i, ok := d.byNode[nodeChange{k, n}]; ok {
		return i
	}
	return -1
}

type nodeChange struct {
	kind ChangeKind
	node cst.Node
}

// pairOfEntry is the key and value of an entry of a mapping.
func pairOfEntry(e cst.Node) cst.Entry {
	if e.Kind() == cst.NodeFlowPair {
		m, _ := e.Mapping()
		for x := range m.Entries() {
			return x
		}
	}
	return pairOf(e)
}

// checkRemoved finds the Removed change of the element a Delete removes.
func (d *differ) checkRemoved(p placed, explained []bool) error {
	k := d.changeOf(Removed, p.want.node)
	if k < 0 || explained[k] {
		return &Error{p.index, "the element is still there after reading back"}
	}
	explained[k] = true
	return nil
}

// checkSet requires the node a SetValue replaces to read back as its value,
// and marks the changes in the node, old or new, explained.
func (d *differ) checkSet(p placed, explained []bool) error {
	old := p.want.node
	np, ok := d.pairs[old]
	if !ok {
		return &Error{p.index, "the value is gone after reading back"}
	}
	if err := sameValue(np.n, p.want.set); err != nil {
		return &Error{p.index, fmt.Sprintf("the value reads back otherwise: %v", err)}
	}
	if d.byOld == nil {
		d.byOld = byStart(d.changes, func(c Change) cst.Node { return c.Old })
		d.byNew = byStart(d.changes, func(c Change) cst.Node { return c.New })
	}
	explainWithin(d.changes, d.byOld, func(c Change) cst.Node { return c.Old }, old.Span(), explained)
	explainWithin(d.changes, d.byNew, func(c Change) cst.Node { return c.New }, np.n.Span(), explained)
	return nil
}

func within(a, b cst.Span) bool { return b.Start <= a.Start && a.End <= b.End }

// byStart is the indexes of the changes that have a node of(c), in the
// order of where that node starts.
func byStart(cs []Change, of func(Change) cst.Node) []int {
	var idx []int
	for i, c := range cs {
		if of(c) != (cst.Node{}) {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return of(cs[idx[a]]).Span().Start < of(cs[idx[b]]).Span().Start })
	return idx
}

// explainWithin marks explained the changes whose node of(c) lies within
// sp: those of idx, made by byStart, that start in sp and end in it.
func explainWithin(cs []Change, idx []int, of func(Change) cst.Node, sp cst.Span, explained []bool) {
	k := sort.Search(len(idx), func(k int) bool { return of(cs[idx[k]]).Span().Start >= sp.Start })
	for ; k < len(idx); k++ {
		n := of(cs[idx[k]])
		if n.Span().Start > sp.End {
			break
		}
		if within(n.Span(), sp) {
			explained[idx[k]] = true
		}
	}
}

// checkComment requires the comment a LineComment promises after its node
// in the new tree. The change it promises is none: every change in the
// diff must be explained by something else.
func (d *differ) checkComment(p placed) error {
	n, ok := d.follow(p.want.node)
	if !ok {
		return &Error{p.index, "the node is gone after reading back"}
	}
	src := treeBytes(n)
	hash, lineBreak, ok := trailing(src, n.ContentSpan().End)
	got := ""
	if hash >= 0 {
		got = string(src[hash:lineBreak])
	}
	if want := "# " + *p.want.comment; ok && (got == want || *p.want.comment == "" && got == "") {
		return nil
	}
	return &Error{p.index, fmt.Sprintf("the comment reads back as %q", got)}
}

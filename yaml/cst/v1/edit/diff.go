package edit

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// ChangeKind is what happened to a node of the logical tree.
type ChangeKind uint8

const (
	Added ChangeKind = iota + 1
	Removed
	Changed
)

func (k ChangeKind) String() string {
	switch k {
	case Added:
		return "Added"
	case Removed:
		return "Removed"
	case Changed:
		return "Changed"
	}
	return "ChangeKind(?)"
}

// Change is one difference of the logical trees before and after Apply:
// kinds of nodes, keys and values of mappings, items of sequences, values
// and tags of scalars, names of anchors and aliases. White space, comments
// and scalar styles are no difference. Old is a node of the old tree and
// New of the new one: for Added and Removed, the entry of a mapping's key
// or the item of a sequence; for Changed, the nodes at Path.
type Change struct {
	Kind     ChangeKind
	Path     Path
	Old, New cst.Node
}

// Path leads from a document's content to a node.
type Path []PathElem

// PathElem is a mapping key when Index is -1, and a sequence index
// otherwise. A key that is no scalar is its source text.
type PathElem struct {
	Key   string
	Index int
}

// String writes keys of letters, digits, '_' and '-' after a '.', other
// keys quoted in brackets, and indexes in brackets:
// jobs.build.steps[0].env["A.B"].
func (p Path) String() string {
	var b strings.Builder
	for i, e := range p {
		switch {
		case e.Index >= 0:
			fmt.Fprintf(&b, "[%d]", e.Index)
		case isName(e.Key):
			if i > 0 {
				b.WriteByte('.')
			}
			b.WriteString(e.Key)
		default:
			fmt.Fprintf(&b, "[%q]", e.Key)
		}
	}
	return b.String()
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (p Path) key(k string) Path { return append(p[:len(p):len(p)], PathElem{Key: k, Index: -1}) }
func (p Path) index(i int) Path  { return append(p[:len(p):len(p)], PathElem{Index: i}) }

// differ pairs the nodes of the old tree with those of the new one and
// collects the changes. A node that no edit's range reaches into and whose
// bytes are the same is the same subtree: it is paired whole, and its
// descendants are found when asked for (follow). Other nodes are compared:
// mapping entries by key, sequence items by the items paired whole around
// them and then in order.
type differ struct {
	ps      []placed
	old     cst.Node // the old tree's root
	pairs   map[cst.Node]pair
	changes []Change
	renamed map[cst.Node]string // keys an edit promises a new value

	// Indexes of changes, made when a check first needs them (check.go).
	byNode       map[nodeChange]int
	byOld, byNew []int
	colls        map[cst.Node]elementIndex // the elements of new collections
}

type pair struct {
	n     cst.Node
	whole bool // the same subtree
}

func diff(old, nt *cst.Tree, ps []placed, renamed map[cst.Node]string) *differ {
	d := &differ{ps: ps, old: old.Root(), pairs: map[cst.Node]pair{}, renamed: renamed}
	d.node(old.Root(), nt.Root(), nil)
	pos := func(c Change) int {
		if c.Kind == Removed {
			return d.newPos(c.Old.Span().Start)
		}
		return c.New.Span().Start
	}
	sort.SliceStable(d.changes, func(i, j int) bool { return pos(d.changes[i]) < pos(d.changes[j]) })
	return d
}

// reached is whether an edit's range reaches into sp: overlaps it, or
// inserts strictly inside it. The edits are in position order and do not
// overlap, so the first that ends after sp starts is the only one to look
// at.
func (d *differ) reached(sp cst.Span) bool {
	k := sort.Search(len(d.ps), func(k int) bool { return d.ps[k].Span.End > sp.Start })
	return k < len(d.ps) && d.ps[k].Span.Start < sp.End
}

// replaces is whether an edit replaces the byte at pos.
func (d *differ) replaces(pos int) bool {
	k := sort.Search(len(d.ps), func(k int) bool { return d.ps[k].Span.End > pos })
	return k < len(d.ps) && d.ps[k].Span.Start <= pos
}

// newPos maps an old position to the new bytes; inside an edit's range,
// to where its replacement starts.
func (d *differ) newPos(pos int) int {
	k := sort.Search(len(d.ps), func(k int) bool { return d.ps[k].Span.End > pos })
	if k < len(d.ps) && d.ps[k].Span.Start <= pos {
		return d.ps[k].at
	}
	return shift(d.ps, pos)
}

func (d *differ) same(o, n cst.Node) bool {
	return !d.reached(o.Span()) && o.Kind() == n.Kind() && bytes.Equal(o.Bytes(), n.Bytes())
}

func (d *differ) change(k ChangeKind, path Path, o, n cst.Node) {
	d.changes = append(d.changes, Change{Kind: k, Path: path, Old: o, New: n})
}

// node pairs o with n and compares them.
func (d *differ) node(o, n cst.Node, path Path) {
	if d.same(o, n) {
		d.pairs[o] = pair{n, true}
		return
	}
	d.pairs[o] = pair{n: n}
	if po, ok := propertiesOf(o); ok {
		if pn, ok := propertiesOf(n); ok {
			d.pairs[po] = pair{n: pn}
		}
	}
	ko, kn := kindOf(o), kindOf(n)
	if ko != kn {
		d.change(Changed, path, o, n)
		return
	}
	props := sameProperties(o, n)
	if !props && ko != cst.NodeScalar && ko != cst.NodeAlias {
		d.change(Changed, path, o, n)
	}
	switch ko {
	case cst.NodeStream:
		d.documents(o, n)
	case cst.NodeDocument:
		co, ok1 := contentOf(o)
		cn, ok2 := contentOf(n)
		if ok1 && ok2 {
			d.node(co, cn, path)
		} else if ok1 != ok2 {
			d.change(Changed, path, o, n)
		}
	case cst.NodeScalar:
		if !props || !sameScalar(o, n) {
			d.change(Changed, path, o, n)
		}
	case cst.NodeAlias:
		if !props || !bytes.Equal(bytes.TrimSpace(o.Bytes()), bytes.TrimSpace(n.Bytes())) {
			d.change(Changed, path, o, n)
		}
	case cst.NodeBlockMapping:
		d.entries(o, n, path)
	case cst.NodeBlockSequence:
		d.items(o, n, path)
	}
}

// kindOf is the logical kind: NodeBlockMapping stands for any mapping and
// NodeBlockSequence for any sequence.
func kindOf(n cst.Node) cst.NodeKind {
	if _, ok := n.Mapping(); ok {
		return cst.NodeBlockMapping
	}
	if _, ok := n.Sequence(); ok {
		return cst.NodeBlockSequence
	}
	return n.Kind()
}

func propertiesOf(n cst.Node) (cst.Node, bool) {
	for e := range n.Children() {
		if c, ok := e.Node(); ok {
			return c, c.Kind() == cst.NodeProperties
		}
	}
	return cst.Node{}, false
}

func sameProperties(o, n cst.Node) bool {
	ao, _ := o.Anchor()
	an, _ := n.Anchor()
	to, _ := o.Tag()
	tn, _ := n.Tag()
	return string(tokenBytes(ao)) == string(tokenBytes(an)) && string(tokenBytes(to)) == string(tokenBytes(tn))
}

func tokenBytes(t cst.Token) []byte {
	if t == (cst.Token{}) {
		return nil
	}
	return t.Bytes()
}

func sameScalar(o, n cst.Node) bool {
	vo, _ := scalar.Decode(o)
	vn, _ := scalar.Decode(n)
	return vo.String() == vn.String() &&
		scalar.Resolve(o, scalar.DirectivesOf(documentOf(o))) == scalar.Resolve(n, scalar.DirectivesOf(documentOf(n)))
}

func contentOf(doc cst.Node) (cst.Node, bool) {
	for e := range doc.Children() {
		if c, ok := e.Node(); ok && c.Kind() != cst.NodeDirective && c.Kind() != cst.NodeError {
			return c, true
		}
	}
	return cst.Node{}, false
}

func (d *differ) documents(o, n cst.Node) {
	var od, nd []cst.Node
	for e := range o.Children() {
		if c, ok := e.Node(); ok && c.Kind() == cst.NodeDocument {
			od = append(od, c)
		}
	}
	for e := range n.Children() {
		if c, ok := e.Node(); ok && c.Kind() == cst.NodeDocument {
			nd = append(nd, c)
		}
	}
	for i := range max(len(od), len(nd)) {
		switch {
		case i >= len(nd):
			d.change(Removed, nil, od[i], cst.Node{})
		case i >= len(od):
			d.change(Added, nil, cst.Node{}, nd[i])
		default:
			d.node(od[i], nd[i], nil)
		}
	}
}

// keyText is a key's value as a string, or its source text when it is no
// scalar.
func keyText(k cst.Node) string {
	if k.Kind() == cst.NodeScalar {
		v, _ := scalar.Decode(k)
		return v.String()
	}
	return string(contentBytes(k))
}

// oldKey is the key an old key is expected to be in the new tree: the
// value an edit promises it, or, for a key that is no scalar, its source
// text with the edits inside it applied.
func (d *differ) oldKey(k cst.Node) string {
	if s, ok := d.renamed[k]; ok {
		return s
	}
	if k.Kind() == cst.NodeScalar {
		return keyText(k)
	}
	sp := k.ContentSpan()
	src := treeBytes(k)
	var b []byte
	prev := sp.Start
	// ps is in position order: the edits inside sp are among those from
	// the first that starts in it.
	first := sort.Search(len(d.ps), func(i int) bool { return d.ps[i].Span.Start >= sp.Start })
	for _, p := range d.ps[first:] {
		if p.Span.Start > sp.End {
			break
		}
		if p.Span.End > sp.End {
			continue
		}
		b = append(append(b, src[prev:p.Span.Start]...), p.New...)
		prev = p.Span.End
	}
	return string(append(b, src[prev:sp.End]...))
}

// entries pairs the entries of two mappings: first those paired whole by
// position, then the rest by key, a repeated key in order.
func (d *differ) entries(o, n cst.Node, path Path) {
	oe, ne := entriesOf(o), entriesOf(n)
	at := make([]int, len(oe))
	used := make([]bool, len(ne))
	byStart := map[int]int{}
	for j, e := range ne {
		byStart[e.Node.Span().Start] = j
	}
	for i, e := range oe {
		at[i] = -1
		if j, ok := byStart[d.newPos(e.Node.Span().Start)]; ok && !used[j] && d.same(e.Node, ne[j].Node) {
			at[i], used[j] = j, true
		}
	}
	var byKey map[string][]int // the new entries of each key, in order; made when needed
	for i, e := range oe {
		if at[i] >= 0 {
			continue
		}
		if byKey == nil {
			byKey = make(map[string][]int, len(ne))
			for j, x := range ne {
				k := keyText(x.Key)
				byKey[k] = append(byKey[k], j)
			}
		}
		k := d.oldKey(e.Key)
		js := byKey[k]
		for len(js) > 0 && used[js[0]] {
			js = js[1:]
		}
		if len(js) > 0 {
			at[i], used[js[0]] = js[0], true
			js = js[1:]
		}
		byKey[k] = js
	}
	// Keys that are no scalar and found no match are paired in order: the
	// edits inside such a key may reach past its content, as a line added
	// to a key that is a block sequence.
	j := 0
	for i, e := range oe {
		if at[i] >= 0 || e.Key.Kind() == cst.NodeScalar {
			continue
		}
		for j < len(ne) && (used[j] || ne[j].Key.Kind() == cst.NodeScalar) {
			j++
		}
		if j < len(ne) {
			at[i], used[j] = j, true
		}
	}
	for i, e := range oe {
		if at[i] < 0 {
			d.change(Removed, path.key(keyText(e.Key)), e.Node, cst.Node{})
			continue
		}
		m := ne[at[i]]
		if d.same(e.Node, m.Node) {
			d.pairs[e.Node] = pair{m.Node, true}
			continue
		}
		k := path.key(keyText(m.Key))
		d.pairs[e.Node] = pair{n: m.Node}
		d.node(e.Key, m.Key, k)
		d.node(e.Value, m.Value, k)
	}
	for j, e := range ne {
		if !used[j] {
			d.change(Added, path.key(keyText(e.Key)), cst.Node{}, e.Node)
		}
	}
}

func entriesOf(n cst.Node) []cst.Entry {
	m, _ := n.Mapping()
	var out []cst.Entry
	for e := range m.Entries() {
		out = append(out, e)
	}
	return out
}

// items pairs the items of two sequences: those at the same place, paired
// whole or starting where no edit replaced bytes, mark the places, and
// the items between two of them are paired in order; the ones left over
// were removed or added.
func (d *differ) items(o, n cst.Node, path Path) {
	oi, ni := itemsOf(o), itemsOf(n)
	byStart := map[int]int{}
	for j, x := range ni {
		byStart[x.Span().Start] = j
	}
	type mark struct{ i, j int }
	var marks []mark
	for i, x := range oi {
		start := x.Span().Start
		j, ok := byStart[d.newPos(start)]
		if !ok || len(marks) > 0 && j <= marks[len(marks)-1].j {
			continue
		}
		// An item no edit replaces the start of is where it was, even
		// when an edit inside it changed it.
		if d.same(x, ni[j]) || !d.replaces(start) {
			marks = append(marks, mark{i, j})
		}
	}
	marks = append(marks, mark{len(oi), len(ni)})
	pi, pj := 0, 0
	for _, m := range marks {
		for pi < m.i && pj < m.j {
			d.item(oi[pi], ni[pj], path.index(pj))
			pi, pj = pi+1, pj+1
		}
		for ; pi < m.i; pi++ {
			d.change(Removed, path.index(pi), oi[pi], cst.Node{})
		}
		for ; pj < m.j; pj++ {
			d.change(Added, path.index(pj), cst.Node{}, ni[pj])
		}
		if m.i < len(oi) {
			d.item(oi[m.i], ni[m.j], path.index(m.j))
			pi, pj = m.i+1, m.j+1
		}
	}
}

func (d *differ) item(o, n cst.Node, path Path) {
	po, ok1 := o.Parent()
	pn, ok2 := n.Parent()
	if ok1 && ok2 && po.Kind() == cst.NodeBlockSequenceEntry && pn.Kind() == cst.NodeBlockSequenceEntry {
		d.pairs[po] = pair{pn, d.same(po, pn)}
	}
	d.node(o, n, path)
}

func itemsOf(n cst.Node) []cst.Node {
	s, _ := n.Sequence()
	var out []cst.Node
	for x := range s.Items() {
		out = append(out, x)
	}
	return out
}

// follow is the node of the new tree paired with old, a node of the old
// tree: from the pairs made, or, below a subtree paired whole, the child
// in the same place in the paired subtree. The place is the index among
// the children: an empty key and an empty value can start at one offset.
func (d *differ) follow(old cst.Node) (cst.Node, bool) {
	if p, ok := d.pairs[old]; ok {
		return p.n, true
	}
	parent, ok := old.Parent()
	if !ok {
		return cst.Node{}, false
	}
	np, ok := d.follow(parent)
	if !ok || !d.wholeBelow(parent) {
		return cst.Node{}, false
	}
	k := 0
	for e := range parent.Children() {
		if c, ok := e.Node(); ok {
			if c == old {
				break
			}
			k++
		}
	}
	for e := range np.Children() {
		c, ok := e.Node()
		if !ok {
			continue
		}
		if k == 0 {
			return c, c.Kind() == old.Kind() && len(c.Bytes()) == len(old.Bytes())
		}
		k--
	}
	return cst.Node{}, false
}

// wholeBelow is whether n lies in a subtree paired whole.
func (d *differ) wholeBelow(n cst.Node) bool {
	for {
		if p, ok := d.pairs[n]; ok {
			return p.whole
		}
		var ok bool
		if n, ok = n.Parent(); !ok {
			return false
		}
	}
}

// Follow is the node of r.Tree that old, a node of the tree Apply was
// given, became: the same entry, item or value, even when its kind
// changed. It is false for a node that was removed, and for a node of
// another tree.
func (r Result) Follow(old cst.Node) (cst.Node, bool) {
	if r.d == nil || rootOf(old) != r.d.old {
		return cst.Node{}, false
	}
	return r.d.follow(old)
}

func contentBytes(n cst.Node) []byte {
	sp := n.ContentSpan()
	return treeBytes(n)[sp.Start:sp.End]
}

func rootOf(n cst.Node) cst.Node {
	for {
		p, ok := n.Parent()
		if !ok {
			return n
		}
		n = p
	}
}

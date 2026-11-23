package edit

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// Editor makes the structural edits and the comments (Insert, InsertItem,
// Delete, SetValue, LineComment), and remembers what they find by looking
// through a whole document, tree or collection: the layout to write in
// (lines.go), the line break, the white space before a comment, where the
// aliases are, and the elements and keys of each collection it edits. Through one Editor, making edits of a tree takes time linear in
// their number; a new Editor for each edit looks through the document
// again, which for many edits of a large document is quadratic. There are
// no functions of these names for that reason. The zero Editor is ready
// to use. An Editor is not safe for concurrent use, and keeps what it
// found for every tree it has seen: use one for a round of edits of one
// tree.
type Editor struct {
	facts map[cst.Node]*facts // by document, or by the root for what is of the whole tree
}

// facts are what an Editor found in a document or a tree, each found when
// first needed.
type facts struct {
	layout  *docLayout
	nl      string
	gap     int              // commentGap, or -1 before it is found
	aliases map[string][]int // where the aliases of each name start, in order
	coll    *collection      // for a collection
}

// collection is what the operations look up in a collection: its
// elements as elementNodes gives them and the index of each; for a
// sequence, its items; for a mapping, its entries and the index of the
// first entry of each key.
type collection struct {
	elems   []cst.Node
	at      map[cst.Node]int
	items   []cst.Node
	entries []cst.Entry
	keys    map[string]int
}

// collection is what e found in the collection c, found once.
func (e *Editor) collection(c cst.Node) *collection {
	f := e.of(c)
	if f.coll == nil {
		x := &collection{elems: elementNodes(c), at: map[cst.Node]int{}}
		for i, el := range x.elems {
			x.at[el] = i
		}
		if _, ok := c.Mapping(); ok {
			x.entries = entriesOf(c)
			x.keys = map[string]int{}
			for i, en := range x.entries {
				if k := keyText(en.Key); !hasKey(x.keys, k) {
					x.keys[k] = i
				}
			}
		} else {
			x.items = itemsOf(c)
		}
		f.coll = x
	}
	return f.coll
}

func hasKey(m map[string]int, k string) bool {
	_, ok := m[k]
	return ok
}

func (e *Editor) of(n cst.Node) *facts {
	if e.facts == nil {
		e.facts = map[cst.Node]*facts{}
	}
	f, ok := e.facts[n]
	if !ok {
		f = &facts{gap: -1}
		e.facts[n] = f
	}
	return f
}

// docLayout is findDocLayout of doc, found once.
func (e *Editor) docLayout(doc cst.Node, src []byte) docLayout {
	f := e.of(doc)
	if f.layout == nil {
		l := findDocLayout(doc, src)
		f.layout = &l
	}
	return *f.layout
}

// newline is the first line break of the tree whose root is root and
// whose bytes are src, or "\n" when it has none.
func (e *Editor) newline(root cst.Node, src []byte) string {
	f := e.of(root)
	if f.nl == "" {
		f.nl = "\n"
		if i := bytes.IndexAny(src, "\r\n"); i >= 0 && bytes.HasPrefix(src[i:], []byte("\r\n")) {
			f.nl = "\r\n"
		}
	}
	return f.nl
}

// commentGap is the white space before the first comment in the tree
// that follows content on its line, or 1 when there is none.
func (e *Editor) commentGap(root cst.Node) int {
	f := e.of(root)
	if f.gap < 0 {
		f.gap = commentGap(root)
	}
	return f.gap
}

// aliasesOutside refuses to remove n when an alias outside it refers to
// an anchor inside it. An alias of the same name as such an anchor counts,
// even when another anchor of that name comes between: that refuses more
// than it needs to, and never less. The alias named is the first in the
// document.
func (e *Editor) aliasesOutside(n cst.Node) error {
	names := map[string]bool{}
	var visit func(x cst.Node)
	visit = func(x cst.Node) {
		if a, ok := x.Anchor(); ok {
			names[string(a.Bytes()[1:])] = true
		}
		for c := range x.Children() {
			if cn, ok := c.Node(); ok {
				visit(cn)
			}
		}
	}
	visit(n)
	if len(names) == 0 {
		return nil
	}
	aliases := e.aliasIndex(documentOf(n))
	sp := n.Span()
	found, at := "", -1
	for name := range names {
		starts := aliases[name]
		first := -1
		if len(starts) > 0 && starts[0] < sp.Start {
			first = starts[0]
		} else if k := sort.SearchInts(starts, sp.End); k < len(starts) {
			first = starts[k]
		}
		if first >= 0 && (at < 0 || first < at) {
			found, at = name, first
		}
	}
	if found != "" {
		return fmt.Errorf("the alias *%s outside refers to an anchor inside", found)
	}
	return nil
}

// aliasIndex is where the aliases of each name start in doc.
func (e *Editor) aliasIndex(doc cst.Node) map[string][]int {
	f := e.of(doc)
	if f.aliases == nil {
		f.aliases = map[string][]int{}
		var visit func(x cst.Node)
		visit = func(x cst.Node) {
			if x.Kind() == cst.NodeAlias {
				name := strings.TrimPrefix(string(bytes.TrimSpace(x.Bytes())), "*")
				f.aliases[name] = append(f.aliases[name], x.Span().Start)
			}
			for c := range x.Children() {
				if cn, ok := c.Node(); ok {
					visit(cn)
				}
			}
		}
		visit(doc)
	}
	return f.aliases
}

package anchor

import (
	"sort"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// Index holds, for each document, the nodes with an anchor by name.
type Index struct {
	docs map[cst.Node]map[string][]def
}

// def is a node with an anchor; at is where the anchor is.
type def struct {
	at   int
	node cst.Node
}

// Build indexes the anchors of t. The anchors of a name are in input order.
func Build(t *cst.Tree) Index {
	x := Index{docs: map[cst.Node]map[string][]def{}}
	for e := range t.Root().Children() {
		doc, ok := e.Node()
		if !ok || doc.Kind() != cst.NodeDocument {
			continue
		}
		names := map[string][]def{}
		var walk func(cst.Node)
		walk = func(n cst.Node) {
			if a, ok := n.Anchor(); ok {
				name := string(a.Bytes()[1:])
				names[name] = append(names[name], def{a.Span().Start, n})
			}
			for c := range n.Children() {
				if cn, ok := c.Node(); ok {
					walk(cn)
				}
			}
		}
		walk(doc)
		x.docs[doc] = names
	}
	return x
}

// Resolve returns the node that alias refers to: the latest one before it
// in its document with the same anchor. It follows one alias, so an alias
// inside the node it refers to (&a [*a]) is returned as is, without a
// loop. It is false when alias is no Alias node or has no definition.
func (x Index) Resolve(alias cst.Node) (cst.Node, bool) {
	if alias.Kind() != cst.NodeAlias {
		return cst.Node{}, false
	}
	defs := x.docs[documentOf(alias)][string(alias.Bytes()[1:])]
	at := alias.Span().Start
	i := sort.Search(len(defs), func(i int) bool { return defs[i].at >= at })
	if i == 0 {
		return cst.Node{}, false
	}
	return defs[i-1].node, true
}

func documentOf(n cst.Node) cst.Node {
	for n.Kind() != cst.NodeDocument {
		p, ok := n.Parent()
		if !ok {
			return n
		}
		n = p
	}
	return n
}

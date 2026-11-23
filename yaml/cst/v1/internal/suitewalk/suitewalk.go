// Package suitewalk visits a cst tree in the order of yaml-test-suite's
// events, for the tests of the packages above cst. It reads the tree only
// through the typed API, as cst's events_test.go does.
package suitewalk

import (
	"fmt"
	"iter"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
)

// Nodes yields the nodes that make a +MAP, +SEQ, =VAL or =ALI event, in
// event order, each with the index of its document.
func Nodes(tr *cst.Tree) iter.Seq2[int, cst.Node] {
	return func(yield func(int, cst.Node) bool) {
		doc := 0
		for e := range tr.Root().Children() {
			d, ok := e.Node()
			if !ok || d.Kind() != cst.NodeDocument {
				continue
			}
			for de := range d.Children() {
				c, ok := de.Node()
				if ok && c.Kind() != cst.NodeDirective && c.Kind() != cst.NodeError && !visit(c, doc, yield) {
					return
				}
			}
			doc++
		}
	}
}

func visit(n cst.Node, doc int, yield func(int, cst.Node) bool) bool {
	if !yield(doc, n) {
		return false
	}
	if m, ok := n.Mapping(); ok {
		for e := range m.Entries() {
			if !visit(e.Key, doc, yield) || !visit(e.Value, doc, yield) {
				return false
			}
		}
	}
	if s, ok := n.Sequence(); ok {
		for it := range s.Items() {
			if !visit(it, doc, yield) {
				return false
			}
		}
	}
	return true
}

// Event is a +MAP, +SEQ, =VAL or =ALI event with its node and the index of
// its document.
type Event struct {
	suitetest.Event
	Node cst.Node
	Doc  int
}

// Events pairs the node events of c with the nodes of tr, the tree of
// c.In, in order. It fails when their numbers differ.
func Events(c suitetest.Case, tr *cst.Tree) ([]Event, error) {
	var evs []Event
	for _, e := range c.Events {
		switch e.Type {
		case suitetest.EventMappingStart, suitetest.EventSequenceStart, suitetest.EventScalar, suitetest.EventAlias:
			evs = append(evs, Event{Event: e})
		}
	}
	i := 0
	for doc, n := range Nodes(tr) {
		if i < len(evs) {
			evs[i].Node, evs[i].Doc = n, doc
		}
		i++
	}
	if i != len(evs) {
		return nil, fmt.Errorf("%d node events, %d nodes", len(evs), i)
	}
	return evs, nil
}

package cst

import "iter"

// Mapping is a BlockMapping, FlowMapping or FlowPair node.
type Mapping struct{ n Node }

// Entry is one key/value pair. Node is the BlockMappingEntry or FlowPair.
// Key and Value are always nodes; an omitted one is an empty Scalar.
type Entry struct{ Node, Key, Value Node }

// Sequence is a BlockSequence or FlowSequence node.
type Sequence struct{ n Node }

type ScalarStyle uint8

const (
	Plain ScalarStyle = iota
	SingleQuoted
	DoubleQuoted
	Literal
	Folded
)

func (n Node) Mapping() (Mapping, bool) {
	switch n.Kind() {
	case NodeBlockMapping, NodeFlowMapping, NodeFlowPair:
		return Mapping{n}, true
	}
	return Mapping{}, false
}

func (n Node) Sequence() (Sequence, bool) {
	switch n.Kind() {
	case NodeBlockSequence, NodeFlowSequence:
		return Sequence{n}, true
	}
	return Sequence{}, false
}

func (n Node) IsFlow() bool {
	switch n.Kind() {
	case NodeFlowMapping, NodeFlowSequence, NodeFlowPair:
		return true
	}
	return false
}

// childNodes yields the child nodes other than Error and Properties.
func (n Node) childNodes() iter.Seq[Node] {
	return func(yield func(Node) bool) {
		for e := range n.Children() {
			c, ok := e.Node()
			if !ok || c.Kind() == NodeError || c.Kind() == NodeProperties {
				continue
			}
			if !yield(c) {
				return
			}
		}
	}
}

func pairOf(e Node) Entry {
	ent := Entry{Node: e}
	i := 0
	for c := range e.childNodes() {
		switch i {
		case 0:
			ent.Key = c
		case 1:
			ent.Value = c
		}
		i++
	}
	return ent
}

func (m Mapping) Entries() iter.Seq[Entry] {
	return func(yield func(Entry) bool) {
		if m.n.Kind() == NodeFlowPair {
			yield(pairOf(m.n))
			return
		}
		for c := range m.n.childNodes() {
			if c.Kind() != NodeBlockMappingEntry && c.Kind() != NodeFlowPair {
				continue
			}
			if !yield(pairOf(c)) {
				return
			}
		}
	}
}

// Items yields the item value nodes; a block entry's '-' is not included.
func (s Sequence) Items() iter.Seq[Node] {
	return func(yield func(Node) bool) {
		for c := range s.n.childNodes() {
			if c.Kind() == NodeBlockSequenceEntry {
				for v := range c.childNodes() {
					c = v
					break
				}
			}
			if !yield(c) {
				return
			}
		}
	}
}

func (n Node) property(k TokenKind) (Token, bool) {
	for e := range n.Children() {
		c, ok := e.Node()
		if !ok || c.Kind() != NodeProperties {
			continue
		}
		for t := range c.Tokens() {
			if t.Kind() == k {
				return t, true
			}
		}
		break
	}
	return Token{}, false
}

func (n Node) Anchor() (Token, bool) { return n.property(TokAnchor) }
func (n Node) Tag() (Token, bool)    { return n.property(TokTag) }

// Style is decided by the scalar's first content token; empty is Plain.
func (n Node) Style() ScalarStyle {
	for e := range n.Children() {
		t, ok := e.Token()
		if !ok {
			continue
		}
		switch t.Kind() {
		case TokSingleQuoted:
			return SingleQuoted
		case TokDoubleQuoted:
			return DoubleQuoted
		case TokBlockHeader:
			if t.Bytes()[0] == '>' {
				return Folded
			}
			return Literal
		case TokPlain:
			return Plain
		}
	}
	return Plain
}

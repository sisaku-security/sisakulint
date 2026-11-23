package cst

import (
	"strings"
	"testing"
)

func firstNode(n Node, k NodeKind) Node {
	for e := range n.Children() {
		if c, ok := e.Node(); ok {
			if c.Kind() == k {
				return c
			}
			if d := firstNode(c, k); d.t != nil {
				return d
			}
		}
	}
	return Node{}
}

func TestMappingEntries(t *testing.T) {
	// "a: b\n]]\n? c\n": second entry has an empty value; an Error node sits between
	tr := build(t, "a: b\n]]\n? c\n", func(b *builder) {
		b.n(NodeDocument, func() {
			b.n(NodeBlockMapping, func() {
				b.n(NodeBlockMappingEntry, func() {
					b.n(NodeScalar, func() { b.tok(TokPlain, "a") })
					b.tok(TokMapValue, ":")
					b.tok(TokSpace, " ")
					b.n(NodeScalar, func() { b.tok(TokPlain, "b") })
				})
				b.tok(TokNewline, "\n")
				b.n(NodeError, func() { b.tok(TokError, "]]") })
				b.tok(TokNewline, "\n")
				b.n(NodeBlockMappingEntry, func() {
					b.tok(TokMapKey, "?")
					b.tok(TokSpace, " ")
					b.n(NodeScalar, func() { b.tok(TokPlain, "c") })
					b.n(NodeScalar, nil)
				})
				b.tok(TokNewline, "\n")
			})
		})
	})
	m, ok := firstNode(tr.Root(), NodeBlockMapping).Mapping()
	if !ok {
		t.Fatal("BlockMapping is not a Mapping")
	}
	var got []string
	for e := range m.Entries() {
		got = append(got, e.Node.Kind().String()+":"+string(e.Key.Bytes())+"="+string(e.Value.Bytes()))
		if e.Value.Kind() != NodeScalar {
			t.Errorf("value kind %v", e.Value.Kind())
		}
	}
	if want := "BlockMappingEntry:a=b BlockMappingEntry:c="; strings.Join(got, " ") != want {
		t.Errorf("entries = %q, want %q", strings.Join(got, " "), want)
	}
	if firstNode(tr.Root(), NodeBlockMapping).IsFlow() {
		t.Error("BlockMapping IsFlow")
	}
	if _, ok := firstNode(tr.Root(), NodeScalar).Mapping(); ok {
		t.Error("Scalar is a Mapping")
	}
}

func TestSequenceItemsAndProperties(t *testing.T) {
	tr := build(t, "- a\n- &x !t 'b'\n", func(b *builder) {
		b.n(NodeDocument, func() {
			b.n(NodeBlockSequence, func() {
				b.n(NodeBlockSequenceEntry, func() {
					b.tok(TokSeqEntry, "-")
					b.tok(TokSpace, " ")
					b.n(NodeScalar, func() { b.tok(TokPlain, "a") })
				})
				b.tok(TokNewline, "\n")
				b.n(NodeBlockSequenceEntry, func() {
					b.tok(TokSeqEntry, "-")
					b.tok(TokSpace, " ")
					b.n(NodeScalar, func() {
						b.n(NodeProperties, func() {
							b.tok(TokAnchor, "&x")
							b.tok(TokSpace, " ")
							b.tok(TokTag, "!t")
						})
						b.tok(TokSpace, " ")
						b.tok(TokSingleQuoted, "'b'")
					})
				})
				b.tok(TokNewline, "\n")
			})
		})
	})
	s, ok := firstNode(tr.Root(), NodeBlockSequence).Sequence()
	if !ok {
		t.Fatal("BlockSequence is not a Sequence")
	}
	var items []Node
	for n := range s.Items() {
		items = append(items, n)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d", len(items))
	}
	if items[0].Style() != Plain || items[1].Style() != SingleQuoted {
		t.Errorf("styles = %v %v", items[0].Style(), items[1].Style())
	}
	if a, ok := items[1].Anchor(); !ok || string(a.Bytes()) != "&x" {
		t.Errorf("anchor = %q %v", a.Bytes(), ok)
	}
	if g, ok := items[1].Tag(); !ok || string(g.Bytes()) != "!t" {
		t.Errorf("tag = %q %v", g.Bytes(), ok)
	}
	if _, ok := items[0].Anchor(); ok {
		t.Error("plain item has an anchor")
	}
}

func flowPairTree(t *testing.T) *Tree {
	return build(t, "[a: b, c]", func(b *builder) {
		b.n(NodeDocument, func() {
			b.n(NodeFlowSequence, func() {
				b.tok(TokFlowSeqStart, "[")
				b.n(NodeFlowPair, func() {
					b.n(NodeScalar, func() { b.tok(TokPlain, "a") })
					b.tok(TokMapValue, ":")
					b.tok(TokSpace, " ")
					b.n(NodeScalar, func() { b.tok(TokPlain, "b") })
				})
				b.tok(TokFlowEntry, ",")
				b.tok(TokSpace, " ")
				b.n(NodeScalar, func() { b.tok(TokPlain, "c") })
				b.tok(TokFlowSeqEnd, "]")
			})
		})
	})
}

func TestFlowPairInSequence(t *testing.T) {
	tr := flowPairTree(t)
	seqNode := firstNode(tr.Root(), NodeFlowSequence)
	if !seqNode.IsFlow() {
		t.Error("FlowSequence not IsFlow")
	}
	s, _ := seqNode.Sequence()
	var items []Node
	for n := range s.Items() {
		items = append(items, n)
	}
	if len(items) != 2 || items[0].Kind() != NodeFlowPair || items[1].Kind() != NodeScalar {
		t.Fatalf("items = %v", items)
	}
	m, ok := items[0].Mapping()
	if !ok || !items[0].IsFlow() {
		t.Fatal("FlowPair is not a flow Mapping")
	}
	n := 0
	for e := range m.Entries() {
		n++
		if e.Node.Kind() != NodeFlowPair || string(e.Key.Bytes()) != "a" || string(e.Value.Bytes()) != "b" {
			t.Errorf("entry = %v %q %q", e.Node.Kind(), e.Key.Bytes(), e.Value.Bytes())
		}
	}
	if n != 1 {
		t.Errorf("FlowPair entries = %d", n)
	}
}

func TestBlockScalarStyle(t *testing.T) {
	for _, c := range []struct {
		hdr  string
		want ScalarStyle
	}{{"|", Literal}, {">-", Folded}} {
		tr := build(t, c.hdr+"\n x\n", func(b *builder) {
			b.n(NodeDocument, func() {
				b.n(NodeScalar, func() {
					b.tok(TokBlockHeader, c.hdr)
					b.tok(TokNewline, "\n")
					b.tok(TokSpace, " ")
					b.tok(TokBlockContent, "x")
					b.tok(TokNewline, "\n")
				})
			})
		})
		if got := firstNode(tr.Root(), NodeScalar).Style(); got != c.want {
			t.Errorf("%s: Style = %v, want %v", c.hdr, got, c.want)
		}
	}
}

func TestEvents(t *testing.T) {
	var got []string
	for _, e := range events(flowPairTree(t)) {
		got = append(got, e.String())
	}
	want := "+STR|+DOC|+SEQ []|+MAP {}|=VAL :|=VAL :|-MAP|=VAL :|-SEQ|-DOC|-STR"
	if strings.Join(got, "|") != want {
		t.Errorf("events = %s\nwant     %s", strings.Join(got, "|"), want)
	}
}

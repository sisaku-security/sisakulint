package cst

import (
	"bytes"
	"fmt"
)

// validate checks the invariants of a tree.
func validate(t *Tree) error {
	if err := validateTokens(t); err != nil {
		return err
	}
	if err := validateNodes(t); err != nil {
		return err
	}
	var buf bytes.Buffer
	n := 0
	var walk func(Node)
	walk = func(nd Node) {
		for e := range nd.Children() {
			if c, ok := e.Node(); ok {
				walk(c)
				continue
			}
			k, _ := e.Token()
			buf.Write(k.Bytes())
			n++
		}
	}
	walk(t.Root())
	if n != len(t.tokens) {
		return fmt.Errorf("preorder walk visited %d tokens, want %d", n, len(t.tokens))
	}
	if !bytes.Equal(buf.Bytes(), t.src) {
		return fmt.Errorf("round-trip mismatch: got %q, want %q", buf.Bytes(), t.src)
	}
	return nil
}

func validateTokens(t *Tree) error {
	if len(t.tokens) == 0 {
		if len(t.src) != 0 {
			return fmt.Errorf("no tokens for %d bytes of input", len(t.src))
		}
		return nil
	}
	if t.tokens[0].start != 0 {
		return fmt.Errorf("first token starts at %d", t.tokens[0].start)
	}
	for i := 1; i < len(t.tokens); i++ {
		if t.tokens[i].start <= t.tokens[i-1].start {
			return fmt.Errorf("token %d starts at %d, not after token %d at %d", i, t.tokens[i].start, i-1, t.tokens[i-1].start)
		}
	}
	if last := t.tokens[len(t.tokens)-1].start; int(last) >= len(t.src) {
		return fmt.Errorf("last token starts at %d, input length %d", last, len(t.src))
	}
	return nil
}

func validateNodes(t *Tree) error {
	ns := t.nodes
	if len(ns) == 0 {
		return fmt.Errorf("no nodes")
	}
	r := ns[0]
	if r.kind != NodeStream || r.parent != -1 || r.tokStart != 0 || int(r.tokEnd) != len(t.tokens) || int(r.subtreeEnd) != len(ns) {
		return fmt.Errorf("bad root %+v", r)
	}
	for i := range ns {
		n := ns[i]
		if n.tokStart > n.tokEnd {
			return fmt.Errorf("node %d: tokStart %d > tokEnd %d", i, n.tokStart, n.tokEnd)
		}
		if int(n.subtreeEnd) <= i || int(n.subtreeEnd) > len(ns) {
			return fmt.Errorf("node %d: subtreeEnd %d out of range", i, n.subtreeEnd)
		}
		if i > 0 {
			p := n.parent
			if p < 0 || int(p) >= i {
				return fmt.Errorf("node %d: parent %d not before it", i, p)
			}
			pn := ns[p]
			if n.subtreeEnd > pn.subtreeEnd {
				return fmt.Errorf("node %d: subtree ends after parent %d's", i, p)
			}
			if n.tokStart < pn.tokStart || n.tokEnd > pn.tokEnd {
				return fmt.Errorf("node %d: tokens [%d,%d) outside parent %d's [%d,%d)", i, n.tokStart, n.tokEnd, p, pn.tokStart, pn.tokEnd)
			}
		}
		prevEnd := n.tokStart
		for j := int32(i) + 1; j < n.subtreeEnd; j = ns[j].subtreeEnd {
			c := ns[j]
			if int(c.parent) != i {
				return fmt.Errorf("node %d: child %d has parent %d", i, j, c.parent)
			}
			if c.tokStart < prevEnd {
				return fmt.Errorf("node %d: child %d starts at token %d before previous sibling ends at %d", i, j, c.tokStart, prevEnd)
			}
			prevEnd = c.tokEnd
		}
	}
	return nil
}

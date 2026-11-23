package ir

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/anchor"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// The path of an element is where a fingerprint of a finding (actions/lint)
// and a key of a summary (Key) say it is: the one implementation of both.

var plainKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// stepID is the form of a step's id GitHub accepts; only such an id stands
// for a step in a path, so that it never reads as an index.
var stepID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// Paths finds the paths of elements (Of), and keeps what it looks up in a tree
// to find them: the index of each item of a sequence, found once for the
// whole sequence, and the anchors. Without it, the path of each item of a
// sequence of n items takes time n, and the fixes of a workflow with n
// findings, each read again with all its findings, take n cubed.
type Paths struct {
	trees map[*cst.Tree]*treePaths
}

type treePaths struct {
	seqs    map[cst.Node]*seqInfo // by sequence
	anchors *anchor.Index
}

// seqInfo is what Paths look up in a sequence: the index of each entry and
// each value, the number of items, and how many steps have each id.
type seqInfo struct {
	index map[cst.Node]int
	n     int
	ids   map[string]int
}

// NewPaths is a Paths that has looked up nothing.
func NewPaths() *Paths { return &Paths{trees: map[*cst.Tree]*treePaths{}} }

// Of is the path of keys from the document to the element node of the
// tree t, reached through the aliases vias, outermost first: keys joined
// by dots, a key that is not letters, digits, - and _ as a JSON string in
// brackets, and an item of a sequence as its index in brackets. An item of
// steps or of a parallel group with an id is its id. An element reached
// through aliases has the path of the outermost alias, then the path from
// what each alias refers to down to the next alias, and at last down to
// the element. What an alias refers to is not read for an id, so an alias
// of a step with an id is its index.
func (p *Paths) Of(tree *cst.Tree, node cst.Node, vias []cst.Node) string {
	t := p.trees[tree]
	if t == nil {
		t = &treePaths{seqs: map[cst.Node]*seqInfo{}}
		p.trees[tree] = t
	}
	if len(vias) == 0 {
		return join(t.pathUp(node, cst.Node{}))
	}
	if t.anchors == nil {
		a := anchor.Build(tree)
		t.anchors = &a
	}
	parts := t.pathUp(vias[0], cst.Node{})
	for i, v := range vias {
		next := node
		if i+1 < len(vias) {
			next = vias[i+1]
		}
		top, ok := t.anchors.Resolve(v)
		if !ok {
			return join(t.pathUp(node, cst.Node{}))
		}
		parts = append(t.pathUp(next, top), parts...)
	}
	return join(parts)
}

// pathUp is the parts of the path from top (the document when top is the
// zero Node) down to n, from n up.
func (t *treePaths) pathUp(n, top cst.Node) []string {
	var parts []string
	cur := n
	for cur != top {
		p, ok := cur.Parent()
		if !ok {
			break
		}
		switch p.Kind() {
		case cst.NodeBlockMappingEntry, cst.NodeFlowPair:
			if k, ok := entryKey(p); ok {
				parts = append(parts, key(k))
			}
		case cst.NodeBlockSequenceEntry:
			if seq, ok := p.Parent(); ok {
				parts = append(parts, t.item(seq, p, cur))
			}
		case cst.NodeFlowSequence:
			parts = append(parts, t.item(p, cur, cur))
		}
		cur = p
	}
	return parts
}

func join(parts []string) string {
	var b strings.Builder
	for i := len(parts) - 1; i >= 0; i-- {
		if b.Len() > 0 && !strings.HasPrefix(parts[i], "[") {
			b.WriteByte('.')
		}
		b.WriteString(parts[i])
	}
	return b.String()
}

// entryKey is the key of the entry e, as text.
func entryKey(e cst.Node) (string, bool) {
	parent := e
	if e.Kind() == cst.NodeBlockMappingEntry {
		if p, ok := e.Parent(); ok {
			parent = p
		}
	}
	m, ok := parent.Mapping()
	if !ok {
		return "", false
	}
	for ent := range m.Entries() {
		if ent.Node == e {
			if v, ok := scalar.Decode(ent.Key); ok {
				return v.String(), true
			}
			return string(ent.Key.Bytes()), true
		}
	}
	return "", false
}

func key(k string) string {
	if plainKey.MatchString(k) {
		return k
	}
	q, _ := json.Marshal(k)
	return "[" + string(q) + "]"
}

// item is [index] of the item whose entry (or value, in a flow sequence)
// is entry in seq, or [id] when seq is the value of steps and the item has
// an id.
func (t *treePaths) item(seq, entry, value cst.Node) string {
	info, ok := t.seqs[seq]
	if !ok {
		s, ok := seq.Sequence()
		if !ok {
			return ""
		}
		info = &seqInfo{index: map[cst.Node]int{}, ids: map[string]int{}}
		for v := range s.Items() {
			info.index[v] = info.n
			if p, ok := v.Parent(); ok && p.Kind() == cst.NodeBlockSequenceEntry {
				info.index[p] = info.n
			}
			if id, ok := stepIDOf(seq, v); ok {
				info.ids[id]++
			}
			info.n++
		}
		t.seqs[seq] = info
	}
	// an id stands for a step only when no other step has it: GitHub
	// refuses two, but the input may be anyone's
	if id, ok := stepIDOf(seq, value); ok && info.ids[id] == 1 {
		return "[" + id + "]"
	}
	i, ok := info.index[value]
	if !ok {
		i, ok = info.index[entry]
	}
	if !ok { // past the last item
		i = info.n
	}
	return "[" + strconv.Itoa(i) + "]"
}

func stepIDOf(seq, value cst.Node) (string, bool) {
	e, ok := seq.Parent()
	if !ok {
		return "", false
	}
	if k, ok := entryKey(e); !ok || k != "steps" && k != "parallel" {
		return "", false
	}
	m, ok := value.Mapping()
	if !ok {
		return "", false
	}
	for ent := range m.Entries() {
		k, _ := scalar.Decode(ent.Key)
		if k.String() != "id" {
			continue
		}
		v, ok := scalar.Decode(ent.Value)
		if ok && stepID.MatchString(v.String()) {
			return v.String(), true
		}
	}
	return "", false
}

package workflow

import (
	"github.com/gh-intel/sisakulint/actions/expr"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// valKey is a value read against a definition: the node as written (an
// alias is its own node, so each use is its own value), the definition,
// the outermost alias the reader came through, and the contexts and the
// functions allowed there.
type valKey struct {
	n     cst.Node
	d     defID
	via   cst.Node
	names expr.Names
}

func keyOf(n cst.Node, p pos, d defID) valKey { return valKey{n, d, viaOf(p), p.names} }

// mapKey is a mapping matched against a definition: its content, the
// definition, and the outermost alias it was reached through.
type mapKey struct {
	n   cst.Node
	d   defID
	via cst.Node
}

func viaOf(p pos) cst.Node {
	if len(p.via) == 0 {
		return cst.Node{}
	}
	return p.via[0]
}

// checkRest checks, against the schema, what the typed reading of the
// document did not read: the values of the keys the model keeps as nodes,
// and the parts it does not read of the values it reads in part (defaults
// beyond run.shell, strategy beyond matrix). A value or a mapping the typed
// reading checked is not checked again, so that no diagnostic is reported
// twice; under a ${{ }} that stands for a collection nothing is checked.
//
// A value is walked once for each key. Through one alias, the key has the
// alias, so a problem is reported where each alias uses it, as the typed
// reading does. Through nested aliases (deep), it does not: what they stand
// for is walked once for each definition and contexts it is read against,
// and its problems are reported where it is first reached, else the walk
// grows with the paths through the aliases, which are exponentially many
// in their depth.
func (r *reader) checkRest(n cst.Node, p pos, d defID, deep bool) {
	k := keyOf(n, p, d)
	if deep {
		k.via = cst.Node{}
	}
	if r.walked[k] {
		return
	}
	r.walked[k] = true
	v, done := r.valued[keyOf(n, p, d)]
	if !done {
		v = r.value(n, p, d)
	}
	if v.st != Present {
		return
	}
	if len(v.p.via) > 1 {
		// only the outermost alias says where a problem is reported
		deep, v.p.via = true, v.p.via[:1:1]
	}
	switch v.kind {
	case valMapping:
		ents, done := r.mapped[mapKey{v.n, d, viaOf(v.p)}]
		if !done {
			ents, _, _ = r.mapping(v, d)
		}
		for i := range ents {
			// the value of a ${{ }} key is read against the definition
			// matchKeys gave it, with the contexts of the mapping
			if e := &ents[i]; !e.dup {
				r.checkRest(e.value, v.p, e.def, deep)
			}
		}
	case valSequence:
		seqs := ofKind(d, nil, kindSequence)
		if len(seqs) == 0 {
			return
		}
		item := schemaDefs[seqs[0]].item
		seq, _ := v.n.Sequence()
		for it := range seq.Items() {
			r.checkRest(it, v.p, item, deep)
		}
	}
}

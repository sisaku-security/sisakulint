package edit

import (
	"iter"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

func allScalars(tr *cst.Tree) iter.Seq[cst.Node] {
	return func(yield func(cst.Node) bool) {
		var walk func(cst.Node) bool
		walk = func(n cst.Node) bool {
			if n.Kind() == cst.NodeScalar && !yield(n) {
				return false
			}
			for e := range n.Children() {
				if c, ok := e.Node(); ok && !walk(c) {
					return false
				}
			}
			return true
		}
		walk(tr.Root())
	}
}

func decode(n cst.Node) (scalar.Value, bool) { return scalar.Decode(n) }

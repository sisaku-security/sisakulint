package ir

import (
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Key is where a summary is: the name of its input, as the engine gives
// it, and the YAML path of its element, by the rules of the fingerprint
// of a finding (Paths). Only this package makes one.
type Key struct {
	input string
	path  string
}

// Input is the name of the input the summary is of.
func (k Key) Input() string { return k.input }

// Path is the YAML path of the element, such as jobs.build.steps[0].
func (k Key) Path() string { return k.path }

func (k Key) String() string { return k.input + ":" + k.path }

// keyOf is the key of the element b of the tree t of the input.
func keyOf(p *Paths, input string, t *cst.Tree, b workflow.Base) Key {
	return Key{input: input, path: p.Of(t, b.Node, b.Via)}
}

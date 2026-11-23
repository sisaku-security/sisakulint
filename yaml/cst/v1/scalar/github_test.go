package scalar

import (
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitewalk"
)

// TestGitHubQuotedValues: the values GitHub gave for quoted scalars whose continuation
// lines are less indented than YAML 1.2.2 allows.
func TestGitHubQuotedValues(t *testing.T) {
	for _, src := range []string{
		"env:\n  A: \"x\n   y\"\n",
		"env:\n  A: \"x\ny\"\n",
		"env:\n  A: \"x\n  y\"\n",
		"env:\n  A: 'x\ny'\n",
		"x:\n  - \"x\ny\"\n",
	} {
		tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
		if errs := tr.Errors(); len(errs) > 0 {
			t.Errorf("%q: %v", src, errs)
			continue
		}
		var got []string
		for _, n := range suitewalk.Nodes(tr) {
			if n.Kind() != cst.NodeScalar {
				continue
			}
			if v, ok := Decode(n); ok {
				got = append(got, v.String())
			}
		}
		if len(got) == 0 || got[len(got)-1] != "x y" {
			t.Errorf("%q: values %q, want the last to be \"x y\"", src, got)
		}
	}
}

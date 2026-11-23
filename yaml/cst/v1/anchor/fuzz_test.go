package anchor

import (
	"os"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
)

// FuzzResolve checks that Build and Resolve on every Alias of any input do
// not panic, and that a resolved node has the alias's anchor, is in its
// document and comes before it.
func FuzzResolve(f *testing.F) {
	cs, err := suitetest.Load(suiteRoot)
	if err != nil {
		f.Fatal(err)
	}
	for _, c := range cs {
		f.Add(c.In)
	}
	_, seeds := suitetest.CorpusSeeds(f)
	for _, path := range seeds {
		b, err := os.ReadFile(path)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		tr := cst.Parse(b)
		x := Build(tr)
		var walk func(cst.Node)
		walk = func(n cst.Node) {
			if d, ok := x.Resolve(n); ok {
				a, _ := d.Anchor()
				if n.Kind() != cst.NodeAlias || string(a.Bytes()[1:]) != string(n.Bytes()[1:]) ||
					a.Span().Start >= n.Span().Start || documentOf(d) != documentOf(n) {
					t.Fatalf("alias %v %q resolved to %v %q", n.Span(), n.Bytes(), d.Span(), d.Bytes())
				}
			}
			for e := range n.Children() {
				if c, ok := e.Node(); ok {
					walk(c)
				}
			}
		}
		walk(tr.Root())
	})
}

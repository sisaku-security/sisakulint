package expr_test

import (
	"os"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/internal/corpus"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// TestCorpusExpressions reads every ${{ }} of every scalar of the corpus.
// Those of the workflows that run on GitHub have no syntax error; the
// others are only counted.
func TestCorpusExpressions(t *testing.T) {
	files := corpus.Files(t)
	exprs, bad := 0, 0
	for _, f := range files {
		src, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		real := f.Kind == corpus.KindWorkflow && (strings.HasPrefix(f.Rel, "files/real-world/") || strings.HasPrefix(f.Rel, "files/org/") || strings.HasPrefix(f.Rel, "files/sisakuintel/") || strings.HasPrefix(f.Rel, "files/labeler-token/"))
		var walk func(n cst.Node)
		walk = func(n cst.Node) {
			if n.Kind() == cst.NodeScalar {
				v, _ := scalar.Decode(n)
				segs, errs := expr.Scan(v.String())
				for _, g := range segs {
					if !g.Expr {
						continue
					}
					exprs++
					if _, perrs := expr.Parse(v.String()[g.Inner.Start:g.Inner.End]); len(perrs) > 0 {
						errs = append(errs, perrs...)
					}
				}
				bad += len(errs)
				if real {
					for _, e := range errs {
						t.Errorf("%s: %q: %v", f.Rel, v.String(), e)
					}
				}
				return
			}
			for e := range n.Children() {
				if c, ok := e.Node(); ok {
					walk(c)
				}
			}
		}
		walk(cst.ParseMode(src, cst.ModeGitHub).Root())
	}
	t.Logf("%d files, %d expressions, %d errors", len(files), exprs, bad)
}

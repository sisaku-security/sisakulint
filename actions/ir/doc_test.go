package ir

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestGeneratedDocNames: the doc of each type summary_gen.go declares
// starts with the type's name (the docs of summaries.json once kept the
// old names).
func TestGeneratedDocNames(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "summary_gen.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.TYPE {
			continue
		}
		for _, s := range g.Specs {
			ts := s.(*ast.TypeSpec)
			doc := g.Doc
			if ts.Doc != nil {
				doc = ts.Doc
			}
			if !ts.Name.IsExported() || doc == nil {
				continue
			}
			if text := doc.Text(); !strings.HasPrefix(text, ts.Name.Name+" ") {
				t.Errorf("the doc of %s starts %q", ts.Name.Name, strings.SplitN(text, " ", 2)[0])
			}
		}
	}
}

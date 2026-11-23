package rules

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	"github.com/gh-intel/sisakulint/actions/internal/jsonorder"
)

// The lists that a new rule adds to are in the order of their keys, one
// member to a line, so that two works that add different rules change
// different lines.

// firstUnsorted is the first pair of keys out of order, as "a before b",
// or "" when they are in order.
func firstUnsorted(keys []string) string {
	for i := 1; i < len(keys); i++ {
		if keys[i-1] >= keys[i] {
			return keys[i-1] + " before " + keys[i]
		}
	}
	return ""
}

// TestAllSorted: All lists the rules in the order of their Go names, each
// on a line of its own.
func TestAllSorted(t *testing.T) {
	for _, list := range []string{"All", "Quality"} {
		listSorted(t, list)
	}
}

// listSorted checks the list the function name of rules.go returns: one
// name on a line, in the order of the names.
func listSorted(t *testing.T, name string) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "rules.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lit *ast.CompositeLit
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CompositeLit); ok && lit == nil {
					lit = c
				}
				return lit == nil
			})
		}
	}
	if lit == nil {
		t.Fatalf("no list in %s", name)
	}
	var names []string
	line := fset.Position(lit.Lbrace).Line
	for _, e := range lit.Elts {
		id, ok := e.(*ast.Ident)
		if !ok {
			t.Fatalf("%s lists %T, not a name", name, e)
		}
		if l := fset.Position(e.Pos()).Line; l == line {
			t.Errorf("%s: %s is on the line of the one before it", name, id.Name)
		} else {
			line = l
		}
		names = append(names, id.Name)
	}
	if s := firstUnsorted(names); s != "" {
		t.Errorf("%s: %s", name, s)
	}
}

// TestFindingsSchemaSorted: the members of $defs of findings-v0.json, and
// the kinds $defs/args lists, are in the order of their names.
func TestFindingsSchemaSorted(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("schema", "findings-v0.json"))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := jsonorder.Keys(b, "$defs")
	if err != nil {
		t.Fatal(err)
	}
	if s := firstUnsorted(keys); s != "" {
		t.Errorf("$defs: %s", s)
	}
	var s struct {
		Defs struct {
			Args struct {
				OneOf []struct {
					Ref string `json:"$ref"`
				} `json:"oneOf"`
			} `json:"args"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, o := range s.Defs.Args.OneOf {
		refs = append(refs, o.Ref)
	}
	if len(refs) == 0 {
		t.Fatal("no $defs/args/oneOf")
	}
	if u := firstUnsorted(refs); u != "" {
		t.Errorf("$defs/args/oneOf: %s", u)
	}
}

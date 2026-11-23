package rules

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// forbidden are the packages whose values a rule does not handle: the
// model, the tree and the shared analyses, which package ir reads for it.
var forbidden = map[string]bool{
	"github.com/gh-intel/sisakulint/actions/workflow":   true,
	"github.com/gh-intel/sisakulint/yaml/cst/v1":        true,
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit":   true,
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar": true,
	"github.com/gh-intel/sisakulint/yaml/cst/v1/anchor": true,
	"github.com/gh-intel/sisakulint/actions/taint":      true,
	"github.com/gh-intel/sisakulint/actions/prcode":     true,
	"github.com/gh-intel/sisakulint/actions/shell":      true,
	"github.com/gh-intel/sisakulint/actions/expr":       true,
}

// allowed are the types of those packages a rule may handle: an edit a
// fix is made of, the name of an event, enumerations the args of findings
// and the Meta are written in (the type of a value of a ${{ }} too), and the names of a runner label,
// of an env and of an input of an action, which a summary of the IR holds
// (a string that is no node of the tree).
var allowed = map[string]bool{
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit.Edit":            true,
	"github.com/gh-intel/sisakulint/actions/workflow.EventName":       true,
	"github.com/gh-intel/sisakulint/actions/workflow.RunnerLabelName": true,
	"github.com/gh-intel/sisakulint/actions/workflow.EnvName":         true,
	"github.com/gh-intel/sisakulint/actions/workflow.InputName":       true,
	"github.com/gh-intel/sisakulint/actions/expr.ValueType":           true,
}

// TestRulesTouchNoModel: the code of the rules handles no value of the
// model, the tree or the analyses, and calls no function of them.
// lint.Context does
// not give them; this finds what else would, such as ir.Handle.Locate.
// Its tests may.
func TestRulesTouchNoModel(t *testing.T) {
	if errs := touches(t, "."); len(errs) > 0 {
		t.Errorf("the rules touch the model:\n%s", strings.Join(errs, "\n"))
	}
}

// TestTouchesFindsWhatItShould: each line of testdata/nomodel/bad marked
// want is found, and no other.
func TestTouchesFindsWhatItShould(t *testing.T) {
	dir := filepath.Join("testdata", "nomodel", "bad")
	src, err := os.ReadFile(filepath.Join(dir, "bad.go"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]bool{}
	for i, line := range strings.Split(string(src), "\n") {
		if strings.Contains(line, "// want") {
			want[i+1] = true
		}
	}
	got := map[int]bool{}
	for _, e := range touches(t, dir) {
		if m := lineOf.FindStringSubmatch(e); m != nil {
			n, _ := strconv.Atoi(m[1])
			got[n] = true
		}
	}
	for n := range want {
		if !got[n] {
			t.Errorf("line %d is not found", n)
		}
	}
	for n := range got {
		if !want[n] {
			t.Errorf("line %d is found, but not marked", n)
		}
	}
}

var lineOf = regexp.MustCompile(`\.go:(\d+):`)

// touches type-checks the package in dir, without its tests, and gives
// each place that handles a value of a forbidden type.
func touches(t *testing.T, dir string) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, p := range pkgs {
		for _, f := range p.Files {
			files = append(files, f)
		}
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	if _, err := conf.Check(dir, fset, files, info); err != nil {
		t.Fatal(err)
	}
	var out []string
	seen := map[token.Pos]bool{}
	for e, tv := range info.Types {
		if tv.IsType() {
			continue // a type written, as in a declaration: the values are what count
		}
		if name, ok := forbiddenIn(tv.Type, map[types.Type]bool{}); ok && !seen[e.Pos()] {
			seen[e.Pos()] = true
			out = append(out, fset.Position(e.Pos()).String()+": handles a value of "+name)
		}
	}
	for id, obj := range info.Uses {
		if name, ok := forbiddenObject(obj); ok && !seen[id.Pos()] {
			seen[id.Pos()] = true
			out = append(out, fset.Position(id.Pos()).String()+": refers to "+name)
		}
	}
	return out
}

// forbiddenObject is the name of obj when it is of a forbidden package
// and not what a rule may use of it: an allowed type, a constant or a
// variable of a type that is not forbidden, or a method of an allowed
// type. A function of such a package, as expr.EqualName, is forbidden
// even when no forbidden type is in its signature: the rules do not call
// the analyses.
func forbiddenObject(obj types.Object) (string, bool) {
	pkg := obj.Pkg()
	if pkg == nil || !forbidden[pkg.Path()] {
		return "", false
	}
	full := pkg.Path() + "." + obj.Name()
	switch o := obj.(type) {
	case *types.TypeName:
		return full, !allowed[full]
	case *types.Const, *types.Var:
		_, bad := forbiddenIn(o.Type(), map[types.Type]bool{})
		return full, bad
	case *types.Func:
		if recv := o.Type().(*types.Signature).Recv(); recv != nil {
			if n := named(recv.Type()); n != nil && allowed[n.Obj().Pkg().Path()+"."+n.Obj().Name()] {
				return "", false
			}
		}
		return full, true
	}
	return full, true
}

// named is the named type t is, or points to; nil for none.
func named(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, _ := t.(*types.Named)
	return n
}

// forbiddenIn is the name of a forbidden type t is made of, looking
// through pointers, slices, arrays, maps, channels, tuples and function
// types, and the type arguments of a named type; not into the fields of a
// named type, whose values a rule handles as a whole.
func forbiddenIn(t types.Type, seen map[types.Type]bool) (string, bool) {
	if seen[t] {
		return "", false
	}
	seen[t] = true
	switch x := t.(type) {
	case *types.Named:
		if o := x.Obj(); o.Pkg() != nil {
			full := o.Pkg().Path() + "." + o.Name()
			if forbidden[o.Pkg().Path()] && !allowed[full] {
				return full, true
			}
		}
		if args := x.TypeArgs(); args != nil {
			for i := range args.Len() {
				if n, ok := forbiddenIn(args.At(i), seen); ok {
					return n, true
				}
			}
		}
	case *types.Alias:
		return forbiddenIn(types.Unalias(x), seen)
	case *types.Pointer:
		return forbiddenIn(x.Elem(), seen)
	case *types.Slice:
		return forbiddenIn(x.Elem(), seen)
	case *types.Array:
		return forbiddenIn(x.Elem(), seen)
	case *types.Chan:
		return forbiddenIn(x.Elem(), seen)
	case *types.Map:
		if n, ok := forbiddenIn(x.Key(), seen); ok {
			return n, true
		}
		return forbiddenIn(x.Elem(), seen)
	case *types.Tuple:
		for i := range x.Len() {
			if n, ok := forbiddenIn(x.At(i).Type(), seen); ok {
				return n, true
			}
		}
	case *types.Signature:
		if n, ok := forbiddenIn(x.Params(), seen); ok {
			return n, true
		}
		return forbiddenIn(x.Results(), seen)
	}
	return "", false
}

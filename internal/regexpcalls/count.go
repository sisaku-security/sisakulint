package regexpcalls

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Dirs are the directories under the root of the module whose Go files
// Files lists: the code of the linter, its commands and the YAML packages.
var Dirs = []string{"actions", "cmd", "internal", "yaml"}

// Files are the regular files under the Dirs of root, as paths from root
// with slashes, in order.
func Files(root string) ([]string, error) {
	var files []string
	for _, dir := range Dirs {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			files = append(files, filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(files)
	return files, nil
}

// calls are the functions of the package regexp that compile a pattern.
var calls = []string{"Compile", "CompilePOSIX", "MustCompile", "MustCompilePOSIX", "Match", "MatchString", "MatchReader"}

// Count is, for each Go file of files (paths from root, with slashes) that
// is not a test and not generated, how many times it calls a function of
// regexp that compiles a pattern; files that call none are left out. It
// reads the syntax, so a call in a comment or a string is not counted.
func Count(root string, files []string) (map[string]int, error) {
	n := map[string]int{}
	fset := token.NewFileSet()
	for _, p := range files {
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(p)), nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		if ast.IsGenerated(f) {
			continue
		}
		if c := countFile(f); c > 0 {
			n[p] = c
		}
	}
	return n, nil
}

// countFile counts the calls of f to the functions calls, through the
// name f imports regexp by.
func countFile(f *ast.File) int {
	name := ""
	for _, im := range f.Imports {
		if path, _ := strconv.Unquote(im.Path.Value); path == "regexp" {
			name = "regexp"
			if im.Name != nil {
				name = im.Name.Name
			}
		}
	}
	if name == "" || name == "_" || name == "." {
		return 0
	}
	c := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == name && slices.Contains(calls, sel.Sel.Name) {
			c++
		}
		return true
	})
	return c
}

const allowedHeader = "path\tcount"

// FormatAllowed writes the counts as allowed.tsv: a header, then a line of
// path and count for each file, in order.
func FormatAllowed(n map[string]int) []byte {
	var b bytes.Buffer
	b.WriteString(allowedHeader + "\n")
	for _, p := range slices.Sorted(maps.Keys(n)) {
		fmt.Fprintf(&b, "%s\t%d\n", p, n[p])
	}
	return b.Bytes()
}

// ParseAllowed reads allowed.tsv.
func ParseAllowed(b []byte) (map[string]int, error) {
	n := map[string]int{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	if !sc.Scan() || sc.Text() != allowedHeader {
		return nil, fmt.Errorf("allowed.tsv does not start with %q", allowedHeader)
	}
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) != 2 {
			return nil, fmt.Errorf("allowed.tsv: %q is not path and count", sc.Text())
		}
		c, err := strconv.Atoi(cols[1])
		if err != nil || c <= 0 {
			return nil, fmt.Errorf("allowed.tsv: %q is no count", cols[1])
		}
		if _, ok := n[cols[0]]; ok {
			return nil, fmt.Errorf("allowed.tsv: %s twice", cols[0])
		}
		n[cols[0]] = c
	}
	return n, sc.Err()
}

// Grown are the files of now with a count above that of base, in order: a
// file of no line of base counts zero there, so a file renamed is grown.
// With no base, none is.
func Grown(base, now map[string]int) []string {
	if base == nil {
		return nil
	}
	var g []string
	for p, c := range now {
		if c > base[p] {
			g = append(g, p)
		}
	}
	slices.Sort(g)
	return g
}

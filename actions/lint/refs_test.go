package lint

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// repoPath is a path into the directory of documents of this repository,
// which is not there when a package of the contract is taken out. A URL
// whose path has a directory named docs does not match: there the name
// follows a slash.
var repoPath = regexp.MustCompile(`(^|[^\w/.-])docs/`)

func TestContractHasNoRepoPaths(t *testing.T) {
	schemas, err := filepath.Glob("../*/schema/*.json")
	if err != nil || len(schemas) < 4 {
		t.Fatalf("schemas %v, %v", schemas, err)
	}
	for _, s := range schemas {
		b, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if m := repoPath.Find(b); m != nil {
			t.Errorf("%s refers to %q, a path of this repository", s, m)
		}
	}
	for _, dir := range []string{".", "../facts", "../facts/github"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			for _, cg := range file.Comments {
				if m := repoPath.FindString(cg.Text()); m != "" {
					t.Errorf("a comment of %s refers to %q, a path of this repository", f, m)
				}
			}
		}
	}
}

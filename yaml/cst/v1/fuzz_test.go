package cst

import (
	"os"
	"testing"

	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
)

func corpusFiles(t testing.TB) []string {
	t.Helper()
	files, err := suitetest.CorpusFiles(suitetest.CorpusRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// FuzzParse checks that any input parses without panicking into a tree that
// satisfies the invariants, in both modes, and that ModeGitHub changes no
// more than ModeGitHub is meant to change. The seeds are the suite and the
// corpus.
func FuzzParse(f *testing.F) {
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
		if err := validate(Parse(b)); err != nil {
			t.Fatal(err)
		}
		sameTreeOrGitHubKeys(t, "input", b)
	})
}

package scalar

import (
	"os"
	"testing"

	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
)

// FuzzDecode checks that every Scalar of any input decodes without
// panicking into a value with the segment properties. The seeds are the
// suite and the corpus, as for cst's FuzzParse.
func FuzzDecode(f *testing.F) {
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
		if err := checkTree(b); err != nil {
			t.Fatal(err)
		}
	})
}

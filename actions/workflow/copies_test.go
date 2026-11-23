package workflow

import (
	"testing"

	"github.com/gh-intel/sisakulint/internal/copytest"
)

// TestThirdPartyCopies keeps the copies of the test data of other projects
// under testdata as they were copied, license files included: for each
// copy, the number of its files and their copytest.Sum, which the README.md
// of the copy gives. A copy that is changed or loses a file fails; the tests
// that read the copies do not see every change, as TestLanguageservicesReader
// counts no files.
func TestThirdPartyCopies(t *testing.T) {
	for _, c := range []struct {
		dir   string
		files int
		sum   string
	}{
		{"testdata/languageservices", 196, "71ba6d1c05c38030ff2123e31eb2bac3daaffce96ae9c79ffb72452792b9f8f5"},
		{"testdata/actionlint", 16, "03fcdbcc729ec157be57ee63a0d542df08674040a033a7e1937b88f607bcfac2"},
		{"testdata/zizmor", 2, "28c167df811da94e23f6ffbd36fc6366cb13d13fbb13656b26ebecd660d9263d"},
	} {
		n, sum, err := copytest.Sum(c.dir)
		if err != nil {
			t.Fatal(err)
		}
		if n != c.files || sum != c.sum {
			t.Errorf("%s: %d files with sum %s, want %d files with sum %s (see the README.md there)", c.dir, n, sum, c.files, c.sum)
		}
	}
}

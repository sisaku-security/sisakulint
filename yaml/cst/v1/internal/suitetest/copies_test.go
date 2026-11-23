package suitetest

import (
	"testing"

	"github.com/gh-intel/sisakulint/internal/copytest"
)

// TestThirdPartyCopies keeps the two copies of yaml-test-suite, which the
// tests of yaml/cst/v1 and its packages read, as they were copied: the
// number of the files and their copytest.Sum, which the README.md of
// yaml-test-suite gives for each directory.
func TestThirdPartyCopies(t *testing.T) {
	for _, c := range []struct {
		dir   string
		files int
		sum   string
	}{
		{"../../../../yaml-test-suite/data-2022-01-17", 1887, "6a5624dc250afa4b501fee5fbc2f21327437d71c9206b811b5c72414dc33e035"},
		{"../../../../yaml-test-suite/main", 369, "7c9a154c5ec96e6363b20c50bfe1f5a6cc5b5a3fd33ba0f5cf84fe6db0d8220a"},
	} {
		n, sum, err := copytest.Sum(c.dir)
		if err != nil {
			t.Fatal(err)
		}
		if n != c.files || sum != c.sum {
			t.Errorf("%s: %d files with sum %s, want %d files with sum %s (see the README.md of yaml-test-suite)", c.dir, n, sum, c.files, c.sum)
		}
	}
}

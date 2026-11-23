package taint

import (
	"testing"

	"github.com/gh-intel/sisakulint/internal/copytest"
)

// TestThirdPartyCopies keeps the copy of the test data of zizmor under
// testdata as it was copied, the license file included: the number of its
// files and their copytest.Sum, which the README.md of the copy gives.
func TestThirdPartyCopies(t *testing.T) {
	const dir, files, want = "testdata/zizmor", 2, "f0923a13a37f32bce9ce87f0b9dc41c8a8720ada46db219318280c23f45cbe02"
	n, sum, err := copytest.Sum(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != files || sum != want {
		t.Errorf("%s: %d files with sum %s, want %d files with sum %s (see the README.md there)", dir, n, sum, files, want)
	}
}

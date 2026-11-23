package artifact

import "testing"

// TestCheckoutVersion: v1 to v5 leave the credential in
// .git/config, v6 on in RUNNER_TEMP; a commit of a tag answers from the
// table, another commit asks, a branch is the worst case.
func TestCheckoutVersion(t *testing.T) {
	for _, c := range []struct {
		ref          string
		leaves, asks bool
	}{
		{"v4", true, false},
		{"v5.0.1", true, false},
		{"v1", true, false},
		{"v6", false, false},
		{"v6.0.0", false, false},
		{"v7.0.1", false, false},
		{"v8", false, false},
		{"main", true, false},
		{"11bd71901bbe5b1630ceea73d27597364c9af683", true, false},  // v4.2.2
		{"1af3b93b6815bc44a9784bd300feb67ff0d1eeb3", false, false}, // v6.0.0
		{"0123456789abcdef0123456789abcdef01234567", true, true},
	} {
		leaves, asks := checkoutVersion(c.ref)
		if leaves != c.leaves || (asks != nil) != c.asks {
			t.Errorf("%s: leaves %v, asks %v; want %v, %v", c.ref, leaves, asks, c.leaves, c.asks)
		}
	}
}

// TestUploadVersion: which releases take hidden files,
// and which can be downloaded while the run goes on (v4 on).
func TestUploadVersion(t *testing.T) {
	for _, c := range []struct {
		ref    string
		hidden hiddenRule
		during bool
	}{
		{"v1", hiddenAlways, false},
		{"v2", hiddenAlways, false},
		{"v2.3.1", hiddenAlways, false},
		{"v3.1.3", hiddenAlways, false},
		{"v3.2.0", hiddenNever, false},
		{"v3.2", hiddenInput, false},
		{"v3.2.1", hiddenInput, false},
		{"v3", hiddenInput, false},
		{"v4.0.0", hiddenAlways, true},
		{"v4.3", hiddenAlways, true},
		{"v4.3.6", hiddenAlways, true},
		{"v4.4.0", hiddenInput, true},
		{"v4.4", hiddenInput, true},
		{"v4", hiddenInput, true},
		{"v7.0.1", hiddenInput, true},
		{"main", hiddenAlways, true},
		{"834a144ee995460fba8ed112a2fc961b36a5ec5a", hiddenAlways, true},  // v4.3.6
		{"a8a3f3ad30e3422c9c7b888a15615d19a852ae32", hiddenAlways, false}, // v3.1.3
		{"9ee08a3b00e91a926cc9547dc79589c20872452f", hiddenNever, false},  // v3.2.0
		{"ea165f8d65b6e75b540449e92b4886f43607fa02", hiddenInput, true},   // v4.6.2
		{"0123456789abcdef0123456789abcdef01234567", hiddenUnless, true},
	} {
		h, during := uploadVersion(c.ref)
		if h != c.hidden || during != c.during {
			t.Errorf("%s: %v %v; want %v %v", c.ref, h, during, c.hidden, c.during)
		}
	}
}

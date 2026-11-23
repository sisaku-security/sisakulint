package workflow

import "testing"

// TestEnvNameOf: a name an environment can hold: not empty, without = and
// NUL.
func TestEnvNameOf(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{"ISSUE_TITLE", true},
		{"issue-title", true},
		{"", false},
		{"A=B", false},
		{"A\x00", false},
	} {
		n, ok := EnvNameOf(c.in)
		if ok != c.ok || ok && n.String() != c.in {
			t.Errorf("%q: %q %v", c.in, n, ok)
		}
	}
}

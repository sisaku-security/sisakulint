package prcode

import "testing"

func TestRelDirOf(t *testing.T) {
	for _, c := range []struct {
		in    string
		want  string
		known bool
	}{
		{"", ".", true},
		{".", ".", true},
		{"./dist/", "dist", true},
		{"a/../b", "b", true},
		{"/tmp/x", "", false},
		{"..", "", false},
		{"../x", "", false},
		{"a/../../x", "", false},
	} {
		d := relDirOf(c.in)
		if d.path != c.want || d.known != c.known {
			t.Errorf("relDirOf(%q) = %v; want %q %v", c.in, d, c.want, c.known)
		}
	}
}

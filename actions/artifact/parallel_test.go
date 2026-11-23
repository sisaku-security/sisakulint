package artifact

import "testing"

// TestAnalyzeParallel: a credential a step of a parallel group leaves is
// there for an upload of the group, written before or after it.
func TestAnalyzeParallel(t *testing.T) {
	up := "          - uses: actions/upload-artifact@v4\n            with: {path: ., include-hidden-files: true}\n"
	ch := "          - uses: actions/checkout@v4\n"
	for _, c := range []struct {
		name, src string
		exposes   int
	}{
		{"checkout written first", job("      - parallel:\n" + ch + up), 1},
		{"upload written first", job("      - parallel:\n" + up + ch), 1},
		{"upload before the group", job("      - uses: actions/upload-artifact@v4\n        with: {path: ., include-hidden-files: true}\n      - parallel:\n" + ch + "          - run: make\n"), 0},
	} {
		us, _ := Analyze(parse(t, c.src), nil)
		if len(us) != 1 || len(us[0].TakenCredentials) != c.exposes {
			t.Errorf("%s: %+v", c.name, us)
		}
	}
}

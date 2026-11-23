package prcode

import (
	"slices"
	"strings"
	"testing"
)

// TestPathLines: the lines of a path, with the ${{ }} of the workspace and
// of runner.temp at the head of a line read by their syntax.
func TestPathLines(t *testing.T) {
	for _, c := range []struct {
		name, value string
		want        []string
	}{
		{"the workspace", "${{ github.workspace }}/a", []string{"./a"}},
		{"by an index", "${{ github['workspace'] }}/a", []string{"./a"}},
		{"spaces and capitals", "  ${{ GITHUB . Workspace }}/a", []string{"./a"}},
		{"runner.temp", "${{ runner.temp }}/x", []string{RunnerTempMark + "/x"}},
		{"runner.temp left out", "!${{ runner.temp }}/x", []string{"!" + RunnerTempMark + "/x"}},
		{"runner.temp left out with spaces", " ! ${{ runner['temp'] }}/x", []string{" ! " + RunnerTempMark + "/x"}},
		{"the workspace not at the head", "a/${{ github.workspace }}", []string{"a/" + ExprMark}},
		{"the workspace left out stays an expression", "!${{ github.workspace }}/a", []string{"!" + ExprMark + "/a"}},
		{"another expression", "${{ matrix.dir }}/a", []string{ExprMark + "/a"}},
		{"a folded literal", "${{ 'github.workspace' }}", []string{"github.workspace"}},
		{"lines", "dist\n${{ github.workspace }}/b\n${{ inputs.x }}", []string{"dist", "./b", ExprMark}},
		{"an expression across lines", "${{ github.workspace\n }}/x\ny", []string{"./x", "y"}},
		{"another expression across lines", "a\n  ${{ inputs.x\n }}/x", []string{"a", "  " + ExprMark + "/x"}},
		{"no expression", "a\nb", []string{"a", "b"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := "on: push\njobs:\n  a:\n    runs-on: u\n    steps:\n      - uses: actions/upload-artifact@v4\n        with:\n          path: " + quote(c.value) + "\n"
			w := mustWorkflow(t, src)
			e, _ := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0].With.Value.Lookup("path")
			var got []string
			for _, l := range PathLines(e.Value.Value) {
				got = append(got, l.Text)
				if strings.Contains(l.Raw, "\n") {
					t.Errorf("Raw %q has a line break", l.Raw)
				}
			}
			if !slices.Equal(got, c.want) {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// quote writes v as a YAML double-quoted scalar.
func quote(v string) string {
	b := []byte{'"'}
	for _, r := range v {
		switch r {
		case '"', '\\':
			b = append(b, '\\', byte(r))
		case '\n':
			b = append(b, '\\', 'n')
		default:
			b = append(b, string(r)...)
		}
	}
	return string(append(b, '"'))
}

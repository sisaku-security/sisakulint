package cli

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

func TestReadRunsUsing(t *testing.T) {
	for _, c := range []struct {
		src  string
		want facts.RunsUsing
	}{
		{"runs:\n  using: node20\n  main: index.js\n", facts.RunsUsingNode20},
		{"runs:\n  using: 'Node20'\n  main: index.js\n", facts.RunsUsingNode20}, // the runner compares without case
		{"runs:\n  using: composite\n  steps:\n    - run: echo\n      shell: bash\n", facts.RunsUsingComposite},
		{"runs:\n  using: node20\n", facts.RunsUsingNode20}, // no main: the runner rejects the action, but it declares node20
	} {
		got, err := readRunsUsing([]byte(c.src))
		if err != nil || got != c.want {
			t.Errorf("%q = %v, %v; want %v", c.src, got, err, c.want)
		}
	}
	for _, bad := range []string{
		"runs:\n  using: node18\n  main: index.js\n",
		"runs:\n  main: index.js\n",
		"name: x\n",
		"runs: [\n",
		"runs:\n  using: ${{ x }}\n",
	} {
		if got, err := readRunsUsing([]byte(bad)); err == nil {
			t.Errorf("%q = %v, want an error", bad, got)
		}
	}
}

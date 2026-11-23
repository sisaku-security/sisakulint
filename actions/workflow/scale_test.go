package workflow

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// The time to read a workflow grows linearly with the number of keys of a
// mapping and of items of a sequence: a workflow is untrusted input, and
// the duplicate check was once quadratic (a 373 KB env took 87 s), and
// checking what the typed reading left was once exponential in nested
// aliases. Each
// shape is read at n and 4n elements; linear time is about 4 times as
// long, quadratic about 16. The best of three runs is compared, against
// the noise of a shared machine. ACTIONS_SCALE=1 only, as the time it
// compares depends on the machine.
func TestScaleLinear(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of n and 4n elements")
	}
	shapes := []struct {
		name   string
		make   func(n int) string
		action bool
	}{
		{"env", func(n int) string {
			var b strings.Builder
			b.WriteString("on: push\nenv:\n")
			for i := range n {
				fmt.Fprintf(&b, "  K%d: v\n", i)
			}
			b.WriteString("jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: x\n")
			return b.String()
		}, false},
		{"jobs", func(n int) string {
			var b strings.Builder
			b.WriteString("on: push\njobs:\n")
			for i := range n {
				fmt.Fprintf(&b, "  j%d:\n    runs-on: x\n    steps:\n      - run: x\n", i)
			}
			return b.String()
		}, false},
		// a chain: each job needs the one before (checkNeeds)
		{"needs", func(n int) string {
			var b strings.Builder
			b.WriteString("on: push\njobs:\n  j0:\n    runs-on: x\n    steps:\n      - run: x\n")
			for i := 1; i < n; i++ {
				fmt.Fprintf(&b, "  j%d:\n    needs: j%d\n    runs-on: x\n    steps:\n      - run: x\n", i, i-1)
			}
			return b.String()
		}, false},
		{"with", func(n int) string {
			var b strings.Builder
			b.WriteString("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: a/b@v1\n        with:\n")
			for i := range n {
				fmt.Fprintf(&b, "          k%d: v\n", i)
			}
			return b.String()
		}, false},
		{"steps", func(n int) string {
			var b strings.Builder
			b.WriteString("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n")
			for i := range n {
				fmt.Fprintf(&b, "      - id: s%d\n        run: echo ${{ github.event.issue.title }}\n", i)
			}
			return b.String()
		}, false},
		// each level is two aliases of the one before: what an alias
		// stands for is read once for each place it is reached from, not
		// once for each path through the aliases (2 to the depth).
		{"nested aliases", func(n int) string {
			var b strings.Builder
			b.WriteString("on: push\njobs:\n  a:\n    runs-on: x\n    strategy:\n      matrix:\n        l0: &l0 [x, x]\n")
			for i := 1; i < n/100; i++ {
				fmt.Fprintf(&b, "        l%d: &l%d [*l%d, *l%d]\n", i, i, i-1, i-1)
			}
			b.WriteString("    steps:\n      - run: x\n")
			return b.String()
		}, false},
		{"action-steps", func(n int) string {
			var b strings.Builder
			b.WriteString("runs:\n  using: composite\n  steps:\n")
			for i := range n {
				fmt.Fprintf(&b, "    - id: s%d\n      run: echo ${{ inputs.x }}\n      shell: bash\n", i)
			}
			return b.String()
		}, true},
		{"action-inputs", func(n int) string {
			var b strings.Builder
			b.WriteString("inputs:\n")
			for i := range n {
				fmt.Fprintf(&b, "  i%d: {description: d, default: v}\n", i)
			}
			b.WriteString(runsOK)
			return b.String()
		}, true},
	}
	const n = 4000
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			small, large := readTime(s.make(n), s.action), readTime(s.make(4*n), s.action)
			if r := float64(large) / float64(small); r > 10 {
				t.Errorf("%d elements took %v, %d took %v: %.1f times, not about 4", n, small, 4*n, large, r)
			}
		})
	}
}

func readTime(src string, action bool) time.Duration {
	best := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		if action {
			ParseActionMetadata(cst.ParseMode([]byte(src), cst.ModeGitHub))
		} else {
			Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		}
		best = min(best, time.Since(start))
	}
	return best
}

// TestScaleCheckCall: checking a call of n names against a workflow_call of
// n inputs takes time about linear in n (each name was once looked up by
// a scan of the
// other side). ACTIONS_SCALE=1 only, as the time it compares depends on
// the machine.
func TestScaleCheckCall(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of n and 4n inputs")
	}
	check := func(n int) time.Duration {
		var called, caller strings.Builder
		called.WriteString("on:\n  workflow_call:\n    inputs:\n")
		caller.WriteString("on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n")
		for i := range n {
			fmt.Fprintf(&called, "      i%d: {type: string, required: true}\n", i)
			fmt.Fprintf(&caller, "      k%d: v\n", i)
		}
		called.WriteString("jobs:\n  j:\n    runs-on: x\n    steps: [{run: y}]\n")
		cw, _ := Parse(cst.ParseMode([]byte(called.String()), cst.ModeGitHub))
		w, _ := Parse(cst.ParseMode([]byte(caller.String()), cst.ModeGitHub))
		job := w.Jobs.Value.Entries[0].Value.Value
		best := time.Duration(1 << 62)
		for range 3 {
			start := time.Now()
			CheckCall(job, cw)
			best = min(best, time.Since(start))
		}
		return best
	}
	const n = 1000
	small, large := check(n), check(4*n)
	if r := float64(large) / float64(small); r > 10 {
		t.Errorf("%d inputs took %v, %d took %v: %.1f times, not about 4", n, small, 4*n, large, r)
	}
}

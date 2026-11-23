package calls_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
)

// TestScaleLocalCalls: a job of n checkouts, each followed by a call of a
// local action, is resolved in time about linear in n (before, each call
// read every checkout of the job).
// ACTIONS_SCALE=1 only, as the time it compares depends on the machine.
func TestScaleLocalCalls(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of n and 4n calls")
	}
	read := func(n int) time.Duration {
		ci := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + strings.Repeat("      - uses: actions/checkout@v4\n      - uses: ./x\n        with: {t: y}\n", n)
		best := time.Duration(1 << 62)
		for range 3 {
			start := time.Now()
			g := callerstest.Graph(t, true, false, [2]string{"x/action.yml", composite}, [2]string{".github/workflows/ci.yml", ci})
			g.CallsOf(name("x/action.yml"))
			best = min(best, time.Since(start))
		}
		return best
	}
	const n = 500
	small, large := read(n), read(4*n)
	if r := float64(large) / float64(small); r > 10 {
		t.Errorf("%d calls took %v, %d took %v: %.1f times, not about 4", n, small, 4*n, large, r)
	}
}

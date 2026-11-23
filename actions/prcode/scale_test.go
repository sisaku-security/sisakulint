package prcode

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestScaleCheckouts: a job of n checkouts is read in time about linear in
// n (each checkout once read the steps after it to the end, and made the
// order of the steps again).
// ACTIONS_SCALE=1 only, as the time it compares depends on the machine.
func TestScaleCheckouts(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of n and 4n checkouts")
	}
	for _, tail := range []string{"", "      - uses: actions/cache@v4\n        with:\n          path: .\n          key: k\n"} {
		scaleCheckouts(t, tail)
	}
}

// scaleCheckouts compares the time of n and 4n checkouts, each followed by
// a run, and then tail: the cache saves of each checkout are read to the
// next checkout of the workspace, which cleans it (the scale of
// cache-poisoning's cacheSaves, which read every step of the job for each
// checkout).
func scaleCheckouts(t *testing.T, tail string) {
	t.Helper()
	read := func(n int) time.Duration {
		src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n" + strings.Repeat("      - uses: actions/checkout@v4\n      - run: npm ci\n", n) + tail
		w := mustWorkflow(t, src)
		best := time.Duration(1 << 62)
		for range 3 {
			start := time.Now()
			Analyze(w, nil)
			AnalyzeDownloads(w, nil, nil)
			best = min(best, time.Since(start))
		}
		return best
	}
	const n = 1000
	small, large := read(n), read(4*n)
	if r := float64(large) / float64(small); r > 10 {
		t.Errorf("%d checkouts and %q took %v, %d took %v: %.1f times, not about 4", n, tail, small, 4*n, large, r)
	}
}

package rules

import (
	"fmt"
	"os"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// pairsWorkflow is a job of n pairs of a step that leaves a credential in a
// file and an upload of actions/upload-artifact that takes the file: form
// a, actions/checkout and an upload of the workspace with its hidden
// files (artipacked); form b, google-github-actions/auth and an upload of
// the workspace (secrets-in-artifacts); form c, actions/checkout v6 whose
// persist-credentials is a ${{ }} and an upload of RUNNER_TEMP (the gap of
// the credential).
func pairsWorkflow(form string, n int) string {
	var b strings.Builder
	switch form {
	case "c":
		b.WriteString("on:\n  workflow_dispatch:\n    inputs:\n      p:\n        type: string\n")
	default:
		b.WriteString("on: push\n")
	}
	b.WriteString("jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n")
	for i := range n {
		switch form {
		case "a":
			fmt.Fprintf(&b, "      - uses: actions/checkout@v4\n      - uses: actions/upload-artifact@v4\n        with:\n          name: a%d\n          path: .\n          include-hidden-files: true\n", i)
		case "b":
			fmt.Fprintf(&b, "      - uses: google-github-actions/auth@v2\n        with:\n          credentials_json: ${{ secrets.GCP_KEY }}\n      - uses: actions/upload-artifact@v4\n        with:\n          name: a%d\n          path: .\n", i)
		case "c":
			fmt.Fprintf(&b, "      - uses: actions/checkout@v6\n        with:\n          persist-credentials: ${{ inputs.p }}\n      - uses: actions/upload-artifact@v4\n        with:\n          name: a%d\n          path: ${{ runner.temp }}\n", i)
		}
	}
	return b.String()
}

// pairsCount is what the forms give: the findings of artipacked (form a),
// of secrets-in-artifacts (form b), and the inconclusive places of
// artipacked (form c).
func pairsCount(rep lint.Report, form string) int {
	n := 0
	switch form {
	case "a", "b":
		id := ArtipackedID
		if form == "b" {
			id = SecretsInArtifactsID
		}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Rule == id {
				n++
			}
		}
	case "c":
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			if g.Rule == ArtipackedID {
				n++
			}
		}
	}
	return n
}

// TestPairsSmall: each form of 30 pairs gives one finding, or one
// inconclusive place, for each pair's step or upload, not for each pair.
func TestPairsSmall(t *testing.T) {
	for _, form := range []string{"a", "b", "c"} {
		rep, _, _ := checkRules(t, []lint.Rule{Artipacked, SecretsInArtifacts}, wfFile(pairsWorkflow(form, 30)), artifactFacts{})
		if got := pairsCount(rep, form); got != 30 {
			t.Errorf("form %s: %d", form, got)
		}
	}
}

// heapPeak samples the bytes of the heap's objects every 10 ms while f runs
// (garbage not yet collected included), and gives the most.
func heapPeak(f func()) uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	var peak uint64
	var mu sync.Mutex
	read := func() {
		metrics.Read(s)
		mu.Lock()
		peak = max(peak, s[0].Value.Uint64())
		mu.Unlock()
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				read()
			}
		}
	})
	f()
	read()
	close(done)
	wg.Wait()
	return peak
}

// TestPairsScale: each form of 1000 pairs ends in its time (form a 30
// seconds, b and c 15) with at most 300 MB of the heap's objects
// (ACTIONS_SCALE=1: the time depends on the machine; run it alone, go test
// -p 1). Form a has a fix on each step, each checked by running the rule
// again on the fixed input, which reads every pair again (101 checks of an
// input of 165 KB). A form of a pin of a release that is in no table,
// another for each upload, is not of these (each upload adds a condition
// of its own to each step's finding).
func TestPairsScale(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 runs 1000 pairs")
	}
	limit := map[string]time.Duration{"a": 30 * time.Second, "b": 15 * time.Second, "c": 15 * time.Second}
	for _, form := range []string{"a", "b", "c"} {
		src := pairsWorkflow(form, 1000)
		var rep lint.Report
		start := time.Now()
		peak := heapPeak(func() {
			rep, _, _ = checkRules(t, []lint.Rule{Artipacked, SecretsInArtifacts}, wfFile(src), artifactFacts{})
		})
		took := time.Since(start)
		t.Logf("form %s: %d bytes, %d of the form, %v, heap %d MB", form, len(src), pairsCount(rep, form), took, peak>>20)
		if got := pairsCount(rep, form); got != 1000 {
			t.Errorf("form %s: %d of the form, want 1000", form, got)
		}
		if took > limit[form] || peak > 300<<20 {
			t.Errorf("form %s: %v and %d MB, more than %v or 300 MB", form, took, peak>>20, limit[form])
		}
	}
}

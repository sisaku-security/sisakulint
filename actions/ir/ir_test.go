package ir

import (
	"testing"
	"time"
)

const usesWorkflow = `on: push
jobs:
  call:
    uses: o/r/.github/workflows/w.yml@v1
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: ./local
      - uses: docker://alpine:3
      - uses: ${{ 'o/folded@v2' }}
`

func newIR(t *testing.T, src string) *IR {
	t.Helper()
	tree, w := parse(t, src)
	return New(".github/workflows/w.yml", tree, w, nil)
}

// TestViewFields: the fields of a view are those views.json declares, in
// the order of Field.
func TestViewFields(t *testing.T) {
	got := ImpostorCommitView.Fields()
	want := []SummaryField{FieldUsesRepo, FieldUsesRef, FieldUsesLevel, FieldUsesUsesText, FieldUsesOutside, FieldUsesReadByOutside, FieldUsesAlwaysSkipped}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TestMadeOnce: the summaries of a type are made once for the IR, however
// many readers ask for them; a type no reader asks for is not made.
func TestMadeOnce(t *testing.T) {
	x := newIR(t, usesWorkflow)
	CommitSHAView.Reader(x.RuleAccess()).Uses()
	ImpostorCommitView.Reader(x.RuleAccess()).Uses()
	if n := x.Made(SummaryUses); n != 1 {
		t.Errorf("Uses made %d times", n)
	}
}

// TestSameInputSameSummaries: two IRs of one input have summaries that do
// not differ in any field.
func TestSameInputSameSummaries(t *testing.T) {
	a, b := newIR(t, usesWorkflow).allUses(), newIR(t, usesWorkflow).allUses()
	if len(a) != len(b) {
		t.Fatalf("%d and %d", len(a), len(b))
	}
	for i := range a {
		if a[i].key != b[i].key || len(a[i].diff(b[i])) != 0 {
			t.Errorf("%d: %s, %v", i, a[i].key, a[i].diff(b[i]))
		}
	}
}

// TestMakingWithinMaking: a summary type made of another (StepFix of
// Sink) asks for it while it is made, and gets it (it once deadlocked).
func TestMakingWithinMaking(t *testing.T) {
	x := newIR(t, usesWorkflow)
	done := make(chan int)
	go func() {
		n := 0
		x.once(summaryUnset, func() { n = len(x.allUses()) })
		done <- n
	}()
	select {
	case n := <-done:
		if n != 3 {
			t.Errorf("uses %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("making a summary type within the making of another does not return")
	}
}

// TestPanicOfMakingForEveryReader: a summary type whose making panicked
// panics for every rule that reads it, not only the first, so that each
// is an error and none reads nothing in silence.
func TestPanicOfMakingForEveryReader(t *testing.T) {
	x := newIR(t, usesWorkflow)
	panics := func() (p any) {
		defer func() { p = recover() }()
		x.once(SummarySink, func() { panic("the analysis failed") })
		return nil
	}
	if p := panics(); p != "the analysis failed" {
		t.Fatalf("first: %v", p)
	}
	if p := panics(); p != "the analysis failed" {
		t.Errorf("second: %v, want the panic again", p)
	}
}

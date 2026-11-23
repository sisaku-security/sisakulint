package job

import (
	"slices"
	"testing"
)

// TestAncestors: every job that a job depends on through needs, directly
// or through other jobs, once each, whatever the ifs; a cycle ends.
func TestAncestors(t *testing.T) {
	w := parse(t, "on: push\njobs:\n  a:\n    needs: [b, c]\n    runs-on: u\n    steps: [{run: a}]\n  b:\n    needs: d\n    if: always()\n    runs-on: u\n    steps: [{run: b}]\n  c:\n    needs: [d, a]\n    runs-on: u\n    steps: [{run: c}]\n  d:\n    runs-on: u\n    steps: [{run: d}]\n")
	e, _ := w.Jobs.Value.Lookup("a")
	j := e.Value.Value
	var ids []string
	for _, n := range Ancestors(w, &j) {
		ids = append(ids, n.ID.AsString())
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"b", "c", "d"}) {
		t.Errorf("got %v, want b, c and d once each", ids)
	}
}

package workflow

import (
	"strings"
	"testing"
)

// TestStepOrder: when steps that run alongside others are done, against
// what GitHub-hosted runners did.
// Each case lists, for each pair i < j of the steps, whether i is done
// before j; MayRunAfter(i, j) is then whether j is not done before i.
func TestStepOrder(t *testing.T) {
	for _, tt := range []struct {
		name  string
		steps string
		done  map[[2]int]bool // the pairs i < j where DoneBefore(i, j); all others are not
	}{
		{"plain", "      - run: a\n      - run: b\n      - run: c\n", map[[2]int]bool{{0, 1}: true, {0, 2}: true, {1, 2}: true}},
		{"group", "      - parallel:\n          - run: a\n          - run: b\n      - run: c\n", map[[2]int]bool{{0, 2}: true, {1, 2}: true}},
		{"background waited", "      - id: a\n        run: a\n        background: true\n      - run: b\n      - wait: a\n      - run: c\n", map[[2]int]bool{{0, 3}: true, {1, 2}: true, {1, 3}: true, {2, 3}: true}},
		{"background wait-all", "      - run: a\n        background: true\n      - run: b\n      - wait-all:\n      - run: c\n", map[[2]int]bool{{0, 3}: true, {1, 2}: true, {1, 3}: true, {2, 3}: true}},
		// a wait names ids; a step without one only
		// wait-all waits for
		{"background without an id", "      - {id: x, run: d}\n      - run: a\n        background: true\n      - wait: [x]\n      - run: c\n", map[[2]int]bool{{0, 1}: true, {0, 2}: true, {0, 3}: true, {2, 3}: true}},
		{"background never waited", "      - id: a\n        run: a\n        background: true\n      - run: b\n      - run: c\n", map[[2]int]bool{{1, 2}: true}},
		{"wait names another", "      - {id: b, run: d}\n      - id: a\n        run: a\n        background: true\n      - wait: b\n      - run: c\n", map[[2]int]bool{{0, 1}: true, {0, 2}: true, {0, 3}: true, {2, 3}: true}},
		{"wait folds case", "      - id: Build\n        run: a\n        background: true\n      - wait: [build]\n      - run: c\n", map[[2]int]bool{{0, 2}: true, {1, 2}: true}},
		{"cancel is no wait", "      - id: a\n        run: a\n        background: true\n      - cancel: a\n      - run: c\n", map[[2]int]bool{{1, 2}: true}},
		{"background in a group", "      - parallel:\n          - run: a\n            background: true\n          - run: b\n      - run: c\n", map[[2]int]bool{{0, 2}: true, {1, 2}: true}},
		{"background false", "      - run: a\n        background: false\n      - run: b\n", map[[2]int]bool{{0, 1}: true}},
		// a wait in a group runs alongside the
		// group's other steps, so what it waits for is done only after the
		// group. GitHub rejects a wait or a wait-all in a group, and the
		// reader reports it, but the rules still read
		// the steps of a workflow with diagnostics, in this order
		{"wait in a group", "      - id: x\n        run: x\n        background: true\n      - parallel:\n          - wait: x\n          - run: b\n      - run: c\n", map[[2]int]bool{{0, 3}: true, {1, 3}: true, {2, 3}: true}},
		{"wait-all in a group", "      - run: x\n        background: true\n      - parallel:\n          - wait-all:\n          - run: b\n      - run: c\n", map[[2]int]bool{{0, 3}: true, {1, 3}: true, {2, 3}: true}},
	} {
		w, diags, _ := parse(t, "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"+tt.steps)
		inGroup := 0 // the rows with a wait in a group, which the reader reports once
		if strings.HasSuffix(tt.name, "in a group") && strings.HasPrefix(tt.name, "wait") {
			inGroup = 1
		}
		if len(diags) != inGroup || inGroup == 1 && !strings.Contains(diags[0].Msg, "cannot be written in a step of a parallel group") {
			t.Fatalf("%s: %v", tt.name, diags)
		}
		steps := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items
		o := OrderOf(steps)
		for i := range steps {
			for j := range steps {
				if got, want := o.DoneBefore(i, j), i < j && tt.done[[2]int{i, j}]; got != want {
					t.Errorf("%s: DoneBefore(%d, %d) = %v", tt.name, i, j, got)
				}
				if got, want := o.MayRunAfter(i, j), i != j && !(j < i && tt.done[[2]int{j, i}]); got != want {
					t.Errorf("%s: MayRunAfter(%d, %d) = %v", tt.name, i, j, got)
				}
			}
		}
	}
}

// TestParallelSteps: the steps of a parallel group stand in its place, with
// where they are written; a group in a group, which GitHub rejects and the
// reader reports, stays a step of its own.
func TestParallelSteps(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n      - parallel:\n          - id: b\n            run: b\n          - parallel:\n              - run: c\n      - wait: [b]\n"
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags, InvalidValue)
	steps := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items
	want := []string{"steps[0]", "steps[1].parallel[0]", "steps[1].parallel[1]", "steps[2]"}
	if len(steps) != len(want) {
		t.Fatalf("%d steps: %+v", len(steps), steps)
	}
	for i, s := range steps {
		if s.Place.String() != want[i] || s.Order != i {
			t.Errorf("step %d at %s, order %d", i, s.Place, s.Order)
		}
	}
	if steps[1].Kind != StepRun || !steps[1].Background || steps[1].ID.Value.Text() != "b" {
		t.Errorf("group step = %+v", steps[1])
	}
	if steps[2].Kind != StepOther {
		t.Errorf("a group in a group is %v", steps[2].Kind)
	}
	if steps[3].Wait.Status != Present || len(steps[3].Wait.Value.Items) != 1 || steps[3].Wait.Value.Items[0].Text() != "b" {
		t.Errorf("wait = %+v", steps[3].Wait)
	}
}

// TestStepDoneAt: where a step is done, and the wait or wait-all that
// waits for it: none for a step that is not background, for a step of a
// parallel group (the end of the group) and for a background step that no
// step waits for (the end of the steps, where the implicit wait-all is).
func TestStepDoneAt(t *testing.T) {
	for _, tt := range []struct {
		name, steps string
		i, at, wait int
		waited      bool
	}{
		{"plain", "      - run: a\n      - run: b\n", 0, 1, 0, false},
		{"group", "      - parallel:\n          - run: a\n          - run: b\n      - run: c\n", 0, 2, 0, false},
		{"background waited", "      - id: a\n        run: a\n        background: true\n      - run: b\n      - wait: a\n      - run: c\n", 0, 3, 2, true},
		{"background wait-all", "      - run: a\n        background: true\n      - run: b\n      - wait-all:\n      - run: c\n", 0, 3, 2, true},
		{"background never waited", "      - id: a\n        run: a\n        background: true\n      - run: b\n", 0, 2, 0, false},
	} {
		w, _, _ := parse(t, "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"+tt.steps)
		o := OrderOf(w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items)
		at, wait, waited := o.DoneAt(tt.i)
		if at != tt.at || waited != tt.waited || waited && wait != tt.wait {
			t.Errorf("%s: DoneAt(%d) = %d, %d, %v, want %d, %d, %v", tt.name, tt.i, at, wait, waited, tt.at, tt.wait, tt.waited)
		}
	}
}

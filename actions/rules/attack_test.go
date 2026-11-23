package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/attackrun"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// TestExampleAttacks: each example of a rule of AttackMarkers is run with
// its attack value in the steps it reaches. A true positive and an
// inconclusive kind show the rule's harm, and a true negative does not,
// with every step ending well. A false positive form and an undetected form
// are not held to a direction: whether they are what they say often lies
// outside the script (the value never reaches it, the harm is another
// rule's), so what came of each is written to testdata/attack-runs.golden
// for a person to read with its attack-run-behavior. The examples not run
// are there too, with why.
func TestExampleAttacks(t *testing.T) {
	var lines []string
	for _, x := range Examples() {
		m := AttackMarkers[x.Rule]
		a := x.Example.Notes.AttackValue
		if m == attackrun.MarkerNone || a.IsZero() {
			continue
		}
		held := x.What == lint.ExampleTruePositive || x.What == lint.ExampleTrueNegative || x.What == lint.ExampleInconclusive
		if m == attackrun.MarkerStdout && strings.Contains("\n"+a.Value()+"\n", "\nPWNED\n") {
			t.Errorf("%s: the value has a line PWNED, which shows without running", x.Path)
			continue
		}
		if held && !strings.Contains(a.Value(), markerText[m]) {
			t.Errorf("%s: the value has no %q: it is not one that shows the harm when it reaches", x.Path, markerText[m])
			continue
		}
		result, err := attackResult(x, m, held)
		if err != nil {
			t.Errorf("%s (%s): %v", x.Path, x.What, err)
		}
		lines = append(lines, x.Path+"\t"+x.What.String()+"\t"+result)
	}
	got := strings.Join(lines, "\n") + "\n"
	golden := filepath.Join("testdata", "attack-runs.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("what came of the attack values differs from %s (go test -update):\n%s", golden, got)
	}
}

// attackResult runs x's attack value and says what came of it: "harm
// shows", "no harm", or "not run: <why>". When held, a true positive and an
// inconclusive kind must show the harm and a true negative must not, with
// no step failing.
func attackResult(x ExampleLocation, m attackrun.Marker, held bool) (string, error) {
	p, err := attackrun.Prepare(x.Example)
	if err != nil {
		return "error", err
	}
	if p.Unrun != attackrun.UnrunNone {
		return "not run: " + p.Unrun.String(), nil
	}
	seen, err := attackrun.Run(context.Background(), p)
	if err != nil {
		return "error", err
	}
	failed := slices.ContainsFunc(seen.Exits, func(c int) bool { return c != 0 })
	if failed && len(seen.Stubbed) > 0 {
		return "not run: " + attackrun.UnrunStubbedCommandFailed.String(), nil
	}
	shows := seen.Shows(m)
	result := "no harm"
	if shows {
		result = "harm shows"
	}
	if !held {
		return result, nil
	}
	want := x.What != lint.ExampleTrueNegative
	switch {
	case !want && failed:
		return result, fmt.Errorf("a step failed (exits %v), so it does not show that the harm is not there; stdout %q", seen.Exits, seen.Stdout)
	case shows != want:
		return result, fmt.Errorf("the harm shows %v, want %v; stdout %q, env %q, output %q, path %q", shows, want, seen.Stdout, seen.Env, seen.Output, seen.Path)
	}
	return result, nil
}

// markerText is what a value has, to show the harm of a marker when it
// reaches: a command that prints PWNED, a name PWNED, the line /tmp/PWNED.
var markerText = map[attackrun.Marker]string{
	attackrun.MarkerStdout: "PWNED",
	attackrun.MarkerEnv:    "PWNED",
	attackrun.MarkerOutput: "PWNED",
	attackrun.MarkerPath:   "/tmp/PWNED",
}

// TestAttackMarkersHaveAttackValues: an example of a rule of AttackMarkers
// has an attack-value, not an attack: what an attacker puts in there is a
// string.
func TestAttackMarkersHaveAttackValues(t *testing.T) {
	for _, x := range Examples() {
		if AttackMarkers[x.Rule] != attackrun.MarkerNone && x.Example.Notes.Attack != "" {
			t.Errorf("%s: an example of %s has attack, not attack-value", x.Path, x.Rule)
		}
		// a review batch writes the carrier in a code span
		if strings.Contains(x.Example.Notes.AttackValue.Carrier(), "`") {
			t.Errorf("%s: the carrier has a backquote", x.Path)
		}
	}
}

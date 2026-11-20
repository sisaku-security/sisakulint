package rules

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// The kinds of each rule's Meta are those findings-v0.json gives it, each
// saying what the schema says (the generated FindingText, not one written
// by hand in the Meta).
func TestMetaKinds(t *testing.T) {
	var declared []lint.FindingText
	for _, m := range allMetas() {
		for _, k := range m.FindingKinds {
			if k.ID.Rule() != m.ID {
				t.Errorf("%s declares %s", m.ID, k.ID)
			}
			declared = append(declared, k.FindingText)
		}
	}
	slices.SortFunc(declared, func(a, b lint.FindingText) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	if !slices.EqualFunc(declared, allFindingTexts, func(a, b lint.FindingText) bool { return reflect.DeepEqual(a, b) }) {
		t.Errorf("the rules declare %v; findings-v0.json has %v", declared, allFindingTexts)
	}
}

// Every rule a Class names is one of All (the registry does not check it:
// it may be made of some of the rules).
func TestMetaClasses(t *testing.T) {
	ids := map[string]bool{}
	for _, r := range All() {
		ids[r.Meta().ID.String()] = true
	}
	for _, r := range All() {
		m := r.Meta()
		for _, l := range m.UndetectedForms {
			if id, ok := l.Disposition.OtherRule(); ok && !ids[id.String()] {
				t.Errorf("%s: the limit %s names %s, which is not a rule", m.ID, l.ID, id)
			}
		}
	}
}

// TestCodeInjectionActorsEvents: code-injection's actors take the events
// actions/taint reads as an attacker's. Both are written by hand from the
// table of the threat model of code-injection; one changed
// without the other is seen here.
func TestInjectionActorsEvents(t *testing.T) {
	for _, m := range []lint.Meta{codeInjectionMeta, envvarInjectionMeta, outputClobberingMeta} {
		var got []workflow.EventName
		for _, a := range m.Threat.Actors {
			got = append(got, a.Events...)
		}
		slices.SortFunc(got, func(a, b workflow.EventName) int { return strings.Compare(a.String(), b.String()) })
		// status, check_suite and check_run are of two actors: the author of
		// a pull request from a fork and the author of a merged commit
		got = slices.Compact(got)
		if want := taint.TableEvents(); !slices.Equal(got, want) {
			t.Errorf("the actors of %s take %v; actions/taint reads %v as an attacker's", m.ID, got, want)
		}
	}
}

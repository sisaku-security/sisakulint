package scalar

import (
	"fmt"
	"os"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitewalk"
)

const suiteRoot = "../../../yaml-test-suite/data-2022-01-17"

var tally suitetest.Tally

func loadSuite(t *testing.T) []suitetest.Case {
	t.Helper()
	cs, err := suitetest.LoadCached(suiteRoot)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestMain(m *testing.M) {
	code := m.Run()
	if r := tally.String(); r != "" {
		fmt.Println("suite:", r)
	}
	os.Exit(code)
}

func runSuite(t *testing.T, check string, f func(*testing.T, suitetest.Case)) {
	suitetest.Run(t, loadSuite(t), check, suiteExclude[check], &tally, f)
}

// eventNodes pairs each event of the type typ with its node; every event
// when typ is EventTypeUnset.
func eventNodes(t *testing.T, c suitetest.Case, typ suitetest.EventType) ([]suitetest.Event, []cst.Node) {
	t.Helper()
	evs, err := suitewalk.Events(c, cst.Parse(c.In))
	if err != nil {
		t.Fatal(err)
	}
	var fe []suitetest.Event
	var fn []cst.Node
	for _, e := range evs {
		if typ == suitetest.EventTypeUnset || e.Type == typ {
			fe, fn = append(fe, e.Event), append(fn, e.Node)
		}
	}
	return fe, fn
}

func TestSuiteValues(t *testing.T) {
	runSuite(t, "values", func(t *testing.T, c suitetest.Case) {
		evs, ns := eventNodes(t, c, suitetest.EventScalar)
		for i, e := range evs {
			v, ok := Decode(ns[i])
			if !ok {
				t.Errorf("scalar %d: Decode failed", i)
				continue
			}
			if v.String() != e.Value {
				t.Errorf("scalar %d = %q, want %q", i, v.String(), e.Value)
			}
		}
	})
}

func TestSuiteTags(t *testing.T) {
	runSuite(t, "tags", func(t *testing.T, c suitetest.Case) {
		evs, ns := eventNodes(t, c, suitetest.EventTypeUnset)
		for i, e := range evs {
			got, ok := Explicit(ns[i], DirectivesOf(documentOf(ns[i])))
			if ok != e.HasTag || got.String() != e.Tag {
				t.Errorf("node %d (%s): Explicit = %q %v, want %q %v", i, e.Type, got, ok, e.Tag, e.HasTag)
			}
		}
	})
}

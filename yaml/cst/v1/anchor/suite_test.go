package anchor

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

func TestMain(m *testing.M) {
	code := m.Run()
	if r := tally.String(); r != "" {
		fmt.Println("suite:", r)
	}
	os.Exit(code)
}

// TestSuiteAliases checks that each =ALI *a resolves to the node of the
// latest event before it, in its document, with &a.
func TestSuiteAliases(t *testing.T) {
	cs, err := suitetest.LoadCached(suiteRoot)
	if err != nil {
		t.Fatal(err)
	}
	suitetest.Run(t, cs, "aliases", nil, &tally, func(t *testing.T, c suitetest.Case) {
		tr := cst.Parse(c.In)
		evs, err := suitewalk.Events(c, tr)
		if err != nil {
			t.Fatal(err)
		}
		x := Build(tr)
		for i, e := range evs {
			if e.Type != suitetest.EventAlias {
				continue
			}
			want := -1
			for j := i - 1; j >= 0 && evs[j].Doc == e.Doc; j-- {
				if evs[j].Anchor == e.Alias {
					want = j
					break
				}
			}
			got, ok := x.Resolve(e.Node)
			if want < 0 {
				if ok {
					t.Errorf("alias %d *%s: resolved without a definition", i, e.Alias)
				}
				continue
			}
			if !ok || got != evs[want].Node {
				t.Errorf("alias %d *%s = %v %v, want node %d %v", i, e.Alias, got.Span(), ok, want, evs[want].Node.Span())
			}
		}
	})
}

package rules

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// TestCachePoisoningComposite: a step of a composite action of another
// repository saves the tree as a step of the job does, where the action
// runs after the checkout; the evidence points into the answer of
// action.definition, as a file of the fact in the JSON. A composite action
// run before the checkout, and an action the archive does not have
// (export-ignore: the runner stops the job), save nothing of the pull
// request: those workflows show writable-job alone, which the job is, so
// they are tests here and not true negatives of saved-checkout.
func TestCachePoisoningComposite(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	for _, c := range []struct {
		file  string
		saved bool
	}{
		{"examples/true-positive/cache-poisoning/saved-checkout.remote-composite.yml", true},
		{"testdata/cachepoisoning/composite-before.yml", false},
		{"testdata/cachepoisoning/export-ignore.yml", false},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{CachePoisoning}, map[string]string{".github/workflows/w.yml": read(c.file)}, limitFacts{})
		if len(rep.Errors) != 0 {
			t.Fatalf("%s: errors %+v", c.file, rep.Errors)
		}
		var kinds []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			kinds = append(kinds, f.Args.KindID().String())
		}
		if got := slices.Contains(kinds, "cache-poisoning.saved-checkout"); got != c.saved || !slices.Contains(kinds, "cache-poisoning.writable-job") {
			t.Errorf("%s: findings %v, saved-checkout %v", c.file, kinds, c.saved)
		}
		if !c.saved {
			continue
		}
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(b, []byte(`"file":{"query":{"kind":"action.definition","repo":"example-org/cache-composite","ref":"v1"}}`)) {
			t.Errorf("no evidence in the file of action.definition:\n%s", b)
		}
	}
}

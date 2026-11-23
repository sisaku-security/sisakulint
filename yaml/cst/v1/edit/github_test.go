package edit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// firstValue is the value of the first mapping entry with key k.
func firstValue(n cst.Node, k string) (cst.Node, bool) {
	if m, ok := n.Mapping(); ok {
		for e := range m.Entries() {
			if string(e.Key.Bytes()) == k {
				return e.Value, true
			}
		}
	}
	for e := range n.Children() {
		if c, ok := e.Node(); ok {
			if v, ok := firstValue(c, k); ok {
				return v, true
			}
		}
	}
	return cst.Node{}, false
}

// A tree read in ModeGitHub is read back in ModeGitHub by Apply, so a
// workflow that ModeSpec rejects (its flow sequence's ']' is at the key's
// column) can be edited without errors.
func TestApplyKeepsMode(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(suitetest.CorpusRoot(t), "real-world/grafana__grafana/.github/workflows/backend-unit-tests.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []cst.Mode{cst.ModeGitHub, cst.ModeSpec} {
		tr := cst.ParseMode(src, m)
		n, ok := firstValue(tr.Root(), "runs-on")
		if !ok {
			t.Fatal("no runs-on")
		}
		v, _ := scalar.Decode(n)
		e, err := Replace(v, 0, len(v.String()), "ubuntu-24.04")
		if err != nil {
			t.Fatal(err)
		}
		r, err := Apply(tr, []Edit{e})
		if err != nil {
			t.Fatalf("mode %v: %v", m, err)
		}
		if r.Tree.Mode() != m {
			t.Errorf("mode %v: result read in %v", m, r.Tree.Mode())
		}
		if got := len(r.Tree.Errors()); (got == 0) != (m == cst.ModeGitHub) {
			t.Errorf("mode %v: %d errors", m, got)
		}
		if !strings.Contains(string(r.Tree.Bytes()), "runs-on: ubuntu-24.04") {
			t.Errorf("mode %v: not replaced", m)
		}
	}
}

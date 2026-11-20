package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExamplesHTML(t *testing.T) {
	a, b := filepath.Join(t.TempDir(), "a.html"), filepath.Join(t.TempDir(), "b.html")
	for _, p := range []string{a, b} {
		if got := run(t, raw("--examples", "--html", p)); got.code != 0 {
			t.Fatalf("%d %s", got.code, got.stderr)
		}
	}
	pa, _ := os.ReadFile(a)
	pb, _ := os.ReadFile(b)
	if len(pa) == 0 || !bytes.Equal(pa, pb) || !bytes.Contains(pa, []byte(`id="catalog-data"`)) {
		t.Error("not the same catalog twice, or no catalog")
	}
	one := filepath.Join(t.TempDir(), "one.html")
	if got := run(t, raw("--examples=code-injection", "--html", one)); got.code != 0 {
		t.Fatalf("%d %s", got.code, got.stderr)
	}
	po, _ := os.ReadFile(one)
	if len(po) >= len(pa) || !bytes.Contains(po, []byte(`"rule":"code-injection","quality":false,"meta"`)) || bytes.Contains(po, []byte(`"rule":"commit-sha","quality":false,"meta"`)) {
		t.Error("--examples=code-injection is not the rule alone")
	}
}

func TestExamplesUsage(t *testing.T) {
	out := filepath.Join(t.TempDir(), "x.html")
	for _, a := range [][]string{
		{"--examples"},
		{"--examples=no-such-rule", "--html", out},
		{"--examples", "--html", out, "--root", "."},
		{"--examples", "--html", out, "--facts", "f.json"},
		{"--examples", "--html", out, "--fix"},
		{"--examples", "--html", out, "x.yml"},
	} {
		if got := run(t, raw(a...)); got.code != ExitUsage {
			t.Errorf("%v: %d, want %d\n%s", a, got.code, ExitUsage, got.stderr)
		}
	}
}

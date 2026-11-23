package anchor

import (
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitewalk"
)

// resolveAll resolves every Alias of src in order, giving the referred
// node's text or "" when there is none.
func resolveAll(src string) []string {
	tr := cst.Parse([]byte(src))
	x := Build(tr)
	var got []string
	for _, n := range suitewalk.Nodes(tr) {
		if n.Kind() != cst.NodeAlias {
			continue
		}
		d, ok := x.Resolve(n)
		if !ok {
			got = append(got, "")
			continue
		}
		got = append(got, string(d.Bytes()))
	}
	return got
}

func TestResolve(t *testing.T) {
	cases := []struct {
		src  string
		want []string
	}{
		{"- &a 1\n- *a\n- &a 2\n- *a\n", []string{"&a 1", "&a 2"}},
		{"- *b\n", []string{""}},
		{"- *a\n- &a 1\n", []string{""}},
		{"&a [*a]\n", []string{"&a [*a]"}},
		{"&a 1\n--- *a\n", []string{""}},
		{"a: &x {b: &y c}\nd: *y\ne: *x\n", []string{"&y c", "&x {b: &y c}"}},
	}
	for _, c := range cases {
		got := resolveAll(c.src)
		if len(got) != len(c.want) {
			t.Errorf("%q: %q, want %q", c.src, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: alias %d = %q, want %q", c.src, i, got[i], c.want[i])
			}
		}
	}
}

func TestResolveNotAlias(t *testing.T) {
	tr := cst.Parse([]byte("&a 1\n"))
	x := Build(tr)
	if _, ok := x.Resolve(tr.Root()); ok {
		t.Error("Resolve accepted a Stream")
	}
	var zero Index
	for _, n := range suitewalk.Nodes(cst.Parse([]byte("*a\n"))) {
		if _, ok := zero.Resolve(n); ok {
			t.Error("the zero Index resolved an alias")
		}
	}
}

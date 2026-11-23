package scalar

import (
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitewalk"
)

// eventNode is the i-th node of src in event order, with its directives.
func eventNode(t *testing.T, src string, i int) (cst.Node, Directives) {
	t.Helper()
	k := 0
	for _, n := range suitewalk.Nodes(cst.Parse([]byte(src))) {
		if k == i {
			return n, DirectivesOf(documentOf(n))
		}
		k++
	}
	t.Fatalf("%q: no node %d", src, i)
	return cst.Node{}, Directives{}
}

func documentOf(n cst.Node) cst.Node {
	for n.Kind() != cst.NodeDocument {
		p, ok := n.Parent()
		if !ok {
			break
		}
		n = p
	}
	return n
}

func TestExplicit(t *testing.T) {
	cases := []struct {
		src  string
		want string
		ok   bool
	}{
		{"!!str a\n", "tag:yaml.org,2002:str", true},
		{"%TAG !e! tag:e.com,2000:\n--- !e!foo a\n", "tag:e.com,2000:foo", true},
		{"!e!foo a\n", "!e!foo", true}, // no %TAG: as written
		{"%TAG ! tag:local,2000:\n--- !foo a\n", "tag:local,2000:foo", true},
		{"%TAG !! tag:other,2000:\n--- !!foo a\n", "tag:other,2000:foo", true},
		{"!<tag:x%21> a\n", "tag:x%21", true},
		{"!foo%21 a\n", "!foo!", true},
		{"! a\n", "!", true},
		{"&x a\n", "", false},
		{"a\n", "", false},
		{"!t [a]\n", "!t", true},
		{"%TAG !e! tag:e.com,2000:\n--- a\n--- !e!foo b\n", "!e!foo", true}, // %TAG is per document
	}
	for _, c := range cases {
		n, d := eventNode(t, c.src, 0)
		if c.src[0] == '%' && c.want == "!e!foo" {
			n, d = eventNode(t, c.src, 1)
		}
		got, ok := Explicit(n, d)
		if got.String() != c.want || ok != c.ok {
			t.Errorf("%q: Explicit = %q %v, want %q %v", c.src, got, ok, c.want, c.ok)
		}
	}
}

func TestResolve(t *testing.T) {
	// Example 10.9 Core Tag Resolution, and the style and tag rules
	src := `A null: null
Also a null: # Empty
Not a null: ""
Booleans: [ true, True, false, FALSE ]
Integers: [ 0, 0o7, 0x3A, -19 ]
Floats: [ 0., -0.0, .5, +12e03, -2E+05 ]
Also floats: [ .inf, -.Inf, +.INF, .NAN ]
Strings: [ tRUE, 0o8, 1_000, .in, nul, 0x, "1", '1', ! 1, !!str 1 ]
Explicit: [ !!int "1", ! [a], ! {a: b}, !foo 1 ]
Alias: [ &a 1, *a ]
Block: |
  1
`
	const (
		null  = "tag:yaml.org,2002:null"
		bool_ = "tag:yaml.org,2002:bool"
		int_  = "tag:yaml.org,2002:int"
		float = "tag:yaml.org,2002:float"
		str   = "tag:yaml.org,2002:str"
		seq   = "tag:yaml.org,2002:seq"
		map_  = "tag:yaml.org,2002:map"
	)
	want := []string{
		map_,
		str, null,
		str, null,
		str, str,
		str, seq, bool_, bool_, bool_, bool_,
		str, seq, int_, int_, int_, int_,
		str, seq, float, float, float, float, float,
		str, seq, float, float, float, float,
		str, seq, str, str, str, str, str, str, str, str, str, str,
		str, seq, "tag:yaml.org,2002:int", seq, str, map_, str, str, "!foo",
		str, seq, int_, "",
		str, str,
	}
	var got []string
	for _, n := range suitewalk.Nodes(cst.Parse([]byte(src))) {
		got = append(got, Resolve(n, DirectivesOf(documentOf(n))).String())
	}
	if len(got) != len(want) {
		t.Fatalf("%d nodes, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("node %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUnescapeURI(t *testing.T) {
	for s, want := range map[string]string{"a%21b": "a!b", "a%2": "a%2", "%zz": "%zz", "a": "a", "%E3%81%82": "\xe3\x81\x82"} {
		if got := unescapeURI(s); got != want {
			t.Errorf("unescapeURI(%q) = %q, want %q", s, got, want)
		}
	}
}

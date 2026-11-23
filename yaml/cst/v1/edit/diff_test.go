package edit

import (
	"strings"
	"testing"

	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// change is a Change as text: its kind, path and the bytes of its nodes.
type change struct{ kind, path, old, new string }

func changes(d []Change) []change {
	var out []change
	for _, c := range d {
		var o, n string
		if c.Old != (cst.Node{}) {
			o = string(contentBytes(c.Old))
		}
		if c.New != (cst.Node{}) {
			n = string(contentBytes(c.New))
		}
		out = append(out, change{c.Kind.String(), c.Path.String(), o, n})
	}
	return out
}

func raw(start, end int, text string) Edit {
	return Edit{Span: cst.Span{Start: start, End: end}, New: []byte(text)}
}

func TestDiffOfRawEdits(t *testing.T) {
	cases := []struct {
		name, src string
		edits     func(src string) []Edit
		want      []change
	}{
		{"add a key", "a: 1\n", func(string) []Edit { return []Edit{raw(5, 5, "b: 2\n")} },
			[]change{{"Added", "b", "", "b: 2"}}},
		{"remove an item", "- a\n- b\n- c\n", func(string) []Edit { return []Edit{raw(4, 8, "")} },
			[]change{{"Removed", "[1]", "b", ""}}},
		{"add an item first", "- a\n- b\n", func(string) []Edit { return []Edit{raw(0, 0, "- z\n")} },
			[]change{{"Added", "[0]", "", "z"}}},
		{"scalar to mapping", "a: x\nb: 1\n", func(string) []Edit { return []Edit{raw(3, 4, "\n  k: 1")} },
			[]change{{"Changed", "a", "x", "k: 1"}}},
		{"a comment without its '#'", "steps:\n  - uses: actions/checkout@abc  # v3\n",
			func(src string) []Edit { i := strings.Index(src, "# v3"); return []Edit{raw(i, i+4, "v4")} },
			[]change{{"Changed", "steps[0].uses", "actions/checkout@abc", "actions/checkout@abc  v4"}}},
		{"a duplicate key", "a: 1\na: 2\n", func(string) []Edit { return []Edit{raw(8, 9, "3")} },
			[]change{{"Changed", "a", "2", "3"}}},
		{"a complex key", "? [a, b]\n: 1\n", func(string) []Edit { return []Edit{raw(11, 12, "2")} },
			[]change{{"Changed", `["[a, b]"]`, "1", "2"}}},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		res, err := Apply(tr, c.edits(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := changes(res.Diff); !equalChanges(got, c.want) {
			t.Errorf("%s: Diff = %v, want %v", c.name, got, c.want)
		}
	}
}

func equalChanges(a, b []change) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDiffOfReplace(t *testing.T) {
	src := "jobs:\n  build:\n    steps:\n      - run: echo hi\n"
	tr := cst.Parse([]byte(src))
	v := valueOf(t, tr, "echo hi")
	ed, err := Replace(v, 5, 7, "yo")
	if err != nil {
		t.Fatal(err)
	}
	res, err := Apply(tr, []Edit{ed})
	if err != nil {
		t.Fatal(err)
	}
	want := []change{{"Changed", "jobs.build.steps[0].run", "echo hi", "echo yo"}}
	if got := changes(res.Diff); !equalChanges(got, want) {
		t.Errorf("Diff = %v, want %v", got, want)
	}
}

// An edit that promises a value is refused when the bytes it writes do
// more than that.
func TestApplyRefusesUnpromisedChange(t *testing.T) {
	tr := cst.Parse([]byte("a: x\nc: 1\n"))
	v := valueOf(t, tr, "x")
	ed, err := Replace(v, 0, 1, "y")
	if err != nil {
		t.Fatal(err)
	}
	ed.New = []byte("y\nb: 2")
	if res, err := Apply(tr, []Edit{ed}); err == nil {
		t.Errorf("Apply = %q, want an error", res.Tree.Bytes())
	}
}

func TestDiffNothingChanged(t *testing.T) {
	for name, src := range inputs(t) {
		tr := cst.Parse(src)
		for _, edits := range [][]Edit{nil, {raw(0, 0, "")}} {
			res, err := Apply(tr, edits)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if len(res.Diff) > 0 {
				t.Errorf("%s: Diff = %v, want none", name, changes(res.Diff))
			}
			seen := map[cst.Node]cst.Node{}
			var visit func(n cst.Node)
			visit = func(n cst.Node) {
				got, ok := res.Follow(n)
				switch {
				case !ok:
					t.Errorf("%s: no node follows %v %q", name, n.Kind(), n.Bytes())
				case got.Kind() != n.Kind() || string(got.Bytes()) != string(n.Bytes()):
					t.Errorf("%s: %v %q follows as %v %q", name, n.Kind(), n.Bytes(), got.Kind(), got.Bytes())
				default:
					if prev, dup := seen[got]; dup {
						t.Errorf("%s: %v %q and %v %q follow as the same node", name, prev.Kind(), prev.Bytes(), n.Kind(), n.Bytes())
					}
					seen[got] = n
				}
				for e := range n.Children() {
					if c, ok := e.Node(); ok {
						visit(c)
					}
				}
			}
			visit(tr.Root())
		}
	}
}

func TestFollow(t *testing.T) {
	src := "a: &p x\nb:\n- 1\n- 2\n- 3\nc: y\n"
	tr := cst.Parse([]byte(src))
	i := strings.Index(src, "- 2\n")
	j := strings.Index(src, "y")
	res, err := Apply(tr, []Edit{raw(i, i+4, ""), raw(j, j+1, "{k: 1}")})
	if err != nil {
		t.Fatal(err)
	}
	a, entryA := walk(t, tr, "a")
	if got, ok := res.Follow(entryA); !ok || string(contentBytes(got)) != "a: &p x" {
		t.Errorf("entry a follows as %q, %v", got.Bytes(), ok)
	}
	for e := range a.Children() {
		if p, ok := e.Node(); ok && p.Kind() == cst.NodeProperties {
			if got, ok := res.Follow(p); !ok || got.Kind() != cst.NodeProperties || string(got.Bytes()) != string(p.Bytes()) {
				t.Errorf("properties follow as %v %q, %v", got.Kind(), got.Bytes(), ok)
			}
		}
	}
	two, _ := walk(t, tr, "b", 1)
	if got, ok := res.Follow(two); ok {
		t.Errorf("a removed item follows as %q", got.Bytes())
	}
	three, _ := walk(t, tr, "b", 2)
	if got, ok := res.Follow(three); !ok || string(got.Bytes()) != "3" {
		t.Errorf("item 3 follows as %q, %v", got.Bytes(), ok)
	}
	y, _ := walk(t, tr, "c")
	if got, ok := res.Follow(y); !ok || got.Kind() != cst.NodeFlowMapping {
		t.Errorf("c follows as %v %q, %v", got.Kind(), got.Bytes(), ok)
	}
	other := cst.Parse([]byte(src))
	if got, ok := res.Follow(other.Root()); ok {
		t.Errorf("a node of another tree follows as %q", got.Bytes())
	}
}

func TestPathString(t *testing.T) {
	cases := []struct {
		p    Path
		want string
	}{
		{Path{{Key: "jobs", Index: -1}, {Key: "a.b", Index: -1}, {Index: 0}}, `jobs["a.b"][0]`},
		{Path{{Key: "x", Index: -1}}, "x"},
		{Path{{Index: 2}, {Key: "run-name", Index: -1}}, "[2].run-name"},
		{Path{{Key: "", Index: -1}}, `[""]`},
		{nil, ""},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("%#v.String() = %q, want %q", c.p, got, c.want)
		}
	}
}

// A Replace of a key pairs the entry by the key it promises; one inside a
// key that is no scalar, by the key's text with the edit applied.
func TestDiffOfRenamedKey(t *testing.T) {
	cases := []struct {
		src, value string
		want       []change
	}{
		{"a: 1\nc: 2\n", "a", []change{{"Changed", "zz", "a", "zz"}}},
		{"? [a, b]\n: 1\n", "a", []change{{"Changed", `["[zz, b]"][0]`, "a", "zz"}}},
	}
	for _, c := range cases {
		tr := cst.Parse([]byte(c.src))
		v := valueOf(t, tr, c.value)
		ed, err := Replace(v, 0, len(c.value), "zz")
		if err != nil {
			t.Fatal(err)
		}
		res, err := Apply(tr, []Edit{ed})
		if err != nil {
			t.Errorf("%q: %v", c.src, err)
			continue
		}
		if got := changes(res.Diff); !equalChanges(got, c.want) {
			t.Errorf("%q: Diff = %v, want %v", c.src, got, c.want)
		}
	}
}

// An item next to one an edit removes or adds
// before pairs with its own new item, not with the next one.
func TestDiffNextToAnEditedItem(t *testing.T) {
	src := "steps:\n  - run: echo a\n  - run: echo b\n  - run: echo c\n"
	tr := cst.Parse([]byte(src))
	_, step0 := walk(t, tr, "steps", 0)
	del := must(t)(new(Editor).Delete(step0))
	rep := replaceIn(t, tr, "echo b", "b", "B")
	res := mustApply(t, tr, del, rep)
	if got := string(res.Tree.Bytes()); got != "steps:\n  - run: echo B\n  - run: echo c\n" {
		t.Errorf("%q", got)
	}
	run1, _ := walk(t, tr, "steps", 1, "run")
	if n, ok := res.Follow(run1); !ok || string(n.Bytes()) != "echo B" {
		t.Errorf("steps[1].run follows as %q, %v", n.Bytes(), ok)
	}

	steps, _ := walk(t, tr, "steps")
	first, _ := walk(t, tr, "steps", 0)
	ins := must(t)(new(Editor).InsertItem(steps, 0, Map{{Key: "run", Value: Str("echo z")}}))
	env := must(t)(new(Editor).Insert(first, Last(), Map{{Key: "env", Value: Map{{Key: "A", Value: Int(1)}}}}))
	res = mustApply(t, tr, ins, env, replaceIn(t, tr, "echo a", "a", "A"))
	want := "steps:\n  - run: echo z\n  - run: echo A\n    env:\n      A: 1\n  - run: echo b\n  - run: echo c\n"
	if got := string(res.Tree.Bytes()); got != want {
		t.Errorf("%q, want %q", got, want)
	}
}

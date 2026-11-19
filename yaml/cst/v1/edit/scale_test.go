package edit

import (
	"cmp"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// Making edits and applying them takes time linear in their number: a
// lint makes one or two per finding in an untrusted workflow. Pairing the
// entries of a changed mapping by key was once quadratic (32,000 Replace
// took 1.7 s), and so was finding the layout for each Insert (4,000 steps
// took 6.6 s), and so was looking up an element for each edit of one
// large collection. Each shape makes and applies edits of a tree of n and
// of 4n elements; linear time is about 4 times as long, quadratic about
// 16. The best of three runs is compared. A shape whose quadratic part is
// small next to the rest is read at a larger n; what is smaller still is
// timed alone (TestScaleChangeOf, TestScaleEntriesByKey). Only the edits
// of n are made and applied unless ACTIONS_SCALE=1, as the time compared
// depends on the machine.
func TestScaleLinear(t *testing.T) {
	// items is a sequence of n mappings "- k: v\n  m: w".
	items := func(n int) *cst.Tree {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "- k%d: v\n  m: w\n", i)
		}
		return cst.Parse([]byte(b.String()))
	}
	// values are the scalars v of items.
	values := func(tr *cst.Tree) []cst.Node {
		var out []cst.Node
		for n := range allScalars(tr) {
			if string(n.Bytes()) == "v" {
				out = append(out, n)
			}
		}
		return out
	}
	shapes := []struct {
		name  string
		tree  func(n int) *cst.Tree
		edits func(t *testing.T, tr *cst.Tree) []Edit
		n     int // the smaller size, when not 1000
	}{
		{"Replace", items, func(t *testing.T, tr *cst.Tree) []Edit {
			var es []Edit
			for _, n := range values(tr) {
				v, _ := decode(n)
				es = append(es, must(t)(Replace(v, 0, 1, "ww")))
			}
			return es
		}, 0},
		{"raw", items, func(t *testing.T, tr *cst.Tree) []Edit {
			var es []Edit
			for _, n := range values(tr) {
				es = append(es, Edit{Span: n.Span(), New: []byte("ww")})
			}
			return es
		}, 0},
		{"raw with errors", func(n int) *cst.Tree {
			var b strings.Builder
			for i := range n {
				fmt.Fprintf(&b, "k%d: v\n@\n", i) // an error on each line of @
			}
			return cst.Parse([]byte(b.String()))
		}, func(t *testing.T, tr *cst.Tree) []Edit {
			var es []Edit
			for _, n := range values(tr) {
				es = append(es, Edit{Span: n.Span(), New: []byte("ww")})
			}
			return es
		}, 0},
		{"SetValue", items, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			for _, n := range values(tr) {
				es = append(es, must(t)(e.SetValue(n, Seq{Str("a")})))
			}
			return es
		}, 0},
		{"Delete", items, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			for _, n := range values(tr) {
				entry, _ := n.Parent()
				es = append(es, must(t)(e.Delete(entry)))
			}
			return es
		}, 0},
		{"Insert", items, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			for _, n := range values(tr) {
				entry, _ := n.Parent()
				m, _ := entry.Parent()
				es = append(es, must(t)(e.Insert(m, Last(), Map{{Key: "x", Value: Str("y")}})))
			}
			return es
		}, 0},
		{"LineComment", items, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			for _, n := range values(tr) {
				es = append(es, must(t)(e.LineComment(n, "c"))) // no comment to take the gap from
			}
			return es
		}, 0},
		{"Delete of anchors", func(n int) *cst.Tree {
			var b strings.Builder
			for i := range n {
				fmt.Fprintf(&b, "- k: &a%d v\n  m: w\n", i) // the aliases are looked for
			}
			return cst.Parse([]byte(b.String()))
		}, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			for n := range allScalars(tr) {
				if !strings.HasPrefix(string(n.Bytes()), "&a") { // the bytes of a scalar hold its properties
					continue
				}
				entry, _ := n.Parent()
				es = append(es, must(t)(e.Delete(entry)))
			}
			if len(es) == 0 {
				t.Fatal("no edits")
			}
			return es
		}, 0},
		// One large collection with many edits: what an operation or a
		// check looks up in the collection must not be looked for anew each time.
		{"Replace in one mapping", flat, func(t *testing.T, tr *cst.Tree) []Edit {
			var es []Edit
			for _, n := range flatValues(tr) {
				v, _ := decode(n)
				es = append(es, must(t)(Replace(v, 0, 1, "ww")))
			}
			return es
		}, 0},
		{"Delete in one mapping", flat, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			for i, n := range flatValues(tr) {
				if i%2 == 0 {
					entry, _ := n.Parent()
					es = append(es, must(t)(e.Delete(entry)))
				}
			}
			return es
		}, 0},
		{"Insert in one mapping", flat, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			m := docContent(tr)
			for i := range len(flatValues(tr)) / 2 {
				es = append(es, must(t)(e.Insert(m, Before(fmt.Sprintf("k%d", 2*i)), Map{{Key: fmt.Sprintf("new%d", i), Value: Str("y")}})))
			}
			return es
		}, 0},
		// An insert next to an element deleted in the same Apply is refused,
		// so a sequence gets one kind of edit at a time.
		{"Delete in one sequence", seq, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			for i, x := range itemsOf(docContent(tr)) {
				if i%2 == 0 {
					es = append(es, must(t)(e.Delete(x)))
				}
			}
			return es
		}, 0},
		{"InsertItem in one sequence", seq, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			s := docContent(tr)
			for i := range len(itemsOf(s)) / 2 {
				es = append(es, must(t)(e.InsertItem(s, 2*i, Str("n"))))
			}
			return es
		}, 0},
		{"Insert into each job", func(n int) *cst.Tree { return steps(n, false) }, func(t *testing.T, tr *cst.Tree) []Edit {
			var e Editor
			var es []Edit
			jobs, _ := walkQuiet(tr, "jobs")
			for _, j := range entriesOf(jobs) {
				es = append(es, must(t)(e.Insert(j.Value, First(), Map{{Key: "permissions", Value: Str("read-all")}})))
			}
			return es
		}, 4000},
		{"Insert env in steps", func(n int) *cst.Tree { return steps(n, false) }, insertEnv, 0},
		{"Insert env in flow steps", func(n int) *cst.Tree { return steps(n, true) }, insertEnv, 0},
	}
	for _, s := range shapes {
		t.Run(s.name, func(t *testing.T) {
			n := cmp.Or(s.n, 1000)
			small := editTime(t, s.tree(n), s.edits)
			if os.Getenv("ACTIONS_SCALE") != "1" {
				return
			}
			large := editTime(t, s.tree(4*n), s.edits)
			if r := float64(large) / float64(small); r > 10 {
				t.Errorf("%d edits took %v, %d took %v: %.1f times, not about 4", n, small, 4*n, large, r)
			}
		})
	}
}

// changeOf finds a change in time that does not grow with the number of
// changes: Apply asks it once for each Insert and Delete. Its share of an
// Apply is too small for TestScaleLinear to see, so it is timed alone.
// Only n changes are looked for unless ACTIONS_SCALE=1, as the time
// compared depends on the machine.
func TestScaleChangeOf(t *testing.T) {
	timeOf := func(n int) time.Duration {
		items := itemsOf(docContent(seq(n)))
		best := time.Duration(1 << 62)
		for range 3 {
			d := &differ{}
			for _, x := range items {
				d.change(Removed, nil, x, cst.Node{})
			}
			start := time.Now()
			for i, x := range items {
				if k := d.changeOf(Removed, x); k != i {
					t.Fatalf("changeOf item %d = %d", i, k)
				}
			}
			best = min(best, time.Since(start))
		}
		return best
	}
	const n = 4000
	small := timeOf(n)
	if os.Getenv("ACTIONS_SCALE") != "1" {
		return
	}
	large := timeOf(4 * n)
	if r := float64(large) / float64(small); r > 10 {
		t.Errorf("%d changes took %v, %d took %v: %.1f times, not about 4", n, small, 4*n, large, r)
	}
}

// Pairing the entries of two mappings by key takes time linear in their
// number. The new mapping has the keys in the reverse order, so that no
// entry pairs by its place and each is found by its key. Only n entries
// are paired unless ACTIONS_SCALE=1, as the time compared depends on the
// machine.
func TestScaleEntriesByKey(t *testing.T) {
	timeOf := func(n int) time.Duration {
		var b strings.Builder
		for i := n - 1; i >= 0; i-- {
			fmt.Fprintf(&b, "k%d: v\n", i)
		}
		o, nt := docContent(flat(n)), docContent(cst.Parse([]byte(b.String())))
		best := time.Duration(1 << 62)
		for range 3 {
			d := &differ{pairs: map[cst.Node]pair{}}
			start := time.Now()
			d.entries(o, nt, nil)
			best = min(best, time.Since(start))
			if len(d.changes) != 0 {
				t.Fatalf("%d changes, want none: %v", len(d.changes), d.changes[0])
			}
		}
		return best
	}
	const n = 4000
	small := timeOf(n)
	if os.Getenv("ACTIONS_SCALE") != "1" {
		return
	}
	large := timeOf(4 * n)
	if r := float64(large) / float64(small); r > 10 {
		t.Errorf("%d entries took %v, %d took %v: %.1f times, not about 4", n, small, 4*n, large, r)
	}
}

// flat is one mapping of n keys "kI: v".
func flat(n int) *cst.Tree {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	return cst.Parse([]byte(b.String()))
}

// seq is one sequence of n items "- vI".
func seq(n int) *cst.Tree {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "- v%d\n", i)
	}
	return cst.Parse([]byte(b.String()))
}

// flatValues are the values of flat, in order.
func flatValues(tr *cst.Tree) []cst.Node {
	var out []cst.Node
	for _, e := range entriesOf(docContent(tr)) {
		out = append(out, e.Value)
	}
	return out
}

// walkQuiet is the value of key in the document's mapping.
func walkQuiet(tr *cst.Tree, key string) (cst.Node, bool) {
	for _, e := range entriesOf(docContent(tr)) {
		if keyText(e.Key) == key {
			return e.Value, true
		}
	}
	return cst.Node{}, false
}

// steps is a workflow of n jobs of one step "run: x", in a block or a
// flow sequence.
func steps(n int, flow bool) *cst.Tree {
	var b strings.Builder
	b.WriteString("on: push\njobs:\n")
	for i := range n {
		if flow {
			fmt.Fprintf(&b, "  j%d:\n    runs-on: x\n    steps: [{run: x}]\n", i)
		} else {
			fmt.Fprintf(&b, "  j%d:\n    runs-on: x\n    steps:\n      - run: x\n", i)
		}
	}
	return cst.Parse([]byte(b.String()))
}

// insertEnv puts an env first into each step, as a fix of code injection
// does, with one Editor.
func insertEnv(t *testing.T, tr *cst.Tree) []Edit {
	var ed Editor
	var es []Edit
	for n := range allScalars(tr) {
		if string(n.Bytes()) != "run" {
			continue
		}
		e, _ := n.Parent()
		m, _ := e.Parent()
		es = append(es, must(t)(ed.Insert(m, First(), Map{{Key: "env", Value: Map{{Key: "A", Value: Str("b")}}}})))
	}
	return es
}

func editTime(t *testing.T, tr *cst.Tree, edits func(*testing.T, *cst.Tree) []Edit) time.Duration {
	best := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		if _, err := Apply(tr, edits(t, tr)); err != nil {
			t.Fatal(err)
		}
		best = min(best, time.Since(start))
	}
	return best
}

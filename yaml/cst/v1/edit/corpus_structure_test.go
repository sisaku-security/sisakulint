package edit

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"os"
	"regexp"
	"sort"
	"sync"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// structuralOps are the operations TestCorpusStructure makes on a tree:
// an Insert at the end of each mapping, a Delete of each entry and item,
// an InsertItem at the end of each sequence, a SetValue to a mapping and
// to a literal and a LineComment of each scalar value of a mapping. Each
// comes with the one change it must make, or none. Each is made with the
// Editor ed gives when it is made.
func structuralOps(tr *cst.Tree, ed func() *Editor) []structuralOp {
	var ops []structuralOp
	var visit func(n cst.Node)
	visit = func(n cst.Node) {
		switch n.Kind() {
		case cst.NodeBlockMapping, cst.NodeFlowMapping:
			m := n
			ops = append(ops, structuralOp{"Insert", Added, func() (Edit, error) {
				return ed().Insert(m, Last(), Map{{Key: "zz_new", Value: Str("x")}})
			}})
			for _, e := range entriesOf(n) {
				e := e
				ops = append(ops, structuralOp{"Delete entry", Removed, func() (Edit, error) { return ed().Delete(e.Node) }})
				if e.Value.Kind() == cst.NodeScalar {
					ops = append(ops, structuralOp{"SetValue", Changed, func() (Edit, error) {
						return ed().SetValue(e.Value, Map{{Key: "a", Value: Int(1)}})
					}}, structuralOp{"SetValue literal", Changed, func() (Edit, error) {
						return ed().SetValue(e.Value, Str("x\n").In(cst.Literal))
					}}, structuralOp{"LineComment", 0, func() (Edit, error) {
						return ed().LineComment(e.Value, "c")
					}})
				}
			}
		case cst.NodeBlockSequence, cst.NodeFlowSequence:
			s, items := n, itemsOf(n)
			ops = append(ops, structuralOp{"InsertItem", Added, func() (Edit, error) { return ed().InsertItem(s, len(items), Str("x")) }})
			for _, x := range items {
				x := x
				ops = append(ops, structuralOp{"Delete item", Removed, func() (Edit, error) { return ed().Delete(x) }})
				if x.Kind() == cst.NodeScalar {
					ops = append(ops, structuralOp{"SetValue", Changed, func() (Edit, error) {
						return ed().SetValue(x, Map{{Key: "a", Value: Int(1)}})
					}})
				}
			}
		}
		for e := range n.Children() {
			if c, ok := e.Node(); ok {
				visit(c)
			}
		}
	}
	visit(tr.Root())
	return ops
}

// sharedEditor gives one Editor for all the operations of a tree.
func sharedEditor() func() *Editor {
	e := new(Editor)
	return func() *Editor { return e }
}

type structuralOp struct {
	name   string
	change ChangeKind
	make   func() (Edit, error)
}

// structureExcluded are the inputs and operations whose edits Apply
// refuses, with the reason. The reason is a form once left unfixed: a
// literal written before white space lines takes them in. SetValue now refuses a literal before a line of
// more spaces or a comment it would take in (suite H2RW), but not before
// a line of a tab.
var structureExcluded = map[string]string{
	"suite/DK95/04 SetValue literal": "a line of a tab follows, which the literal cannot hold",
	"suite/DK95/05 SetValue literal": "a line of a space and a tab follows, which the literal cannot hold",
}

var quoted = regexp.MustCompile(`"[^"]*"|\*\S+|\d+`)

// sampled is 1 in how many operations TestCorpusStructure makes unless
// EDIT_CORPUS=full: all of them take minutes, as each Apply reads the
// whole input back twice (the edit and its inverse).
const sampled = 20

// TestCorpusStructure makes the structural operations on every input
// without errors: each must be refused by the operation, or be applied
// with the one change it promises and be undone by its inverse. It makes
// every sampled-th operation of each input, from an offset the input's
// name decides, and all of them with EDIT_CORPUS=full.
func TestCorpusStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("the structural operations on the corpus take a while")
	}
	every := sampled
	if os.Getenv("EDIT_CORPUS") == "full" {
		every = 1
	}
	var names []string
	in := inputs(t)
	for name := range in {
		names = append(names, name)
	}
	sort.Strings(names)
	const parts = 4
	var mu sync.Mutex
	made, bad, refused := 0, 0, map[string]int{}
	t.Run("parts", func(t *testing.T) {
		for p := range parts {
			t.Run(fmt.Sprint(p), func(t *testing.T) {
				t.Parallel()
				for k := p; k < len(names); k += parts {
					m, b, r := structureOn(t, names[k], in[names[k]], every)
					mu.Lock()
					made, bad = made+m, bad+b
					for reason, n := range r {
						refused[reason] += n
					}
					mu.Unlock()
				}
			})
		}
	})
	var reasons []string
	for r, k := range refused {
		reasons = append(reasons, fmt.Sprintf("%6d %s", k, r))
	}
	sort.Strings(reasons)
	t.Logf("%d edits made (1 in %d operations), %d wrong", made, every, bad)
	for _, r := range reasons {
		t.Log(r)
	}
}

func structureOn(t *testing.T, name string, src []byte, every int) (made, bad int, refused map[string]int) {
	refused = map[string]int{}
	tr := cst.Parse(src)
	if len(tr.Errors()) > 0 {
		return
	}
	offset := int(crc32.ChecksumIEEE([]byte(name)) % uint32(every))
	for k, op := range structuralOps(tr, sharedEditor()) {
		if k%every != offset {
			continue
		}
		ed, err := op.make()
		if err != nil {
			refused[op.name+": "+quoted.ReplaceAllString(err.Error(), "_")]++
			continue
		}
		made++
		res, err := Apply(tr, []Edit{ed})
		if err == nil && op.change == 0 && len(res.Diff) > 0 || err == nil && op.change != 0 && (len(res.Diff) != 1 || res.Diff[0].Kind != op.change) {
			err = fmt.Errorf("Diff = %v", changes(res.Diff))
		}
		if err == nil {
			back, e := Apply(res.Tree, res.Inverse)
			if e != nil || !bytes.Equal(back.Tree.Bytes(), src) {
				err = fmt.Errorf("the inverse does not give it back: %v", e)
			}
		}
		if _, excluded := structureExcluded[name+" "+op.name]; err != nil && excluded {
			continue
		}
		if err != nil {
			bad++
			if bad <= 10 {
				t.Errorf("%s: %s: %v\n  edit %v %q", name, op.name, err, ed.Span, ed.New)
			}
		}
	}
	return
}

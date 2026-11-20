package edit

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// target is the first word of a scalar's value in a tree.
type target struct {
	tr   *cst.Tree
	v    scalar.Value
	s, e int
}

// realWorld is the real-world files, and the first word of the first
// multi-line literal of each file that has one.
func realWorld(b *testing.B) (ins [][]byte, ts []target) {
	root := suitetest.CorpusRoot(b)
	files, err := suitetest.CorpusFiles(root)
	if err != nil {
		b.Fatal(err)
	}
	for _, path := range files {
		if !strings.HasPrefix(path, filepath.Join(root, "real-world")) {
			continue
		}
		in, err := os.ReadFile(path)
		if err != nil {
			b.Fatal(err)
		}
		ins = append(ins, in)
		tr := cst.Parse(in)
		for n := range allScalars(tr) {
			v, _ := decode(n)
			if v.Style() != cst.Literal || !strings.Contains(v.String(), "\n") {
				continue
			}
			if s, e, ok := firstWord(v.String()); ok {
				ts = append(ts, target{tr, v, s, e})
				break
			}
		}
	}
	return ins, ts
}

func BenchmarkParseRealWorld(b *testing.B) {
	ins, _ := realWorld(b)
	b.ReportAllocs()
	for b.Loop() {
		for _, in := range ins {
			cst.Parse(in)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(ins)), "ns/file")
}

// BenchmarkReplaceApply replaces one word of a run: script and applies it,
// for each real-world file that has one.
func BenchmarkReplaceApply(b *testing.B) {
	_, ts := realWorld(b)
	b.ReportAllocs()
	for b.Loop() {
		for _, t := range ts {
			ed, err := Replace(t.v, t.s, t.e, "zz")
			if err != nil {
				b.Fatal(err)
			}
			if _, err := Apply(t.tr, []Edit{ed}); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(ts)), "ns/file")
	b.ReportMetric(float64(len(ts)), "files")
}

// firstStep is the first step mapping of the first steps: of a tree.
func firstStep(tr *cst.Tree) (cst.Node, bool) {
	var found cst.Node
	ok := false
	var visit func(n cst.Node)
	visit = func(n cst.Node) {
		if ok {
			return
		}
		if n.Kind() == cst.NodeBlockMappingEntry {
			e := pairOf(n)
			if keyText(e.Key) == "steps" && e.Value.Kind() == cst.NodeBlockSequence {
				if items := itemsOf(e.Value); len(items) > 0 && items[0].Kind() == cst.NodeBlockMapping {
					found, ok = items[0], true
					return
				}
			}
		}
		for c := range n.Children() {
			if x, isNode := c.Node(); isNode {
				visit(x)
			}
		}
	}
	visit(tr.Root())
	return found, ok
}

// BenchmarkInsertApply puts an env var into the first step of each
// real-world file that has one: into its env, or into a new env.
func BenchmarkInsertApply(b *testing.B) {
	ins, _ := realWorld(b)
	type step struct {
		tr *cst.Tree
		m  cst.Node
	}
	var steps []step
	for _, in := range ins {
		tr := cst.Parse(in)
		if m, ok := firstStep(tr); ok && len(tr.Errors()) == 0 {
			steps = append(steps, step{tr, m})
		}
	}
	title := Map{{Key: "ZZ_TITLE", Value: Str("${{ github.event.issue.title }}")}}
	b.ReportAllocs()
	for b.Loop() {
		for _, s := range steps {
			ed, err := new(Editor).Insert(s.m, Last(), Map{{Key: "env", Value: title}})
			if err != nil {
				for _, e := range entriesOf(s.m) {
					if keyText(e.Key) == "env" {
						ed, err = new(Editor).Insert(e.Value, Last(), title)
					}
				}
			}
			if err != nil {
				b.Fatal(err)
			}
			if _, err := Apply(s.tr, []Edit{ed}); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(steps)), "ns/file")
	b.ReportMetric(float64(len(steps)), "files")
}

// BenchmarkManyReplaces applies 5,000 Replace edits, one per scalar, in
// one Apply.
func BenchmarkManyReplaces(b *testing.B) {
	var src strings.Builder
	for i := range 5000 {
		src.WriteString("k" + strconv.Itoa(i) + ": v\n")
	}
	tr := cst.Parse([]byte(src.String()))
	var edits []Edit
	for _, e := range entriesOf(docContent(tr)) {
		v, _ := decode(e.Value)
		ed, err := Replace(v, 0, 1, "w")
		if err != nil {
			b.Fatal(err)
		}
		edits = append(edits, ed)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Apply(tr, edits); err != nil {
			b.Fatal(err)
		}
	}
}

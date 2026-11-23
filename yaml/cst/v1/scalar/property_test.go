package scalar

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
)

// checkValue checks the properties of the segments on v, the value of
// n: the segments cover the value in order without gaps, a verbatim one
// equals its input, their input ranges are in order inside the node, and
// the whole value maps inside the node's content.
func checkValue(n cst.Node, v Value) error {
	src := n.Bytes()
	base := n.Span().Start
	span := n.Span()
	prevEnd := span.Start
	for k, g := range v.segs {
		end := v.segEnd(k)
		if k == 0 && g.at != 0 {
			return fmt.Errorf("first segment at %d", g.at)
		}
		if int(g.at) >= end {
			return fmt.Errorf("segment %d is empty or out of order", k)
		}
		if g.src.Start < prevEnd || g.src.End < g.src.Start || g.src.End > span.End {
			return fmt.Errorf("segment %d input %v: previous ends at %d, node %v", k, g.src, prevEnd, span)
		}
		prevEnd = g.src.End
		if g.verbatim && string(src[g.src.Start-base:g.src.End-base]) != v.s[g.at:end] {
			return fmt.Errorf("verbatim segment %d: input %q, value %q", k, src[g.src.Start-base:g.src.End-base], v.s[g.at:end])
		}
	}
	if len(v.segs) > 0 && v.segEnd(len(v.segs)-1) != len(v.s) {
		return fmt.Errorf("segments end at %d, value is %d bytes", v.segEnd(len(v.segs)-1), len(v.s))
	}
	if len(v.segs) == 0 && v.s != "" {
		return fmt.Errorf("value %q without segments", v.s)
	}
	// A block scalar's line feeds come from the Newline tokens that
	// ContentSpan leaves out, so it is checked against Span.
	within := n.ContentSpan()
	if v.style == cst.Literal || v.style == cst.Folded {
		within = span
	}
	sp, exact := v.Source(0, len(v.s))
	// an empty block scalar has no exact place for content
	wantExact := len(v.s) > 0 || (v.style != cst.Literal && v.style != cst.Folded)
	if exact != wantExact || sp.Start < within.Start || sp.End > within.End {
		return fmt.Errorf("Source(0,%d) = %v %v, outside %v", len(v.s), sp, exact, within)
	}
	return nil
}

// checkTree decodes every Scalar of the tree of src and checks it.
func checkTree(src []byte) error {
	tr := cst.Parse(src)
	for n := range allNodes(tr.Root()) {
		v, ok := Decode(n)
		if ok != (n.Kind() == cst.NodeScalar) {
			return fmt.Errorf("%v %v: Decode %v", n.Kind(), n.Span(), ok)
		}
		if !ok {
			continue
		}
		if err := checkValue(n, v); err != nil {
			return fmt.Errorf("scalar %v %q: %v", n.Span(), n.Bytes(), err)
		}
	}
	return nil
}

func TestPropertiesSuite(t *testing.T) {
	for _, c := range loadSuite(t) {
		if err := checkTree(c.In); err != nil {
			t.Errorf("%s: %v", c.ID, err)
		}
	}
}

func TestPropertiesCorpus(t *testing.T) {
	files, err := suitetest.CorpusFiles(suitetest.CorpusRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkTree(b); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	t.Logf("%d files", len(files))
}

// TestHugeLiteral: a huge run: | takes time and segments linear in its lines.
// The time is compared with ACTIONS_SCALE=1 only, as it depends on the
// machine.
func TestHugeLiteral(t *testing.T) {
	const lines = 100000
	var b strings.Builder
	b.WriteString("run: |\n")
	for i := range lines {
		if i%10 == 5 {
			b.WriteString("\n")
			continue
		}
		fmt.Fprintf(&b, "  echo ${{ matrix.v%d }}\n", i)
	}
	tr := cst.Parse([]byte(b.String()))
	var n cst.Node
	for c := range allNodes(tr.Root()) {
		if c.Kind() == cst.NodeScalar && c.Style() == cst.Literal {
			n = c
		}
	}
	start := time.Now()
	v, ok := Decode(n)
	d := time.Since(start)
	if !ok || strings.Count(v.String(), "\n") != lines {
		t.Fatalf("Decode: %v, %d lines", ok, strings.Count(v.String(), "\n"))
	}
	if os.Getenv("ACTIONS_SCALE") == "1" && d > time.Second {
		t.Errorf("Decode took %v", d)
	}
	if len(v.segs) > 3*lines {
		t.Errorf("%d segments for %d lines", len(v.segs), lines)
	}
	t.Logf("%v, %d segments", d, len(v.segs))
}

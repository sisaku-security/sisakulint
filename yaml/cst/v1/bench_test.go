package cst

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/yaml/cst/v1/internal/suitetest"
)

func benchInputs(b *testing.B, inputs [][]byte) { benchInputsMode(b, inputs, ModeSpec) }

func benchInputsMode(b *testing.B, inputs [][]byte, m Mode) {
	total := 0
	for _, in := range inputs {
		total += len(in)
	}
	b.SetBytes(int64(total))
	b.ReportAllocs()
	for b.Loop() {
		for _, in := range inputs {
			ParseMode(in, m)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(inputs)), "ns/file")
}

func BenchmarkSuite(b *testing.B) {
	cs, err := suitetest.Load(suiteRoot)
	if err != nil {
		b.Fatal(err)
	}
	var ins [][]byte
	for _, c := range cs {
		ins = append(ins, c.In)
	}
	benchInputs(b, ins)
}

func realWorld(b *testing.B) [][]byte {
	var ins [][]byte
	root := suitetest.CorpusRoot(b)
	for _, path := range corpusFiles(b) {
		if !strings.HasPrefix(path, filepath.Join(root, "real-world")) {
			continue
		}
		in, err := os.ReadFile(path)
		if err != nil {
			b.Fatal(err)
		}
		ins = append(ins, in)
	}
	return ins
}

func BenchmarkRealWorld(b *testing.B) { benchInputs(b, realWorld(b)) }

func BenchmarkRealWorldGitHub(b *testing.B) { benchInputsMode(b, realWorld(b), ModeGitHub) }

// BenchmarkUnclosedNestedGitHub nests unclosed flow sequences inside a
// block, which ModeGitHub reads loosely and then again strictly.
func BenchmarkUnclosedNestedGitHub(b *testing.B) {
	in := []byte("a:\n  k: " + strings.Repeat("[x, ", 999) + "\nb: 2\n")
	for name, m := range map[string]Mode{"spec": ModeSpec, "github": ModeGitHub} {
		b.Run(name, func(b *testing.B) { benchInputsMode(b, [][]byte{in}, m) })
	}
}

// BenchmarkScale parses one workflow repeated as a sequence of documents, so
// that the time per byte can be compared across sizes.
func BenchmarkScale(b *testing.B) {
	var unit []byte
	for _, in := range realWorld(b) {
		if len(in) > len(unit) && len(in) < 64*1024 && len(Parse(in).Errors()) == 0 {
			unit = in
		}
	}
	for _, copies := range []int{1, 16, 256} {
		var buf bytes.Buffer
		for range copies {
			buf.WriteString("---\n")
			buf.Write(unit)
		}
		b.Run(fmt.Sprintf("%dKB", buf.Len()>>10), func(b *testing.B) { benchInputs(b, [][]byte{buf.Bytes()}) })
	}
}

// BenchmarkNestedFlowKeys nests implicit flow keys: [[[a]: b]: c]...
func BenchmarkNestedFlowKeys(b *testing.B) {
	for _, depth := range []int{10, 100, 500} {
		in := strings.Repeat("[", depth) + "a" + strings.Repeat("]: x", depth)
		b.Run(fmt.Sprint(depth), func(b *testing.B) { benchInputs(b, [][]byte{[]byte(in)}) })
	}
}

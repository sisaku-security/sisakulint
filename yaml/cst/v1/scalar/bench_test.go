package scalar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/internal/suitetest"
)

func realWorld(b *testing.B) [][]byte {
	root := suitetest.CorpusRoot(b)
	files, err := suitetest.CorpusFiles(root)
	if err != nil {
		b.Fatal(err)
	}
	var ins [][]byte
	for _, path := range files {
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

// BenchmarkParseRealWorld is cst.Parse on the same inputs, for comparison.
func BenchmarkParseRealWorld(b *testing.B) {
	ins := realWorld(b)
	b.ReportAllocs()
	for b.Loop() {
		for _, in := range ins {
			cst.Parse(in)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(ins)), "ns/file")
}

// BenchmarkDecodeRealWorld decodes every Scalar of the real-world files,
// parsed beforehand.
func BenchmarkDecodeRealWorld(b *testing.B) {
	ins := realWorld(b)
	var ns []cst.Node
	for _, in := range ins {
		for n := range allNodes(cst.Parse(in).Root()) {
			if n.Kind() == cst.NodeScalar {
				ns = append(ns, n)
			}
		}
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, n := range ns {
			Decode(n)
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(ins)), "ns/file")
	b.ReportMetric(float64(len(ns))/float64(len(ins)), "scalars/file")
}

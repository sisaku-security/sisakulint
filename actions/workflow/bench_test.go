package workflow

import (
	"os"
	"testing"

	"github.com/gh-intel/sisakulint/internal/corpus"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// realWorkflows are the workflows of yaml/corpus/files/real-world/, all of
// them whatever ACTIONS_CORPUS says, so that the numbers compare.
func realWorkflows(b *testing.B) [][]byte {
	b.Helper()
	b.Setenv("ACTIONS_CORPUS", "full")
	files := corpus.Files(b, "files/real-world/")
	var srcs [][]byte
	for _, f := range files {
		if f.Kind != corpus.KindWorkflow {
			continue
		}
		src, err := os.ReadFile(f.Path)
		if err != nil {
			b.Fatal(err)
		}
		srcs = append(srcs, src)
	}
	return srcs
}

func bench(b *testing.B, model bool) {
	srcs := realWorkflows(b)
	n := 0
	for _, s := range srcs {
		n += len(s)
	}
	b.SetBytes(int64(n / len(srcs)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		t := cst.ParseMode(srcs[i%len(srcs)], cst.ModeGitHub)
		if model {
			Parse(t)
		}
	}
}

// BenchmarkCST reads the workflows with cst alone; BenchmarkWorkflow adds
// the model. The difference is what the model costs.
func BenchmarkCST(b *testing.B)      { bench(b, false) }
func BenchmarkWorkflow(b *testing.B) { bench(b, true) }

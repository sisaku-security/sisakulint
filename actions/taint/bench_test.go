package taint

import (
	"os"
	"testing"

	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/internal/corpus"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// BenchmarkParse reads the workflows of yaml/corpus/files/real-world/ into
// the model; BenchmarkAnalyze adds Analyze. The difference is what the
// analysis costs. The numbers are in BENCH.md.
func BenchmarkParse(b *testing.B)   { bench(b, false) }
func BenchmarkAnalyze(b *testing.B) { bench(b, true) }

func bench(b *testing.B, analyze bool) {
	b.Setenv("ACTIONS_CORPUS", "full")
	files := corpus.Files(b, "files/real-world/")
	var srcs [][]byte
	for _, f := range files {
		if f.Kind == corpus.KindWorkflow {
			src, err := os.ReadFile(f.Path)
			if err != nil {
				b.Fatal(err)
			}
			srcs = append(srcs, src)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		w, _ := workflow.Parse(cst.ParseMode(srcs[i%len(srcs)], cst.ModeGitHub))
		if analyze {
			Analyze(w, nil)
		}
	}
}

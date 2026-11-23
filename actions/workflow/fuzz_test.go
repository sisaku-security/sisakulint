package workflow

import (
	"os"
	"testing"

	"github.com/gh-intel/sisakulint/internal/corpus"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// FuzzWorkflow: Parse does not panic, and every span lies in the input.
func FuzzWorkflow(f *testing.F) {
	f.Add("on: push\n" + jobsOK)
	files := corpus.SeedFiles(f, "files/real-world/")
	for _, c := range files {
		if src, err := os.ReadFile(c.Path); err == nil {
			f.Add(string(src))
		}
	}
	f.Fuzz(func(t *testing.T, src string) {
		w, diags := Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		for _, d := range diags {
			checkSpan(t, "fuzz", len(src), d.Span)
		}
		walkModel(w, func(s cst.Span) { checkSpan(t, "fuzz", len(src), s) })
	})
}

// FuzzAction: ParseActionMetadata does not panic, and every span lies in the input.
func FuzzAction(f *testing.F) {
	f.Add(runsOK)
	files := corpus.SeedFiles(f, "files/real-world/")
	for _, c := range files {
		if c.Kind != corpus.KindAction {
			continue
		}
		if src, err := os.ReadFile(c.Path); err == nil {
			f.Add(string(src))
		}
	}
	f.Fuzz(func(t *testing.T, src string) {
		a, diags := ParseActionMetadata(cst.ParseMode([]byte(src), cst.ModeGitHub))
		for _, d := range diags {
			checkSpan(t, "fuzz", len(src), d.Span)
		}
		walkAction(a, func(s cst.Span) { checkSpan(t, "fuzz", len(src), s) })
	})
}

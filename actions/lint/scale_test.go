package lint

import (
	"fmt"
	"github.com/gh-intel/sisakulint/actions/ir"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/internal/corpus"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// usesFixer reports every step not marked, and fixes those with uses.
func usesFixer() Rule {
	fixer := meta("fixer")
	fixer = fixing(fixer, FixKind{ID: fixF, Title: "f", Safety: SafetySafe})
	return unmarkedStep(fixer, func(c *RuleContext, s workflow.Step) FindingDraft {
		if s.Uses.Status != workflow.Present {
			return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), NoFix: &NoFix{Reason: ir.NoFixReasonManual}}
		}
		return FindingDraft{Args: said("x"), Location: At(c.input, s.Base), Fix: &Fix{KindID: fixF, Title: "f", Edits: []edit.Edit{markEdit(c, s, "m")}}}
	})
}

// fastest is the least of three runs, so that a busy machine does not make
// the time.
func fastest(t *testing.T, src string, rule Rule) (Report, time.Duration) {
	var rep Report
	best := time.Hour
	for range 3 {
		start := time.Now()
		rep = run(t, wf(src), nil, rule)
		best = min(best, time.Since(start))
	}
	return rep, best
}

// TestReparseScale: every fix reads its input
// again and runs its rule on it. The fixes of the largest workflow of
// yaml/corpus (home-assistant/core's ci.yaml: 60 KB, 78 fixes of uses) are
// checked in less than a second (ACTIONS_SCALE=1; 30 uses otherwise, and
// the time is not compared). The checks use every CPU, so the time is
// true only of a machine doing nothing else: run it alone (go test -p 1).
func TestReparseScale(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
	for i := range 30 {
		src += fmt.Sprintf("      - uses: actions/checkout@v%d\n", i)
	}
	if os.Getenv("ACTIONS_SCALE") == "1" {
		b, err := os.ReadFile(filepath.Join(corpus.Dir(t), "files/real-world/home-assistant__core/.github/workflows/ci.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		src = string(b)
	}
	rep, took := fastest(t, src, usesFixer())
	fixes := 0
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Fix != nil {
			fixes++
		}
	}
	if fixes == 0 || len(rep.Errors) != 0 {
		t.Fatalf("fixes %d, errors %+v", fixes, rep.Errors)
	}
	t.Logf("%d fixes of %d bytes checked in %v", fixes, len(src), took)
	if os.Getenv("ACTIONS_SCALE") == "1" && took > time.Second {
		t.Errorf("%d fixes took %v, more than a second", fixes, took)
	}
}

// TestReparseBounded: a workflow of the largest size GitHub runs (500 KB)
// with a fix on every step gets as many checks as maxCheckedBytes allows,
// and no more, whatever the machine. Whatever the size, the checks read
// maxCheckedBytes again, which takes seconds (ACTIONS_SCALE=1);
// TestFixCheckLimit is the bound by number for the short tests.
func TestReparseBounded(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 checks the bound on a workflow of 500 KB")
	}
	size := 500_000
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for b.Len() < size {
		b.WriteString("      - uses: actions/checkout@v4\n")
	}
	rep := run(t, wf(b.String()), nil, usesFixer())
	checked, limited := 0, 0
	for _, f := range rep.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
		if f.Fix != nil {
			checked++
		}
		if f.NoFix != nil && f.NoFix.Reason == ir.NoFixReasonTooManyFixes {
			limited++
		}
	}
	if want := min(maxCheckedFixes, maxCheckedBytes/b.Len()); checked != want || limited != len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional))-want || len(rep.Errors) != 0 {
		t.Errorf("checked %d, limited %d of %d, errors %d; want %d checked", checked, limited, len(rep.FindingsWith(CertaintyConfirmed, CertaintyConditional)), len(rep.Errors), want)
	}
}

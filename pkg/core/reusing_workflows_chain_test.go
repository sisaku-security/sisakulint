package core

import (
	"sync"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestSinkTypeString(t *testing.T) {
	cases := map[SinkType]string{
		SinkRun:          "run",
		SinkGitHubScript: "github-script",
		SinkEnv:          "env",
		SinkType(99):     "unknown",
	}
	for st, want := range cases {
		if got := st.String(); got != want {
			t.Errorf("SinkType(%d).String() = %q, want %q", st, got, want)
		}
	}
}

func TestRecordAndCallersOf(t *testing.T) {
	c := NewLocalReusableWorkflowCache(nil, "/cwd", nil)
	taint := &CallerTaint{
		CallerWorkflowPath: "./.github/workflows/ci.yml",
		InputName:          "branch",
		UntrustedSources:   []string{"github.event.pull_request.head.ref"},
		Pos:                &ast.Position{Line: 5, Col: 7},
	}
	c.RecordCallerTaint("./.github/workflows/build.yml", taint)
	got := c.CallersOf("./.github/workflows/build.yml")
	if len(got) != 1 || got[0] != taint {
		t.Fatalf("CallersOf returned %#v, want [%p]", got, taint)
	}
	if got := c.CallersOf("./.github/workflows/missing.yml"); len(got) != 0 {
		t.Errorf("expected nil/empty for unknown spec, got %d", len(got))
	}
}

func TestRecordAndSinksOf(t *testing.T) {
	c := NewLocalReusableWorkflowCache(nil, "/cwd", nil)
	sink := &CalleeSink{
		CalleeWorkflowPath: "./.github/workflows/build.yml",
		InputName:          "branch",
		InputPath:          "inputs.branch",
		SinkType:           SinkRun,
		Pos:                &ast.Position{Line: 12, Col: 9},
	}
	c.RecordCalleeSink("./.github/workflows/build.yml", sink)
	got := c.SinksOf("./.github/workflows/build.yml")
	if len(got) != 1 || got[0] != sink {
		t.Fatalf("SinksOf returned %#v, want [%p]", got, sink)
	}
}

func TestCalleeSpecsSortedUnion(t *testing.T) {
	c := NewLocalReusableWorkflowCache(nil, "/cwd", nil)
	c.RecordCallerTaint("./.github/workflows/b.yml", &CallerTaint{InputName: "x"})
	c.RecordCalleeSink("./.github/workflows/a.yml", &CalleeSink{InputName: "y"})
	c.RecordCalleeSink("./.github/workflows/b.yml", &CalleeSink{InputName: "z"})
	got := c.CalleeSpecs()
	want := []string{"./.github/workflows/a.yml", "./.github/workflows/b.yml"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("CalleeSpecs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestRecordRaceFreedom(t *testing.T) {
	c := NewLocalReusableWorkflowCache(nil, "/cwd", nil)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); c.RecordCallerTaint("./x.yml", &CallerTaint{InputName: "k"}) }()
		go func() { defer wg.Done(); c.RecordCalleeSink("./x.yml", &CalleeSink{InputName: "k"}) }()
	}
	wg.Wait()
	if got := len(c.CallersOf("./x.yml")); got != 100 {
		t.Errorf("expected 100 callers, got %d", got)
	}
	if got := len(c.SinksOf("./x.yml")); got != 100 {
		t.Errorf("expected 100 sinks, got %d", got)
	}
}

func TestIsChainResolutionEnabled(t *testing.T) {
	if NewLocalReusableWorkflowCache(nil, "/cwd", nil).IsChainResolutionEnabled() {
		t.Errorf("nil project should disable chain resolution")
	}
}

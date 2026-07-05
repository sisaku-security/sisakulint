// pkg/core/chain/assembler_test.go
package chain

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func nodeByID(m *ChainModel, id string) *Node {
	for _, n := range m.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func hasEdge(m *ChainModel, from, to string, k EdgeKind) bool {
	for _, e := range m.Edges {
		if e.From == from && e.To == to && e.Kind == k {
			return true
		}
	}
	return false
}

func TestAssembleSingleChain(t *testing.T) {
	in := AssemblerInput{
		FilePath:     ".github/workflows/ci.yml",
		WorkflowName: "CI",
		JobContexts: []JobContext{{
			JobID: "build",
			Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true,
				Pos: &ast.Position{Line: 2, Col: 3}}},
			Permission: PermissionRef{Label: "contents:write", Pos: &ast.Position{Line: 4, Col: 3}},
		}},
		Records: []SinkRecord{{
			FilePath: ".github/workflows/ci.yml", JobID: "build",
			StepPos: &ast.Position{Line: 10, Col: 9}, StepSummary: "run: curl ...",
			SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SourceOrigin: "secrets.TOKEN",
			SinkKind: SinkNetwork, RuleName: "secret-exfiltration", Severity: "critical",
		}},
	}

	m := Assemble(in)

	// 5種のノードが1つずつ
	for _, id := range []string{
		"trigger:pull_request_target", "perm:build",
		"source:build:0:secrets.TOKEN", "action:build:10:9",
		"sink:secret-exfiltration:build:10:9",
	} {
		if nodeByID(m, id) == nil {
			t.Errorf("missing node %q", id)
		}
	}
	// 文脈エッジ（破線）とデータフローエッジ（実線）
	if !hasEdge(m, "trigger:pull_request_target", "perm:build", EdgeGrants) {
		t.Error("missing Grants edge")
	}
	if !hasEdge(m, "perm:build", "source:build:0:secrets.TOKEN", EdgeEnables) {
		t.Error("missing Enables edge")
	}
	if !hasEdge(m, "source:build:0:secrets.TOKEN", "action:build:10:9", EdgeUsedBy) {
		t.Error("missing UsedBy edge")
	}
	if !hasEdge(m, "action:build:10:9", "sink:secret-exfiltration:build:10:9", EdgeFlowsTo) {
		t.Error("missing FlowsTo edge")
	}
}

func TestAssembleFanOutSharedSource(t *testing.T) {
	base := func(sink SinkKind, rule string, line int) SinkRecord {
		return SinkRecord{JobID: "build", StepPos: &ast.Position{Line: line, Col: 9},
			SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SourceOrigin: "secrets.TOKEN",
			SinkKind: sink, RuleName: rule, Severity: "critical"}
	}
	in := AssemblerInput{
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "push", Untrusted: false, Pos: &ast.Position{Line: 2, Col: 3}}},
			Permission: PermissionRef{Label: "contents:read", Pos: &ast.Position{Line: 4, Col: 3}}}},
		Records: []SinkRecord{base(SinkLog, "secret-in-log", 10), base(SinkNetwork, "secret-exfiltration", 12)},
	}
	m := Assemble(in)
	// 共有 source ノードは1つ、sink は2つ
	if n := nodeByID(m, "source:build:0:secrets.TOKEN"); n == nil {
		t.Fatal("shared source node missing")
	}
	sinks := 0
	for _, n := range m.Nodes {
		if n.Kind == NodeSink {
			sinks++
		}
	}
	if sinks != 2 {
		t.Errorf("sink count = %d, want 2", sinks)
	}
}

func TestAssembleNoRecordsNoDataflowEdges(t *testing.T) {
	// 捏造しない担保: Records が空ならデータフローエッジはゼロ
	in := AssemblerInput{
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
			Permission: PermissionRef{Label: "contents:write"}}},
		Records: nil,
	}
	m := Assemble(in)
	for _, e := range m.Edges {
		if !e.Kind.IsContext() {
			t.Errorf("dataflow edge fabricated with no records: %+v", e)
		}
	}
	// source/action/sink ノードも生成されない
	for _, n := range m.Nodes {
		if n.Kind == NodeSource || n.Kind == NodeAction || n.Kind == NodeSink {
			t.Errorf("dataflow node fabricated with no records: %+v", n)
		}
	}
}

func TestAssembleChainCountAndReachable(t *testing.T) {
	rec := func(sink SinkKind, rule string, line int) SinkRecord {
		return SinkRecord{JobID: "build", StepPos: &ast.Position{Line: line, Col: 9},
			SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SourceOrigin: "secrets.TOKEN",
			SinkKind: sink, RuleName: rule}
	}
	in := AssemblerInput{
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true}},
			Permission: PermissionRef{Label: "contents:write"}}},
		Records: []SinkRecord{rec(SinkLog, "secret-in-log", 10), rec(SinkNetwork, "secret-exfiltration", 12)},
	}
	m := Assemble(in)

	// 共有 source は 2チェーンを通過
	if n := nodeByID(m, "source:build:0:secrets.TOKEN"); n == nil || n.ChainCount != 2 {
		t.Errorf("source ChainCount = %v, want 2", n)
	}
	// untrusted trigger から全ノードが到達可能
	for _, n := range m.Nodes {
		if !n.UntrustedReachable {
			t.Errorf("node %q not marked UntrustedReachable", n.ID)
		}
	}
}

func TestAssembleUntrustedReachableSafeTrigger(t *testing.T) {
	in := AssemblerInput{
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "push", Untrusted: false}},
			Permission: PermissionRef{Label: "contents:read"}}},
		Records: []SinkRecord{{JobID: "build", StepPos: &ast.Position{Line: 10, Col: 9},
			SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SinkKind: SinkLog, RuleName: "secret-in-log"}},
	}
	m := Assemble(in)
	// secret source + safe trigger のみ: untrusted 到達はゼロ
	for _, n := range m.Nodes {
		if n.UntrustedReachable {
			t.Errorf("node %q wrongly marked UntrustedReachable under safe trigger", n.ID)
		}
	}
}

func TestAssembleDoesNotShareSourceReachabilityAcrossJobs(t *testing.T) {
	in := AssemblerInput{
		JobContexts: []JobContext{
			{JobID: "unsafe",
				Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true}},
				Permission: PermissionRef{Label: "contents:write"}},
			{JobID: "manual",
				Triggers:   []TriggerRef{{Name: "workflow_dispatch", Untrusted: false, SecretsAvailable: true}},
				Permission: PermissionRef{Label: "contents:write"}},
		},
		Records: []SinkRecord{
			{JobID: "unsafe", StepPos: &ast.Position{Line: 10, Col: 1},
				SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SourceOrigin: "secrets.TOKEN",
				SinkKind: SinkLog, RuleName: "secret-in-log"},
			{JobID: "manual", StepPos: &ast.Position{Line: 20, Col: 1},
				SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SourceOrigin: "secrets.TOKEN",
				SinkKind: SinkNetwork, RuleName: "secret-exfiltration"},
		},
	}

	m := Assemble(in)

	unsafeSink := nodeByID(m, "sink:secret-in-log:unsafe:10:1")
	if unsafeSink == nil {
		t.Fatal("missing unsafe job sink")
	}
	if !unsafeSink.UntrustedReachable {
		t.Errorf("unsafe job sink should be reachable from pull_request_target")
	}
	manualSink := nodeByID(m, "sink:secret-exfiltration:manual:20:1")
	if manualSink == nil {
		t.Fatal("missing manual job sink")
	}
	if manualSink.UntrustedReachable {
		t.Errorf("manual-only job sink should not be reachable through another job's shared secret source")
	}
}

func TestAssembleSummaryAndLeverage(t *testing.T) {
	rec := func(sink SinkKind, rule string, line int) SinkRecord {
		return SinkRecord{JobID: "build", StepPos: &ast.Position{Line: line, Col: 9},
			SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SinkKind: sink, RuleName: rule}
	}
	in := AssemblerInput{
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true}},
			Permission: PermissionRef{Label: "contents:write"}}},
		Records: []SinkRecord{rec(SinkLog, "secret-in-log", 10), rec(SinkNetwork, "secret-exfiltration", 12)},
	}
	m := Assemble(in)

	if m.Summary.UntrustedTriggers != 1 {
		t.Errorf("UntrustedTriggers = %d, want 1", m.Summary.UntrustedTriggers)
	}
	if m.Summary.Secrets != 1 {
		t.Errorf("Secrets = %d, want 1", m.Summary.Secrets)
	}
	if m.Summary.Sinks != 2 {
		t.Errorf("Sinks = %d, want 2", m.Summary.Sinks)
	}
	if m.Summary.SinkCountsByKind[SinkLog] != 1 || m.Summary.SinkCountsByKind[SinkNetwork] != 1 {
		t.Errorf("SinkCountsByKind = %v", m.Summary.SinkCountsByKind)
	}
	// trigger と source は共に ChainCount=2（2チェーンを通過）。タイのため
	// 上流優先ルールで trigger が選ばれる。
	if m.LeverageID != "trigger:pull_request_target" {
		t.Errorf("LeverageID = %q, want trigger:pull_request_target", m.LeverageID)
	}
	if n := nodeByID(m, m.LeverageID); n == nil || !n.Leverage {
		t.Error("leverage node not flagged")
	}
}

func TestAssembleCrossJobNeeds(t *testing.T) {
	in := AssemblerInput{
		JobContexts: []JobContext{
			{JobID: "produce", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
				Permission: PermissionRef{Label: "contents:write"}},
			{JobID: "consume", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
				Permission: PermissionRef{Label: "contents:write"}},
		},
		Records: []SinkRecord{
			// produce: untrusted 入力 → GITHUB_OUTPUT（sink=expr 相当の action）
			{JobID: "produce", StepPos: &ast.Position{Line: 10, Col: 9},
				SourceKind: SourceUntrusted, SourceName: "github.head_ref", SourceOrigin: "github.head_ref",
				SinkKind: SinkExpr, RuleName: "output-clobbering-critical", OutputName: "ref"},
			// consume: needs.produce.outputs.ref を使う → network
			{JobID: "consume", StepPos: &ast.Position{Line: 20, Col: 9},
				SourceKind: SourceUntrusted, SourceName: "needs.produce.outputs.ref",
				SourceOrigin: "needs.produce.outputs.ref",
				SinkKind:     SinkNetwork, RuleName: "request-forgery-critical"},
		},
	}
	m := Assemble(in)
	upAction := "action:produce:10:9"
	downSource := "source:consume:1:needs.produce.outputs.ref"
	if !hasEdge(m, upAction, downSource, EdgeNeeds) {
		t.Errorf("missing cross-job Needs edge %s -> %s", upAction, downSource)
	}
}

func TestAssembleCrossJobNeedsDoesNotGuessWithoutProducerOutputName(t *testing.T) {
	in := AssemblerInput{
		JobContexts: []JobContext{
			{JobID: "produce", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
				Permission: PermissionRef{Label: "contents:write"}},
			{JobID: "consume", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
				Permission: PermissionRef{Label: "contents:write"}},
		},
		Records: []SinkRecord{
			{JobID: "produce", StepPos: &ast.Position{Line: 10, Col: 9},
				SourceKind: SourceUntrusted, SourceName: "github.head_ref", SourceOrigin: "github.head_ref",
				SinkKind: SinkExpr, RuleName: "output-clobbering-critical"},
			{JobID: "consume", StepPos: &ast.Position{Line: 20, Col: 9},
				SourceKind: SourceUntrusted, SourceName: "needs.produce.outputs.ref",
				SourceOrigin: "needs.produce.outputs.ref",
				SinkKind:     SinkNetwork, RuleName: "request-forgery-critical"},
		},
	}
	m := Assemble(in)

	if hasEdge(m, "action:produce:10:9", "source:consume:1:needs.produce.outputs.ref", EdgeNeeds) {
		t.Error("cross-job Needs edge should not be drawn when the producer output name is unknown")
	}
}

func TestAssembleCrossJobNeedsLinksOnlyMatchingProducerOutput(t *testing.T) {
	in := AssemblerInput{
		JobContexts: []JobContext{
			{JobID: "produce", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
				Permission: PermissionRef{Label: "contents:write"}},
			{JobID: "consume", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
				Permission: PermissionRef{Label: "contents:write"}},
		},
		Records: []SinkRecord{
			{JobID: "produce", StepPos: &ast.Position{Line: 5, Col: 9},
				SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SourceOrigin: "secrets.TOKEN",
				SinkKind: SinkLog, RuleName: "secret-in-log"},
			{JobID: "produce", StepPos: &ast.Position{Line: 10, Col: 9},
				SourceKind: SourceUntrusted, SourceName: "github.event.pull_request.body", SourceOrigin: "github.event.pull_request.body",
				SinkKind: SinkExpr, RuleName: "output-clobbering-critical", OutputName: "body"},
			{JobID: "produce", StepPos: &ast.Position{Line: 15, Col: 9},
				SourceKind: SourceUntrusted, SourceName: "github.head_ref", SourceOrigin: "github.head_ref",
				SinkKind: SinkExpr, RuleName: "output-clobbering-critical", OutputName: "ref"},
			{JobID: "consume", StepPos: &ast.Position{Line: 20, Col: 9},
				SourceKind: SourceUntrusted, SourceName: "needs.produce.outputs.ref",
				SourceOrigin: "needs.produce.outputs.ref (tainted via github.head_ref)",
				SinkKind:     SinkNetwork, RuleName: "request-forgery-critical"},
		},
	}
	m := Assemble(in)
	downSource := "source:consume:1:needs.produce.outputs.ref"

	if hasEdge(m, "action:produce:5:9", downSource, EdgeNeeds) {
		t.Error("unrelated producer action must not get a cross-job Needs edge")
	}
	if hasEdge(m, "action:produce:10:9", downSource, EdgeNeeds) {
		t.Error("producer action for a different output must not get a cross-job Needs edge")
	}
	if !hasEdge(m, "action:produce:15:9", downSource, EdgeNeeds) {
		t.Error("missing cross-job Needs edge from the matching producer output action")
	}
}

// TestAssembleRecordOrderInvariant guards the determinism fix: getNode keeps
// first-seen field values for shared nodes and SinkCollector.Add order is not
// guaranteed, so Assemble sorts records first. Source A is referenced at lines
// 5 and 15 (fan-out) with source B between them at line 10 — if the shared A
// node took its Pos from whichever record arrived first, reversing the records
// would reorder A vs B in the rendered output.
func TestAssembleRecordOrderInvariant(t *testing.T) {
	base := AssemblerInput{
		FilePath: "x.yml", WorkflowName: "X",
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "push"}},
			Permission: PermissionRef{Label: "contents:read"}}},
	}
	recs := []SinkRecord{
		{JobID: "build", StepPos: &ast.Position{Line: 5, Col: 1}, SourceKind: SourceSecret, SourceName: "secrets.A", SinkKind: SinkLog, RuleName: "r1"},
		{JobID: "build", StepPos: &ast.Position{Line: 10, Col: 1}, SourceKind: SourceSecret, SourceName: "secrets.B", SinkKind: SinkLog, RuleName: "r2"},
		{JobID: "build", StepPos: &ast.Position{Line: 15, Col: 1}, SourceKind: SourceSecret, SourceName: "secrets.A", SinkKind: SinkNetwork, RuleName: "r3"},
	}
	forward := base
	forward.Records = recs
	reversed := base
	reversed.Records = []SinkRecord{recs[2], recs[1], recs[0]}

	a := NewMermaidRenderer().Render(Assemble(forward))
	b := NewMermaidRenderer().Render(Assemble(reversed))
	if a != b {
		t.Errorf("record order changes rendered output (non-deterministic):\n--- forward ---\n%s\n--- reversed ---\n%s", a, b)
	}
}

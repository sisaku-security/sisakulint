// pkg/core/chain/mermaid_test.go
package chain

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func sampleModel() *ChainModel {
	in := AssemblerInput{
		FilePath: ".github/workflows/ci.yml", WorkflowName: "CI",
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true, Pos: &ast.Position{Line: 2, Col: 3}}},
			Permission: PermissionRef{Label: "contents:write", Pos: &ast.Position{Line: 4, Col: 3}}}},
		Records: []SinkRecord{{JobID: "build", StepPos: &ast.Position{Line: 10, Col: 9},
			StepSummary: "run: curl", SourceKind: SourceSecret, SourceName: "secrets.TOKEN",
			SinkKind: SinkNetwork, RuleName: "secret-exfiltration", Severity: "critical"}},
	}
	return Assemble(in)
}

func TestMermaidBasicStructure(t *testing.T) {
	out := NewMermaidRenderer().Render(sampleModel())

	if !strings.Contains(out, "flowchart TD") {
		t.Error("missing flowchart TD header")
	}
	// 実線データフロー (source -> action -> sink)
	if !strings.Contains(out, "-->|used-by|") {
		t.Error("missing solid used-by edge")
	}
	// 破線文脈 (trigger -> permission)
	if !strings.Contains(out, "-.->|grants|") {
		t.Error("missing dashed grants edge")
	}
	// job subgraph
	if !strings.Contains(out, "subgraph job_build") {
		t.Error("missing job subgraph cluster")
	}
}

func TestMermaidEmphasis(t *testing.T) {
	// 2 sink にファンアウトする untrusted チェーン
	in := AssemblerInput{
		FilePath: ".github/workflows/ci.yml", WorkflowName: "CI",
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true, Pos: &ast.Position{Line: 2, Col: 3}}},
			Permission: PermissionRef{Label: "contents:write", Pos: &ast.Position{Line: 4, Col: 3}}}},
		Records: []SinkRecord{
			{JobID: "build", StepPos: &ast.Position{Line: 10, Col: 9}, SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SinkKind: SinkLog, RuleName: "secret-in-log"},
			{JobID: "build", StepPos: &ast.Position{Line: 12, Col: 9}, SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SinkKind: SinkNetwork, RuleName: "secret-exfiltration"},
		},
	}
	out := NewMermaidRenderer().Render(Assemble(in))

	if !strings.Contains(out, "%% blast-radius:") {
		t.Error("missing summary comment line")
	}
	if !strings.Contains(out, "classDef untrusted") {
		t.Error("missing untrusted classDef")
	}
	if !strings.Contains(out, "[&rarr;2 sinks]") {
		t.Error("missing fan-out badge for shared source")
	}
	if !strings.Contains(out, "class ") || !strings.Contains(out, "fixhere") {
		t.Error("missing leverage (fixhere) class assignment")
	}
}

func TestMermaidGolden(t *testing.T) {
	out := NewMermaidRenderer().Render(sampleModel())
	golden := filepath.Join("testdata", "blastradius.mmd")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden: %v (run with UPDATE_GOLDEN=1 to create)", err)
	}
	if out != string(want) {
		t.Errorf("mermaid output drift:\n--- got ---\n%s\n--- want ---\n%s", out, want)
	}
}

// 決定性: 同一入力を2回描画してバイト一致
func TestMermaidDeterministic(t *testing.T) {
	a := NewMermaidRenderer().Render(sampleModel())
	b := NewMermaidRenderer().Render(sampleModel())
	if a != b {
		t.Error("render is non-deterministic")
	}
}

// TestSanitizeTokenEncodesStructuralCharacters pins the node-id encoding:
// SourceName values carry mermaid-structural characters (parens from
// "expr (tainted via src)", commas from multi-path joins, quotes from
// code-injection, "*" from secrets.*), none of which may survive literally into
// a node ID or collapse distinct model IDs together.
func TestSanitizeTokenEncodesStructuralCharacters(t *testing.T) {
	cases := map[string]string{
		"needs.produce.outputs.ref (tainted via github.head_ref)": "needs_x2E_produce_x2E_outputs_x2E_ref_x20__x28_tainted_x20_via_x20_github_x2E_head_x5F_ref_x29_",
		"a, b":            "a_x2C__x20_b",
		"secrets.*":       "secrets_x2E__x2A_",
		`x"y`:             "x_x22_y",
		"build-and-test":  "build_x2D_and_x2D_test",
		"already_ok_1234": "already_x5F_ok_x5F_1234",
	}
	for in, want := range cases {
		if got := sanitizeToken(in); got != want {
			t.Errorf("sanitizeToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMermaidRenderSanitizesIDs is the regression test for malformed-mermaid
// IDs: a SourceName with parens/commas/star must not leak those characters into
// emitted node IDs (which appear in node defs, edges, and class lines). Labels,
// which are quoted, may still contain the original text.
func TestMermaidRenderSanitizesIDs(t *testing.T) {
	in := AssemblerInput{
		FilePath: "x.yml", WorkflowName: "X",
		JobContexts: []JobContext{{
			JobID:      "build-and-test",
			Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
			Permission: PermissionRef{Label: "contents:write"},
		}},
		Records: []SinkRecord{{
			JobID: "build-and-test", StepPos: &ast.Position{Line: 5, Col: 3},
			SourceKind: SourceUntrusted,
			SourceName: "needs.a.outputs.x (tainted via github.head_ref), secrets.*",
			SinkKind:   SinkNetwork, RuleName: "request-forgery-critical",
		}},
	}
	out := NewMermaidRenderer().Render(Assemble(in))

	// If the id were unsanitized it would contain "_(" (a space-then-paren from
	// the SourceName). Labels keep the literal " (" instead.
	if strings.Contains(out, "_(") || strings.Contains(out, "_*") {
		t.Errorf("unsanitized structural character leaked into a node ID:\n%s", out)
	}
	// The hyphenated job id must also be sanitized in the subgraph declaration.
	if strings.Contains(out, "subgraph job_build-and-test") {
		t.Errorf("subgraph id not sanitized for hyphenated job name:\n%s", out)
	}
	// And the encoded source is still present (proves the source rendered).
	wantSourceID := mermaidID("source:build-and-test:1:needs.a.outputs.x (tainted via github.head_ref), secrets.*")
	if !strings.Contains(out, wantSourceID) {
		t.Errorf("expected sanitized source node id in output:\n%s", out)
	}
}

var (
	reMermaidNodeDef  = regexp.MustCompile(`^(n_[A-Za-z0-9_]+)[\[({>]`)
	reMermaidEdge     = regexp.MustCompile(`^(n_[A-Za-z0-9_]+)\s+(?:-->|-\.->)\|[^|]*\|\s+(n_[A-Za-z0-9_]+)$`)
	reMermaidClass    = regexp.MustCompile(`^class\s+(n_[A-Za-z0-9_]+)\s+\w+$`)
	reMermaidSubgraph = regexp.MustCompile(`^subgraph\s+(job_[A-Za-z0-9_]+)\[`)
)

// assertMermaidRenderable encodes the two structural contracts a real mermaid
// parser enforces, so a pure-Go test catches the classes of bug that only show
// up when the graph is actually rendered:
//  1. Type detection: the FIRST non-empty line must be the "flowchart TD"
//     declaration. Anything before it (e.g. a leading %% comment) yields
//     "No diagram type detected" — the exact bug this guards.
//  2. Referential integrity: every node id used on an edge or a class line must
//     have a corresponding node definition, or mermaid renders a dangling node.
func assertMermaidRenderable(t *testing.T, out string) {
	t.Helper()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	firstMeaningful := ""
	for _, ln := range lines {
		if strings.TrimSpace(ln) != "" {
			firstMeaningful = strings.TrimSpace(ln)
			break
		}
	}
	if firstMeaningful != "flowchart TD" {
		t.Fatalf("first meaningful line must be %q for mermaid type detection, got %q\n%s",
			"flowchart TD", firstMeaningful, out)
	}

	defined := map[string]bool{}
	for _, ln := range lines {
		if m := reMermaidNodeDef.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
			if defined[m[1]] {
				t.Errorf("duplicate node id %q:\n%s", m[1], out)
			}
			defined[m[1]] = true
		}
	}
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if m := reMermaidEdge.FindStringSubmatch(trimmed); m != nil {
			for _, id := range m[1:] {
				if !defined[id] {
					t.Errorf("edge references undefined node %q:\n%s", id, out)
				}
			}
		}
		if m := reMermaidClass.FindStringSubmatch(trimmed); m != nil {
			if !defined[m[1]] {
				t.Errorf("class line references undefined node %q:\n%s", m[1], out)
			}
		}
	}
}

func assertMermaidSubgraphsUnique(t *testing.T, out string) {
	t.Helper()
	seen := map[string]bool{}
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if m := reMermaidSubgraph.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
			if seen[m[1]] {
				t.Fatalf("duplicate subgraph id %q:\n%s", m[1], out)
			}
			seen[m[1]] = true
		}
	}
}

func assertRenderedModelIDsUnique(t *testing.T, m *ChainModel, out string) {
	t.Helper()
	defined := map[string]bool{}
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if match := reMermaidNodeDef.FindStringSubmatch(strings.TrimSpace(ln)); match != nil {
			defined[match[1]] = true
		}
	}
	if len(defined) != len(m.Nodes) {
		t.Fatalf("rendered node ids collapsed: got %d unique mermaid ids for %d model nodes\n%s",
			len(defined), len(m.Nodes), out)
	}
	for _, n := range m.Nodes {
		if !defined[mermaidID(n.ID)] {
			t.Fatalf("missing rendered node for model node %q as %q\n%s", n.ID, mermaidID(n.ID), out)
		}
	}
}

func assertRenderableModel(t *testing.T, m *ChainModel) string {
	t.Helper()
	out := NewMermaidRenderer().Render(m)
	assertMermaidRenderable(t, out)
	assertMermaidSubgraphsUnique(t, out)
	assertRenderedModelIDsUnique(t, m, out)
	return out
}

func sourceKindName(k SourceKind) string {
	switch k {
	case SourceSecret:
		return "secret"
	case SourceUntrusted:
		return "untrusted"
	default:
		return "unknown"
	}
}

// TestMermaidRenderIsParseable is the regression guard for the "No diagram type
// detected" bug (a leading %% comment shadowed the flowchart declaration) and
// for dangling node references. It exercises a rich graph (fan-out, subgraph,
// classes, leverage) and the degenerate empty graph.
func TestMermaidRenderIsParseable(t *testing.T) {
	fanOut := AssemblerInput{
		FilePath: ".github/workflows/ci.yml", WorkflowName: "CI",
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true, Pos: &ast.Position{Line: 2, Col: 3}}},
			Permission: PermissionRef{Label: "contents:write", Pos: &ast.Position{Line: 4, Col: 3}}}},
		Records: []SinkRecord{
			{JobID: "build", StepPos: &ast.Position{Line: 10, Col: 9}, SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SinkKind: SinkLog, RuleName: "secret-in-log"},
			{JobID: "build", StepPos: &ast.Position{Line: 12, Col: 9}, SourceKind: SourceSecret, SourceName: "secrets.TOKEN", SinkKind: SinkNetwork, RuleName: "secret-exfiltration"},
		},
	}
	cases := map[string]*ChainModel{
		"sample": sampleModel(),
		"fanout": Assemble(fanOut),
		"empty":  Assemble(AssemblerInput{FilePath: "x.yml", WorkflowName: "X"}),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			assertMermaidRenderable(t, NewMermaidRenderer().Render(m))
		})
	}
}

// TestMermaidLabelCollapsesNewlines pins the fix for %q-escaped multiline labels:
// a multi-line run script must render on a single node-definition line (newlines
// collapsed to spaces), never as a literal \n nor a node def split across lines.
func TestMermaidLabelCollapsesNewlines(t *testing.T) {
	in := AssemblerInput{
		FilePath: "x.yml", WorkflowName: "X",
		JobContexts: []JobContext{{JobID: "build",
			Triggers:   []TriggerRef{{Name: "push"}},
			Permission: PermissionRef{Label: "contents:read"}}},
		Records: []SinkRecord{{
			JobID: "build", StepPos: &ast.Position{Line: 5, Col: 1},
			StepSummary: "run: echo a\necho b", SourceKind: SourceSecret, SourceName: "secrets.T",
			SinkKind: SinkLog, RuleName: "secret-in-log",
		}},
	}
	out := NewMermaidRenderer().Render(Assemble(in))
	assertMermaidRenderable(t, out) // referential integrity catches a node def split by a raw newline
	if strings.Contains(out, `\n`) {
		t.Errorf("label contains a literal \\n (Go-escaped, not collapsed):\n%s", out)
	}
	if !strings.Contains(out, "run: echo a echo b") {
		t.Errorf("multiline label not collapsed to a single spaced line:\n%s", out)
	}
}

func TestMermaidRenderCoversAssembledDiagramPatterns(t *testing.T) {
	sourceKinds := []SourceKind{SourceSecret, SourceUntrusted}
	sinkKinds := []SinkKind{SinkLog, SinkNetwork, SinkArtifact, SinkExpr, SinkBoundary}
	contexts := map[string][]JobContext{
		"no_context": nil,
		"safe_explicit": {{
			JobID:      "job.safe",
			Triggers:   []TriggerRef{{Name: "push", Pos: &ast.Position{Line: 1, Col: 1}}},
			Permission: PermissionRef{Label: "contents:read", Pos: &ast.Position{Line: 2, Col: 1}},
		}},
		"untrusted_implicit": {{
			JobID: "job.unsafe",
			Triggers: []TriggerRef{
				{Name: "pull_request_target", Untrusted: true, SecretsAvailable: true, Pos: &ast.Position{Line: 1, Col: 1}},
				{Name: "workflow_dispatch", Pos: &ast.Position{Line: 1, Col: 20}},
			},
			Permission: PermissionRef{Implicit: true, Pos: &ast.Position{Line: 2, Col: 1}},
		}},
	}

	for contextName, jobContexts := range contexts {
		jobID := ""
		if len(jobContexts) > 0 {
			jobID = jobContexts[0].JobID
		}
		for _, sourceKind := range sourceKinds {
			for _, sinkKind := range sinkKinds {
				t.Run(contextName+"/"+sourceKindName(sourceKind)+"/"+sinkKind.String(), func(t *testing.T) {
					sourceName := "src." + sourceKindName(sourceKind) + "-" + sinkKind.String()
					in := AssemblerInput{
						FilePath:     "workflow-" + contextName + ".yml",
						WorkflowName: "wf " + contextName,
						JobContexts:  jobContexts,
						Records: []SinkRecord{{
							JobID: jobID,
							StepPos: &ast.Position{
								Line: int(sourceKind)*10 + int(sinkKind) + 1,
								Col:  int(sinkKind) + 1,
							},
							StepSummary:  "run: echo \"" + sourceName + "\"\nsecond line",
							SourceKind:   sourceKind,
							SourceName:   sourceName,
							SourceOrigin: sourceName,
							SinkKind:     sinkKind,
							RuleName:     "rule." + sinkKind.String(),
							Severity:     "severity-" + sinkKind.String(),
						}},
					}
					out := assertRenderableModel(t, Assemble(in))
					if strings.Contains(out, `\n`) {
						t.Fatalf("rendered output contains literal newline escape in labels:\n%s", out)
					}
					if sinkKind.String() != "unknown" && !strings.Contains(out, ">\""+sinkKind.String()+"\"]") {
						t.Fatalf("rendered sink label for %s is missing:\n%s", sinkKind.String(), out)
					}
				})
			}
		}
	}

	t.Run("nil_position_empty_strings", func(t *testing.T) {
		in := AssemblerInput{Records: []SinkRecord{{
			SourceKind: SourceSecret,
			SinkKind:   SinkLog,
		}}}
		assertRenderableModel(t, Assemble(in))
	})

	t.Run("cross_job_needs", func(t *testing.T) {
		in := AssemblerInput{
			JobContexts: []JobContext{
				{JobID: "produce-job", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
					Permission: PermissionRef{Label: "contents:write"}},
				{JobID: "consume-job", Triggers: []TriggerRef{{Name: "pull_request_target", Untrusted: true}},
					Permission: PermissionRef{Label: "contents:write"}},
			},
			Records: []SinkRecord{
				{JobID: "produce-job", StepPos: &ast.Position{Line: 5, Col: 1},
					SourceKind: SourceUntrusted, SourceName: "github.head_ref", SourceOrigin: "github.head_ref",
					SinkKind: SinkExpr, RuleName: "output-clobbering-critical", OutputName: "ref-name"},
				{JobID: "consume-job", StepPos: &ast.Position{Line: 9, Col: 1},
					SourceKind: SourceUntrusted, SourceName: "needs.produce-job.outputs.ref-name",
					SourceOrigin: "needs.produce-job.outputs.ref-name (tainted via github.head_ref)",
					SinkKind:     SinkNetwork, RuleName: "request-forgery-critical"},
			},
		}
		out := assertRenderableModel(t, Assemble(in))
		if !strings.Contains(out, "-->|needs|") {
			t.Fatalf("cross-job case did not render a needs edge:\n%s", out)
		}
	})
}

func TestMermaidRenderCoversNodeAndEdgeKinds(t *testing.T) {
	m := &ChainModel{
		Summary: Summary{UntrustedTriggers: 1, Secrets: 1, Sinks: 5, SinkCountsByKind: map[SinkKind]int{
			SinkLog: 1, SinkNetwork: 1, SinkArtifact: 1, SinkExpr: 1, SinkBoundary: 1,
		}},
		LeverageID: "trigger:pull_request_target",
		Nodes: []*Node{
			{ID: "trigger:pull_request_target", Kind: NodeTrigger, Label: "pull_request_target", Untrusted: true, ChainCount: 2, Leverage: true, UntrustedReachable: true},
			{ID: "perm:job.a-b", Kind: NodePermission, Label: "implicit(default token)", Implicit: true, ChainCount: 2, UntrustedReachable: true},
			{ID: "source:job.a-b:0:secrets.DEPLOY_TOKEN", Kind: NodeSource, Label: "secrets.DEPLOY_TOKEN", SourceKind: SourceSecret, ChainCount: 2, UntrustedReachable: true},
			{ID: "source:job.a-b:1:github.event.issue.title", Kind: NodeSource, Label: "github.event.issue.title", SourceKind: SourceUntrusted, Untrusted: true, UntrustedReachable: true},
			{ID: "action:job.a-b:10:1", Kind: NodeAction, Label: "run: echo \"quoted\"\r\nnext", JobID: "job.a-b", UntrustedReachable: true},
			{ID: "sink:log:job.a-b:10:1", Kind: NodeSink, Label: SinkLog.String(), SinkKind: SinkLog, JobID: "job.a-b", UntrustedReachable: true},
			{ID: "sink:network:job.a-b:11:1", Kind: NodeSink, Label: SinkNetwork.String(), SinkKind: SinkNetwork, JobID: "job.a-b", UntrustedReachable: true},
			{ID: "sink:artifact:job.a-b:12:1", Kind: NodeSink, Label: SinkArtifact.String(), SinkKind: SinkArtifact, JobID: "job.a-b", UntrustedReachable: true},
			{ID: "sink:expr:job.a-b:13:1", Kind: NodeSink, Label: SinkExpr.String(), SinkKind: SinkExpr, JobID: "job.a-b", UntrustedReachable: true},
			{ID: "sink:boundary:job.a-b:14:1", Kind: NodeSink, Label: SinkBoundary.String(), SinkKind: SinkBoundary, JobID: "job.a-b", UntrustedReachable: true},
		},
		Edges: []Edge{
			{From: "trigger:pull_request_target", To: "perm:job.a-b", Kind: EdgeGrants},
			{From: "perm:job.a-b", To: "source:job.a-b:0:secrets.DEPLOY_TOKEN", Kind: EdgeEnables},
			{From: "source:job.a-b:0:secrets.DEPLOY_TOKEN", To: "action:job.a-b:10:1", Kind: EdgeUsedBy},
			{From: "action:job.a-b:10:1", To: "sink:log:job.a-b:10:1", Kind: EdgeFlowsTo},
			{From: "action:job.a-b:10:1", To: "source:job.a-b:1:github.event.issue.title", Kind: EdgeNeeds},
		},
	}

	out := assertRenderableModel(t, m)
	for _, want := range []string{
		"-.->|grants|",
		"-.->|enables|",
		"-->|used-by|",
		"-->|flows-to|",
		"-->|needs|",
		"n_sink_x3A_log_x3A_job_x2E_a_x2D_b_x3A_10_x3A_1>\"log\"]",
		"&quot;quoted&quot; next",
		"[&rarr;2 sinks]",
		"class n_trigger_x3A_pull_x5F_request_x5F_target fixhere",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected rendered pattern %q in output:\n%s", want, out)
		}
	}
}

func TestMermaidIDsDoNotCollideForDistinctModelIDs(t *testing.T) {
	in := AssemblerInput{
		FilePath: "x.yml", WorkflowName: "X",
		JobContexts: []JobContext{
			{JobID: "build-dot",
				Triggers:   []TriggerRef{{Name: "workflow_dispatch"}},
				Permission: PermissionRef{Label: "contents:read"}},
			{JobID: "build.dot",
				Triggers:   []TriggerRef{{Name: "workflow_dispatch"}},
				Permission: PermissionRef{Label: "contents:read"}},
		},
		Records: []SinkRecord{
			{JobID: "build-dot", StepPos: &ast.Position{Line: 1, Col: 1},
				StepSummary: "run: echo dot", SourceKind: SourceUntrusted, SourceName: "input.a.b",
				SinkKind: SinkLog, RuleName: "log-dot"},
			{JobID: "build.dot", StepPos: &ast.Position{Line: 2, Col: 1},
				StepSummary: "run: echo dash", SourceKind: SourceUntrusted, SourceName: "input.a-b",
				SinkKind: SinkNetwork, RuleName: "network-dash"},
		},
	}
	m := Assemble(in)
	out := NewMermaidRenderer().Render(m)

	assertMermaidRenderable(t, out)
	assertMermaidSubgraphsUnique(t, out)
	assertRenderedModelIDsUnique(t, m, out)
}

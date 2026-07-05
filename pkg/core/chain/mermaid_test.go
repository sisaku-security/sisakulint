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

// TestSanitizeTokenWhitelist pins the whitelist normalization: SourceName values
// carry mermaid-structural characters (parens from "expr (tainted via src)",
// commas from multi-path joins, quotes from code-injection, "*" from secrets.*),
// none of which may survive into a node ID.
func TestSanitizeTokenWhitelist(t *testing.T) {
	cases := map[string]string{
		"needs.produce.outputs.ref (tainted via github.head_ref)": "needs_produce_outputs_ref__tainted_via_github_head_ref_",
		"a, b":            "a__b",
		"secrets.*":       "secrets__",
		`x"y`:             "x_y",
		"build-and-test":  "build_and_test",
		"already_ok_1234": "already_ok_1234",
	}
	for in, want := range cases {
		if got := sanitizeToken(in); got != want {
			t.Errorf("sanitizeToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMermaidRenderSanitizesIDs is the regression test for the malformed-mermaid
// bug: a SourceName with parens/commas/star must not leak those characters into
// emitted node IDs (which appear in node defs, edges, and class lines). Labels,
// which are quoted, may still contain them.
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
	// the SourceName collapsed into the id). Labels keep the literal " (" instead.
	if strings.Contains(out, "_(") || strings.Contains(out, "_*") {
		t.Errorf("unsanitized structural character leaked into a node ID:\n%s", out)
	}
	// The hyphenated job id must also be sanitized in the subgraph declaration.
	if strings.Contains(out, "subgraph job_build-and-test") {
		t.Errorf("subgraph id not sanitized for hyphenated job name:\n%s", out)
	}
	// And the sanitized source is still present (proves the source rendered).
	if !strings.Contains(out, "needs_a_outputs_x__tainted_via_github_head_ref___secrets__") {
		t.Errorf("expected sanitized source node id in output:\n%s", out)
	}
}

var (
	reMermaidNodeDef = regexp.MustCompile(`^(n_[A-Za-z0-9_]+)[\[({>]`)
	reMermaidEdge    = regexp.MustCompile(`^(n_[A-Za-z0-9_]+)\s+(?:-->|-\.->)\|[^|]*\|\s+(n_[A-Za-z0-9_]+)$`)
	reMermaidClass   = regexp.MustCompile(`^class\s+(n_[A-Za-z0-9_]+)\s+\w+$`)
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

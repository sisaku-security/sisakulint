// pkg/core/chain/mermaid_test.go
package chain

import (
	"os"
	"path/filepath"
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

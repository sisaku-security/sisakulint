// pkg/core/chain/mermaid_test.go
package chain

import (
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

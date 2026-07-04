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
		"source:0:secrets.TOKEN", "action:build:10:9",
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
	if !hasEdge(m, "perm:build", "source:0:secrets.TOKEN", EdgeEnables) {
		t.Error("missing Enables edge")
	}
	if !hasEdge(m, "source:0:secrets.TOKEN", "action:build:10:9", EdgeUsedBy) {
		t.Error("missing UsedBy edge")
	}
	if !hasEdge(m, "action:build:10:9", "sink:secret-exfiltration:build:10:9", EdgeFlowsTo) {
		t.Error("missing FlowsTo edge")
	}
}

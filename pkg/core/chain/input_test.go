// pkg/core/chain/input_test.go
package chain

import (
	"testing"

	"github.com/sisaku-security/sisakulint/pkg/ast"
)

func TestAssemblerInputConstruction(t *testing.T) {
	in := AssemblerInput{
		FilePath:     ".github/workflows/ci.yml",
		WorkflowName: "CI",
		JobContexts: []JobContext{{
			JobID: "build",
			Triggers: []TriggerRef{{
				Name: "pull_request_target", Untrusted: true, SecretsAvailable: true,
				Pos: &ast.Position{Line: 2, Col: 3},
			}},
			Permission: PermissionRef{Label: "contents:write", Implicit: false, Pos: &ast.Position{Line: 4, Col: 3}},
		}},
		Records: []SinkRecord{{JobID: "build", SinkKind: SinkLog}},
	}
	if in.JobContexts[0].Triggers[0].Name != "pull_request_target" {
		t.Fatal("trigger name not preserved")
	}
}

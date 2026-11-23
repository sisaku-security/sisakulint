package rules

import (
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

// TestArgTypesOfAnalysis: the values of the types of actions/analysis that
// the args of findings hold (x-go-type of findings-v0.json) are written as
// the consts of their $defs, each once, and every const is one of them.
func TestArgTypesOfAnalysis(t *testing.T) {
	b, err := os.ReadFile("schema/findings-v0.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]struct {
			OneOf []struct {
				Const string `json:"const"`
			} `json:"oneOf"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	for def, values := range map[string][]any{
		"sink-kind":       {analysis.SinkRun, analysis.SinkScript},
		"approval":        {analysis.ApprovalLabel, analysis.ApprovalEnvironment},
		"agent-action":    {analysis.AgentActionClaudeCode, analysis.AgentActionClaudeCodeBase, analysis.AgentActionCodex, analysis.AgentActionGeminiCLI, analysis.AgentActionAIInference},
		"agent-input":     {analysis.AgentInputAllowedNonWriteUsers, analysis.AgentInputAllowedBots, analysis.AgentInputAllowUsers, analysis.AgentInputClaudeArgs, analysis.AgentInputSettings, analysis.AgentInputSafetyStrategy, analysis.AgentInputSandbox, analysis.AgentInputPermissionProfile, analysis.AgentInputCodexArgs, analysis.AgentInputPrompt, analysis.AgentInputSystemPrompt, analysis.AgentInputInput, analysis.AgentInputCopilotAllowTools},
		"image-site-kind": {analysis.ImageSiteKindContainer, analysis.ImageSiteKindService, analysis.ImageSiteKindStep, analysis.ImageSiteKindAction},
	} {
		var want, got []string
		for _, c := range schema.Defs[def].OneOf {
			want = append(want, `"`+c.Const+`"`)
		}
		for _, v := range values {
			j, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, string(j))
			if s := v.(interface{ String() string }).String(); `"`+s+`"` != string(j) {
				t.Errorf("$defs/%s: %v is %s in JSON but %s by String", def, v, j, s)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("$defs/%s: the values are %v, the schema's %v", def, got, want)
		}
	}
}

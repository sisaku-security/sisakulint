package agent

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// SettingValue is a value of an input of a step of an agent action whose
// words or JSON set what its agent may do: its flags, its settings, its
// tools.
type SettingValue struct {
	Input analysis.AgentInput
	Value workflow.String
}

// settingInputs are the inputs each action splits into words or reads as
// JSON after GitHub writes the ${{ }} into them, so that a quote a value
// closes adds a flag, a key or a tool.
var settingInputs = map[analysis.AgentAction][]analysis.AgentInput{
	analysis.AgentActionClaudeCode:     {analysis.AgentInputClaudeArgs, analysis.AgentInputSettings},
	analysis.AgentActionClaudeCodeBase: {analysis.AgentInputClaudeArgs, analysis.AgentInputSettings},
	analysis.AgentActionCodex:          {analysis.AgentInputCodexArgs},
	analysis.AgentActionGeminiCLI:      {analysis.AgentInputSettings},
	analysis.AgentActionAIInference:    {analysis.AgentInputCopilotAllowTools},
}

// Settings are the values of the setting inputs of s, a step of the agent
// action a, but under a whole with that is a ${{ }}.
func Settings(s workflow.Step, a analysis.AgentAction) []SettingValue {
	if s.With.Status != workflow.Present {
		return nil
	}
	var out []SettingValue
	for _, in := range settingInputs[a] {
		if v, ok := valueOf(s, in); ok {
			out = append(out, SettingValue{Input: in, Value: v})
		}
	}
	return out
}

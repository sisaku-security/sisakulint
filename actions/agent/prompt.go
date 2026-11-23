package agent

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// PromptValue is a value of a step of an agent action that reaches the
// agent as text.
type PromptValue struct {
	Route analysis.PromptRoute
	Input analysis.AgentInput // by PromptRouteInput
	Env   workflow.EnvName    // by PromptRouteEnv
	Value workflow.String
}

// promptInputs are the inputs each action writes into the agent's prompt:
// ai-inference puts system-prompt before the prompt, and writes input into
// the variables of a .prompt.yml. The inputs that name a file are not
// read, nor claude_args, whose --system-prompt and --append-system-prompt
// are prompts too: which flag a ${{ }} is the value of is read with the
// flags' meanings, which the rule of the tools reads.
var promptInputs = map[analysis.AgentAction][]analysis.AgentInput{
	analysis.AgentActionClaudeCode:     {analysis.AgentInputPrompt},
	analysis.AgentActionClaudeCodeBase: {analysis.AgentInputPrompt},
	analysis.AgentActionCodex:          {analysis.AgentInputPrompt},
	analysis.AgentActionGeminiCLI:      {analysis.AgentInputPrompt},
	analysis.AgentActionAIInference:    {analysis.AgentInputPrompt, analysis.AgentInputSystemPrompt, analysis.AgentInputInput},
}

// geminiEnv are the names gemini-cli passes to its tools on GitHub,
// compared upper-cased, where it drops the others but those its settings
// allow and those of the prefixes geminiEnvPrefixes
// (environmentSanitization.ts of gemini-cli v0.63.0).
var geminiEnv = []string{
	"PATH", "SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "SYSTEMDRIVE", "HOME", "LANG", "SHELL", "TMPDIR", "USER", "LOGNAME", "TERM", "COLORTERM",
	"ADDITIONAL_CONTEXT", "AVAILABLE_LABELS", "BRANCH_NAME", "DESCRIPTION", "EVENT_NAME", "GITHUB_ENV", "IS_PULL_REQUEST",
	"ISSUES_TO_TRIAGE", "ISSUE_BODY", "ISSUE_NUMBER", "ISSUE_TITLE", "PULL_REQUEST_NUMBER", "REPOSITORY", "TITLE", "TRIGGERING_ACTOR",
}

var geminiEnvPrefixes = []string{"GEMINI_CLI_", "GIT_CONFIG_"}

// geminiPasses is whether gemini-cli passes the env n to its tools, when
// no settings may allow more.
func geminiPasses(n workflow.EnvName) bool {
	u := strings.ToUpper(n.String())
	return slices.Contains(geminiEnv, u) || slices.ContainsFunc(geminiEnvPrefixes, func(p string) bool { return strings.HasPrefix(u, p) })
}

// Prompts are the values of s, a step of the agent action a, that reach
// the agent as text: the inputs a writes into its prompt but under a
// whole with that is a ${{ }}, and the env of the step, which the agent's
// process gets and its tools read, but under codex-action's
// safety-strategy unprivileged-user, whose sudo resets the env, and the
// names gemini-cli drops when no settings is given.
func Prompts(s workflow.Step, a analysis.AgentAction) []PromptValue {
	var out []PromptValue
	if s.With.Status == workflow.Present {
		for _, in := range promptInputs[a] {
			if v, ok := valueOf(s, in); ok {
				out = append(out, PromptValue{Route: analysis.PromptRouteInput, Input: in, Value: v})
			}
		}
	}
	if a == analysis.AgentActionCodex {
		if v, _ := inputOf(s, analysis.AgentInputSafetyStrategy).raw(); v == "unprivileged-user" {
			return out
		}
	}
	if s.Env.Status != workflow.Present {
		return out
	}
	// settings may allow any name (allowedEnvironmentVariables)
	filter := a == analysis.AgentActionGeminiCLI && !inputOf(s, analysis.AgentInputSettings).present
	for _, e := range s.Env.Value.Entries {
		n, ok := workflow.EnvNameOf(e.Key.AsString())
		if !ok || filter && !geminiPasses(n) {
			continue
		}
		if v, ok := fieldValue(e.Value); ok {
			out = append(out, PromptValue{Route: analysis.PromptRouteEnv, Env: n, Value: v})
		}
	}
	return out
}

// valueOf is the value of the input in of s's with.
func valueOf(s workflow.Step, in analysis.AgentInput) (workflow.String, bool) {
	e, ok := s.With.Value.Lookup(in.String())
	if !ok {
		return workflow.String{}, false
	}
	return fieldValue(e.Value)
}

// fieldValue is the string of f, written out or a ${{ }}.
func fieldValue(f workflow.Field[workflow.String]) (workflow.String, bool) {
	switch {
	case f.Status == workflow.Present:
		return f.Value, true
	case f.Status == workflow.Dynamic && f.Expr != nil:
		return *f.Expr, true
	}
	return workflow.String{}, false
}

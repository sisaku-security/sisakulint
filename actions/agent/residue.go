package agent

import (
	"path"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// UserOf is whom the agent of s runs as: codex-action's safety-strategy
// decides it, drop-sudo when it is not written (as read on 2026-10-14);
// the other actions run their agent as the runner's user. A ${{ }} is
// the settings' inconclusive, read here as the default.
func UserOf(s Step) analysis.AgentUser {
	if s.Action != analysis.AgentActionCodex {
		return analysis.AgentUserRunner
	}
	v, _ := inputOf(s.Step, analysis.AgentInputSafetyStrategy).raw()
	switch v {
	case "unprivileged-user":
		return analysis.AgentUserOther
	case "unsafe", "read-only":
		return analysis.AgentUserRunner
	}
	return analysis.AgentUserWithoutSudo
}

// GitWriteOf is whether the edits of the agent of s may write .git
// (as read on 2026-10-14): gemini-cli's; claude's in auto
// mode, where a classifier decides writes to protected paths; not
// claude's in its other modes, nor codex's; not decided for the Copilot
// CLI's.
func GitWriteOf(s Step, evs []analysis.EventActivity, env []workflow.Field[workflow.Map[workflow.String]]) analysis.AgentGitWrite {
	switch s.Action {
	case analysis.AgentActionGeminiCLI:
		return analysis.AgentGitWriteYes
	case analysis.AgentActionAIInference:
		return analysis.AgentGitWriteUndecided
	case analysis.AgentActionClaudeCode, analysis.AgentActionClaudeCodeBase:
		if AutoMode(s, evs, env) == analysis.AgentAutoModeOn {
			return analysis.AgentGitWriteYes
		}
	}
	return analysis.AgentGitWriteNo
}

// HeldInputs are the values of the with of s that reach its agent's
// process: none for codex-action, which gives its key to a proxy, not to
// codex; all for the others, whose inputs
// the runner makes the env of a node action, and a composite action passes
// on to its steps.
func HeldInputs(s Step) []workflow.String {
	if s.Action == analysis.AgentActionCodex {
		return nil
	}
	return job.MapValues(s.Step.With)
}

// DefaultHeldToken is whether the agent of s holds the job's token
// without a with that names it: ai-inference's token defaults to
// github.token when the step does not write it, and the runner makes it
// the env of the action.
func DefaultHeldToken(s Step) bool {
	return s.Action == analysis.AgentActionAIInference && !inputOf(s.Step, analysis.AgentInputToken).present && s.Step.With.Status != workflow.Dynamic
}

// WorkingDirectory is the directory of the workspace the agent of s works
// in, cleaned and relative to the workspace: codex-action's
// working-directory, else the workspace. known is false for a ${{ }} and
// a path out of the workspace.
func WorkingDirectory(s Step) (root string, known bool) {
	switch {
	case s.Action != analysis.AgentActionCodex:
		return ".", true
	case s.Step.With.Status == workflow.Dynamic:
		return "", false
	case s.Step.With.Status != workflow.Present:
		return ".", true
	}
	e, ok := s.Step.With.Value.Lookup("working-directory")
	if !ok {
		return ".", true
	}
	if e.Value.Status != workflow.Present || e.Value.Value.Parts != nil {
		return "", false
	}
	p := strings.TrimSpace(e.Value.Value.AsString())
	if p == "" {
		return ".", true
	}
	if path.IsAbs(p) || p == ".." || strings.HasPrefix(path.Clean(p), "../") {
		return "", false
	}
	return path.Clean(p), true
}

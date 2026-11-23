package agent

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// scrubVar is the variable of Claude Code's subprocess env scrub
// (https://code.claude.com/docs/en/env-vars). Under it the CLI starts in
// the default permission mode whatever mode it is given (observed with
// Claude Code 2.1.293 and 2.1.310).
const scrubVar = "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB"

// ScrubSource is what makes a scrub undecided, as written, and where: the
// input allowed_non_write_users or the whole with (Input unset) at its
// value, or the variable of env (Input unset), or an env that is a whole
// ${{ }}, at the key.
type ScrubSource struct {
	Input analysis.AgentInput
	Text  string
	At    workflow.Base
}

// ScrubOf is whether the agent of s runs under the subprocess env scrub,
// with env the env of its workflow, job and step, the nearest last.
// claude-code-action sets the variable to the env's value when it is not
// empty, else to 1 when allowed_non_write_users is not empty, untrimmed
// (https://github.com/anthropics/claude-code-action/blob/925afb53776cf1a2b738c6bdbed37b4d4000ef13/action.yml,
// L301); the base-action passes the env on. The CLI reads 1, true, yes
// and on, trimmed and in any case, as true. An env that is a whole ${{ }}
// nearer than the variable may set it. Off for any other action.
func ScrubOf(s Step, env []workflow.Field[workflow.Map[workflow.String]]) (analysis.SubprocessScrub, ScrubSource) {
	if s.Action != analysis.AgentActionClaudeCode && s.Action != analysis.AgentActionClaudeCodeBase {
		return analysis.SubprocessScrubOff, ScrubSource{}
	}
	for i := len(env) - 1; i >= 0; i-- {
		f := env[i]
		if f.Status == workflow.Dynamic && f.Expr != nil {
			return analysis.SubprocessScrubUndecided, ScrubSource{Text: f.Expr.Text(), At: f.Expr.Base}
		}
		if f.Status != workflow.Present {
			continue
		}
		e, ok := f.Value.Lookup(scrubVar)
		if !ok || e.Value.Status != workflow.Present {
			continue
		}
		v := e.Value.Value
		if v.HasExpr() {
			return analysis.SubprocessScrubUndecided, ScrubSource{Text: scrubVar + ": " + v.Text(), At: e.Key.Base}
		}
		if v.AsString() == "" {
			break // the action reads an empty value as none
		}
		switch strings.ToLower(strings.TrimSpace(v.AsString())) {
		case "1", "true", "yes", "on":
			return analysis.SubprocessScrubOn, ScrubSource{}
		}
		return analysis.SubprocessScrubOff, ScrubSource{}
	}
	if s.Action == analysis.AgentActionClaudeCodeBase {
		return analysis.SubprocessScrubOff, ScrubSource{}
	}
	if s.Step.With.Status == workflow.Dynamic && s.Step.With.Expr != nil {
		return analysis.SubprocessScrubUndecided, ScrubSource{Text: s.Step.With.Expr.Text(), At: s.Step.With.Expr.Base}
	}
	users := inputOf(s.Step, analysis.AgentInputAllowedNonWriteUsers)
	switch {
	case !users.present:
		return analysis.SubprocessScrubOff, ScrubSource{}
	case users.whole || users.value.HasExpr():
		return analysis.SubprocessScrubUndecided, ScrubSource{Input: users.name, Text: users.text, At: users.at}
	case users.value.AsString() != "":
		return analysis.SubprocessScrubOn, ScrubSource{}
	}
	return analysis.SubprocessScrubOff, ScrubSource{}
}

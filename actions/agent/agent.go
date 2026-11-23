package agent

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// Step is a step of an agent action and what of its with lets someone
// start the agent, or takes a layer of its sandbox off.
type Step struct {
	Step           workflow.Step
	Action         analysis.AgentAction
	OpenGates      []OpenGate
	GateInputs     []GateInput
	UnsafeSettings []UnsafeSetting
	Inconclusive   []InconclusiveSetting
}

// OpenGate is a gate the step opens.
type OpenGate struct {
	Gate  analysis.AgentGate
	Input analysis.AgentInput // the input that opens it; unset for AgentGateUnchecked
	Text  string              // the input's value as written; empty for AgentGateUnchecked
	At    workflow.Base       // its value, or the uses for AgentGateUnchecked
}

// GateInput is an input that opens the gate of the step whose value has
// a ${{ }}: whom it lets in is read by event, with the ifs
// (attacker.Table.ActorListed).
type GateInput struct {
	Gate  analysis.AgentGate
	Input analysis.AgentInput
	Value workflow.String // as written
	At    workflow.Base
}

// UnsafeSetting is a setting of the step that takes a layer off.
type UnsafeSetting struct {
	Layer analysis.SandboxLayer
	Input analysis.AgentInput
	Value string // the word of its value that takes the layer off
	At    workflow.Base
}

// InconclusiveSetting is an input the analysis does not read: a ${{ }}, or
// a settings that names a file.
type InconclusiveSetting struct {
	Kind  analysis.InconclusiveAgentKind
	Input analysis.AgentInput // unset when the whole with is a ${{ }}
	Text  string              // as written
	At    workflow.Base
}

var (
	claudeCodeRepo     = mustRepo("anthropics/claude-code-action")
	claudeCodeBaseRepo = mustRepo("anthropics/claude-code-base-action")
	codexRepo          = mustRepo("openai/codex-action")
	geminiCLIRepo      = mustRepo("google-github-actions/run-gemini-cli")
	aiInferenceRepo    = mustRepo("actions/ai-inference")
)

func mustRepo(s string) facts.Repo {
	r, err := facts.ParseRepo(s)
	if err != nil {
		panic(err)
	}
	return r
}

// actionOf is the agent action of a uses of another repository, compared
// as GitHub compares owners and names: claude-code-action's base-action
// is the one path under a repository that is one.
func actionOf(fu workflow.Field[workflow.Uses]) analysis.AgentAction {
	if fu.Status != workflow.Present {
		return analysis.AgentActionUnset
	}
	for _, a := range fu.Value.Actions() {
		if got := agentActionOf(a); got != analysis.AgentActionUnset {
			return got
		}
	}
	return analysis.AgentActionUnset
}

// agentActionOf is the agent action a reads as.
func agentActionOf(a workflow.UsesAction) analysis.AgentAction {
	r, err := facts.ParseRepo(a.Owner + "/" + a.Repo)
	if err != nil {
		return analysis.AgentActionUnset
	}
	path := a.Path.String()
	switch {
	case r == claudeCodeRepo && path == "":
		return analysis.AgentActionClaudeCode
	case r == claudeCodeRepo && path == "base-action", r == claudeCodeBaseRepo && path == "":
		return analysis.AgentActionClaudeCodeBase
	case path != "":
		return analysis.AgentActionUnset
	case r == codexRepo:
		return analysis.AgentActionCodex
	case r == geminiCLIRepo:
		return analysis.AgentActionGeminiCLI
	case r == aiInferenceRepo:
		return analysis.AgentActionAIInference
	}
	return analysis.AgentActionUnset
}

// Of is s as a step of an agent action; false when it is not one.
func Of(s workflow.Step) (Step, bool) {
	a := actionOf(s.Uses)
	if a == analysis.AgentActionUnset {
		return Step{}, false
	}
	out := Step{Step: s, Action: a}
	switch a {
	case analysis.AgentActionClaudeCodeBase, analysis.AgentActionGeminiCLI, analysis.AgentActionAIInference:
		// they check no actor
		out.OpenGates = append(out.OpenGates, OpenGate{Gate: analysis.AgentGateUnchecked, At: s.Uses.Value.Base})
	}
	if s.With.Status == workflow.Dynamic && s.With.Expr != nil {
		e := s.With.Expr
		if a == analysis.AgentActionClaudeCode || a == analysis.AgentActionCodex {
			out.Inconclusive = append(out.Inconclusive, InconclusiveSetting{Kind: analysis.InconclusiveAgentGate, Text: e.Text(), At: e.Base})
		}
		if a != analysis.AgentActionGeminiCLI && a != analysis.AgentActionAIInference {
			out.Inconclusive = append(out.Inconclusive, InconclusiveSetting{Kind: analysis.InconclusiveAgentSetting, Text: e.Text(), At: e.Base})
		}
		return out, true
	}
	switch a {
	case analysis.AgentActionClaudeCode:
		out.claudeGates(s)
		out.claudeSettings(s, a)
	case analysis.AgentActionClaudeCodeBase:
		out.claudeSettings(s, a)
	case analysis.AgentActionCodex:
		out.codexGates(s)
		out.codexSettings(s)
	}
	return out, true
}

// UnderScrub is s under the subprocess env scrub sc of src (ScrubOf),
// which keeps the CLI in the default mode: claude's bypass takes no layer
// off then, and is the settings' inconclusive, once, at what decides the
// scrub, when sc is undecided. The settings of the other actions stay.
func (s Step) UnderScrub(sc analysis.SubprocessScrub, src ScrubSource) Step {
	if sc == analysis.SubprocessScrubOff || s.Action != analysis.AgentActionClaudeCode && s.Action != analysis.AgentActionClaudeCodeBase {
		return s
	}
	var kept []UnsafeSetting
	bypass := false
	for _, u := range s.UnsafeSettings {
		if u.Layer == analysis.SandboxLayerCommands {
			bypass = true
			continue
		}
		kept = append(kept, u)
	}
	s.UnsafeSettings = kept
	if bypass && sc == analysis.SubprocessScrubUndecided {
		s.Inconclusive = append(slices.Clone(s.Inconclusive), InconclusiveSetting{Kind: analysis.InconclusiveAgentSetting, Input: src.Input, Text: src.Text, At: src.At})
	}
	return s
}

// input is an input of a step's with.
type input struct {
	name    analysis.AgentInput
	value   workflow.String // when present and not dynamic
	written workflow.String // the value as written: a literal, or the whole ${{ }}
	text    string          // as written
	at      workflow.Base
	present bool
	dynamic bool // a ${{ }}, or one in it
	whole   bool // the value is a whole ${{ }}
}

func inputOf(s workflow.Step, name analysis.AgentInput) input {
	in := input{name: name}
	if s.With.Status != workflow.Present {
		return in
	}
	e, ok := s.With.Value.Lookup(name.String())
	if !ok {
		return in
	}
	switch e.Value.Status {
	case workflow.Present:
		v := e.Value.Value
		in.value, in.text, in.at, in.present, in.dynamic = v, v.Text(), v.Base, true, v.Parts != nil
		in.written = v
	case workflow.Dynamic:
		if x := e.Value.Expr; x != nil {
			in.text, in.at = x.Text(), x.Base
			in.written = *x
		}
		in.present, in.dynamic, in.whole = true, true, true
	}
	return in
}

// literal is the value of in, trimmed, when it is a literal.
func (in input) literal() (string, bool) {
	v, ok := in.raw()
	return strings.TrimSpace(v), ok
}

// raw is the value of in as written, when it is a literal: for the inputs
// an action does not trim.
func (in input) raw() (string, bool) {
	if !in.present || in.dynamic {
		return "", false
	}
	return in.value.AsString(), true
}

func (out *Step) inconclusive(k analysis.InconclusiveAgentKind, in input) {
	out.Inconclusive = append(out.Inconclusive, InconclusiveSetting{Kind: k, Input: in.name, Text: in.text, At: in.at})
}

func (out *Step) unsafe(l analysis.SandboxLayer, in input, value string) {
	out.UnsafeSettings = append(out.UnsafeSettings, UnsafeSetting{Layer: l, Input: in.name, Value: value, At: in.at})
}

// gate opens g when in is '*' after a trim; a value with a
// ${{ }} is a GateInput, read by event in the IR.
func (out *Step) gate(g analysis.AgentGate, in input) {
	if in.dynamic {
		if in.written.Parts == nil {
			out.inconclusive(analysis.InconclusiveAgentGate, in)
			return
		}
		out.GateInputs = append(out.GateInputs, GateInput{Gate: g, Input: in.name, Value: in.written, At: in.at})
		return
	}
	if v, ok := in.literal(); ok && v == "*" {
		out.OpenGates = append(out.OpenGates, OpenGate{Gate: g, Input: in.name, Text: in.text, At: in.at})
	}
}

// claudeGates: allowed_non_write_users works only with a github_token that
// is not empty, untrimmed (!!process.env), and a ${{ }} of it may be;
// allowed_bots needs none.
func (out *Step) claudeGates(s workflow.Step) {
	tok := inputOf(s, analysis.AgentInputGitHubToken)
	if v, _ := tok.raw(); tok.dynamic || v != "" {
		out.gate(analysis.AgentGateAnyUser, inputOf(s, analysis.AgentInputAllowedNonWriteUsers))
	}
	out.gate(analysis.AgentGateAnyBot, inputOf(s, analysis.AgentInputAllowedBots))
}

func (out *Step) codexGates(s workflow.Step) {
	out.gate(analysis.AgentGateAnyUser, inputOf(s, analysis.AgentInputAllowUsers))
}

// claudeSettings reads claude_args as the action's record of its flags:
// --dangerously-skip-permissions, the --permission-mode the
// CLI takes, and the defaultMode of --settings; and the defaultMode of the
// input settings. claude-code-action's tag mode puts --permission-mode
// acceptEdits first, and the mode is not read: a --permission-mode=v
// before a --permission-mode v wins in one mode and not the other, which
// is inconclusive when only one of them is bypassPermissions.
func (out *Step) claudeSettings(s workflow.Step, a analysis.AgentAction) {
	if in := inputOf(s, analysis.AgentInputClaudeArgs); in.dynamic {
		out.inconclusive(analysis.InconclusiveAgentSetting, in)
	} else if v, ok := in.raw(); ok {
		r := record(scan(stripComments(v), nil, nil))
		for _, f := range r {
			if f.key == "dangerously-skip-permissions" {
				out.unsafe(analysis.SandboxLayerCommands, in, "--dangerously-skip-permissions")
			}
		}
		agentMode, _ := lastValue(r, "permission-mode")
		bypass := agentMode == "bypassPermissions"
		if a == analysis.AgentActionClaudeCode {
			tagMode, _ := lastValue(record(append([]word{{text: "--permission-mode"}, {text: "acceptEdits"}}, scan(stripComments(v), nil, nil)...)), "permission-mode")
			if (tagMode == "bypassPermissions") != bypass {
				out.inconclusive(analysis.InconclusiveAgentSetting, in)
				bypass = false
			}
		}
		if bypass {
			out.unsafe(analysis.SandboxLayerCommands, in, agentMode)
		}
		if agentMode != "" {
			return // a --permission-mode overrides the defaultMode of settings
		}
		if set, ok := lastValue(r, "settings"); ok {
			out.settings(in, set)
		}
	}
	in := inputOf(s, analysis.AgentInputSettings)
	if in.dynamic {
		out.inconclusive(analysis.InconclusiveAgentSetting, in)
		return
	}
	if v, ok := in.literal(); ok && v != "" {
		out.settings(in, v)
	}
}

// settings reads v, the settings in, as JSON, or as a file's path.
func (out *Step) settings(in input, v string) {
	mode, ok := defaultMode(v)
	switch {
	case !ok:
		out.inconclusive(analysis.InconclusiveAgentSetting, in) // a file's path
	case mode == "bypassPermissions":
		out.unsafe(analysis.SandboxLayerCommands, in, mode)
	}
}

// codexSettings: safety-strategy unsafe keeps sudo; sandbox and
// permission-profile danger-full-access, and the flags of codex-args that
// bypass the sandbox, which the action refuses with a profile or a
// read-only sandbox, take the limits off. safety-strategy
// and codex-args are not trimmed.
func (out *Step) codexSettings(s workflow.Step) {
	readOnly, profile := false, false
	strategy, sandbox, perm := inputOf(s, analysis.AgentInputSafetyStrategy), inputOf(s, analysis.AgentInputSandbox), inputOf(s, analysis.AgentInputPermissionProfile)
	for _, in := range []input{strategy, sandbox, perm} {
		if in.dynamic {
			out.inconclusive(analysis.InconclusiveAgentSetting, in)
		}
	}
	if v, ok := strategy.raw(); ok {
		readOnly = readOnly || v == "read-only"
		if v == "unsafe" {
			out.unsafe(analysis.SandboxLayerPrivileges, strategy, v)
		}
	}
	// the sandbox the action passes: read-only for the strategy
	// read-only, else the profile, else the sandbox (runCodexExec.ts of
	// codex-action)
	strategyReadOnly := readOnly
	if v, ok := perm.literal(); ok && v != "" {
		profile = true
		if v == ":danger-full-access" && !strategyReadOnly {
			out.unsafe(analysis.SandboxLayerCommands, perm, v)
		}
	}
	if v, ok := sandbox.literal(); ok {
		readOnly = readOnly || v == "read-only"
		if v == "danger-full-access" && !strategyReadOnly && !profile && !perm.dynamic {
			out.unsafe(analysis.SandboxLayerCommands, sandbox, v)
		}
	}
	args := inputOf(s, analysis.AgentInputCodexArgs)
	if args.dynamic {
		out.inconclusive(analysis.InconclusiveAgentSetting, args)
		return
	}
	v, ok := args.raw()
	if !ok || profile || readOnly || strategy.dynamic || sandbox.dynamic || perm.dynamic {
		return
	}
	var ws []string
	if strings.HasPrefix(v, "[") {
		if json.Unmarshal([]byte(v), &ws) != nil {
			return // the action fails
		}
	} else {
		ws = argv(v)
	}
	for _, w := range ws {
		if w == "--dangerously-bypass-approvals-and-sandbox" || w == "--yolo" {
			out.unsafe(analysis.SandboxLayerCommands, args, w)
		}
	}
}

// claudeEvents are the events claude-code-action runs on: it checks the
// actor on those of an issue, a pull request and workflow_run, and fails
// on the others but the three no outsider triggers.
var claudeEvents = []workflow.EventName{
	workflow.EventNameIssues, workflow.EventNameIssueComment, workflow.EventNamePullRequest, workflow.EventNamePullRequestTarget,
	workflow.EventNamePullRequestReview, workflow.EventNamePullRequestReviewComment, workflow.EventNameWorkflowRun,
	workflow.EventNameWorkflowDispatch, workflow.EventNameRepositoryDispatch, workflow.EventNameSchedule,
}

// Supported are the events of evs a step of a runs on.
func Supported(a analysis.AgentAction, evs []analysis.EventActivity) []analysis.EventActivity {
	if a != analysis.AgentActionClaudeCode {
		return evs
	}
	var out []analysis.EventActivity
	for _, e := range evs {
		if slices.Contains(claudeEvents, e.Name()) {
			out = append(out, e)
		}
	}
	return out
}

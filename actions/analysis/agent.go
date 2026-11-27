package analysis

import (
	"encoding/json"
	"errors"
)

// AgentAction is an action that runs an AI agent, one that the analysis
// of agent actions (actions/agent) reads.
type AgentAction uint8

const (
	AgentActionUnset          AgentAction = iota
	AgentActionClaudeCode                 // anthropics/claude-code-action
	AgentActionClaudeCodeBase             // anthropics/claude-code-action/base-action and anthropics/claude-code-base-action, its mirror
	AgentActionCodex                      // openai/codex-action
	AgentActionGeminiCLI                  // google-github-actions/run-gemini-cli
	AgentActionAIInference                // actions/ai-inference
)

// agentActionNames are the values of $defs/agent-action of the schema of
// findings (actions/rules/schema/findings-v0.json), which the args of
// findings hold.
var agentActionNames = [...]string{"AgentActionUnset", "claude-code-action", "claude-code-base-action", "codex-action", "run-gemini-cli", "ai-inference"}

func (a AgentAction) String() string { return agentActionNames[a] }

// MarshalJSON writes a as the schema of findings names it
// (findings-v0.json, $defs/agent-action); AgentActionUnset has no name
// there.
func (a AgentAction) MarshalJSON() ([]byte, error) {
	if a == AgentActionUnset {
		return nil, errors.New("AgentActionUnset is no action")
	}
	return json.Marshal(a.String())
}

// AgentInput is an input of an agent action that the analysis of agent
// actions reads: one that opens a gate, or may take a layer off.
type AgentInput uint8

const (
	AgentInputUnset                AgentInput = iota // the whole with, when it is a ${{ }}
	AgentInputAllowedNonWriteUsers                   // claude-code-action's users without write access it lets in
	AgentInputAllowedBots                            // claude-code-action's bots it lets in
	AgentInputAllowUsers                             // codex-action's users it lets in
	AgentInputClaudeArgs                             // the flags claude-code-action and its base-action pass to the CLI
	AgentInputSettings                               // claude-code-action's and run-gemini-cli's settings: JSON, or for claude a file's path
	AgentInputSafetyStrategy                         // codex-action's privileges of the agent's process
	AgentInputSandbox                                // codex-action's sandbox
	AgentInputPermissionProfile                      // codex-action's profile of permissions
	AgentInputCodexArgs                              // the flags codex-action passes to the CLI
	AgentInputGitHubToken                            // claude-code-action's token, without which it reads no allowed_non_write_users
	AgentInputPrompt                                 // the prompt each action passes to the agent
	AgentInputSystemPrompt                           // ai-inference's system prompt, put before the prompt
	AgentInputInput                                  // ai-inference's values of the variables of a .prompt.yml
	AgentInputCopilotAllowTools                      // ai-inference's tools the Copilot CLI may use
	AgentInputTrackProgress                          // claude-code-action's track_progress, which puts it in its tag mode
	AgentInputUseCommitSigning                       // claude-code-action's commits through the API, in place of git
	AgentInputSSHSigningKey                          // claude-code-action's key of SSH signing, with which it commits through git
	AgentInputUseBedrock                             // claude-code-action's and its base-action's Amazon Bedrock, a third-party provider
	AgentInputUseVertex                              // claude-code-action's and its base-action's Google Vertex AI, a third-party provider
	AgentInputUseFoundry                             // claude-code-action's and its base-action's Microsoft Foundry, a third-party provider
	AgentInputToken                                  // ai-inference's token, which defaults to the job's
)

// agentInputNames are the inputs' names as the actions' action.yml write
// them, and the values of $defs/agent-input of the schema of findings.
var agentInputNames = [...]string{"AgentInputUnset", "allowed_non_write_users", "allowed_bots", "allow-users", "claude_args", "settings", "safety-strategy", "sandbox", "permission-profile", "codex-args", "github_token", "prompt", "system-prompt", "input", "copilot-allow-tools", "track_progress", "use_commit_signing", "ssh_signing_key", "use_bedrock", "use_vertex", "use_foundry", "token"}

func (i AgentInput) String() string { return agentInputNames[i] }

// MarshalJSON writes i as the schema of findings names it
// (findings-v0.json, $defs/agent-input); AgentInputUnset has no name
// there.
func (i AgentInput) MarshalJSON() ([]byte, error) {
	if i == AgentInputUnset {
		return nil, errors.New("AgentInputUnset is no input")
	}
	return json.Marshal(i.String())
}

// AgentGate is whom a step of an agent action lets start the agent past
// the action's own check of the actor: the action checks that the actor
// can write to the repository, unless an input opens it, and some actions
// check nothing.
type AgentGate uint8

const (
	AgentGateUnset     AgentGate = iota
	AgentGateAnyUser             // any user: allowed_non_write_users '*' with a github_token, or allow-users '*'
	AgentGateAnyBot              // any bot, whose App anyone makes: allowed_bots '*'
	AgentGateUnchecked           // anyone: the action checks no actor
)

var agentGateNames = [...]string{"AgentGateUnset", "any-user", "any-bot", "unchecked"}

func (g AgentGate) String() string { return agentGateNames[g] }

// SandboxLayer is what a setting of an agent action takes off.
type SandboxLayer uint8

const (
	SandboxLayerUnset      SandboxLayer = iota
	SandboxLayerCommands                // the limits on the commands the agent runs: its sandbox, its checks of permissions
	SandboxLayerPrivileges              // the privileges of the agent's process: it keeps sudo
)

var sandboxLayerNames = [...]string{"SandboxLayerUnset", "commands", "privileges"}

func (l SandboxLayer) String() string { return sandboxLayerNames[l] }

// AgentCapability is what a permission of a step of an agent action lets
// its agent do that an attacker who steers it can use.
type AgentCapability uint8

const (
	AgentCapabilityUnset              AgentCapability = iota
	AgentCapabilityRunsAnyCode                        // run any code it chooses
	AgentCapabilityEditsWorkspace                     // edit the files of the workspace, which a command it is allowed may run
	AgentCapabilityWritesChosenTarget                 // write with the token to a target it chooses
	AgentCapabilitySendsChosenHost                    // send to a host it chooses
)

var agentCapabilityNames = [...]string{"AgentCapabilityUnset", "runs-any-code", "edits-workspace", "writes-chosen-target", "sends-chosen-host"}

func (c AgentCapability) String() string { return agentCapabilityNames[c] }

// InconclusiveAgentKind is what of a step of an agent action the analysis
// reaches no conclusion on. Its String is the ID of the kind in the
// registry of rules (lint.InconclusiveKindID).
type InconclusiveAgentKind uint8

const (
	InconclusiveAgentGate    InconclusiveAgentKind = iota // an input that decides whom the step lets start the agent is a ${{ }}
	InconclusiveAgentSetting                              // an input that may take a layer off, or that lists or sets the agent's tools, is a ${{ }} or has one where a flag or a tool is; or settings names a file or is no JSON
	InconclusiveAgentCommand                              // a permission of a command the table of commands does not know, or of an option it does not declare
	InconclusiveAgentMCP                                  // a permission of a tool of an MCP server the step adds
)

var inconclusiveAgentKindNames = [...]string{"gate-expr", "setting-expr", "unknown-command", "custom-mcp"}

func (k InconclusiveAgentKind) String() string { return inconclusiveAgentKindNames[k] }

// AgentUser is whom the process of the agent of a step of an agent action
// runs as, which decides whether it keeps the runner's sudo.
type AgentUser uint8

const (
	AgentUserUnset       AgentUser = iota
	AgentUserRunner                // the runner's user, with its sudo
	AgentUserWithoutSudo           // the runner's user, its sudo dropped: codex-action's drop-sudo
	AgentUserOther                 // another user: codex-action's unprivileged-user
)

var agentUserNames = [...]string{"AgentUserUnset", "runner", "runner-without-sudo", "other-user"}

func (u AgentUser) String() string { return agentUserNames[u] }

// AgentGitWrite is whether the edits of the agent of a step of an agent
// action may write .git, whose hooks and config git runs.
type AgentGitWrite uint8

const (
	AgentGitWriteUnset     AgentGitWrite = iota
	AgentGitWriteNo                      // they cannot: claude's protected paths but in auto mode, codex's read-only .git
	AgentGitWriteYes                     // they may: gemini-cli's, claude's in its auto mode
	AgentGitWriteUndecided               // the sources do not say: the Copilot CLI's
)

var agentGitWriteNames = [...]string{"AgentGitWriteUnset", "no", "yes", "undecided"}

func (g AgentGitWrite) String() string { return agentGitWriteNames[g] }

// AgentAutoMode is whether the agent of a step of claude-code-action or its
// base-action starts in Claude Code's auto mode, where a classifier, not
// the permissions, decides what runs past an edit of the working
// directory.
type AgentAutoMode uint8

const (
	AgentAutoModeUnset     AgentAutoMode = iota
	AgentAutoModeOff                     // it does not: another permission mode, the built-in default, the subprocess env scrub, the tag mode's acceptEdits, another action
	AgentAutoModeOn                      // it does: a permission mode of auto, with no subprocess env scrub
	AgentAutoModeUndecided               // a ${{ }} or a settings file may set it, or a ${{ }} decides the subprocess env scrub
)

var agentAutoModeNames = [...]string{"AgentAutoModeUnset", "off", "on", "undecided"}

func (m AgentAutoMode) String() string { return agentAutoModeNames[m] }

// ClaudeStartMode is the permission mode Claude Code starts in on the runs
// of a step of claude-code-action or its base-action, as the step's YAML
// decides it.
type ClaudeStartMode uint8

const (
	ClaudeStartModeUnset  ClaudeStartMode = iota
	ClaudeStartModeAuto                   // auto: a classifier, not the permissions, decides what runs
	ClaudeStartModePlan                   // plan, where the classifier decides the shell commands
	ClaudeStartModeOther                  // a mode that runs only what the permissions allow, or bypassPermissions
	ClaudeStartModeUnread                 // an input that may set it is not read: a ${{ }} or a file, or a ${{ }} decides the subprocess env scrub
)

var claudeStartModeNames = [...]string{"ClaudeStartModeUnset", "auto", "plan", "other", "unread"}

func (m ClaudeStartMode) String() string { return claudeStartModeNames[m] }

// SubprocessScrub is whether Claude Code runs with its subprocess env
// scrub (CLAUDE_CODE_SUBPROCESS_ENV_SCRUB), which claude-code-action turns
// on with allowed_non_write_users: the CLI then starts in the default
// permission mode, whatever mode it is given.
type SubprocessScrub uint8

const (
	SubprocessScrubUnset     SubprocessScrub = iota
	SubprocessScrubOff                       // the variable is false or not set, and allowed_non_write_users is empty
	SubprocessScrubOn                        // the variable is true, or allowed_non_write_users is not empty
	SubprocessScrubUndecided                 // a ${{ }} decides it
)

var subprocessScrubNames = [...]string{"SubprocessScrubUnset", "off", "on", "undecided"}

func (s SubprocessScrub) String() string { return subprocessScrubNames[s] }

// PromptRoute is how a value of a step of an agent action reaches the
// agent as text.
type PromptRoute uint8

const (
	PromptRouteUnset       PromptRoute = iota
	PromptRouteInput                   // an input the action writes into the agent's prompt
	PromptRouteEnv                     // an env of the step, which the agent's tools read
	PromptRouteJobEnv                  // an env of the job of the step, which the agent's tools read too
	PromptRouteWorkflowEnv             // an env of the workflow of the step, which the agent's tools read too
)

var promptRouteNames = [...]string{"PromptRouteUnset", "input", "env", "job-env", "workflow-env"}

// InEnv is whether r is the route of an env, of the step, the job or the
// workflow.
func (r PromptRoute) InEnv() bool {
	return r == PromptRouteEnv || r == PromptRouteJobEnv || r == PromptRouteWorkflowEnv
}

func (r PromptRoute) String() string { return promptRouteNames[r] }

// AgentValueRoute is how a value of a step of an agent action reaches the
// agent: as text, through an input the action writes into the prompt or
// an env of the step, the job or the workflow (PromptRoute), through an
// input whose words or JSON set what the agent may do, or through an input
// of a composite action of another repository whose step runs the agent.
type AgentValueRoute uint8

const (
	AgentValueRouteUnset        AgentValueRoute = iota
	AgentValueRoutePromptInput                  // an input the action writes into the agent's prompt
	AgentValueRouteStepEnv                      // an env of the step, which the agent's tools read
	AgentValueRouteSettingInput                 // an input whose words or JSON set what the agent may do
	// an input of a composite action of another repository whose step runs
	// the agent, which the with of the step that uses the composite action
	// gives: the steps of the composite action are read without the with,
	// so the input is read as a value that reaches the agent
	AgentValueRouteCompositeInput
	AgentValueRouteJobEnv      // an env of the job of the step, which the agent's tools read too
	AgentValueRouteWorkflowEnv // an env of the workflow of the step, which the agent's tools read too
)

var agentValueRouteNames = [...]string{"AgentValueRouteUnset", "prompt-input", "step-env", "setting-input", "composite-input", "job-env", "workflow-env"}

func (r AgentValueRoute) String() string { return agentValueRouteNames[r] }

// Package agent is the analysis of the steps of actions that run an AI
// agent: which action a step uses, whom it lets start the agent past the
// action's check of the actor, and which of its settings take a layer of
// the agent's sandbox off, and which of its values reach the agent as
// text, and what its permissions let the agent do; the mode Claude Code
// starts in, whom the agent runs as and whether it may write .git, and the
// steps that may run after the agent has started. It reads the with of a
// step as the actions read their inputs, at the commit of each action that
// was read, and not by the version the step names:
// an input an older version does not have is read as the newest reads it.
//
// Where things are:
//
//	agent.go  Of: a step's action, gates and settings; Step.UnderScrub:
//	          the settings under the subprocess env scrub; Supported: the
//	          events an action runs on
//	args.go   the words of claude_args and codex-args
//	prompt.go Prompts: the values of a step that reach the agent as text
//	permissions.go the permissions of a step by the grammar of its action
//	grant.go  Grants: what the permissions let the agent do
//	mcp.go    the tools of the MCP servers claude-code-action runs
//	settings.go Settings: the values of the inputs that set the agent's tools
//	scrub.go  ScrubOf: whether Claude Code runs under its subprocess env
//	          scrub, which keeps it in the default mode
//	startmode.go StartMode, StartModeOf, AutoMode: the permission mode Claude
//	          Code starts in; ScrubDecides: whether a ${{ }} of the scrub
//	          leaves the agent's mode or edits open
//	residue.go UserOf, GitWriteOf, HeldInputs, DefaultHeldToken,
//	          WorkingDirectory: whom the agent runs as, whether its edits may
//	          write .git, what it holds, and where it works
//	later.go  LaterSteps: the steps that may run after the agent has started,
//	          or beside it, and what each holds and runs of what the agent
//	          may leave
package agent

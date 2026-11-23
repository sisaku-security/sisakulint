package agent

import (
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/prcode"
	"github.com/sisaku-security/sisakulint/actions/shell"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// CapabilityGrant is a capability a permission of a step of an agent
// action gives its agent: through the permission alone, or with an edit
// of the workspace (Partner) whose code the permitted command runs.
type CapabilityGrant struct {
	Capability analysis.AgentCapability
	Permission ToolPermission
	Partner    *ToolPermission
}

// Grants are the capabilities the permissions of s, a step of the agent
// action a that runs on evs under the subprocess env scrub sc of src
// (ScrubOf), give its agent, and the permissions whose capabilities are
// not decided. codex-action's permissions of commands are rules in files
// which are not read; its sandbox lets codex
// edit its working directory (codexGrants).
func Grants(s workflow.Step, a analysis.AgentAction, evs []analysis.EventActivity, sc analysis.SubprocessScrub, src ScrubSource) ([]CapabilityGrant, []UndecidedPermission) {
	if a == analysis.AgentActionCodex {
		return codexGrants(s), nil
	}
	if s.With.Status == workflow.Dynamic && s.With.Expr != nil {
		e := s.With.Expr
		return nil, []UndecidedPermission{{Kind: analysis.InconclusiveAgentSetting, Permission: ToolPermission{Text: e.Text(), At: TextAt{Base: e.Base}}}}
	}
	var l lists
	switch a {
	case analysis.AgentActionClaudeCode, analysis.AgentActionClaudeCodeBase:
		l = claudeLists(s, a, evs, sc, src)
	case analysis.AgentActionGeminiCLI:
		l = geminiLists(s)
	case analysis.AgentActionAIInference:
		l = copilotLists(s)
	}
	return l.grants()
}

// family is what kind of tool a permission is of.
type family uint8

const (
	familyNone   family = iota
	familyShell         // runs commands
	familyEdit          // edits files
	familyFetch         // fetches a URL
	familyMCP           // a tool of an MCP server, by Claude's name
	familyServer        // a tool of an MCP server of the Copilot CLI
)

// parsedPermission is a permission read with its action's grammar.
type parsedPermission struct {
	family  family
	tool    string   // the tool's name; for familyMCP the tool's name in its server
	words   []string // familyShell: the words that limit the command, before a *
	open    bool     // familyShell: the agent chooses what comes after the words
	any     bool     // any command, any host, any tool of the server
	unknown bool     // familyShell: a * inside the command's name
	partial bool     // familyShell: a * inside a word, which the words before it leave out
	scoped  bool     // familyEdit: a path limits it
	server  string   // familyMCP
}

var permissionRE = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_-]*)(?:\((.*)\))?$`)

func parsePermission(a analysis.AgentAction, text string) parsedPermission {
	switch a {
	case analysis.AgentActionClaudeCode, analysis.AgentActionClaudeCodeBase:
		return claudePermission(text)
	case analysis.AgentActionGeminiCLI:
		return geminiPermission(text)
	case analysis.AgentActionAIInference:
		return copilotPermission(text)
	}
	return parsedPermission{}
}

// claudePermission reads a permission of Claude Code: Bash(x) is
// exactly x; a * limits a command by the words before it, and a :* at the
// end is a * after a blank; mcp__server and mcp__server__* are all its
// tools.
func claudePermission(t string) parsedPermission {
	if t == acceptEdits {
		return parsedPermission{family: familyEdit, tool: acceptEdits}
	}
	if rest, ok := strings.CutPrefix(t, "mcp__"); ok {
		server, tool, _ := strings.Cut(rest, "__")
		return parsedPermission{family: familyMCP, server: server, tool: tool, any: tool == "" || tool == "*"}
	}
	m := permissionRE.FindStringSubmatch(t)
	if m == nil {
		return parsedPermission{}
	}
	name, spec, hasSpec := m[1], m[2], strings.HasSuffix(t, ")")
	switch name {
	case "Bash", "PowerShell", "Monitor":
		tool := name
		if name == "Monitor" {
			tool = "Bash" // it runs a command under the rules of Bash (Claude Code's tools reference)
		}
		if !hasSpec || spec == "*" {
			return parsedPermission{family: familyShell, tool: tool, any: true}
		}
		return shellPermission(tool, spec)
	case "Edit", "Write", "NotebookEdit", "MultiEdit":
		return parsedPermission{family: familyEdit, tool: name, scoped: hasSpec}
	case "WebFetch":
		return parsedPermission{family: familyFetch, tool: name, any: !hasSpec || spec == "domain:*"}
	}
	return parsedPermission{tool: name}
}

// shellPermission reads spec, a command with or without a *.
func shellPermission(tool, spec string) parsedPermission {
	i := strings.IndexByte(spec, '*')
	if i < 0 {
		return parsedPermission{family: familyShell, tool: tool, words: strings.Fields(spec)}
	}
	prefix := spec[:i]
	if i == len(spec)-1 && strings.HasSuffix(prefix, ":") {
		prefix = strings.TrimSuffix(prefix, ":") + " "
	}
	ws := strings.Fields(prefix)
	partial := len(ws) > 0 && !strings.HasSuffix(prefix, " ")
	if partial {
		ws = ws[:len(ws)-1] // a * inside a word: the word is the agent's
		if len(ws) == 0 {
			return parsedPermission{family: familyShell, tool: tool, open: true, unknown: true, partial: true}
		}
	}
	return parsedPermission{family: familyShell, tool: tool, words: ws, open: true, any: len(ws) == 0, partial: partial}
}

// geminiPermission reads a tool of gemini-cli's tools.core:
// run_shell_command(x) matches a command that begins x.
func geminiPermission(t string) parsedPermission {
	m := permissionRE.FindStringSubmatch(t)
	if m == nil {
		return parsedPermission{}
	}
	name, spec, hasSpec := m[1], m[2], strings.HasSuffix(t, ")")
	switch name {
	case "run_shell_command":
		if !hasSpec {
			return parsedPermission{family: familyShell, tool: name, any: true}
		}
		ws := strings.Fields(spec)
		return parsedPermission{family: familyShell, tool: name, words: ws, open: true, any: len(ws) == 0}
	case "write_file", "replace":
		return parsedPermission{family: familyEdit, tool: name}
	case "web_fetch":
		return parsedPermission{family: familyFetch, tool: name, any: true}
	}
	return parsedPermission{tool: name}
}

// copilotPermission reads a permission of the Copilot CLI:
// shell(x) matches the command x whatever its arguments, and shell(x:*)
// those that begin x; any other kind but write, read, url and memory is an
// MCP server.
func copilotPermission(t string) parsedPermission {
	m := permissionRE.FindStringSubmatch(t)
	if m == nil {
		return parsedPermission{}
	}
	name, spec, hasSpec := m[1], m[2], strings.HasSuffix(t, ")")
	switch name {
	case "shell":
		ws := strings.Fields(strings.TrimSuffix(spec, ":*"))
		return parsedPermission{family: familyShell, tool: name, words: ws, open: true, any: !hasSpec || len(ws) == 0}
	case "write":
		return parsedPermission{family: familyEdit, tool: name}
	case "url":
		return parsedPermission{family: familyFetch, tool: name, any: !hasSpec}
	case "read", "memory":
		return parsedPermission{tool: name}
	}
	return parsedPermission{family: familyServer, tool: name}
}

// covers is whether the deny d takes the allow r away: a deny of a tool
// covers all of it, a deny of a command with a * those that begin it, one
// without the same command. A deny that covers part of r
// leaves r, which may still allow more: one of an edit in a path, one with
// a * inside a word (read wider than it is). acceptEdits is a mode, which
// no deny of a tool takes away (it lets Write, mkdir, cp and sed run too).
func covers(d, r parsedPermission) bool {
	if d.family != r.family || d.family == familyNone || d.tool != r.tool {
		return false
	}
	switch d.family {
	case familyShell:
		if d.any {
			return true
		}
		if d.unknown || d.partial || r.any || r.unknown || len(d.words) > len(r.words) || !slices.Equal(d.words, r.words[:len(d.words)]) {
			return false
		}
		return d.open || !r.open && len(d.words) == len(r.words)
	case familyMCP:
		return d.server == r.server && (d.any || !r.any && d.tool == r.tool)
	case familyFetch:
		return d.any
	}
	return !d.scoped
}

// claudeRefuses are the commands a permission of Claude Code with a *
// does not let run what they run: exec wrappers and find's actions
// (Claude Code's permissions document).
var claudeRefuses = []string{"find", "setsid", "watch", "ionice", "flock"}

// shellCapabilities are what r, a permission of a shell command of the
// action a, lets the agent do: with a *, a command that runs another or
// reads code runs any code, and one that writes with the token or sends
// does so where the agent chooses; workspace is whether the command runs
// code of the workspace, and git whether that code is git's (hooks and
// config in .git): by the table of tools (prcode.PermissionRunsTree), and
// for git by the table of commands. false when the table of commands does
// not know the command, whose workspace is still the table of tools';
// more when, with a *, the agent may add a subcommand or an option the
// table does not declare, whose effects it does not read: one of
// a command with subcommands, or one that runs the workspace's code
// (npm install <package>, go run <module>), but git's, whose code is in
// .git.
func shellCapabilities(r parsedPermission, a analysis.AgentAction) (caps []analysis.AgentCapability, workspace, git, more, ok bool) {
	if r.any {
		return []analysis.AgentCapability{analysis.AgentCapabilityRunsAnyCode}, false, false, false, true
	}
	if r.unknown || len(r.words) == 0 {
		return nil, false, false, false, false
	}
	tree := prcode.PermissionRunsTree(r.words, r.open)
	if r.words[0] == gitPushWrapper {
		return []analysis.AgentCapability{analysis.AgentCapabilityWritesChosenTarget}, false, false, false, true
	}
	ws := make([]shell.CommandWord, len(r.words))
	for i, w := range r.words {
		ws[i] = shell.CommandWord{Text: w, Known: true}
	}
	m := shell.LookupCommand(ws)
	// a permission without a * fixes its arguments: an option the table
	// does not declare leaves the command it found; one with a * does not
	if m.Entry == nil || m.Extent == shell.MatchNone || r.open && m.Extent != shell.MatchComplete {
		return nil, tree, false, false, false
	}
	e := m.Entry
	entries := []*shell.CommandEntry{e}
	open := r.open && !((a == analysis.AgentActionClaudeCode || a == analysis.AgentActionClaudeCodeBase) && slices.ContainsFunc(e.Names, func(n string) bool { return slices.Contains(claudeRefuses, n) }))
	if open {
		if e.Has(shell.CommandTraitRunsOperand) || e.Has(shell.CommandTraitCodeArguments) || e.Has(shell.CommandTraitCodeStdin) ||
			slices.ContainsFunc(e.Options, func(o shell.CommandOption) bool {
				return o.Runs() // read as code or a program, or seen to run one (an attack spelling)
			}) {
			return []analysis.AgentCapability{analysis.AgentCapabilityRunsAnyCode}, false, false, false, true
		}
		subs := shell.Subcommands(e)
		more = len(subs) > 0
		entries = append(entries, subs...)
	}
	for _, x := range entries {
		if open && x.Has(shell.CommandTraitWritesWithToken) && !slices.Contains(caps, analysis.AgentCapabilityWritesChosenTarget) {
			caps = append(caps, analysis.AgentCapabilityWritesChosenTarget)
		}
		if open && x.Has(shell.CommandTraitSendsNetwork) && !slices.Contains(caps, analysis.AgentCapabilitySendsChosenHost) {
			caps = append(caps, analysis.AgentCapabilitySendsChosenHost)
		}
		if x.Has(shell.CommandTraitRunsGitDirectoryCode) {
			workspace, git = true, true
		}
	}
	workspace = workspace || tree
	more = more || open && workspace && !git
	// without a *, an interpreter given a file runs the workspace's code
	if !r.open && (e.Has(shell.CommandTraitCodeStdin) || e.Has(shell.CommandTraitRunsOperand)) {
		for i := 1; i < len(r.words); i++ {
			if m.Readings[i] == shell.ArgumentReadingUnset && !strings.HasPrefix(r.words[i], "-") {
				workspace = true
			}
		}
	}
	return caps, workspace, git, more, true
}

// mcp is the capability of r, a tool of an MCP server: by the table for
// github-mcp-server, which claude-code-action runs; none for its other
// servers; undecided for a server of an inline --mcp-config. A server of
// no list is not run, or is in a file, which is not read.
func (l *lists) mcp(r parsedPermission) (analysis.AgentCapability, bool) {
	if l.action == analysis.AgentActionClaudeCode && slices.Contains(actionServers, r.server) {
		if r.server == "github" && l.githubMCP && slices.ContainsFunc(githubMCPWrites, func(t string) bool {
			ok, _ := path.Match(r.tool, t)
			return r.any || ok
		}) {
			return analysis.AgentCapabilityWritesChosenTarget, false
		}
		return analysis.AgentCapabilityUnset, false
	}
	return analysis.AgentCapabilityUnset, slices.Contains(l.servers, r.server)
}

// grants are the capabilities of l's allows that no deny covers. An edit
// with a command that runs the workspace's code runs any code; on claude
// that of git's does not, as its edits cannot write .git.
func (l lists) grants() ([]CapabilityGrant, []UndecidedPermission) {
	var denied []parsedPermission
	for _, p := range l.deny {
		denied = append(denied, parsePermission(l.action, p.Text))
	}
	var out []CapabilityGrant
	grant := func(c analysis.AgentCapability, p ToolPermission) {
		out = append(out, CapabilityGrant{Capability: c, Permission: p})
	}
	type runner struct {
		p   ToolPermission
		git bool
	}
	var editors []ToolPermission
	var runners []runner
	for _, p := range l.allow {
		r := parsePermission(l.action, p.Text)
		if slices.ContainsFunc(denied, func(d parsedPermission) bool { return covers(d, r) }) {
			continue
		}
		switch r.family {
		case familyShell:
			caps, workspace, git, more, ok := shellCapabilities(r, l.action)
			if !ok || more {
				l.undecide(analysis.InconclusiveAgentCommand, p)
			}
			for _, c := range caps {
				grant(c, p)
			}
			if workspace {
				runners = append(runners, runner{p, git})
			}
		case familyEdit:
			grant(analysis.AgentCapabilityEditsWorkspace, p)
			editors = append(editors, p)
		case familyFetch:
			if r.any {
				grant(analysis.AgentCapabilitySendsChosenHost, p)
			}
		case familyMCP:
			c, undecided := l.mcp(r)
			if undecided {
				l.undecide(analysis.InconclusiveAgentMCP, p)
			}
			if c != analysis.AgentCapabilityUnset {
				grant(c, p)
			}
		case familyServer:
			l.undecide(analysis.InconclusiveAgentMCP, p)
		}
	}
	if len(editors) > 0 {
		for _, r := range runners {
			if r.git && !l.writesGit {
				continue
			}
			e := editors[0]
			out = append(out, CapabilityGrant{Capability: analysis.AgentCapabilityRunsAnyCode, Permission: r.p, Partner: &e})
		}
	}
	return out, l.undecided
}

// codexGrants: codex-action's sandbox, but read-only, lets codex edit its
// working directory, not its .git. Its
// profile wins over its sandbox, and the strategy read-only over both
// (codex-action as read on 2026-10-09). A ${{ }} of one of them is the settings'
// inconclusive (Of), not a grant.
func codexGrants(s workflow.Step) []CapabilityGrant {
	if s.With.Status == workflow.Dynamic {
		return nil
	}
	strategy, sandbox, perm := inputOf(s, analysis.AgentInputSafetyStrategy), inputOf(s, analysis.AgentInputSandbox), inputOf(s, analysis.AgentInputPermissionProfile)
	if strategy.dynamic || perm.dynamic {
		return nil
	}
	if v, _ := strategy.raw(); v == "read-only" {
		return nil
	}
	p := ToolPermission{Text: "sandbox: workspace-write", At: TextAt{Base: s.Uses.Value.Base}}
	if v, ok := perm.literal(); ok && v != "" {
		// a profile of codex-home's config is read as one that writes
		// (the undetected form codex-writable-roots of
		// ai-action-execution-order)
		if v == ":read-only" {
			return nil
		}
		p = ToolPermission{Input: perm.name, Text: perm.text, At: TextAt{Base: perm.at}}
	} else if sandbox.dynamic {
		return nil
	} else if v, ok := sandbox.literal(); ok && v != "" {
		if v == "read-only" {
			return nil
		}
		p = ToolPermission{Input: sandbox.name, Text: sandbox.text, At: TextAt{Base: sandbox.at}}
	}
	return []CapabilityGrant{{Capability: analysis.AgentCapabilityEditsWorkspace, Permission: p}}
}

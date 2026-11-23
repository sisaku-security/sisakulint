package agent

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// grantLines are the grants of s as "<capability> <permission>[ + <partner>]"
// and its undecided permissions as "<kind> <permission>".
func grantLines(t *testing.T, step string, evs ...analysis.EventActivity) (grants, undecided []string) {
	t.Helper()
	s := stepOf(t, step)
	a, ok := Of(s)
	if !ok {
		t.Fatalf("not an agent step: %s", step)
	}
	gs, us := Grants(s, a.Action, evs, analysis.SubprocessScrubOff, ScrubSource{})
	for _, g := range gs {
		l := g.Capability.String() + " " + g.Permission.Text
		if g.Partner != nil {
			l += " + " + g.Partner.Text
		}
		grants = append(grants, l)
	}
	for _, u := range us {
		undecided = append(undecided, u.Kind.String()+" "+u.Permission.Text)
	}
	return grants, undecided
}

func claudeArgs(args string) string {
	return "uses: anthropics/claude-code-action@v1\n        with:\n          prompt: p\n          claude_args: " + args
}

// TestGrants: the capabilities that each permission of each agent action
// grants, as the actions and their CLIs were read on 2026-10-11.
func TestGrants(t *testing.T) {
	labeled := ev(t, workflow.EventNameIssues, workflow.ActivityTypeLabeled)
	for _, c := range []struct {
		name, step        string
		grants, undecided []string
	}{
		{"bash", claudeArgs(`--allowedTools "Bash,Read"`), []string{"runs-any-code Bash"}, nil},
		{"a command with *", claudeArgs(`--allowedTools "Bash(gh issue edit:*)"`), []string{"writes-chosen-target Bash(gh issue edit:*)"}, nil},
		{"a command without *", claudeArgs(`--allowedTools "Bash(gh issue edit 1 --add-label x)"`), nil, nil},
		{"a group with *", claudeArgs(`--allowedTools "Bash(gh issue *)"`), []string{"writes-chosen-target Bash(gh issue *)"}, []string{"unknown-command Bash(gh issue *)"}},
		{"an interpreter with *", claudeArgs(`--allowedTools "Bash(python:*)"`), []string{"runs-any-code Bash(python:*)"}, nil},
		{"git with *", claudeArgs(`--allowedTools "Bash(git:*)"`), []string{"runs-any-code Bash(git:*)"}, nil},
		{"find, which claude does not run past a prefix", claudeArgs(`--allowedTools "Bash(find:*)"`), nil, nil},
		{"read commands", claudeArgs(`--allowedTools "Bash(cat:*),Bash(gh issue view:*)"`), nil, nil},
		{"curl with *", claudeArgs(`--allowedTools "Bash(curl:*)"`), []string{"sends-chosen-host Bash(curl:*)"}, nil},
		// an option an attacker's word was seen to run a program by
		{"tar with *", claudeArgs(`--allowedTools "Bash(tar:*)"`), []string{"runs-any-code Bash(tar:*)"}, nil},
		{"sed with *", claudeArgs(`--allowedTools "Bash(sed:*)"`), []string{"runs-any-code Bash(sed:*)"}, nil},
		{"make with *", claudeArgs(`--allowedTools "Bash(make:*)"`), []string{"runs-any-code Bash(make:*)"}, nil},
		{"git fetch with *", claudeArgs(`--allowedTools "Bash(git fetch:*)"`), []string{"runs-any-code Bash(git fetch:*)"}, nil},
		{"tar without *", claudeArgs(`--allowedTools "Bash(tar -xf a.tar)"`), nil, nil},
		{"webfetch", claudeArgs(`--allowedTools "WebFetch,WebFetch(domain:docs.python.org)"`), []string{"sends-chosen-host WebFetch"}, nil},
		{"edit and a build", claudeArgs(`--allowedTools "Edit,Bash(npm test)"`), []string{"edits-workspace Edit", "runs-any-code Bash(npm test) + Edit"}, nil},
		{"edit and git: .git is protected", claudeArgs(`--allowedTools "Edit,Bash(git commit:*)"`), []string{"edits-workspace Edit"}, nil},
		// the table of tools: a tool that runs the workspace's code, past
		// the wrappers, and one the table of commands does not know
		{"edit and npm ci", claudeArgs(`--allowedTools "Edit,Bash(npm ci)"`), []string{"edits-workspace Edit", "runs-any-code Bash(npm ci) + Edit"}, nil},
		{"edit and a script of pnpm", claudeArgs(`--allowedTools "Edit,Bash(pnpm build)"`), []string{"edits-workspace Edit", "runs-any-code Bash(pnpm build) + Edit"}, nil},
		{"edit and a script of yarn", claudeArgs(`--allowedTools "Edit,Bash(yarn build)"`), []string{"edits-workspace Edit", "runs-any-code Bash(yarn build) + Edit"}, nil},
		{"edit and timeout", claudeArgs(`--allowedTools "Edit,Bash(timeout 60 npm test)"`), []string{"edits-workspace Edit", "runs-any-code Bash(timeout 60 npm test) + Edit"}, nil},
		{"edit and env", claudeArgs(`--allowedTools "Edit,Bash(env CI=1 npm test)"`), []string{"edits-workspace Edit", "runs-any-code Bash(env CI=1 npm test) + Edit"}, nil},
		{"edit and sudo", claudeArgs(`--allowedTools "Edit,Bash(sudo npm test)"`), []string{"edits-workspace Edit", "runs-any-code Bash(sudo npm test) + Edit"}, nil},
		{"edit and composer", claudeArgs(`--allowedTools "Edit,Bash(composer install)"`), []string{"edits-workspace Edit", "runs-any-code Bash(composer install) + Edit"}, []string{"unknown-command Bash(composer install)"}},
		{"edit and npm view", claudeArgs(`--allowedTools "Edit,Bash(npm view x)"`), []string{"edits-workspace Edit"}, nil},
		{"edit and git status", claudeArgs(`--allowedTools "Edit,Bash(git status)"`), []string{"edits-workspace Edit"}, nil},
		{"unknown command", claudeArgs(`--allowedTools "Bash(./triage.sh:*)"`), nil, []string{"unknown-command Bash(./triage.sh:*)"}},
		{"deny of the tool", claudeArgs(`--allowedTools Bash --disallowedTools Bash`), nil, nil},
		{"deny of a prefix covers", claudeArgs(`--allowedTools "Bash(gh issue edit:*)" --disallowedTools "Bash(gh:*)"`), nil, nil},
		{"deny of an exact command does not cover", claudeArgs(`--allowedTools "Bash(gh issue edit:*)" --disallowedTools "Bash(gh issue edit 1)"`), []string{"writes-chosen-target Bash(gh issue edit:*)"}, nil},
		{"github mcp", claudeArgs(`--allowedTools "mcp__github__update_issue,mcp__github__get_issue"`), []string{"writes-chosen-target mcp__github__update_issue"}, nil},
		{"github mcp, all", claudeArgs(`--allowedTools mcp__github`), []string{"writes-chosen-target mcp__github"}, nil},
		{"action's own server", claudeArgs(`--allowedTools mcp__github_inline_comment__create_inline_comment`), nil, nil},
		{"inline server", claudeArgs(`--mcp-config '{"mcpServers":{"tracker":{"command":"t"}}}' --allowedTools mcp__tracker__create`), nil, []string{"custom-mcp mcp__tracker__create"}},
		{"server in a file", claudeArgs(`--mcp-config .mcp.json --allowedTools mcp__tracker__create`), nil, nil},
		{"base-action has no github server", "uses: anthropics/claude-code-action/base-action@v1\n        with:\n          prompt: p\n          claude_args: --allowedTools mcp__github__update_issue", nil, nil},
		{"gemini without tools.core", "uses: google-github-actions/run-gemini-cli@v0", []string{"runs-any-code run_shell_command", "edits-workspace write_file", "sends-chosen-host web_fetch"}, nil},
		{"gemini prefix", "uses: google-github-actions/run-gemini-cli@v0\n        with: {settings: '{\"tools\": {\"core\": [\"run_shell_command(gh issue edit)\", \"run_shell_command(gh label list)\"]}}'}", []string{"writes-chosen-target run_shell_command(gh issue edit)"}, nil},
		{"gemini edit and git", "uses: google-github-actions/run-gemini-cli@v0\n        with: {settings: '{\"tools\": {\"core\": [\"write_file\", \"run_shell_command(git commit)\"]}}'}", []string{"edits-workspace write_file", "runs-any-code run_shell_command(git commit) + write_file"}, nil},
		{"copilot", "uses: actions/ai-inference@v3\n        with: {copilot-allow-tools: 'shell(gh issue edit), url, github-mcp-server(create_issue)'}", []string{"writes-chosen-target shell(gh issue edit)", "sends-chosen-host url"}, []string{"custom-mcp github-mcp-server(create_issue)"}},
		{"codex: its sandbox edits, its rules of commands are not read", "uses: openai/codex-action@v1\n        with: {prompt: p}", []string{"edits-workspace sandbox: workspace-write"}, nil},
	} {
		g, u := grantLines(t, c.step, labeled)
		if !slices.Equal(g, c.grants) || !slices.Equal(u, c.undecided) {
			t.Errorf("%s: grants %q undecided %q", c.name, g, u)
		}
	}
}

// TestGrantsTagMode: the tag mode's push, its acceptEdits with a build the
// user allows, and github-mcp-server, which it runs only for a tool that
// begins mcp__github__.
func TestGrantsTagMode(t *testing.T) {
	comment := ev(t, workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	tag := func(args string) string {
		return "uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: " + args
	}
	for _, c := range []struct {
		name, step string
		grants     []string
	}{
		{"push", "uses: anthropics/claude-code-action@v1", []string{"writes-chosen-target Bash(" + gitPushWrapper + ":*)", "edits-workspace " + acceptEdits}},
		{"a build", tag(`--allowedTools "Bash(npm test)"`), []string{"writes-chosen-target Bash(" + gitPushWrapper + ":*)", "edits-workspace " + acceptEdits, "runs-any-code Bash(npm test) + " + acceptEdits}},
		{"bare mcp__github is dropped", tag(`--allowedTools mcp__github`), []string{"writes-chosen-target Bash(" + gitPushWrapper + ":*)", "edits-workspace " + acceptEdits}},
		{"api signing", "uses: anthropics/claude-code-action@v1\n        with: {use_commit_signing: true}", []string{"edits-workspace " + acceptEdits}},
	} {
		g, _ := grantLines(t, c.step, comment)
		if !slices.Equal(g, c.grants) {
			t.Errorf("%s: %q", c.name, g)
		}
	}
}

// TestGitHubMCPWrites: the write tools of github-mcp-server v0.17.1
// (its tools that write).
func TestGitHubMCPWrites(t *testing.T) {
	if len(githubMCPWrites) != 38 || !slices.Contains(githubMCPWrites, "update_issue") || slices.Contains(githubMCPWrites, "get_issue") {
		t.Errorf("%d tools: %v", len(githubMCPWrites), githubMCPWrites)
	}
}

// TestGrantsDenyAndInterpreters: a deny
// that covers part of an allow leaves it, a deny of a tool covers that tool
// only, a script an interpreter runs is the workspace's, and a * after a
// command whose undeclared subcommands or options may run code is not
// decided.
func TestGrantsDenyAndInterpreters(t *testing.T) {
	labeled := ev(t, workflow.EventNameIssues, workflow.ActivityTypeLabeled)
	comment := ev(t, workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	for _, c := range []struct {
		name, step        string
		on                analysis.EventActivity
		grants, undecided []string
	}{
		{"a scoped deny of Edit", claudeArgs(`--allowedTools "Edit,Bash(npm test)" --disallowedTools "Edit(.github/**)"`), labeled,
			[]string{"edits-workspace Edit", "runs-any-code Bash(npm test) + Edit"}, nil},
		{"a deny of Edit leaves acceptEdits", "uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: --allowedTools \"Bash(npm test)\" --disallowedTools Edit", comment,
			[]string{"writes-chosen-target Bash(" + gitPushWrapper + ":*)", "edits-workspace " + acceptEdits, "runs-any-code Bash(npm test) + " + acceptEdits}, nil},
		{"a deny with * inside a word covers nothing", claudeArgs(`--allowedTools "Bash(gh issue comment:*)" --disallowedTools "Bash(gh issue ed*)"`), labeled,
			[]string{"writes-chosen-target Bash(gh issue comment:*)"}, nil},
		{"a deny of PowerShell leaves Bash", claudeArgs(`--allowedTools Bash --disallowedTools PowerShell`), labeled,
			[]string{"runs-any-code Bash"}, nil},
		{"a script an interpreter runs", claudeArgs(`--allowedTools "Edit,Bash(python scripts/triage.py)"`), labeled,
			[]string{"edits-workspace Edit", "runs-any-code Bash(python scripts/triage.py) + Edit"}, nil},
		{"a toolchain with *", claudeArgs(`--allowedTools "Bash(npm install:*)"`), labeled,
			nil, []string{"unknown-command Bash(npm install:*)"}},
		{"a command of subcommands with *", claudeArgs(`--allowedTools "Bash(gh:*)"`), labeled,
			[]string{"writes-chosen-target Bash(gh:*)"}, []string{"unknown-command Bash(gh:*)"}},
		{"mcp__github in settings runs no server", "uses: anthropics/claude-code-action@v1\n        with: {prompt: p, settings: '{\"permissions\": {\"allow\": [\"mcp__github__update_issue\"]}}'}", labeled,
			nil, nil},
		{"--mcp-config with a ${{ }}", claudeArgs(`--mcp-config '${{ vars.MCP }}' --allowedTools mcp__t__x`), labeled,
			nil, []string{"setting-expr --mcp-config '${{ vars.MCP }}' --allowedTools mcp__t__x"}},
	} {
		g, u := grantLines(t, c.step, c.on)
		if !slices.Equal(g, c.grants) || !slices.Equal(u, c.undecided) {
			t.Errorf("%s: grants %q undecided %q", c.name, g, u)
		}
	}
}

// TestGrantsSplitAndMonitor: --allowedTools
// split at blanks too, as the CLI reads it; Monitor runs commands as Bash;
// an accumulating flag given again with no value drops its values, as the
// action makes it a bare flag.
func TestGrantsSplitAndMonitor(t *testing.T) {
	labeled := ev(t, workflow.EventNameIssues, workflow.ActivityTypeLabeled)
	for _, c := range []struct {
		name, step        string
		grants, undecided []string
	}{
		{"blanks", claudeArgs(`--allowedTools "Read Bash"`), []string{"runs-any-code Bash"}, nil},
		{"blanks inside a permission", claudeArgs(`--allowedTools "Read Bash(gh issue edit:*)"`), []string{"writes-chosen-target Bash(gh issue edit:*)"}, nil},
		{"monitor", claudeArgs(`--allowedTools Monitor`), []string{"runs-any-code Monitor"}, nil},
		{"a deny of Bash covers Monitor", claudeArgs(`--allowedTools Monitor --disallowedTools Bash`), nil, nil},
		{"a deny given again bare", claudeArgs(`--disallowedTools Bash --allowedTools Bash --disallowedTools`), []string{"runs-any-code Bash"}, nil},
		{"an allow given again bare", claudeArgs(`--allowedTools Bash --allowedTools`), nil, nil},
	} {
		g, u := grantLines(t, c.step, labeled)
		if !slices.Equal(g, c.grants) || !slices.Equal(u, c.undecided) {
			t.Errorf("%s: grants %q undecided %q", c.name, g, u)
		}
	}
}

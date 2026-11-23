package agent

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// stepOf is the only step of a workflow whose step is written step.
func stepOf(t *testing.T, step string) workflow.Step {
	t.Helper()
	src := "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - " + step + "\n"
	w, _ := workflow.Parse(cst.Parse([]byte(src)))
	return w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0]
}

// name is i's name; empty for the whole with or no input.
func name(i analysis.AgentInput) string {
	if i == analysis.AgentInputUnset {
		return ""
	}
	return i.String()
}

func gates(s Step) []string {
	var out []string
	for _, g := range s.OpenGates {
		out = append(out, g.Gate.String()+" "+name(g.Input))
	}
	return out
}

func settings(s Step) []string {
	var out []string
	for _, u := range s.UnsafeSettings {
		out = append(out, u.Layer.String()+" "+u.Input.String()+" "+u.Value)
	}
	return out
}

func inconclusive(s Step) []string {
	var out []string
	for _, g := range s.Inconclusive {
		out = append(out, g.Kind.String()+" "+name(g.Input))
	}
	return out
}

// TestOfAction: the six agent actions, by owner and name as GitHub
// compares them and the path of base-action; nothing else.
func TestOfAction(t *testing.T) {
	for _, c := range []struct {
		uses string
		want analysis.AgentAction
	}{
		{"anthropics/claude-code-action@v1", analysis.AgentActionClaudeCode},
		{"Anthropics/Claude-Code-Action@v1", analysis.AgentActionClaudeCode},
		{"anthropics/claude-code-action/base-action@v1", analysis.AgentActionClaudeCodeBase},
		{"anthropics/claude-code-base-action@beta", analysis.AgentActionClaudeCodeBase},
		{"openai/codex-action@v1", analysis.AgentActionCodex},
		{"google-github-actions/run-gemini-cli@v0", analysis.AgentActionGeminiCLI},
		{"actions/ai-inference@v3", analysis.AgentActionAIInference},
		{"anthropics/claude-code-action/other@v1", analysis.AgentActionUnset},
		{"openai/codex-action-malicious@v1", analysis.AgentActionUnset},
		{"github/copilot-swe-agent@v1", analysis.AgentActionUnset},
		{"./claude-code-action", analysis.AgentActionUnset},
	} {
		s, ok := Of(stepOf(t, "uses: "+c.uses))
		if ok != (c.want != analysis.AgentActionUnset) || s.Action != c.want {
			t.Errorf("%s: %v %v", c.uses, s.Action, ok)
		}
	}
	if _, ok := Of(stepOf(t, "run: claude")); ok {
		t.Error("a run is an agent action")
	}
}

func gateInputs(s Step) []string {
	var out []string
	for _, g := range s.GateInputs {
		out = append(out, g.Gate.String()+" "+name(g.Input)+" "+g.Value.Text())
	}
	return out
}

// TestOfGates: the gates as the actions read their
// inputs; a ${{ }} is read in the IR, by event.
func TestOfGates(t *testing.T) {
	for _, c := range []struct {
		name, step         string
		gates, inc, inputs []string
	}{
		{"default", "uses: anthropics/claude-code-action@v1", nil, nil, nil},
		{"any user", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*', github_token: '${{ secrets.GITHUB_TOKEN }}'}", []string{"any-user allowed_non_write_users"}, nil, nil},
		{"spaces", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: ' * ', github_token: t}", []string{"any-user allowed_non_write_users"}, nil, nil},
		{"no token", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*'}", nil, nil, nil},
		{"empty token", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*', github_token: ''}", nil, nil, nil},
		{"a list with *", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: 'alice,*', github_token: t}", nil, nil, nil},
		{"expr", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '${{ vars.USERS }}', github_token: t}", nil, nil, []string{"any-user allowed_non_write_users ${{ vars.USERS }}"}},
		{"whole expr", "uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: ${{ github.event.issue.user.login }}\n          github_token: t", nil, nil, []string{"any-user allowed_non_write_users ${{ github.event.issue.user.login }}"}},
		{"expr, no token", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '${{ github.actor }}'}", nil, nil, nil},
		{"any bot", "uses: anthropics/claude-code-action@v1\n        with: {allowed_bots: '*'}", []string{"any-bot allowed_bots"}, nil, nil},
		{"bots expr", "uses: anthropics/claude-code-action@v1\n        with: {allowed_bots: '${{ github.actor }}'}", nil, nil, []string{"any-bot allowed_bots ${{ github.actor }}"}},
		{"listed bots", "uses: anthropics/claude-code-action@v1\n        with: {allowed_bots: 'dependabot[bot]'}", nil, nil, nil},
		{"whole with", "uses: anthropics/claude-code-action@v1\n        with: ${{ fromJSON(vars.W) }}", nil, []string{"gate-expr ", "setting-expr "}, nil},
		{"codex any user", "uses: openai/codex-action@v1\n        with: {allow-users: '*'}", []string{"any-user allow-users"}, nil, nil},
		{"codex expr", "uses: openai/codex-action@v1\n        with: {allow-users: '${{ github.actor }}'}", nil, nil, []string{"any-user allow-users ${{ github.actor }}"}},
		{"codex listed", "uses: openai/codex-action@v1\n        with: {allow-users: 'alice'}", nil, nil, nil},
		{"base", "uses: anthropics/claude-code-base-action@beta", []string{"unchecked "}, nil, nil},
		{"gemini", "uses: google-github-actions/run-gemini-cli@v0", []string{"unchecked "}, nil, nil},
		{"ai-inference", "uses: actions/ai-inference@v3", []string{"unchecked "}, nil, nil},
	} {
		s, _ := Of(stepOf(t, c.step))
		if !slices.Equal(gates(s), c.gates) || !slices.Equal(inconclusive(s), c.inc) || !slices.Equal(gateInputs(s), c.inputs) {
			t.Errorf("%s: gates %q, inconclusive %q, inputs %q", c.name, gates(s), inconclusive(s), gateInputs(s))
		}
	}
	if s, _ := Of(stepOf(t, "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: ' * ', github_token: t}")); s.OpenGates[0].Text != " * " {
		t.Errorf("text %q", s.OpenGates[0].Text)
	}
}

// TestOfSettings: the settings that take a layer
// off, as the actions pass them.
func TestOfSettings(t *testing.T) {
	for _, c := range []struct {
		name, step string
		set, inc   []string
	}{
		{"skip", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--dangerously-skip-permissions --allowedTools Bash'}", []string{"commands claude_args --dangerously-skip-permissions"}, nil},
		{"mode", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--permission-mode bypassPermissions'}", []string{"commands claude_args bypassPermissions"}, nil},
		{"mode equals", "uses: anthropics/claude-code-action/base-action@v1\n        with: {claude_args: '--permission-mode=bypassPermissions'}", []string{"commands claude_args bypassPermissions"}, nil},
		{"mode overridden", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--permission-mode bypassPermissions --permission-mode default'}", nil, nil},
		{"commented", "uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: |\n            # --dangerously-skip-permissions\n            --model x", nil, nil},
		{"camel case of the upstream", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--dangerouslySkipPermissions'}", nil, nil},
		{"claude args expr", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '${{ inputs.args }}'}", nil, []string{"setting-expr claude_args"}},
		{"settings bypass", "uses: anthropics/claude-code-action@v1\n        with: {settings: '{\"permissions\": {\"defaultMode\": \"bypassPermissions\"}}'}", []string{"commands settings bypassPermissions"}, nil},
		{"settings default", "uses: anthropics/claude-code-action@v1\n        with: {settings: '{\"permissions\": {\"defaultMode\": \"acceptEdits\"}}'}", nil, nil},
		{"settings file", "uses: anthropics/claude-code-action@v1\n        with: {settings: .github/claude.json}", nil, []string{"setting-expr settings"}},
		{"codex unsafe", "uses: openai/codex-action@v1\n        with: {safety-strategy: unsafe}", []string{"privileges safety-strategy unsafe"}, nil},
		{"codex drop-sudo", "uses: openai/codex-action@v1\n        with: {safety-strategy: drop-sudo}", nil, nil},
		{"codex full access", "uses: openai/codex-action@v1\n        with: {sandbox: danger-full-access}", []string{"commands sandbox danger-full-access"}, nil},
		{"codex profile", "uses: openai/codex-action@v1\n        with: {permission-profile: ':danger-full-access'}", []string{"commands permission-profile :danger-full-access"}, nil},
		{"codex yolo", "uses: openai/codex-action@v1\n        with: {codex-args: '--yolo'}", []string{"commands codex-args --yolo"}, nil},
		{"codex bypass json", "uses: openai/codex-action@v1\n        with: {codex-args: '[\"--dangerously-bypass-approvals-and-sandbox\"]'}", []string{"commands codex-args --dangerously-bypass-approvals-and-sandbox"}, nil},
		{"codex yolo refused by a profile", "uses: openai/codex-action@v1\n        with: {codex-args: '--yolo', permission-profile: ':workspace'}", nil, nil},
		{"codex yolo refused by read-only", "uses: openai/codex-action@v1\n        with: {codex-args: '--yolo', safety-strategy: read-only}", nil, nil},
		{"codex full-auto: no such flag", "uses: openai/codex-action@v1\n        with: {codex-args: '--full-auto'}", nil, nil},
		{"codex both", "uses: openai/codex-action@v1\n        with: {safety-strategy: unsafe, sandbox: danger-full-access}", []string{"privileges safety-strategy unsafe", "commands sandbox danger-full-access"}, nil},
		{"codex expr", "uses: openai/codex-action@v1\n        with: {safety-strategy: '${{ inputs.s }}'}", nil, []string{"setting-expr safety-strategy"}},
		{"gemini: no gate and no setting", "uses: google-github-actions/run-gemini-cli@v0", nil, nil},
	} {
		s, _ := Of(stepOf(t, c.step))
		if !slices.Equal(settings(s), c.set) || !slices.Equal(inconclusive(s), c.inc) {
			t.Errorf("%s: settings %q, inconclusive %q", c.name, settings(s), inconclusive(s))
		}
	}
}

// TestSupported: claude-code-action fails on the events
// it does not handle; the others run on any.
func TestSupported(t *testing.T) {
	evs := []analysis.EventActivity{
		analysis.MustEventActivity(workflow.EventNameIssues, workflow.ActivityTypeOpened),
		analysis.MustEventActivity(workflow.EventNameDiscussion, workflow.ActivityTypeCreated),
		analysis.MustEventActivity(workflow.EventNameFork, workflow.ActivityTypeUnset),
	}
	if got := Supported(analysis.AgentActionClaudeCode, evs); len(got) != 1 || got[0].Name() != workflow.EventNameIssues {
		t.Errorf("claude: %v", got)
	}
	if got := Supported(analysis.AgentActionCodex, evs); len(got) != 3 {
		t.Errorf("codex: %v", got)
	}
}

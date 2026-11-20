package agent

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// agentOf is the agent step of a workflow whose step is written step.
func agentOf(t *testing.T, step string) Step {
	t.Helper()
	a, ok := Of(stepOf(t, step))
	if !ok {
		t.Fatalf("not an agent step: %s", step)
	}
	return a
}

// envOf is the env of a workflow written "KEY: value"; none for "".
func envOf(t *testing.T, kv string) []workflow.Field[workflow.Map[workflow.String]] {
	t.Helper()
	if kv == "" {
		return nil
	}
	w, _ := workflow.Parse(cst.Parse([]byte("on: push\nenv:\n  " + kv + "\njobs:\n  a:\n    runs-on: x\n    steps: [{run: x}]\n")))
	return []workflow.Field[workflow.Map[workflow.String]]{w.Env}
}

func TestUserOf(t *testing.T) {
	for _, c := range []struct {
		with string
		want analysis.AgentUser
	}{
		{"          prompt: p\n", analysis.AgentUserWithoutSudo},
		{"          safety-strategy: drop-sudo\n", analysis.AgentUserWithoutSudo},
		{"          safety-strategy: unprivileged-user\n", analysis.AgentUserOther},
		{"          safety-strategy: unsafe\n", analysis.AgentUserRunner},
		{"          safety-strategy: read-only\n", analysis.AgentUserRunner},
	} {
		if got := UserOf(agentOf(t, codexWith(c.with))); got != c.want {
			t.Errorf("codex %q: %s, want %s", c.with, got, c.want)
		}
	}
	if got := UserOf(agentOf(t, claudeWith("          prompt: p\n"))); got != analysis.AgentUserRunner {
		t.Errorf("claude: %s", got)
	}
}

func TestAutoMode(t *testing.T) {
	issues := []analysis.EventActivity{ev(t, workflow.EventNameIssues, workflow.ActivityTypeOpened)}
	comment := []analysis.EventActivity{ev(t, workflow.EventNameIssueComment, workflow.ActivityTypeCreated)}
	on, off, undecided := analysis.AgentAutoModeOn, analysis.AgentAutoModeOff, analysis.AgentAutoModeUndecided
	for _, c := range []struct {
		name, with, env string
		evs             []analysis.EventActivity
		want            analysis.AgentAutoMode
	}{
		{"agent mode, no mode", "          prompt: p\n", "", issues, off},
		{"default", "          prompt: p\n          claude_args: --permission-mode default\n", "", issues, off},
		{"auto", "          prompt: p\n          claude_args: --permission-mode auto\n", "", issues, on},
		{"last wins", "          prompt: p\n          claude_args: --permission-mode auto --permission-mode acceptEdits\n", "", issues, off},
		{"settings", "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", "", issues, on},
		{"settings with a ${{ }} in a hook's command", "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"auto\"},\"hooks\":{\"Stop\":[{\"hooks\":[{\"type\":\"command\",\"command\":\"${{ github.workspace }}/x.sh\"}]}]}}'\n", "", issues, on},
		{"settings with a mode of a ${{ }}", "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"${{ vars.M }}\"}}'\n", "", issues, undecided},
		{"settings a file", "          prompt: p\n          settings: .claude/ci.json\n", "", issues, undecided},
		{"args whole expr", "          prompt: p\n          claude_args: ${{ inputs.a }}\n", "", issues, undecided},
		{"an expr in another flag's value", "          prompt: p\n          claude_args: --permission-mode acceptEdits --model ${{ vars.M }}\n", "", issues, off},
		{"vertex", "          prompt: p\n          use_vertex: 'true'\n", "", issues, off},
		{"bedrock upper", "          prompt: p\n          use_bedrock: 'TRUE'\n", "", issues, off},
		{"bedrock false", "          prompt: p\n          use_bedrock: 'false'\n", "", issues, off},
		{"nonessential traffic", "          prompt: p\n", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: 1", issues, off},
		{"telemetry 0", "          prompt: p\n", "DISABLE_TELEMETRY: 0", issues, off},
		{"auto, users", "          prompt: p\n          allowed_non_write_users: '*'\n          claude_args: --permission-mode auto\n", "", issues, off},
		{"auto, users expr", "          prompt: p\n          allowed_non_write_users: ${{ vars.U }}\n          claude_args: --permission-mode auto\n", "", issues, undecided},
		{"auto, users, opted out", "          prompt: p\n          allowed_non_write_users: '*'\n          claude_args: --permission-mode auto\n", "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '0'", issues, on},
		{"tag mode", "          github_token: t\n", "", issues, off},
		{"tag mode, settings auto: acceptEdits wins", "          settings: '{\"permissions\":{\"defaultMode\":\"auto\"}}'\n", "", comment, off},
		{"tag mode, a flag of auto wins", "          claude_args: --permission-mode auto\n", "", comment, on},
	} {
		if got := AutoMode(agentOf(t, claudeWith(c.with)), c.evs, envOf(t, c.env)); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if got := AutoMode(agentOf(t, codexWith("          prompt: p\n")), issues, nil); got != off {
		t.Errorf("codex: %s", got)
	}
}

func TestGitWriteOf(t *testing.T) {
	issues := []analysis.EventActivity{ev(t, workflow.EventNameIssues, workflow.ActivityTypeOpened)}
	for _, c := range []struct {
		name, step string
		want       analysis.AgentGitWrite
	}{
		{"claude acceptEdits", claudeWith("          prompt: p\n          claude_args: --permission-mode acceptEdits\n"), analysis.AgentGitWriteNo},
		{"claude auto", claudeWith("          prompt: p\n          claude_args: --permission-mode auto\n"), analysis.AgentGitWriteYes},
		{"claude agent mode", claudeWith("          prompt: p\n"), analysis.AgentGitWriteNo},
		{"codex", codexWith("          prompt: p\n"), analysis.AgentGitWriteNo},
		{"gemini", "uses: google-github-actions/run-gemini-cli@v0\n        with: {prompt: p}", analysis.AgentGitWriteYes},
		{"copilot", "uses: actions/ai-inference@v2\n        with: {prompt: p, copilot-allow-tools: write}", analysis.AgentGitWriteUndecided},
	} {
		if got := GitWriteOf(agentOf(t, c.step), issues, nil); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestHeldInputs(t *testing.T) {
	if got := HeldInputs(agentOf(t, codexWith("          openai-api-key: ${{ secrets.K }}\n"))); len(got) != 0 {
		t.Errorf("codex: %d", len(got))
	}
	if got := HeldInputs(agentOf(t, claudeWith("          anthropic_api_key: ${{ secrets.K }}\n"))); len(got) != 1 {
		t.Errorf("claude: %d", len(got))
	}
	if !DefaultHeldToken(agentOf(t, "uses: actions/ai-inference@v2\n        with: {prompt: p}")) || DefaultHeldToken(agentOf(t, claudeWith("          prompt: p\n"))) {
		t.Error("the default token")
	}
	if DefaultHeldToken(agentOf(t, "uses: actions/ai-inference@v2\n        with: {prompt: p, token: \"${{ secrets.PAT }}\"}")) {
		t.Error("a token written: the default")
	}
}

func TestWorkingDirectory(t *testing.T) {
	for _, c := range []struct {
		step, root string
		known      bool
	}{
		{codexWith("          working-directory: ./sub/\n"), "sub", true},
		{codexWith("          working-directory: ${{ inputs.d }}\n"), "", false},
		{codexWith("          working-directory: /tmp/x\n"), "", false},
		{codexWith("          working-directory: ../x\n"), "", false},
		{codexWith("          prompt: p\n"), ".", true},
		{claudeWith("          prompt: p\n"), ".", true},
	} {
		if r, ok := WorkingDirectory(agentOf(t, c.step)); r != c.root || ok != c.known {
			t.Errorf("%q: %q %v, want %q %v", c.step, r, ok, c.root, c.known)
		}
	}
}

// TestGrantsCodex: codex's sandbox but read-only lets it edit the
// workspace; a ${{ }} of it is the settings' inconclusive, not a grant.
func TestGrantsCodex(t *testing.T) {
	for _, c := range []struct {
		with string
		want []string
	}{
		{"          prompt: p\n", []string{"edits-workspace sandbox: workspace-write"}},
		{"          sandbox: workspace-write\n", []string{"edits-workspace workspace-write"}},
		{"          permission-profile: ':workspace'\n          sandbox: read-only\n", []string{"edits-workspace :workspace"}},
		{"          sandbox: danger-full-access\n", []string{"edits-workspace danger-full-access"}},
		{"          sandbox: read-only\n", nil},
		{"          permission-profile: ':read-only'\n", nil},
		{"          safety-strategy: read-only\n", nil},
		{"          sandbox: ${{ inputs.s }}\n", nil},
		{"          permission-profile: ':workspace'\n          sandbox: ${{ inputs.s }}\n", []string{"edits-workspace :workspace"}},
	} {
		g, u := grantLines(t, codexWith(c.with))
		if !slices.Equal(g, c.want) || len(u) != 0 {
			t.Errorf("%q: %q %q, want %q", c.with, g, u, c.want)
		}
	}
}

package agent

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

func prompts(t *testing.T, step string) []string {
	t.Helper()
	s := stepOf(t, step)
	a, ok := Of(s)
	if !ok {
		t.Fatalf("not an agent action: %s", step)
	}
	var out []string
	for _, p := range Prompts(s, a.Action) {
		switch p.Route {
		case analysis.PromptRouteInput:
			out = append(out, "input "+p.Input.String())
		case analysis.PromptRouteEnv:
			out = append(out, "env "+p.Env.String())
		}
	}
	return out
}

// TestPrompts: the inputs each action writes into
// the prompt, and the env of the step but where it does not
// reach the agent's tools.
func TestPrompts(t *testing.T) {
	for _, c := range []struct {
		name, step string
		want       []string
	}{
		{"claude: not claude_args", "uses: anthropics/claude-code-action@v1\n        with: {prompt: p, claude_args: a, allowed_bots: b}\n        env: {T: t}", []string{"input prompt", "env T"}},
		{"base", "uses: anthropics/claude-code-base-action@beta\n        with: {prompt: p, prompt_file: f, claude_args: a}", []string{"input prompt"}},
		{"codex", "uses: openai/codex-action@v1\n        with: {prompt: p, prompt-file: f, codex-args: a}\n        env: {T: t}", []string{"input prompt", "env T"}},
		{"codex unprivileged-user", "uses: openai/codex-action@v1\n        with: {prompt: p, safety-strategy: unprivileged-user}\n        env: {T: t}", []string{"input prompt"}},
		{"codex drop-sudo", "uses: openai/codex-action@v1\n        with: {prompt: p, safety-strategy: drop-sudo}\n        env: {T: t}", []string{"input prompt", "env T"}},
		{"gemini", "uses: google-github-actions/run-gemini-cli@v0\n        with: {prompt: p}\n        env: {ISSUE_TITLE: t, PR_TITLE: u}", []string{"input prompt", "env ISSUE_TITLE"}},
		{"gemini: names compared upper-cased, prefixes passed", "uses: google-github-actions/run-gemini-cli@v0\n        env: {issue_title: t, GEMINI_CLI_X: u, GIT_CONFIG_Y: v, HOME: w, PR_TITLE: x}", []string{"env issue_title", "env GEMINI_CLI_X", "env GIT_CONFIG_Y", "env HOME"}},
		{"gemini: settings may allow more names", "uses: google-github-actions/run-gemini-cli@v0\n        with: {settings: '{}'}\n        env: {PR_TITLE: x}", []string{"env PR_TITLE"}},
		{"ai-inference", "uses: actions/ai-inference@v3\n        with: {prompt: p, system-prompt: s, input: 'x: y', file_input: 'z: f'}", []string{"input prompt", "input system-prompt", "input input"}},
		{"whole with", "uses: anthropics/claude-code-action@v1\n        with: ${{ fromJSON(vars.W) }}\n        env: {T: t}", []string{"env T"}},
		{"prompt expr", "uses: anthropics/claude-code-action@v1\n        with:\n          prompt: ${{ github.event.issue.title }}", []string{"input prompt"}},
	} {
		if got := prompts(t, c.step); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSettings: the inputs whose words or JSON set the agent's tools and
// sandbox, by action; none under a whole with
// that is a ${{ }}.
func TestSettings(t *testing.T) {
	for _, c := range []struct {
		step string
		want []string
	}{
		{"uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--model x', settings: '{}', prompt: p}", []string{"claude_args --model x", "settings {}"}},
		{"uses: openai/codex-action@v1\n        with: {codex-args: '--model x', prompt: p}", []string{"codex-args --model x"}},
		{"uses: google-github-actions/run-gemini-cli@v0\n        with: {settings: '{}'}", []string{"settings {}"}},
		{"uses: actions/ai-inference@v3\n        with: {copilot-allow-tools: write}", []string{"copilot-allow-tools write"}},
		{"uses: anthropics/claude-code-action@v1\n        with: ${{ fromJSON(vars.W) }}", nil},
	} {
		s := stepOf(t, c.step)
		a, _ := Of(s)
		var got []string
		for _, v := range Settings(s, a.Action) {
			got = append(got, v.Input.String()+" "+v.Value.Text())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %q", c.step, got)
		}
	}
}

package agent

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

func TestScrubOf(t *testing.T) {
	const users = "          allowed_non_write_users: \"*\"\n"
	const v = "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "
	base := func(with string) string {
		return "uses: anthropics/claude-code-action/base-action@v1\n        with:\n          prompt: p\n" + with
	}
	for _, c := range []struct {
		name, step string
		env        [3]string // workflow, job, step
		want       analysis.SubprocessScrub
	}{
		{"none", claudeWith("          prompt: p\n"), [3]string{}, analysis.SubprocessScrubOff},
		{"users", claudeWith(users), [3]string{}, analysis.SubprocessScrubOn},
		{"users blank", claudeWith("          allowed_non_write_users: \" \"\n"), [3]string{}, analysis.SubprocessScrubOn},
		{"users empty", claudeWith("          allowed_non_write_users: \"\"\n"), [3]string{}, analysis.SubprocessScrubOff},
		{"users expr", claudeWith("          allowed_non_write_users: ${{ vars.U }}\n"), [3]string{}, analysis.SubprocessScrubUndecided},
		{"opt-out job", claudeWith(users), [3]string{"", v + "'0'", ""}, analysis.SubprocessScrubOff},
		{"opt-out false", claudeWith(users), [3]string{"", "", v + "'false'"}, analysis.SubprocessScrubOff},
		{"opt-out abc", claudeWith(users), [3]string{"", "", v + "'abc'"}, analysis.SubprocessScrubOff},
		{"on yes", claudeWith("          prompt: p\n"), [3]string{v + "'yes'", "", ""}, analysis.SubprocessScrubOn},
		{"on TRUE", claudeWith("          prompt: p\n"), [3]string{"", "", v + "'TRUE'"}, analysis.SubprocessScrubOn},
		{"on spaced", claudeWith("          prompt: p\n"), [3]string{"", "", v + "' 1 '"}, analysis.SubprocessScrubOn},
		{"nearer empty", claudeWith(users), [3]string{"", v + "'0'", v + "''"}, analysis.SubprocessScrubOn},
		{"var expr", claudeWith(users), [3]string{"", "", v + "${{ vars.S }}"}, analysis.SubprocessScrubUndecided},
		{"base none", base(users), [3]string{}, analysis.SubprocessScrubOff},
		{"base on", base(""), [3]string{"", v + "'1'", ""}, analysis.SubprocessScrubOn},
		{"codex", codexWith("          prompt: p\n"), [3]string{"", "", v + "'1'"}, analysis.SubprocessScrubOff},
	} {
		got, src := ScrubOf(agentOf(t, c.step), envsOf(t, c.env[0], c.env[1], c.env[2]))
		if got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		if got == analysis.SubprocessScrubUndecided && src.Text == "" {
			t.Errorf("%s: undecided with no source", c.name)
		}
	}
}

// TestScrubOfSource: an undecided scrub names what decides it, the input
// or the variable.
func TestScrubOfSource(t *testing.T) {
	_, src := ScrubOf(agentOf(t, claudeWith("          allowed_non_write_users: ${{ vars.U }}\n")), nil)
	if src.Input != analysis.AgentInputAllowedNonWriteUsers || src.Text != "${{ vars.U }}" {
		t.Errorf("input: %+v", src)
	}
	_, src = ScrubOf(agentOf(t, claudeWith("          prompt: p\n")), envsOf(t, "", "", "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: ${{ vars.S }}"))
	if src.Input != analysis.AgentInputUnset || src.Text != "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: ${{ vars.S }}" {
		t.Errorf("variable: %+v", src)
	}
}

// TestScrubOfExprs: an env that is a
// whole ${{ }} nearer than the variable may set it, a whole with may set
// allowed_non_write_users, and a ${{ }} of one quoted literal is that
// literal.
func TestScrubOfExprs(t *testing.T) {
	read := func(job, step string) analysis.SubprocessScrub {
		t.Helper()
		src := "on: issues\njobs:\n  a:\n    runs-on: x\n" + job + "    steps:\n      - " + step + "\n"
		w, _ := workflow.Parse(cst.Parse([]byte(src)))
		j := w.Jobs.Value.Entries[0].Value.Value
		s := j.Steps.Value.Items[0]
		a, ok := Of(s)
		if !ok {
			t.Fatalf("not an agent step: %s", step)
		}
		got, src2 := ScrubOf(a, []workflow.Field[workflow.Map[workflow.String]]{w.Env, j.Env, s.Env})
		if got == analysis.SubprocessScrubUndecided && src2.Text == "" {
			t.Errorf("%s: undecided with no source", step)
		}
		return got
	}
	const users = "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*'}"
	for _, c := range []struct {
		name, job, step string
		want            analysis.SubprocessScrub
	}{
		{"step env expr", "", users + "\n        env: ${{ fromJSON(vars.E) }}", analysis.SubprocessScrubUndecided},
		{"job 0, step env expr", "    env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '0'}\n", users + "\n        env: ${{ fromJSON(vars.E) }}", analysis.SubprocessScrubUndecided},
		{"job env expr, step 1", "    env: ${{ fromJSON(vars.E) }}\n", users + "\n        env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '1'}", analysis.SubprocessScrubOn},
		{"whole with", "", "uses: anthropics/claude-code-action@v1\n        with: ${{ fromJSON(vars.W) }}", analysis.SubprocessScrubUndecided},
		{"folded 1", "", "uses: anthropics/claude-code-action@v1\n        env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: \"${{ '1' }}\"}", analysis.SubprocessScrubOn},
		{"folded empty users", "", "uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: \"${{ '' }}\"}", analysis.SubprocessScrubOff},
	} {
		if got := read(c.job, c.step); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

package rules

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestAIActionUnsafeSandbox: a finding on a run whose payload has what an
// attacker wrote, else
// reach-unknown.
func TestAIActionUnsafeSandbox(t *testing.T) {
	for _, c := range []struct {
		name, on, step string
		kinds          []string
		gaps           []string
	}{
		{"codex unsafe on issues", "issues", "uses: openai/codex-action@v1\n        with: {safety-strategy: unsafe}", []string{"ai-action-unsafe-sandbox.privileges"}, nil},
		{"codex full access on issue_comment", "issue_comment", "uses: openai/codex-action@v1\n        with: {sandbox: danger-full-access}", []string{"ai-action-unsafe-sandbox.commands"}, nil},
		{"claude skip on issues", "issues", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: --dangerously-skip-permissions}", []string{"ai-action-unsafe-sandbox.commands"}, nil},
		{"codex unsafe on schedule", "{schedule: [{cron: '0 0 * * *'}]}", "uses: openai/codex-action@v1\n        with: {safety-strategy: unsafe}", nil, []string{"reach-unknown"}},
		{"codex drop-sudo", "issues", "uses: openai/codex-action@v1\n        with: {safety-strategy: drop-sudo}", nil, nil},
		{"setting expr", "issues", "uses: openai/codex-action@v1\n        with: {sandbox: '${{ inputs.s }}'}", nil, []string{"setting-expr"}},
		{"setting expr on push: no attacker run, still not read", "push", "uses: openai/codex-action@v1\n        with: {sandbox: '${{ inputs.s }}'}", nil, []string{"setting-expr"}},
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n    runs-on: x\n    steps:\n      - " + c.step + "\n"
		rep, _, _ := checkRules(t, []lint.Rule{AIActionUnsafeSandbox}, wfFile(src), exposureFacts{})
		var kinds, gaps []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			kinds = append(kinds, f.Args.KindID().String())
		}
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			gaps = append(gaps, g.InconclusiveKind.String())
		}
		if len(kinds) != len(c.kinds) || (len(kinds) > 0 && kinds[0] != c.kinds[0]) || len(gaps) != len(c.gaps) || (len(gaps) > 0 && gaps[0] != c.gaps[0]) {
			t.Errorf("%s: %v %v", c.name, kinds, gaps)
		}
	}
}

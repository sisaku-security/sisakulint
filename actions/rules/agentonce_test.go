package rules

import (
	"fmt"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestAgentStepReportedOnce: an agent step in a ./ callee that is among the
// inputs is read in the callee's file and reached through its caller's
// call; each agent rule reports it once.
func TestAgentStepReportedOnce(t *testing.T) {
	const step = "uses: openai/codex-action@v1\n        with: {safety-strategy: unsafe, prompt: '${{ github.event.issue.body }}'}"
	for _, c := range []struct {
		name  string
		files map[string]string
	}{
		{"reusable workflow", map[string]string{
			".github/workflows/caller.yml": "on: issues\njobs:\n  call:\n    uses: ./.github/workflows/called.yml\n",
			".github/workflows/called.yml": "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - " + step + "\n",
		}},
		{"composite action", map[string]string{
			".github/workflows/caller.yml": "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./agent\n",
			"agent/action.yml":             "runs:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n      with: {safety-strategy: unsafe, prompt: '${{ github.event.issue.body }}'}\n",
		}},
	} {
		for _, r := range []lint.Rule{AIActionExcessiveTools, AIActionExecutionOrder, AIActionPromptInjection, AIActionUnrestrictedTrigger, AIActionUnsafeSandbox} {
			rep, _, _ := checkRules(t, []lint.Rule{r}, c.files, exposureFacts{})
			seen := map[string]int{}
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional, lint.CertaintyInconclusive) {
				seen[fmt.Sprintf("%s %s %d-%d", f.KindText(), f.Location.File.Input, f.Location.Span.Start, f.Location.Span.End)]++
			}
			for k, n := range seen {
				if n != 1 {
					t.Errorf("%s: %s: %s reported %d times", c.name, r.Meta().ID, k, n)
				}
			}
			if r.Meta().ID == AIActionUnsafeSandboxID && len(seen) == 0 {
				t.Errorf("%s: %s reports nothing", c.name, r.Meta().ID)
			}
		}
	}
}

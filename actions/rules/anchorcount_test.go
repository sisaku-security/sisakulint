package rules

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// fingerprintsAt are the fingerprints of the findings of the rule id in
// rep on the line line, in the order of the report.
func fingerprintsAt(rep lint.Report, id lint.RuleID, line int) []string {
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule == id && f.Location.Position().Line == line {
			out = append(out, f.Fingerprint.String())
		}
	}
	return out
}

// TestAnchorCountsEveryReference: a rule counts every reference of a text
// in a sink before it decides whether the reference gives a finding, so
// the fingerprint of a later finding does not move when an earlier
// reference of the same text stops giving one. In the step of the agent,
// ${{ env.X }} in the prompt reads the env of the step and ${{ env.X }} in
// the env of the step reads the env of the job: an X of the step that is
// fixed text leaves the reference in the prompt with no finding.
func TestAnchorCountsEveryReference(t *testing.T) {
	src := func(stepX string) string {
		return "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env:\n      X: ${{ github.event.issue.body }}\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        env:\n" + stepX + "          Y: ${{ env.X }}\n        with:\n          allowed_non_write_users: \"*\"\n          github_token: t\n          prompt: \"Read ${{ env.X }} and Y\"\n"
	}
	// the line of Y: one more where the step sets X
	withX, _ := runAdded(t, map[string]string{".github/workflows/w.yml": src("          X: fixed\n")})
	withoutX, _ := runAdded(t, map[string]string{".github/workflows/w.yml": src("")})
	a, b := fingerprintsAt(withX, AIActionPromptInjectionID, 11), fingerprintsAt(withoutX, AIActionPromptInjectionID, 10)
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Errorf("the finding of Y: %v where the prompt gives none, %v where it gives one, want one and the same", a, b)
	}
}

// TestAnchorFixSequences: the references a fix replaces and those it does
// not are counted apart, so the finding that remains after a fix keeps its
// fingerprint: output-clobbering fixes the value of NAME=value, not the
// name.
func TestAnchorFixSequences(t *testing.T) {
	src := func(value string) string {
		return "on: issue_comment\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - id: s\n        env:\n          BODY: ${{ github.event.comment.body }}\n        run: |\n          echo \"a=" + value + "\" >> \"$GITHUB_OUTPUT\"\n          echo \"${{ github.event.comment.body }}=b\" >> \"$GITHUB_OUTPUT\"\n"
	}
	before, _ := runAdded(t, map[string]string{".github/workflows/w.yml": src("${{ github.event.comment.body }}")})
	after, _ := runAdded(t, map[string]string{".github/workflows/w.yml": src("$BODY")})
	a, b := fingerprintsAt(before, OutputClobberingID, 11), fingerprintsAt(after, OutputClobberingID, 11)
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Errorf("the finding of the name: %v before the fix of the value, %v after it, want one and the same", a, b)
	}
}

package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// grantLinesUnder is grantLines with the subprocess env scrub sc of the
// source src.
func grantLinesUnder(t *testing.T, step string, sc analysis.SubprocessScrub, src ScrubSource, evs ...analysis.EventActivity) (grants, undecided []string) {
	t.Helper()
	s := stepOf(t, step)
	a, ok := Of(s)
	if !ok {
		t.Fatalf("not an agent step: %s", step)
	}
	gs, us := Grants(s, a.Action, evs, sc, src)
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

// TestGrantsUnderScrub: under the subprocess env scrub, acceptEdits lets
// the agent edit nothing (the tag mode's, of claude_args, of settings); an
// Edit it allows still edits; an undecided scrub leaves acceptEdits
// undecided.
func TestGrantsUnderScrub(t *testing.T) {
	comment := ev(t, workflow.EventNameIssueComment, workflow.ActivityTypeCreated)
	dispatch := ev(t, workflow.EventNameWorkflowDispatch, workflow.ActivityTypeUnset)
	on, off, undecided := analysis.SubprocessScrubOn, analysis.SubprocessScrubOff, analysis.SubprocessScrubUndecided
	src := ScrubSource{Input: analysis.AgentInputAllowedNonWriteUsers, Text: "${{ vars.U }}"}
	push := "writes-chosen-target Bash(" + gitPushWrapper + ":*)"
	tagBuild := "uses: anthropics/claude-code-action@v1\n        with:\n          claude_args: --allowedTools \"Bash(npm test)\""
	for _, c := range []struct {
		name, step string
		sc         analysis.SubprocessScrub
		ev         analysis.EventActivity
		grants     []string
		undecided  []string
	}{
		{"tag mode, off", "uses: anthropics/claude-code-action@v1", off, comment, []string{push, "edits-workspace " + acceptEdits}, nil},
		{"tag mode, on", "uses: anthropics/claude-code-action@v1", on, comment, []string{push}, nil},
		{"tag mode, undecided", "uses: anthropics/claude-code-action@v1", undecided, comment, []string{push}, []string{"setting-expr ${{ vars.U }}"}},
		{"tag mode build, on", tagBuild, on, comment, []string{push}, nil},
		{"settings acceptEdits, on", "uses: anthropics/claude-code-action@v1\n        with:\n          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"acceptEdits\"}}'", on, dispatch, nil, nil},
		{"flag acceptEdits and Edit, on", claudeArgs(`--permission-mode acceptEdits --allowedTools "Edit,Bash(npm test)"`), on, dispatch, []string{"edits-workspace Edit", "runs-any-code Bash(npm test) + Edit"}, nil},
	} {
		g, u := grantLinesUnder(t, c.step, c.sc, src, c.ev)
		slices.Sort(g)
		want := slices.Clone(c.grants)
		slices.Sort(want)
		if !slices.Equal(g, want) || !slices.Equal(u, c.undecided) {
			t.Errorf("%s: grants %q, undecided %q", c.name, g, u)
		}
		if c.sc != off && slices.ContainsFunc(g, func(l string) bool { return strings.Contains(l, acceptEdits) }) {
			t.Errorf("%s: acceptEdits grants under the scrub: %q", c.name, g)
		}
	}
}

// TestUnderScrub: under the subprocess env scrub, claude's bypass takes no
// layer off; an undecided scrub makes it the settings' inconclusive, at
// what decides the scrub; codex keeps its settings.
func TestUnderScrub(t *testing.T) {
	src := ScrubSource{Input: analysis.AgentInputAllowedNonWriteUsers, Text: "${{ vars.U }}"}
	for _, c := range []struct {
		name, step string
		sc         analysis.SubprocessScrub
		set, inc   []string
	}{
		{"skip, on", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--dangerously-skip-permissions'}", analysis.SubprocessScrubOn, nil, nil},
		{"mode, on", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--permission-mode bypassPermissions'}", analysis.SubprocessScrubOn, nil, nil},
		{"settings, on", "uses: anthropics/claude-code-action@v1\n        with: {settings: '{\"permissions\": {\"defaultMode\": \"bypassPermissions\"}}'}", analysis.SubprocessScrubOn, nil, nil},
		{"skip, undecided", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--dangerously-skip-permissions'}", analysis.SubprocessScrubUndecided, nil, []string{"setting-expr allowed_non_write_users"}},
		{"two, undecided", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--dangerously-skip-permissions --permission-mode bypassPermissions'}", analysis.SubprocessScrubUndecided, nil, []string{"setting-expr allowed_non_write_users"}},
		{"skip, off", "uses: anthropics/claude-code-action@v1\n        with: {claude_args: '--dangerously-skip-permissions'}", analysis.SubprocessScrubOff, []string{"commands claude_args --dangerously-skip-permissions"}, nil},
		{"codex, on", "uses: openai/codex-action@v1\n        with: {sandbox: danger-full-access}", analysis.SubprocessScrubOn, []string{"commands sandbox danger-full-access"}, nil},
	} {
		s, _ := Of(stepOf(t, c.step))
		s = s.UnderScrub(c.sc, src)
		if !slices.Equal(settings(s), c.set) || !slices.Equal(inconclusive(s), c.inc) {
			t.Errorf("%s: settings %q, inconclusive %q", c.name, settings(s), inconclusive(s))
		}
	}
}

// TestScrubDecides: a ${{ }} of the scrub leaves the agent open only where
// the step reads a mode the scrub keeps in default, or runs the tag mode's
// acceptEdits.
func TestScrubDecides(t *testing.T) {
	issues := []analysis.EventActivity{ev(t, workflow.EventNameIssues, workflow.ActivityTypeOpened)}
	comment := []analysis.EventActivity{ev(t, workflow.EventNameIssueComment, workflow.ActivityTypeCreated)}
	const users = "          allowed_non_write_users: ${{ vars.U }}\n"
	for _, c := range []struct {
		name, with string
		evs        []analysis.EventActivity
		want       bool
	}{
		{"auto", users + "          prompt: p\n          claude_args: --permission-mode auto\n", issues, true},
		{"acceptEdits", users + "          prompt: p\n          claude_args: --permission-mode acceptEdits\n", issues, true},
		{"skip", users + "          prompt: p\n          claude_args: --dangerously-skip-permissions\n", issues, true},
		{"settings bypass", users + "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"bypassPermissions\"}}'\n", issues, true},
		{"tag mode", users, comment, true},
		{"no mode", users + "          prompt: p\n          claude_args: --allowedTools Bash\n", issues, false},
		{"dontAsk", users + "          prompt: p\n          claude_args: --permission-mode dontAsk\n", issues, false},
		{"decided", "          allowed_non_write_users: '*'\n          prompt: p\n          claude_args: --permission-mode auto\n", issues, false},
	} {
		if got := ScrubDecides(agentOf(t, claudeWith(c.with)), c.evs, nil); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

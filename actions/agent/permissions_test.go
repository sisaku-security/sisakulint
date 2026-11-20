package agent

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func ev(t *testing.T, n workflow.EventName, a workflow.ActivityType) analysis.EventActivity {
	t.Helper()
	e, err := analysis.NewEventActivity(n, a)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// listLines are the allows, the denies and the undecided of l, each as
// "<input> <text>", and the spanned text of the allows as written in v.
func listLines(l lists) (allow, deny, undecided []string) {
	line := func(p ToolPermission) string { return name(p.Input) + " " + p.Text }
	for _, p := range l.allow {
		allow = append(allow, line(p))
	}
	for _, p := range l.deny {
		deny = append(deny, line(p))
	}
	for _, u := range l.undecided {
		undecided = append(undecided, u.Kind.String()+" "+line(u.Permission))
	}
	return
}

// TestClaudeLists: the lists of claude_args and of
// settings, a ${{ }} that is the value of another flag skipped, one in a
// list or where a flag may be undecided.
func TestClaudeLists(t *testing.T) {
	agentEvs := []analysis.EventActivity{ev(t, workflow.EventNameIssues, workflow.ActivityTypeLabeled)}
	for _, c := range []struct {
		name, with             string
		allow, deny, undecided []string
	}{
		{"flags", `{prompt: p, claude_args: '--model ${{ vars.M }} --allowedTools "Bash(gh issue edit:*),Read" --disallowedTools Bash(gh:*)'}`,
			[]string{"claude_args Bash(gh issue edit:*)", "claude_args Read"}, []string{"claude_args Bash(gh:*)"}, nil},
		{"settings", `{prompt: p, settings: '{"permissions": {"allow": ["Bash"], "deny": ["WebFetch"], "defaultMode": "acceptEdits"}}'}`,
			[]string{"settings Bash", "settings --permission-mode acceptEdits"}, []string{"settings WebFetch"}, nil},
		{"expr in the list", `{prompt: p, claude_args: '--allowedTools "Read,${{ vars.T }}"'}`,
			[]string{"claude_args Read"}, nil, []string{"setting-expr claude_args ${{ vars.T }}"}},
		{"expr where a flag may be", `{prompt: p, claude_args: '${{ vars.A }} --allowedTools Read'}`,
			[]string{"claude_args Read"}, nil, []string{"setting-expr claude_args ${{ vars.A }} --allowedTools Read"}},
		{"whole", `{prompt: p, claude_args: '${{ vars.A }}'}`, nil, nil, []string{"setting-expr claude_args ${{ vars.A }}"}},
		{"settings is a file", `{prompt: p, settings: .claude/s.json}`, nil, nil, []string{"setting-expr settings .claude/s.json"}},
		{"joined", `{prompt: p, claude_args: '--allowedTools=Bash,Read'}`, []string{"claude_args Bash", "claude_args Read"}, nil, nil},
	} {
		l := claudeLists(stepOf(t, "uses: anthropics/claude-code-action@v1\n        with: "+c.with), analysis.AgentActionClaudeCode, agentEvs, analysis.SubprocessScrubOff, ScrubSource{})
		allow, deny, undecided := listLines(l)
		if !slices.Equal(allow, c.allow) || !slices.Equal(deny, c.deny) || !slices.Equal(undecided, c.undecided) {
			t.Errorf("%s: allow %q deny %q undecided %q", c.name, allow, deny, undecided)
		}
	}
}

// TestClaudeTagDefaults: the tools of the tag mode on a
// step without a prompt on a comment, git's but under the API's commits,
// and acceptEdits unless claude_args sets the mode; none on a step with a
// prompt.
func TestClaudeTagDefaults(t *testing.T) {
	comment := []analysis.EventActivity{ev(t, workflow.EventNameIssueComment, workflow.ActivityTypeCreated)}
	git := []string{" Bash(git add:*)", " Bash(git commit:*)", " Bash(" + gitPushWrapper + ":*)", " Bash(git rm:*)"}
	for _, c := range []struct {
		name, with string
		allow      []string
	}{
		{"tag", `{github_token: t}`, append(slices.Clone(git), " "+acceptEdits)},
		{"agent", `{prompt: p}`, nil},
		{"prompt is an expr", `{prompt: '${{ inputs.p }}'}`, append(slices.Clone(git), " "+acceptEdits)},
		{"api signing", `{use_commit_signing: true}`, []string{" " + acceptEdits}},
		{"ssh signing", `{use_commit_signing: true, ssh_signing_key: '${{ secrets.K }}'}`, append(slices.Clone(git), " "+acceptEdits)},
		{"mode set", `{claude_args: --permission-mode default}`, git},
	} {
		l := claudeLists(stepOf(t, "uses: anthropics/claude-code-action@v1\n        with: "+c.with), analysis.AgentActionClaudeCode, comment, analysis.SubprocessScrubOff, ScrubSource{})
		allow, _, _ := listLines(l)
		if !slices.Equal(allow, c.allow) {
			t.Errorf("%s: %q", c.name, allow)
		}
	}
}

// TestClaudeModes: the modes claude-code-action runs in, by its inputs and
// the event, as its detector.ts decides them.
func TestClaudeModes(t *testing.T) {
	issues := ev(t, workflow.EventNameIssues, workflow.ActivityTypeOpened)
	pr := ev(t, workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	sched := ev(t, workflow.EventNameSchedule, workflow.ActivityTypeUnset)
	for _, c := range []struct {
		with       string
		evs        []analysis.EventActivity
		agent, tag bool
	}{
		{`{prompt: p}`, []analysis.EventActivity{issues}, true, false},
		{`{github_token: t}`, []analysis.EventActivity{issues}, false, true},
		{`{github_token: t}`, []analysis.EventActivity{pr}, false, false},
		{`{track_progress: true, prompt: p}`, []analysis.EventActivity{pr}, true, true},
		{`{prompt: p}`, []analysis.EventActivity{sched}, true, false},
		{`{prompt: 'Triage #${{ github.event.issue.number }}'}`, []analysis.EventActivity{issues}, true, false},
		{`{prompt: '  ${{ inputs.p }}  '}`, []analysis.EventActivity{issues}, true, true},
	} {
		a, g := claudeModes(stepOf(t, "uses: anthropics/claude-code-action@v1\n        with: "+c.with), c.evs)
		if a != c.agent || g != c.tag {
			t.Errorf("%s %v: agent %v tag %v", c.with, c.evs, a, g)
		}
	}
}

// TestGeminiAndCopilotLists: tools.core of run-gemini-cli's settings, every
// tool without it (and not the coreTools at the top); the
// elements of copilot-allow-tools.
func TestGeminiAndCopilotLists(t *testing.T) {
	for _, c := range []struct {
		step                   string
		allow, deny, undecided []string
	}{
		{"uses: google-github-actions/run-gemini-cli@v0\n        with: {settings: '{\"tools\": {\"core\": [\"run_shell_command(gh issue edit)\"], \"exclude\": [\"web_fetch\", \"run_shell_command(rm)\"]}}'}",
			[]string{"settings run_shell_command(gh issue edit)"}, []string{"settings web_fetch"}, nil},
		{"uses: google-github-actions/run-gemini-cli@v0\n        with: {settings: '{\"coreTools\": [\"run_shell_command(echo)\"]}'}",
			[]string{"settings run_shell_command", "settings write_file", "settings web_fetch"}, nil, nil},
		{"uses: google-github-actions/run-gemini-cli@v0",
			[]string{" run_shell_command", " write_file", " web_fetch"}, nil, nil},
		{"uses: actions/ai-inference@v3\n        with: {copilot-allow-tools: 'shell(git:*), write'}",
			[]string{"copilot-allow-tools shell(git:*)", "copilot-allow-tools write"}, nil, nil},
		{"uses: actions/ai-inference@v3",
			nil, nil, nil},
	} {
		s := stepOf(t, c.step)
		a, _ := Of(s)
		var l lists
		if a.Action == analysis.AgentActionGeminiCLI {
			l = geminiLists(s)
		} else {
			l = copilotLists(s)
		}
		allow, deny, undecided := listLines(l)
		if !slices.Equal(allow, c.allow) || !slices.Equal(deny, c.deny) || !slices.Equal(undecided, c.undecided) {
			t.Errorf("%s: allow %q deny %q undecided %q", strings.SplitN(c.step, "\n", 2)[0], allow, deny, undecided)
		}
	}
}

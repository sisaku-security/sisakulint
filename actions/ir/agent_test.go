package ir

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

const agentWF = `on:
  issues: {types: [opened, labeled]}
  issue_comment: {types: [created]}
  discussion: {types: [created]}
  schedule: [{cron: '0 0 * * *'}]
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/checkout@v4
      - uses: anthropics/claude-code-action@v1
        env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "0"}
        with: {allowed_non_write_users: '*', github_token: t, claude_args: --dangerously-skip-permissions}
      - uses: openai/codex-action@v1
        with: {allow-users: '*', safety-strategy: unsafe}
  owner:
    if: github.event_name == 'issue_comment' && github.event.comment.author_association == 'OWNER'
    runs-on: x
    steps:
      - uses: openai/codex-action@v1
        with: {allow-users: '*'}
`

func names(evs []analysis.EventActivity) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Name().String()+"."+e.ActivityType().String())
	}
	return out
}

// TestAgentStepProjection: the steps of agent actions,
// their gates and settings, the events an attacker triggers as the actor
// and those whose payload has what they wrote; claude-code-action does not
// run on discussion; the owner's comment is not the attacker's to trigger.
func TestAgentStepProjection(t *testing.T) {
	got := newIR(t, agentWF).allAgentSteps()
	if len(got) != 3 {
		t.Fatalf("%d steps", len(got))
	}
	claude, codex, owner := got[0], got[1], got[2]
	if claude.key.Path() != "jobs.a.steps[1]" || claude.action != analysis.AgentActionClaudeCode || codex.action != analysis.AgentActionCodex {
		t.Errorf("%s %v %v", claude.key.Path(), claude.action, codex.action)
	}
	if len(claude.openGates) != 1 || claude.openGates[0].Gate != analysis.AgentGateAnyUser || len(claude.unsafeSettings) != 1 || claude.unsafeSettings[0].Layer != analysis.SandboxLayerCommands {
		t.Errorf("claude: %+v %+v", claude.openGates, claude.unsafeSettings)
	}
	if want := []string{"issue_comment.created", "issues.opened"}; !slices.Equal(names(claude.actorOn), want) {
		t.Errorf("claude actor on %v", names(claude.actorOn))
	}
	if want := []string{"discussion.created", "issue_comment.created", "issues.opened"}; !slices.Equal(names(codex.actorOn), want) {
		t.Errorf("codex actor on %v", names(codex.actorOn))
	}
	if !slices.Contains(names(codex.attackerOn), "issues.labeled") {
		t.Errorf("codex attacker on %v: the label is on the attacker's issue", names(codex.attackerOn))
	}
	if len(owner.actorOn) != 0 || !slices.Equal(names(owner.attackerOn), []string{"issue_comment.created"}) {
		t.Errorf("owner: actor on %v, attacker on %v", names(owner.actorOn), names(owner.attackerOn))
	}
}

// TestAgentStepAction: a composite action's step runs on the events of
// its callers, or on any.
func TestAgentStepAction(t *testing.T) {
	src := "name: x\nruns:\n  using: composite\n  steps:\n    - uses: google-github-actions/run-gemini-cli@v0\n"
	tree, a := parseAction(t, src)
	x := New("action.yml", tree, nil, a)
	got := x.allAgentSteps()
	if len(got) != 1 || len(got[0].actorOn) == 0 || got[0].openGates[0].Gate != analysis.AgentGateUnchecked {
		t.Fatalf("%+v", got)
	}
}

// TestAgentStepCalledUnknownCallers: a workflow that can be called, whose
// callers are not all known, runs on any privileged event, as a composite
// action does.
func TestAgentStepCalledUnknownCallers(t *testing.T) {
	src := "on: workflow_call\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*', github_token: t}\n"
	got := newIR(t, src).allAgentSteps()
	if len(got) != 1 || len(got[0].actorOn) == 0 || len(got[0].attackerOn) == 0 {
		t.Fatalf("%+v", got)
	}
}

const promptWF = `on:
  issues: {types: [opened, labeled]}
  issue_comment: {types: [created]}
  schedule: [{cron: '0 0 * * *'}]
jobs:
  a:
    runs-on: x
    env:
      C: ${{ github.event.comment.body }}
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          T: ${{ github.event.issue.title }}
        with:
          prompt: "${{ github.event.issue.title }} ${{ github.event.comment.body }} ${{ env.C }} ${{ github.sha }}"
`

// TestAgentStepPromptRefs: each reference of
// the prompt and the env, the events an attacker controls it on of those
// the action runs on, and of them those a run whose actor is not the
// attacker reaches.
func TestAgentStepPromptRefs(t *testing.T) {
	got := newIR(t, promptWF).allAgentSteps()
	if len(got) != 1 {
		t.Fatalf("%d steps", len(got))
	}
	var lines []string
	for _, r := range got[0].promptRefs {
		lines = append(lines, r.Route.String()+" "+r.Ref.Text+" on "+strings.Join(names(r.On), ",")+" others "+strings.Join(names(r.OthersOn), ","))
	}
	want := []string{
		"input github.event.issue.title on issue_comment.created,issues.labeled,issues.opened others issue_comment.created,issues.labeled",
		"input github.event.comment.body on issue_comment.created others ",
		"input env.C on issue_comment.created others issue_comment.created",
		"input github.sha on  others ",
		"env github.event.issue.title on issue_comment.created,issues.labeled,issues.opened others issue_comment.created,issues.labeled",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// TestAgentStepPromptRefsAlias: a step
// shared through an alias is read in the scope of each job it is in.
func TestAgentStepPromptRefsAlias(t *testing.T) {
	src := `on: {issues: {types: [labeled]}}
jobs:
  a:
    runs-on: x
    env: {T: '${{ github.event.issue.title }}'}
    steps:
      - &s
        uses: google-github-actions/run-gemini-cli@v0
        with: {prompt: '${{ env.T }}'}
  b:
    runs-on: x
    env: {T: safe}
    steps:
      - *s
`
	got := newIR(t, src).allAgentSteps()
	if len(got) != 2 {
		t.Fatalf("%d steps", len(got))
	}
	for i, want := range []analysis.Verdict{analysis.Controlled, analysis.NotControlled} {
		if refs := got[i].promptRefs; len(refs) != 1 || refs[0].Ref.Verdict != want {
			t.Errorf("job %d: %+v", i, refs)
		}
	}
}

const toolsWF = `on:
  issues: {types: [opened, labeled]}
  schedule: [{cron: '0 0 * * *'}]
jobs:
  a:
    runs-on: x
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: p
          claude_args: --allowedTools "Edit,Bash(npm test),Bash(./x.sh)" --append-system-prompt "${{ github.event.issue.title }}"
`

// TestAgentStepTools: the grants with their partner, the undecided
// permissions, the references of the setting inputs, and the events a run
// of another's reaches the step on (labeled, not opened).
func TestAgentStepTools(t *testing.T) {
	got := newIR(t, toolsWF).allAgentSteps()
	if len(got) != 1 {
		t.Fatalf("%d steps", len(got))
	}
	s := got[0]
	var lines []string
	for _, g := range s.capabilityGrants {
		lines = append(lines, g.Capability.String()+" "+g.Permission+" + "+g.Partner)
	}
	for _, u := range s.undecidedPermissions {
		lines = append(lines, u.Kind.String()+" "+u.Permission)
	}
	for _, r := range s.settingRefs {
		lines = append(lines, r.Input.String()+" "+r.Ref.Text+" on "+strings.Join(names(r.On), ",")+" others "+strings.Join(names(r.OthersOn), ","))
	}
	lines = append(lines, "others "+strings.Join(names(s.othersOn), ","))
	want := []string{
		"edits-workspace Edit + ",
		"runs-any-code Bash(npm test) + Edit",
		"unknown-command Bash(./x.sh)",
		"claude_args github.event.issue.title on issues.labeled,issues.opened others issues.labeled",
		"others issues.labeled",
	}
	if !slices.Equal(lines, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

const gateWF = `on:
  issues: {types: [opened, labeled]}
  issue_comment: {types: [created]}
jobs:
  a:
    runs-on: x
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: t
          allowed_non_write_users: ${{ github.event.issue.user.login }}
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: t
          allowed_non_write_users: ${{ vars.USERS }}
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: t
          allowed_non_write_users: ${{ github.repository_owner }}
      - uses: anthropics/claude-code-action@v1
        with: {allowed_non_write_users: '*', github_token: t}
      - uses: anthropics/claude-code-action@v1
        with: ${{ fromJSON(vars.W) }}
`

func gateSummary(s *AgentStep) (open []string, undecided []string) {
	for _, g := range s.openGates {
		open = append(open, g.Gate.String()+" "+g.Text+" "+strings.Join(names(g.OpenOn), ","))
	}
	for _, g := range s.inconclusiveSettings {
		if g.Kind == analysis.InconclusiveAgentGate {
			undecided = append(undecided, strings.Join(names(g.UndecidedOn), ","))
		}
	}
	return open, undecided
}

// TestAgentStepGateOn: a gate's ${{ }} on each event the attacker triggers
// as the actor: the issue's author lets them in on opened and on a comment
// on their own issue, not on labeled (a maintainer's run); a variable is
// not decided; the repository's owner is closed.
func TestAgentStepGateOn(t *testing.T) {
	got := newIR(t, gateWF).allAgentSteps()
	if len(got) != 5 {
		t.Fatalf("%d steps", len(got))
	}
	both := "issue_comment.created,issues.opened"
	for i, c := range []struct{ open, undecided []string }{
		{[]string{"any-user ${{ github.event.issue.user.login }} " + both}, nil},
		{nil, []string{both}},
		{nil, nil},
		{[]string{"any-user * " + both}, nil},
		{nil, []string{both}},
	} {
		open, undecided := gateSummary(got[i])
		if !slices.Equal(open, c.open) || !slices.Equal(undecided, c.undecided) {
			t.Errorf("step %d: open %q, undecided %q", i, open, undecided)
		}
	}
}

const gateRunWF = `on:
  workflow_run: {workflows: [ci], types: [completed]}
jobs:
  a:
    runs-on: x
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: t
          allowed_non_write_users: ${{ github.actor }}
      - uses: openai/codex-action@v1
        with:
          allow-users: ${{ github.actor }}
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: t
          allowed_non_write_users: ${{ '*' }}
`

// TestAgentStepGateWorkflowRun: claude-code-action
// checks the actor of the run before workflow_run too, whom the attacker
// run does not hold; codex-action checks GITHUB_ACTOR alone.
func TestAgentStepGateWorkflowRun(t *testing.T) {
	got := newIR(t, gateRunWF).allAgentSteps()
	if len(got) != 3 {
		t.Fatalf("%d steps", len(got))
	}
	// '*' lets in the actor of the run before too
	if starOpen, _ := gateSummary(got[2]); !slices.Equal(starOpen, []string{"any-user ${{ '*' }} workflow_run.completed"}) {
		t.Errorf("claude '*': open %q", starOpen)
	}
	claudeOpen, claudeUndecided := gateSummary(got[0])
	codexOpen, codexUndecided := gateSummary(got[1])
	if claudeOpen != nil || !slices.Equal(claudeUndecided, []string{"workflow_run.completed"}) {
		t.Errorf("claude: open %q, undecided %q", claudeOpen, claudeUndecided)
	}
	if !slices.Equal(codexOpen, []string{"any-user ${{ github.actor }} workflow_run.completed"}) || codexUndecided != nil {
		t.Errorf("codex: open %q, undecided %q", codexOpen, codexUndecided)
	}
}

const orderWF = `on:
  issues: {types: [opened]}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: openai/codex-action@v1
        with: {sandbox: danger-full-access}
      - run: npm test
        env: {NPM: "${{ secrets.NPM }}"}
`

// TestAgentStepLater: the agent's user, the runner's sudo, .git, the auto
// mode and the steps after it, with what they hold and run.
func TestAgentStepLater(t *testing.T) {
	got := newIR(t, orderWF).allAgentSteps()
	if len(got) != 1 {
		t.Fatalf("%d steps", len(got))
	}
	s := got[0]
	if s.agentUser != analysis.AgentUserWithoutSudo || !s.runnerSudo || s.gitWrite != analysis.AgentGitWriteNo || s.autoMode != analysis.AgentAutoModeOff {
		t.Errorf("%s %v %s %s", s.agentUser, s.runnerSudo, s.gitWrite, s.autoMode)
	}
	if len(s.laterSteps) != 1 {
		t.Fatalf("%+v", s.laterSteps)
	}
	l := s.laterSteps[0]
	if !slices.Equal(l.Secrets, []string{"NPM"}) || len(l.CodeRuns) != 1 || l.CodeRuns[0].Text != "npm test" || !slices.Equal(names(l.On), []string{"issues.opened"}) {
		t.Errorf("%+v", l)
	}
}

// TestAgentStepLaterAction: a step in an action metadata file knows no
// runner, so no sudo, and reads its later steps.
func TestAgentStepLaterAction(t *testing.T) {
	src := "name: x\nruns:\n  using: composite\n  steps:\n    - uses: anthropics/claude-code-action@v1\n      with: {prompt: p, claude_args: --allowedTools Bash}\n    - run: npm test\n      shell: bash\n"
	tree, a := parseAction(t, src)
	got := New("action.yml", tree, nil, a).allAgentSteps()
	if len(got) != 1 || got[0].runnerSudo || len(got[0].laterSteps) != 1 || len(got[0].laterSteps[0].CodeRuns) != 1 {
		t.Errorf("%+v", got)
	}
}

// TestAgentStepStartModes: the env of the job decides whether the
// subprocess env scrub keeps claude in the default mode; codex starts in
// none.
func TestAgentStepStartModes(t *testing.T) {
	got := newIR(t, `on:
  issues: {types: [opened]}
jobs:
  a:
    runs-on: x
    env:
      CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "0"
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: p, allowed_non_write_users: "*", claude_args: --permission-mode auto}
      - uses: openai/codex-action@v1
        with: {prompt: p}
  b:
    runs-on: x
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {prompt: p, allowed_non_write_users: "*", claude_args: --permission-mode auto}
`).allAgentSteps()
	if len(got) != 3 || len(got[0].startModes) != 1 || len(got[1].startModes) != 0 || len(got[2].startModes) != 1 {
		t.Fatalf("%d steps", len(got))
	}
	m := got[0].startModes[0]
	if m.Mode != analysis.ClaudeStartModeAuto || m.Source != "--permission-mode auto" || !slices.Equal(names(m.On), []string{"issues.opened"}) {
		t.Errorf("start mode: %+v", m)
	}
	if got[0].autoMode != analysis.AgentAutoModeOn {
		t.Errorf("auto mode: %s", got[0].autoMode)
	}
	if m := got[2].startModes[0]; m.Mode != analysis.ClaudeStartModeOther || got[2].autoMode != analysis.AgentAutoModeOff {
		t.Errorf("under the scrub: %+v %s", m, got[2].autoMode)
	}
}

// TestAgentStepUnderScrub: allowed_non_write_users turns the subprocess
// env scrub on, under which the tag mode's acceptEdits edits nothing and
// a bypass takes no layer off; a job's env that turns it off brings both
// back.
func TestAgentStepUnderScrub(t *testing.T) {
	src := func(env string) string {
		return `on:
  issue_comment: {types: [created]}
jobs:
  a:
    runs-on: x
` + env + `    steps:
      - uses: anthropics/claude-code-action@v1
        with: {github_token: t, allowed_non_write_users: "*", claude_args: --dangerously-skip-permissions}
`
	}
	edits := func(s *AgentStep) bool {
		return slices.ContainsFunc(s.capabilityGrants, func(g CapabilityGrant) bool { return g.Capability == analysis.AgentCapabilityEditsWorkspace })
	}
	got := newIR(t, src("")).allAgentSteps()
	if len(got) != 1 || len(got[0].unsafeSettings) != 0 {
		t.Fatalf("under the scrub: %d steps, %+v", len(got), got)
	}
	got = newIR(t, src("    env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: \"0\"}\n")).allAgentSteps()
	if len(got) != 1 || len(got[0].unsafeSettings) != 1 {
		t.Fatalf("opted out: %+v", got)
	}
	tag := `on:
  issue_comment: {types: [created]}
jobs:
  a:
    runs-on: x
    steps:
      - uses: anthropics/claude-code-action@v1
        with: {github_token: t, allowed_non_write_users: "*"}
`
	if got := newIR(t, tag).allAgentSteps(); len(got) != 1 || edits(got[0]) {
		t.Errorf("tag mode under the scrub edits: %+v", got)
	}
	opted := strings.Replace(tag, "    runs-on: x\n", "    runs-on: x\n    env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: \"0\"}\n", 1)
	if got := newIR(t, opted).allAgentSteps(); len(got) != 1 || !edits(got[0]) {
		t.Errorf("tag mode opted out edits nothing: %+v", got)
	}
}

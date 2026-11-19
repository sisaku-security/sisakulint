package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

type orderCase struct {
	name, src string
	kinds     []string // the kinds of the findings and the inconclusive, sorted
}

func checkOrder(t *testing.T, c orderCase) {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{AIActionExecutionOrder}, wfFile(c.src), exposureFacts{})
	var kinds []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		kinds = append(kinds, strings.TrimPrefix(f.Args.KindID().String(), "ai-action-execution-order."))
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		kinds = append(kinds, g.InconclusiveKind.String())
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, c.kinds) {
		t.Errorf("%s: got %q, want %q", c.name, kinds, c.kinds)
	}
}

// orderWF is a workflow on on whose job runs on runsOn a checkout, the
// agent step uses with with (a flow mapping), and then the steps later.
func orderWF(on, runsOn, uses, with, later string) string {
	return "on: " + on + "\njobs:\n  a:\n    runs-on: " + runsOn + "\n    steps:\n      - uses: actions/checkout@v4\n      - uses: " + uses + "\n        with: " + with + "\n" + later
}

const (
	opened     = "{issues: {types: [opened]}}"
	secretStep = "      - run: deploy\n        env: {K: \"${{ secrets.K }}\"}\n"
	testStep   = "      - run: npm test\n"
	gitStep    = "      - run: git commit -m x\n"
	claudeOpen = `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --allowedTools Bash}`
)

// scrubExpr is src whose claude-code-action step's subprocess env scrub a
// ${{ }} decides.
func scrubExpr(src string) string {
	return strings.Replace(src, "anthropics/claude-code-action@v1\n", "anthropics/claude-code-action@v1\n        env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '${{ vars.S }}'}\n", 1)
}

// optedOut is src whose claude-code-action step turns the subprocess env
// scrub off.
func optedOut(src string) string {
	return strings.Replace(src, "anthropics/claude-code-action@v1\n", "anthropics/claude-code-action@v1\n        env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '0'}\n", 1)
}

// TestAIActionExecutionOrder: the kinds by the agent's capability, user
// and runner, and by the
// steps after it.
func TestAIActionExecutionOrder(t *testing.T) {
	for _, c := range []orderCase{
		{"codex any code, a later secret", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*", sandbox: danger-full-access}`, secretStep), []string{"later-secrets"}},
		{"codex any code, the job's env only", "on: " + opened + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n    env: {K: \"${{ secrets.K }}\"}\n    steps:\n      - uses: openai/codex-action@v1\n        with: {allow-users: \"*\", sandbox: danger-full-access}\n      - run: deploy\n        env: {K: \"${{ secrets.K }}\"}\n", nil},
		{"claude Bash with sudo", orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", claudeOpen, secretStep), nil},
		{"claude Bash self-hosted", orderWF(opened, "self-hosted", "anthropics/claude-code-action@v1", claudeOpen, secretStep), []string{"later-secrets"}},
		{"codex edit, later npm test", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*"}`, testStep), []string{"edited-code"}},
		{"codex edit, a checkout then npm test", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*"}`, "      - uses: actions/checkout@v4\n"+testStep), nil},
		{"codex edit, later git only", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*"}`, gitStep), nil},
		{"gemini edit, later git", orderWF(opened, "ubuntu-latest", "google-github-actions/run-gemini-cli@v0", `{settings: '{"tools":{"core":["write_file"]}}'}`, gitStep), []string{"edited-code"}},
		{"copilot edit, later git", orderWF(opened, "ubuntu-latest", "actions/ai-inference@v2", `{prompt: p, copilot-allow-tools: write}`, gitStep), []string{"copilot-git"}},
		{"copilot edit, later npm test", orderWF(opened, "ubuntu-latest", "actions/ai-inference@v2", `{prompt: p, copilot-allow-tools: write}`, testStep+gitStep), []string{"edited-code"}},
		{"unprivileged", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*", sandbox: danger-full-access, safety-strategy: unprivileged-user}`, secretStep), []string{"unprivileged-user"}},
		{"the agent last", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*"}`, ""), nil},
		{"a later step on push only", orderWF("{issues: {types: [opened]}, push: {}}", "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*", sandbox: danger-full-access}`, "      - if: github.event_name == 'push'\n        run: deploy\n        env: {K: \"${{ secrets.K }}\"}\n"), nil},
		{"a closed gate, opened only", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", "{prompt: p}", testStep), []string{"reach-unknown"}},
		{"a gate of a ${{ }}", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", "{allow-users: '${{ vars.U }}'}", testStep), []string{"gate-expr"}},
		{"a sandbox of a ${{ }}", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*", sandbox: "${{ inputs.s }}"}`, testStep), []string{"setting-expr"}},
		{"the agent mode with no mode", orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p}`, testStep), nil},
		{"a mode of a ${{ }}", optedOut(orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: "--permission-mode ${{ vars.M }}"}`, testStep)), []string{"setting-expr"}},
		{"auto mode, a later secret off GitHub-hosted runners", optedOut(orderWF(opened, "self-hosted", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --permission-mode auto}`, secretStep)), []string{"later-secrets"}},
		{"auto mode under the scrub", orderWF(opened, "self-hosted", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --permission-mode auto}`, secretStep), nil},
		{"acceptEdits, later npm test", optedOut(orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --permission-mode acceptEdits}`, testStep)), []string{"edited-code"}},
		{"acceptEdits under the scrub", orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --permission-mode acceptEdits}`, testStep), nil},
		// a ${{ }} decides the scrub
		{"bypass, a scrub of a ${{ }}", scrubExpr(orderWF(opened, "self-hosted", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --dangerously-skip-permissions}`, secretStep)), []string{"setting-expr"}},
		{"acceptEdits, a scrub of a ${{ }}", scrubExpr(orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --permission-mode acceptEdits}`, testStep)), []string{"setting-expr"}},
		{"Bash only, a scrub of a ${{ }}", scrubExpr(orderWF(opened, "self-hosted", "anthropics/claude-code-action@v1", claudeOpen, secretStep)), []string{"later-secrets"}},
		{"schedule only", orderWF("{schedule: [{cron: '0 0 * * *'}]}", "ubuntu-latest", "openai/codex-action@v1", "{prompt: p}", testStep), []string{"reach-unknown"}},
		{"agent mode with Edit, later git only", orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --allowedTools Edit}`, gitStep), nil},
		{"agent mode with Edit, later npm test", orderWF(opened, "ubuntu-latest", "anthropics/claude-code-action@v1", `{github_token: t, allowed_non_write_users: "*", prompt: p, claude_args: --allowedTools Edit}`, testStep), []string{"edited-code"}},
		{"ai-inference with its own token, a later step with the job's", strings.Replace(orderWF(opened, "self-hosted", "actions/ai-inference@v2", `{prompt: p, copilot-allow-tools: shell, token: "${{ secrets.MODELS_PAT }}"}`, "      - run: gh issue list\n        env: {GH_TOKEN: \"${{ github.token }}\"}\n"), "      - uses: actions/checkout@v4\n", "", 1), []string{"later-secrets"}},
		{"ai-inference with the default token", strings.Replace(orderWF(opened, "self-hosted", "actions/ai-inference@v2", `{prompt: p, copilot-allow-tools: shell}`, "      - run: gh issue list\n        env: {GH_TOKEN: \"${{ github.token }}\"}\n"), "      - uses: actions/checkout@v4\n", "", 1), nil},
		{"a gate of a ${{ }}, the later step on push only", orderWF("{issues: {types: [opened]}, push: {}}", "ubuntu-latest", "openai/codex-action@v1", "{allow-users: '${{ vars.U }}'}", "      - if: github.event_name == 'push'\n        run: npm test\n"), nil},
		{"a profile over a sandbox of a ${{ }}", orderWF(opened, "ubuntu-latest", "openai/codex-action@v1", `{allow-users: "*", permission-profile: ":workspace", sandbox: "${{ vars.S }}"}`, testStep), []string{"edited-code"}},
	} {
		checkOrder(t, c)
	}
}

// TestAIActionExecutionOrderUpstream: sisakulint's examples (17c2d82151a966e6e388a17619b060ae2919712e,
// script/actions/ai-action-execution-order-{vulnerable,safe}.yaml). The
// vulnerable one runs on push, which no attacker triggers, and npm publish
// is not in the table of the workspace's code: nothing. The safe one has no
// step after the agent.
func TestAIActionExecutionOrderUpstream(t *testing.T) {
	vulnerable := `name: Vulnerable AI Execution Order

on:
  push:

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: openai/codex-action@v1
        with:
          safety-strategy: drop-sudo
      - run: npm publish
`
	safe := `name: Safe AI Execution Order

on:
  push:

jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: openai/codex-action@v1
        with:
          safety-strategy: drop-sudo
`
	checkOrder(t, orderCase{"upstream vulnerable", vulnerable, nil})
	checkOrder(t, orderCase{"upstream safe", safe, nil})
}

// TestAIActionExecutionOrderCondition: the condition is that of the runs
// that reach the later steps counted, not of the step's runs: the later
// step runs only on issues, which only a bot
// reaches, past allowed_bots.
func TestAIActionExecutionOrderCondition(t *testing.T) {
	src := orderWF("{issues: {types: [opened]}, issue_comment: {types: [created]}}", "ubuntu-latest", "anthropics/claude-code-action@v1", `{allowed_bots: "*", prompt: p, claude_args: --allowedTools Edit}`, "      - if: github.event_name == 'issues'\n        run: npm test\n")
	rep, _, _ := checkRules(t, []lint.Rule{AIActionExecutionOrder}, wfFile(src), exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Condition == nil {
		t.Errorf("want one finding on repo.public: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

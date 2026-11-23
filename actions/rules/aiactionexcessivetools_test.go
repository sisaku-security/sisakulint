package rules

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

type toolsCase struct {
	name, src string
	kinds     []string // sorted
	cond      bool     // a finding holds on repo.public
	gaps      []string // sorted
}

func checkTools(t *testing.T, c toolsCase) {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{AIActionExcessiveTools}, wfFile(c.src), exposureFacts{})
	var kinds, gaps []string
	cond := false
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		kinds = append(kinds, f.Args.KindID().String())
		cond = cond || f.Certainty != lint.CertaintyConfirmed
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		gaps = append(gaps, g.InconclusiveKind.String())
	}
	slices.Sort(kinds)
	slices.Sort(gaps)
	if !slices.Equal(kinds, c.kinds) || !slices.Equal(gaps, c.gaps) || cond != c.cond {
		t.Errorf("%s: kinds %v, conditional %v, inconclusive %v", c.name, kinds, cond, gaps)
	}
}

const (
	toolsJobs  = "jobs:\n  a:\n    runs-on: x\n    steps:\n"
	claudeBash = "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: \"Triage #${{ github.event.issue.number }}\"\n          claude_args: --allowedTools Bash\n"
)

// TestAIActionExcessiveTools: the kinds of ai-action-excessive-tools by
// the gate, the event and the tools each agent action allows.
func TestAIActionExcessiveTools(t *testing.T) {
	for _, c := range []toolsCase{
		{"gate closed, opened only", "on: {issues: {types: [opened]}}\n" + toolsJobs + claudeBash, nil, false, []string{"reach-unknown"}},
		{"gate closed, labeled", "on: {issues: {types: [opened, labeled]}}\n" + toolsJobs + claudeBash, []string{"ai-action-excessive-tools.run-code"}, false, nil},
		{"gate open", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: '*'\n          prompt: p\n          claude_args: --allowedTools Bash\n", []string{"ai-action-excessive-tools.run-code"}, false, nil},
		{"any bot: on repo.public", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: '*'\n          prompt: p\n          claude_args: --allowedTools Bash\n", []string{"ai-action-excessive-tools.run-code"}, true, nil},
		{"gate expr", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ vars.U }}\n          prompt: p\n          claude_args: --allowedTools Bash\n", nil, false, []string{"gate-expr"}},
		{"schedule only", "on: {schedule: [{cron: '0 0 * * *'}]}\n" + toolsJobs + claudeBash, nil, false, []string{"reach-unknown"}},
		{"unchecked gemini", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: p\n", []string{"ai-action-excessive-tools.run-code", "ai-action-excessive-tools.send-network"}, false, nil},
		{"tag mode push", "on: {issue_comment: {types: [created]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n", []string{"ai-action-excessive-tools.write-token"}, false, nil},
		{"setting value", "on: {issues: {types: [labeled]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: p\n          claude_args: --append-system-prompt \"${{ github.event.issue.title }}\"\n", []string{"ai-action-excessive-tools.setting-value"}, false, nil},
		{"setting value, gate closed, opened only", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: p\n          claude_args: --append-system-prompt \"${{ github.event.issue.title }}\"\n", nil, false, nil},
		{"setting value, whole: no setting-expr", "on: {issues: {types: [labeled]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: p\n          claude_args: ${{ github.event.issue.title }}\n", []string{"ai-action-excessive-tools.setting-value"}, false, nil},
		{"unknown command", "on: {issues: {types: [labeled]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: p\n          claude_args: --allowedTools \"Bash(./triage.sh:*)\"\n", nil, false, []string{"unknown-command"}},
		{"a value not analyzed in a setting", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - id: s\n        run: echo\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: p\n          settings: '{\"tools\": {\"core\": [\"read_file\"]}, \"model\": {\"name\": \"${{ steps.s.outputs.t }}\"}}'\n", nil, false, []string{"setting-expr"}},
		{"codex", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n          prompt: p\n          codex-args: --model \"${{ github.event.issue.title }}\"\n", []string{"ai-action-excessive-tools.setting-value"}, false, nil},
		{"the author's login, labeled too: opened only past the gate", "on: {issues: {types: [opened, labeled]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event.issue.user.login }}\n          prompt: p\n          claude_args: --allowedTools Bash\n", []string{"ai-action-excessive-tools.run-code"}, false, nil},
		{"open on issues only, a setting value of a comment", "on: {issues: {types: [opened]}, issue_comment: {types: [created]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event_name == 'issues' && '*' || 'nobody' }}\n          prompt: p\n          claude_args: --append-system-prompt \"${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"undecided on issues only, a setting value of a comment", "on: {issues: {types: [opened]}, issue_comment: {types: [created]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event_name == 'issues' && vars.USERS || '' }}\n          prompt: p\n          claude_args: --append-system-prompt \"${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"any bot on issues only, a setting value of a comment", "on: {issues: {types: [opened]}, issue_comment: {types: [created]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: ${{ github.event_name == 'issues' && '*' || '' }}\n          prompt: p\n          claude_args: --append-system-prompt \"${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"the repository's owner, opened only", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.repository_owner }}\n          prompt: p\n          claude_args: --allowedTools Bash\n", nil, false, []string{"reach-unknown"}},
	} {
		checkTools(t, c)
	}
}

// TestAIActionExcessiveToolsIncidents: the workflows of the incidents the
// Meta cites, cut to their trigger and the step.
//   - cline/cline 7bdbf0a9a745f6abc09483fe9b08874c80fb44f3
//     .github/workflows/claude-issue-triage.yml:3-5,44-55 (Clinejection)
//   - google-gemini/gemini-cli 6390b81646e324bfbb86ccd73247f5d3e2a423f8
//     .github/workflows/gemini-automated-issue-triage.yml:3-16,35-43,57-90
//     (PromptPwnd)
//   - MIC-DKFZ/nnUNet 94300b49e716fae38fe4c9d0ec9e935ee18af071
//     .github/workflows/issue-triage.yml:3-5,22-35,70-74 (GHSA-63mx-j37w-gh59)
//     is the example
//     examples/true-positive/ai-action-excessive-tools/write-token.ghsa-63mx-j37w-gh59.yml
//   - MIC-DKFZ/nnUNet 11bd8746fc0626bc6ed3cdf394fd96d789ee6260
//     .github/workflows/issue-agent.yml:129 (its form after the fix)
//   - anthropics/claude-code cc70d3ab50728d12fc1244865a13906e8f7e3787
//     .github/workflows/claude-issue-triage.yml:3-5,46-57,100-103
func TestAIActionExcessiveToolsIncidents(t *testing.T) {
	cline := `on:
  issues:
    types: [opened]
  workflow_dispatch:
jobs:
  claude-issue-triage:
    runs-on: ubuntu-latest
    steps:
      - name: Run Issue Response & Triage
        uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          claude_args: --model claude-opus-4-5-20251101 --allowedTools "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"
          prompt: |
            **Title:** ${{ github.event.issue.title || 'See issue details below' }}
`
	gemini := `on:
  issues:
    types:
      - 'opened'
      - 'reopened'
  issue_comment:
    types:
      - 'created'
  workflow_dispatch:
jobs:
  triage-issue:
    if: >
      github.repository == 'google-gemini/gemini-cli' &&
      (github.event_name == 'issues' ||
       github.event_name == 'workflow_dispatch' ||
       (github.event_name == 'issue_comment' &&
       contains(github.event.comment.body, '@gemini-cli /triage') &&
       (github.event.comment.author_association == 'OWNER' ||
        github.event.comment.author_association == 'MEMBER' ||
        github.event.comment.author_association == 'COLLABORATOR')))
    runs-on: 'ubuntu-latest'
    steps:
      - name: 'Run Gemini Issue Triage'
        uses: 'google-github-actions/run-gemini-cli@20351b5ea2b4179431f1ae8918a246a0808f8747'
        env:
          ISSUE_TITLE: '${{ github.event.issue.title }}'
        with:
          settings: |-
            {
              "maxSessionTurns": 25,
              "coreTools": [
                "run_shell_command(echo)",
                "run_shell_command(gh label list)",
                "run_shell_command(gh issue edit)",
                "run_shell_command(gh issue list)"
              ]
            }
          prompt: 'Review the issue title and body in "${ISSUE_TITLE}"'
`
	nnunetFixed := `on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: ${{ github.token }}
          allowed_non_write_users: '*'
          prompt: "Answer issue #${{ github.event.issue.number }}"
          claude_args: --allowedTools "Read,Write,Glob,Grep,Bash(gh issue view:*),Bash(gh search issues:*),Bash(grep:*),Bash(ls:*)"
`
	claudeCode := `on:
  issues:
    types: [opened]
jobs:
  triage-issue:
    runs-on: ubuntu-latest
    steps:
      - name: Run Claude Code for Issue Triage
        uses: anthropics/claude-code-action@v1
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          prompt: |
            - ISSUE_NUMBER: ${{ github.event.issue.number }}
          claude_args: |
            --model claude-sonnet-4-5-20250929
            --mcp-config /tmp/mcp-config/mcp-servers.json
            --allowedTools "Bash(gh label list),mcp__github__get_issue,mcp__github__get_issue_comments,mcp__github__update_issue,mcp__github__search_issues,mcp__github__list_issues"
`
	checkTools(t, toolsCase{"clinejection", cline, []string{"ai-action-excessive-tools.run-code", "ai-action-excessive-tools.send-network"}, false, nil})
	checkTools(t, toolsCase{"promptpwnd: coreTools at the top is not read", gemini, []string{"ai-action-excessive-tools.run-code", "ai-action-excessive-tools.send-network"}, false, nil})
	// the fixed form, past an open gate: its tools neither write nor run code
	checkTools(t, toolsCase{"nnunet fixed", nnunetFixed, nil, false, nil})
	// the gate is closed in this version: only the author's run
	checkTools(t, toolsCase{"claude-code triage", claudeCode, nil, false, []string{"reach-unknown"}})
}

// TestAIActionExcessiveToolsUpstream: the upstream's examples (sisakulint
// 17c2d82151a966e6e388a17619b060ae2919712e,
// script/actions/ai-action-excessive-tools-{vulnerable,safe}.yaml). Both
// run in claude-code-action's tag mode: its push is the agent's too.
func TestAIActionExcessiveToolsUpstream(t *testing.T) {
	vulnerable := `on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]
jobs:
  agent:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	safe := `on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          claude_args: --allowedTools "Read,Glob,Grep"
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`
	checkTools(t, toolsCase{"upstream vulnerable", vulnerable, []string{"ai-action-excessive-tools.run-code", "ai-action-excessive-tools.send-network", "ai-action-excessive-tools.write-token"}, false, nil})
	checkTools(t, toolsCase{"upstream safe", safe, nil, false, []string{"reach-unknown"}})
}

// TestAIActionExcessiveToolsAutoMode: auto mode is reported apart from a
// grant of Bash; the built-in default and the subprocess env scrub, which
// the open gate turns on, start no auto mode; the tag mode's acceptEdits
// wins over settings.
func TestAIActionExcessiveToolsAutoMode(t *testing.T) {
	const scrubbed = "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: '*'\n"
	const open = "      - uses: anthropics/claude-code-action@v1\n        env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '0'}\n        with:\n          github_token: t\n          allowed_non_write_users: '*'\n"
	for _, c := range []toolsCase{
		{"auto mode and Bash", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          claude_args: --permission-mode auto --allowedTools Bash\n", []string{"ai-action-excessive-tools.auto-mode", "ai-action-excessive-tools.run-code"}, false, nil},
		{"auto mode with Bash denied: a hook it writes runs", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          claude_args: --permission-mode auto --disallowedTools Bash\n", []string{"ai-action-excessive-tools.auto-mode"}, false, nil},
		{"plan mode", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          claude_args: --permission-mode plan\n", []string{"ai-action-excessive-tools.auto-mode"}, false, nil},
		{"plan mode without the classifier", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          claude_args: --permission-mode plan\n          settings: '{\"useAutoModeDuringPlan\": false}'\n", nil, false, nil},
		{"no mode", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n", nil, false, nil},
		{"auto mode under the scrub", "on: {issues: {types: [opened]}}\n" + toolsJobs + scrubbed + "          prompt: p\n          claude_args: --permission-mode auto --allowedTools Read\n", nil, false, nil},
		{"auto mode, a scrub of a ${{ }}", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        env: {CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '${{ vars.S }}'}\n        with:\n          github_token: t\n          allowed_non_write_users: '*'\n          prompt: p\n          claude_args: --permission-mode auto --allowedTools Read\n", nil, false, []string{"setting-expr"}},
		{"no mode, gate closed", "on: {issues: {types: [opened]}}\n" + toolsJobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: p\n", nil, false, nil},
		{"bedrock, no mode", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          use_bedrock: 'true'\n", nil, false, nil},
		{"a defaultMode of a ${{ }}", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          settings: '{\"permissions\":{\"defaultMode\":\"${{ vars.MODE }}\"}}'\n", nil, false, []string{"setting-expr"}},
		{"auto over a settings file", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          claude_args: --permission-mode auto --settings ./ci.json\n", []string{"ai-action-excessive-tools.auto-mode"}, false, []string{"setting-expr"}},
		{"a mode of a ${{ }}", "on: {issues: {types: [opened]}}\n" + toolsJobs + open + "          prompt: p\n          claude_args: --permission-mode ${{ vars.M }}\n", nil, false, []string{"setting-expr"}},
		{"telemetry off in the env of the job", "on: {issues: {types: [opened]}}\n" + "jobs:\n  a:\n    runs-on: x\n    env:\n      DISABLE_TELEMETRY: '1'\n    steps:\n" + open + "          prompt: p\n", nil, false, nil},
		{"tag mode on bedrock", "on: {issue_comment: {types: [created]}}\n" + toolsJobs + open + "          use_bedrock: 'true'\n", []string{"ai-action-excessive-tools.write-token"}, false, nil},
		{"tag mode, a flag of auto", "on: {issue_comment: {types: [created]}}\n" + toolsJobs + open + "          claude_args: --permission-mode auto\n", []string{"ai-action-excessive-tools.auto-mode", "ai-action-excessive-tools.write-token"}, false, nil},
		{"track_progress on issues, auto on dispatch only", "on: {issues: {types: [opened]}, workflow_dispatch: {}}\n" + toolsJobs + open + "          prompt: p\n          track_progress: 'true'\n          use_bedrock: 'true'\n", []string{"ai-action-excessive-tools.write-token"}, false, nil},
	} {
		checkTools(t, c)
	}
}

// TestAIActionExcessiveToolsAutoModeAt: the finding is at the flag that
// sets auto mode, and relates nothing.
func TestAIActionExcessiveToolsAutoModeAt(t *testing.T) {
	src := "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: x\n    env:\n      CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: '0'\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: '*'\n          prompt: p\n          claude_args: --permission-mode auto\n"
	rep, _, _ := checkRules(t, []lint.Rule{AIActionExcessiveTools}, wfFile(src), exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("findings: %d", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	at := func(sp cst.Span) string { return src[sp.Start:sp.End] }
	if at(f.Location.Span) != "--permission-mode auto" || len(f.Related) != 0 {
		t.Errorf("at %q, related %+v", at(f.Location.Span), f.Related)
	}
}

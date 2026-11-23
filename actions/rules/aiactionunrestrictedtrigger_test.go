package rules

import (
	"context"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// TestAIActionUnrestrictedTrigger: the kinds of
// ai-action-unrestricted-trigger by the gate and the event.
func TestAIActionUnrestrictedTrigger(t *testing.T) {
	for _, c := range []struct {
		name, src string
		kinds     []string
		gaps      int
	}{
		{"any user", "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*', github_token: t}\n", []string{"ai-action-unrestricted-trigger.any-user"}, 0},
		{"no token", "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*'}\n", nil, 0},
		{"schedule only", "on: {schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*', github_token: t}\n", nil, 0},
		{"labeled only: a maintainer", "on: {issues: {types: [labeled]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*', github_token: t}\n", nil, 0},
		{"claude on discussion fails", "on: discussion\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '*', github_token: t}\n", nil, 0},
		{"codex on discussion", "on: discussion\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: openai/codex-action@v1\n        with: {allow-users: '*'}\n", []string{"ai-action-unrestricted-trigger.any-user"}, 0},
		{"any bot", "on: issue_comment\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_bots: '*'}\n", []string{"ai-action-unrestricted-trigger.any-bot"}, 0},
		{"unchecked", "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n", []string{"ai-action-unrestricted-trigger.unchecked"}, 0},
		{"unchecked on push", "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-base-action@beta\n", nil, 0},
		{"gate expr", "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '${{ vars.U }}', github_token: t}\n", nil, 1},
		{"gate expr on push", "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_non_write_users: '${{ vars.U }}', github_token: t}\n", nil, 0},
		{"the author's login on opened (nnUNet)", "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event.issue.user.login }}\n", []string{"ai-action-unrestricted-trigger.any-user"}, 0},
		{"the author's login on labeled only", "on: {issues: {types: [labeled]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event.issue.user.login }}\n", nil, 0},
		{"the repository's owner", "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.repository_owner }}\n", nil, 0},
		{"the actor as a bot", "on: {issue_comment: {types: [created]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: ${{ github.actor }}\n", []string{"ai-action-unrestricted-trigger.any-bot"}, 0},
		{"the actor on workflow_run: claude checks the run before too", "on: {workflow_run: {workflows: [ci], types: [completed]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.actor }}\n", nil, 1},
		{"open on issues, undecided on a comment: the open gate is reported alone", "on: {issues: {types: [opened]}, issue_comment: {types: [created]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event_name == 'issues' && '*' || vars.USERS }}\n", []string{"ai-action-unrestricted-trigger.any-user"}, 0},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{AIActionUnrestrictedTrigger}, wfFile(c.src), exposureFacts{})
		var got []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got = append(got, f.Args.KindID().String())
		}
		if len(got) != len(c.kinds) || (len(got) > 0 && got[0] != c.kinds[0]) || len(rep.FindingsWith(lint.CertaintyInconclusive)) != c.gaps {
			t.Errorf("%s: %v %+v", c.name, got, rep.FindingsWith(lint.CertaintyInconclusive))
		}
	}
}

// TestAIActionUnrestrictedTriggerAnyBotPrivate: the fact false drops the
// finding of any-bot.
func TestAIActionUnrestrictedTriggerAnyBotPrivate(t *testing.T) {
	src := "on: issue_comment\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_bots: '*'}\n"
	rep, _, _ := checkRules(t, []lint.Rule{AIActionUnrestrictedTrigger}, wfFile(src), exposureFacts{public: ptr(false)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestAIActionUnrestrictedTriggerIncidents: the workflows of the reports
// the Meta cites, cut to their trigger and the step.
//   - cline/cline 7bdbf0a9a745f6abc09483fe9b08874c80fb44f3
//     .github/workflows/claude-issue-triage.yml:3-5,44-50 (Clinejection)
//   - google-gemini/gemini-cli 6390b81646e324bfbb86ccd73247f5d3e2a423f8
//     .github/workflows/gemini-automated-issue-triage.yml:3-16,35-43,59-64
//     (PromptPwnd): the job's if checks the commenter of issue_comment
//     only, so issues opened reaches it
//   - anthropics/claude-code 74cc597eb5c1a604e955ce97e7e3b82524f1062c
//     .github/workflows/claude-issue-triage.yml:3-5,46-51 (cited by GMO
//     Flatt Security as a common misconfiguration)
//   - MIC-DKFZ/nnUNet 94300b49e716fae38fe4c9d0ec9e935ee18af071
//     .github/workflows/issue-triage.yml:3-5,9-13,22-27 (GHSA-63mx-j37w-gh59):
//     the gate is the issue's author, the actor of issues opened; the
//     example
//     examples/true-positive/ai-action-unrestricted-trigger/any-user.ghsa-63mx-j37w-gh59.yml
func TestAIActionUnrestrictedTriggerIncidents(t *testing.T) {
	cline := `on:
  issues:
    types: [opened]
  workflow_dispatch:
jobs:
  claude-issue-triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
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
          ISSUE_BODY: '${{ github.event.issue.body }}'
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
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          prompt: |
            You're an issue triage assistant for GitHub issues.
`
	for _, c := range []struct{ name, src, kind string }{
		{"clinejection", cline, "ai-action-unrestricted-trigger.any-user"},
		{"promptpwnd", gemini, "ai-action-unrestricted-trigger.unchecked"},
		{"claude-code 74cc597", claudeCode, "ai-action-unrestricted-trigger.any-user"},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{AIActionUnrestrictedTrigger}, wfFile(c.src), exposureFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != c.kind || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConfirmed {
			t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
}

// TestAIActionUnrestrictedTriggerGateValue: the finding names the gate's
// value as written.
func TestAIActionUnrestrictedTriggerGateValue(t *testing.T) {
	for _, c := range []struct{ value, want string }{
		{"${{ github.event.issue.user.login }}", "${{ github.event.issue.user.login }}"},
		{"'*'", "*"},
		{"' * '", "*"},
		{"|\n            ${{ github.actor }}", "${{ github.actor }}"},
	} {
		src := "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: " + c.value + "\n"
		rep, _, _ := checkRules(t, []lint.Rule{AIActionUnrestrictedTrigger}, wfFile(src), exposureFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Fatalf("%s: %+v", c.value, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
		if a, ok := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.(AIActionUnrestrictedTriggerAnyUser); !ok || a.GateValue != c.want {
			t.Errorf("%s: %+v", c.value, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args)
		}
	}
}

// pullRequestTargetBlocked answers repo.pull-request-target-allowed false and
// repo.public true, and nothing else.
type pullRequestTargetBlocked struct{}

func (pullRequestTargetBlocked) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	switch q.(type) {
	case facts.RepoPullRequestTargetAllowed:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
	case facts.RepoPublic:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
}

// TestAIActionUnrestrictedTriggerAnyBotPullRequestTarget: a GitHub App of the
// attacker opens a pull request from a fork it is installed on, so any-bot
// is reported on pull_request_target alone, and a repository whose Actions
// policies block the runs on pull_request_target drops it.
func TestAIActionUnrestrictedTriggerAnyBotPullRequestTarget(t *testing.T) {
	src := "on: {pull_request_target: {types: [opened]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {allowed_bots: '*'}\n"
	rep, _, _ := checkRules(t, []lint.Rule{AIActionUnrestrictedTrigger}, wfFile(src), exposureFacts{public: ptr(true)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != "ai-action-unrestricted-trigger.any-bot" {
		t.Fatalf("assumed: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _, _ = checkRules(t, []lint.Rule{AIActionUnrestrictedTrigger}, wfFile(src), pullRequestTargetBlocked{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("blocked: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

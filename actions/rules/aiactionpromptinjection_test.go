package rules

import (
	"os"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

type promptCase struct {
	name, src string
	kinds     []string
	cond      bool // the finding holds on repo.public
	gaps      []string
}

func checkPrompt(t *testing.T, c promptCase) {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{AIActionPromptInjection}, wfFile(c.src), exposureFacts{})
	var kinds, gaps []string
	cond := false
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		kinds = append(kinds, f.Args.KindID().String())
		cond = cond || f.Certainty != lint.CertaintyConfirmed
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		gaps = append(gaps, g.InconclusiveKind.String())
	}
	if !equalStrings(kinds, c.kinds) || !equalStrings(gaps, c.gaps) || cond != c.cond {
		t.Errorf("%s: kinds %v, conditional %v, inconclusive %v", c.name, kinds, cond, gaps)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

const claudeStep = "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: \"Triage: ${{ github.event.issue.title }}\"\n"

// TestAIActionPromptInjection: the kinds of ai-action-prompt-injection by
// the gate, the event and what reaches the prompt.
func TestAIActionPromptInjection(t *testing.T) {
	jobs := "jobs:\n  a:\n    runs-on: x\n    steps:\n"
	for _, c := range []promptCase{
		{"gate closed, opened only", "on: {issues: {types: [opened]}}\n" + jobs + claudeStep, nil, false, nil},
		{"gate closed, labeled", "on: {issues: {types: [opened, labeled]}}\n" + jobs + claudeStep, []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"gate open", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: '*'\n          prompt: \"${{ github.event.issue.title }}\"\n", []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"gate open, but only the owner passes the if", "on: {issue_comment: {types: [created]}}\njobs:\n  a:\n    if: github.event.comment.author_association == 'OWNER'\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: '*'\n          prompt: \"${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"any bot: on repo.public", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: '*'\n          prompt: \"${{ github.event.issue.title }}\"\n", []string{"ai-action-prompt-injection.prompt"}, true, nil},
		{"comment body, gate closed", "on: {issue_comment: {types: [created]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: \"${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"comment body, deleted by a maintainer", "on: {issue_comment: {types: [deleted]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: \"${{ github.event.comment.body }}\"\n", []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"issue title on a comment, gate closed", "on: issue_comment\n" + jobs + claudeStep, []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"indirect, gate closed (indirect-value)", "on: {issue_comment: {types: [created]}}\njobs:\n  a:\n    runs-on: x\n    env: {C: '${{ github.event.comment.body }}'}\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: \"${{ env.C }}\"\n", []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"unchecked", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: \"${{ github.event.issue.body }}\"\n", []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"env", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: google-github-actions/run-gemini-cli@v0\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n        with:\n          prompt: /gemini-triage\n", []string{"ai-action-prompt-injection.env"}, false, nil},
		{"schedule only", "on: {schedule: [{cron: '0 0 * * *'}]}\n" + jobs + "      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: \"${{ github.event.issue.body }}\"\n", nil, false, nil},
		{"push: claude fails", "on: push\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: \"${{ github.event.head_commit.message }}\"\n", nil, false, nil},
		{"value unknown", "on: {issues: {types: [opened]}}\n" + jobs + "      - id: s\n        run: echo\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: \"${{ steps.s.outputs.x }}\"\n", nil, false, []string{"value-unknown"}},
		{"gate expr", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ vars.U }}\n          prompt: \"${{ github.event.issue.title }}\"\n", nil, false, []string{"gate-expr"}},
		{"a number", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: \"Triage #${{ github.event.issue.number }}\"\n", nil, false, nil},
		{"the author's login on opened (nnUNet)", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event.issue.user.login }}\n          prompt: \"${{ github.event.issue.title }}\"\n", []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"open on issues only, the comment's body on a comment", "on: {issues: {types: [opened]}, issue_comment: {types: [created]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event_name == 'issues' && '*' || 'nobody' }}\n          prompt: \"${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"undecided on issues only, the comment's body on a comment", "on: {issues: {types: [opened]}, issue_comment: {types: [created]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.event_name == 'issues' && vars.USERS || '' }}\n          prompt: \"x ${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"any bot on issues only, the comment's body on a comment", "on: {issues: {types: [opened]}, issue_comment: {types: [created]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: ${{ github.event_name == 'issues' && '*' || '' }}\n          prompt: \"x ${{ github.event.comment.body }}\"\n", nil, false, nil},
		{"a comment by the actor, on the owner's issue: the comment is theirs", "on: {issue_comment: {types: [created]}}\njobs:\n  a:\n    if: github.event.issue.author_association == 'OWNER'\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.actor }}\n          prompt: \"${{ github.event.comment.body }}\"\n", []string{"ai-action-prompt-injection.prompt"}, false, nil},
		{"the repository's owner", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: t\n          allowed_non_write_users: ${{ github.repository_owner }}\n          prompt: \"${{ github.event.issue.title }}\"\n", nil, false, nil},
		{"the actor as a bot: on repo.public", "on: {issues: {types: [opened]}}\n" + jobs + "      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: ${{ github.actor }}\n          prompt: \"${{ github.event.issue.title }}\"\n", []string{"ai-action-prompt-injection.prompt"}, true, nil},
	} {
		checkPrompt(t, c)
	}
}

// TestAIActionPromptInjectionIncidents: the workflows of the reports the
// Meta cites, cut to their trigger and the step.
//   - cline/cline 7bdbf0a9a745f6abc09483fe9b08874c80fb44f3
//     .github/workflows/claude-issue-triage.yml:3-5,44-55 (Clinejection)
//   - google-gemini/gemini-cli 6390b81646e324bfbb86ccd73247f5d3e2a423f8
//     .github/workflows/gemini-automated-issue-triage.yml:3-16,35-43,59-64
//     (PromptPwnd)
func TestAIActionPromptInjectionIncidents(t *testing.T) {
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
          ISSUE_BODY: '${{ github.event.issue.body }}'
`
	checkPrompt(t, promptCase{"clinejection", cline, []string{"ai-action-prompt-injection.prompt"}, false, nil})
	checkPrompt(t, promptCase{"promptpwnd", gemini, []string{"ai-action-prompt-injection.env", "ai-action-prompt-injection.env"}, false, nil})
	nnunet := `on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: ${{ github.token }}
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          prompt: |
            TITLE: ${{ github.event.issue.title }}
            BODY: ${{ github.event.issue.body }}
`
	checkPrompt(t, promptCase{"nnunet", nnunet, []string{"ai-action-prompt-injection.prompt", "ai-action-prompt-injection.prompt"}, false, nil})
}

// TestAIActionPromptInjectionUpstream: the upstream's examples
// (sisakulint 17c2d82151a966e6e388a17619b060ae2919712e,
// script/actions/ai-action-prompt-injection-{vulnerable,safe}.yaml): the
// safe one moves the values into env, which the agent reads.
func TestAIActionPromptInjectionUpstream(t *testing.T) {
	vulnerable := `on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: |
            Please triage this issue:
            Title: ${{ github.event.issue.title }}
            Body: ${{ github.event.issue.body }}
`
	safe := `on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
          ISSUE_BODY: ${{ github.event.issue.body }}
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          prompt: "Please triage the issue described in the environment variables ISSUE_TITLE and ISSUE_BODY."
`
	// the gate is closed and only the author opens an issue: neither reaches the agent
	checkPrompt(t, promptCase{"upstream vulnerable", vulnerable, nil, false, nil})
	checkPrompt(t, promptCase{"upstream safe", safe, nil, false, nil})
	open := `      - uses: google-github-actions/run-gemini-cli@v0
        env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        with:
          prompt: "Please triage the issue in ISSUE_TITLE"
`
	checkPrompt(t, promptCase{"the safe form without a gate", "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n" + open, []string{"ai-action-prompt-injection.env"}, false, nil})
}

// TestAIActionPromptInjectionAnchors: two references in one prompt are two
// findings with their own fingerprints (a repository of the corpus,
// thedotmack/claude-mem's summary.yml, has the title and the body).
func TestAIActionPromptInjectionAnchors(t *testing.T) {
	src := "on: {issues: {types: [opened]}}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: |\n            Title: ${{ github.event.issue.title }}\n            Body: ${{ github.event.issue.body }} ${{ github.event.issue.body }}\n"
	rep, _, _ := checkRules(t, []lint.Rule{AIActionPromptInjection}, wfFile(src), exposureFacts{})
	seen := map[lint.Fingerprint]bool{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		seen[f.Fingerprint] = true
	}
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 3 || len(seen) != 3 {
		t.Errorf("%d findings, %d fingerprints", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), len(seen))
	}
}

// TestIndirectValueIsFalsePositive: the example
// of indirect-value is a false positive only if the same value written
// directly gives no finding.
func TestIndirectValueIsFalsePositive(t *testing.T) {
	b, err := os.ReadFile("examples/false-positive/ai-action-prompt-injection/indirect-value.yml")
	if err != nil {
		t.Fatal(err)
	}
	src := strings.ReplaceAll(string(b), "${{ env.C }}", "${{ github.event.comment.body }}")
	rep, _, _ := checkRules(t, []lint.Rule{AIActionPromptInjection}, wfFile(src), exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("written directly, the value gives %d findings: the example is no false positive", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
}

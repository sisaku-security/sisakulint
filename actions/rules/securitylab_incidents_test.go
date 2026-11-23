package rules

import (
	"fmt"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// The advisories of GitHub Security Lab on workflows, each cut to the steps
// of its harm: what the examples (examples/*/<rule>/*.ghsl-*) cannot hold,
// the answer of the other rules and the reading of a reusable workflow of
// another repository.

// GHSL-2026-229
// (https://securitylab.github.com/advisories/GHSL-2026-229_ipdxco_unified-github-workflows/,
// ipdxco/unified-github-workflows e08e90c46d931f457e5d8e292ffa988c0c0b5b70
// .github/workflows/release-check.yml:68-103,154-184): "The release-check.yml
// reusable workflow reads a version string from a file in the head commit of
// a pull request and writes it to $GITHUB_OUTPUT with a single-line echo.
// ... The corrupted prefix is then interpolated directly into a sed program,
// where sed's e flag turns it into command execution." Here the steps are in
// one workflow on pull_request_target, the event of the caller of the
// advisory; the head SHA comes from the event, not from an earlier step.
// output-clobbering does not follow the variable that the script sets from
// the file (the undetected form script-var), and argument-injection does not
// read a value inside the program of sed (program-argument). The advisory's
// caller calls the workflow from another repository, which the rules do not
// read (remote-callee; the example of output-clobbering). The examples
// examples/undetected/output-clobbering/script-var.ghsl-2026-229.yml and
// examples/undetected/argument-injection/program-argument.ghsl-2026-229.yml
// hold the two rules to the forms; this test holds code-injection to
// nothing on the steps.
func TestSecurityLabGHSL2026229(t *testing.T) {
	const src = `on:
  pull_request_target:
    paths: [ "version.json" ]
permissions:
  contents: write
  pull-requests: write
jobs:
  release-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - id: version
        env:
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          prefix="v"
          echo "prefix=$prefix" | tee -a $GITHUB_OUTPUT
          git fetch origin "$HEAD_SHA"
          git checkout "$HEAD_SHA" -- version.json
          version="$(yq -r '.version | select(type == "!!str")' version.json)"
          git checkout HEAD -- version.json
          version="${version#v}"
          echo "version=$version" | tee -a $GITHUB_OUTPUT
          echo "tag=${prefix}${version}" | tee -a $GITHUB_OUTPUT
      - id: prev
        env:
          PREFIX: ${{ steps.version.outputs.prefix }}
        run: |
          git fetch origin --tags
          vs=$(git tag | grep "^${PREFIX}" | sed "s#^${PREFIX}#v#" | paste -sd , -)
          echo "vs=$vs"
`
	rep, _, _ := checkRules(t, []lint.Rule{CodeInjection}, wfFile(src), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
		t.Errorf("findings %+v, inconclusive %+v; want none", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestSecurityLabGHSL2026229Remote: the caller of GHSL-2026-229, as the
// advisory quotes it (the template of
// ipdxco/unified-github-workflows e08e90c46d931f457e5d8e292ffa988c0c0b5b70
// templates/.github/workflows/release-check.yml, rendered), calls the
// reusable workflow of another repository; workflow.definition answers the
// steps of TestSecurityLabGHSL2026229 (workflowDefinitionAnswer). The rules
// read the steps of the reusable workflow on the events of the calling job,
// and report nothing there for the same reason as in the same repository:
// the value comes from a file of the pull request (output-clobbering
// script-var) and goes to a program of sed (argument-injection
// program-argument).
func TestSecurityLabGHSL2026229Remote(t *testing.T) {
	const src = `on:
  pull_request_target:
    paths: [ "version.json" ]
    types: [ opened, synchronize, reopened, labeled, unlabeled ]
permissions:
  contents: write
  pull-requests: write
jobs:
  release-check:
    uses: ipdxco/unified-github-workflows/.github/workflows/release-check.yml@v1.0
`
	// every rule runs, so that a rule that reads reusable workflows of
	// other repositories asks workflow.definition
	rep, _, _ := checkRules(t, All(), wfFile(src), limitFacts{})
	declared := []lint.RuleID{OutputClobberingID, ArgumentInjectionID, CodeInjectionID}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if slices.Contains(declared, f.Rule) {
			t.Errorf("finding %+v; want none (script-var, program-argument)", f)
		}
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if slices.Contains(declared, g.Rule) {
			t.Errorf("inconclusive %+v; want none (script-var, program-argument)", g)
		}
	}
	asked := false
	for _, x := range rep.Facts {
		if q, ok := x.Query.(facts.WorkflowDefinition); ok && q.Repo.String() == "ipdxco/unified-github-workflows" {
			asked = true
			if x.RawAnswer.State != facts.StateFound {
				t.Errorf("workflow.definition of ipdxco/unified-github-workflows is %v, want found: the test does not show that the answer is there", x.RawAnswer.State)
			}
		}
	}
	if !asked {
		t.Error("workflow.definition of ipdxco/unified-github-workflows was not asked: the test does not show that the answer is there")
	}
}

// GHSL-2020-191
// (https://securitylab.github.com/advisories/GHSL-2020-191-KanCraft-kanColleWidget-workflow/,
// KanCraft/kanColleWidget d2065402071547f935a2c79014bc0fc8e4ccfb61
// .github/workflows/contrib-notice.yml): "The comment text is used to format
// a bash script." The step of issue_comment writes the body of a comment
// into its run script (line 39), which code-injection reports. The step of
// gollum puts the name of a wiki page (page_name) in env and writes the
// name with echo -ne to a file, whose content a later step passes to npm as
// one argument that begins with fixed text: the name is not at the head of
// a word of a command and is not printed to the log, so argument-injection,
// unsecure-commands and set-output-injection report nothing. The example
// examples/true-positive/code-injection/controlled.ghsl-2020-191.yml holds
// code-injection to the finding; this test holds the other three rules to
// nothing.
func TestSecurityLabGHSL2020191(t *testing.T) {
	const src = `name: Contribution Notice

on:
  issues:
    types: [opened, reopened]
  issue_comment:
    types: [created]
  gollum:
  # pull_request:
  # PullRequestの通知は、IFTTTにしました。
  # ソースブランチがこのRepoの外だと、このWorkflowの中でSecretsのTWITTER_*が利用できないので。

jobs:
  notification:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - uses: actions/setup-node@v1
      with:
        node-version: 12.x
    - run: npm install

    - name: Issue用ツイート内容の生成
      if: github.event_name == 'issues' && github.event.action == 'opened'
      env:
        SENDER: ${{ github.event.sender.login}}
        TITLE: ${{ github.event.issue.title}}
        URL: ${{ github.event.issue.html_url }}
      run: |
        echo -ne "ご意見が届きました！\n\n> ${TITLE}\n${SENDER}さん より\n\n#艦これウィジェット\n${URL}" >> announcement.txt

    - name: Issueコメント用ツイート内容の生成
      if: github.event_name == 'issue_comment' && github.event.action == 'created' && github.event.sender.login != 'coveralls'
      env:
        SENDER: ${{ github.event.sender.login }}
        BODY: ${{ github.event.comment.body }}
        URL: ${{ github.event.comment.html_url }}
      run: |
        echo "[DEBUG] ORIG: ${{ github.event.comment.body }}"
        echo "[DEBUG] BODY: ${BODY}"
        if [ ${#BODY} -gt 80 ]; then TEXT="$(echo ${BODY} | cut -c1-80)…"; else TEXT=${BODY}; fi;
        echo "[DEBUG] TEXT: ${TEXT}"
        echo -ne "${SENDER}さんがコメントしました！\n> ${TEXT}\n${URL}" >> announcement.txt

    - name: Wiki用ツイート内容の生成
      if: github.event_name == 'gollum'
      env:
        SENDER: ${{ github.event.sender.login }}
        TITLE: ${{ github.event.pages[0].page_name }}
        URL: ${{ github.event.pages[0].html_url }}
      run: |
        echo -ne "Wikiが更新されました！ありがとう！！\n\n> ${TITLE}\n${SENDER}さん より\n\n#艦これウィジェット\n${URL}" >> announcement.txt

    # - name: PR用ツイート内容の生成
    #   if: github.event_name == 'pull_request' && github.event.pull_request.merged == true
    #   env:
    #     SENDER: ${{ github.event.sender.login}}
    #     TITLE: ${{ github.event.pull_request.title}}
    #     URL: ${{ github.event.pull_request.html_url }}
    #   run: |
    #     echo -ne "開発ありがとう！\n\n${TITLE}\nby ${SENDER}\n#艦これウィジェット\n${URL}" >> announcement.txt

    - name: Tweet
      run: |
        if [ -f announcement.txt ]; then
          announcement=` + "`" + `cat announcement.txt` + "`" + `
          npm run tweet "${announcement}"
        fi
      env:
        TWITTER_CONSUMER_KEY: ${{ secrets.TWITTER_CONSUMER_KEY }}
        TWITTER_CONSUMER_SECRET: ${{ secrets.TWITTER_CONSUMER_SECRET }}
        TWITTER_ACCESS_TOKEN_KEY: ${{ secrets.TWITTER_ACCESS_TOKEN_KEY }}
        TWITTER_ACCESS_TOKEN_SECRET: ${{ secrets.TWITTER_ACCESS_TOKEN_SECRET }}
`
	rep, _, _ := checkRules(t, []lint.Rule{ArgumentInjection, UnsecureCommands, SetOutputInjection}, wfFile(src), nil)
	var got []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		got = append(got, fmt.Sprintf("%s %+v", f.Args.KindID(), f.Args))
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		got = append(got, fmt.Sprintf("%s %s", g.Rule, g.InconclusiveKind))
	}
	if len(got) != 0 {
		t.Errorf("got %q, want none", got)
	}
}

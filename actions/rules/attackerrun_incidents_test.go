package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// The workflows Synacktiv's article cites, as they were before
// and after their fix:
//
//   - spring-projects/spring-security bb3738dbfda2340adc834ae1af64b4a50834f468
//     .github/workflows/merge-dependabot-pr.yml (3: on, 7: permissions,
//     12: the if), fixed by 4c1294030462cb4469f3412f05114fc662aba09a
//   - trpc/trpc 00f01aacaec9fda8e1c8f48c4c61005f0bb5603d
//     .github/workflows/dependabot-approve.yml (3, 12), fixed by
//     818759449d62d37162259574b0d62e0827cda0e9
//
// and woodruffw/gha-hazmat c34857d4ab14af4fdd4c492ba72b9eeb4844da77
// .github/workflows/bot-conditions.yml and unsound-contains.yml, whole.
const (
	springWorkflow = `name: Merge Dependabot PR

on: pull_request_target

run-name: Merge Dependabot PR ${{ github.ref_name }}

permissions: write-all

jobs:
  merge-dependabot-pr:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:

      - uses: actions/checkout@v4
        with:
          show-progress: false
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 17

      - name: Set Milestone to Dependabot Pull Request
        id: set-milestone
        run: |
          if test -f pom.xml
          then
            CURRENT_VERSION=$(mvn help:evaluate -Dexpression="project.version" -q -DforceStdout)
          else
            CURRENT_VERSION=$(cat gradle.properties | sed -n '/^version=/ { s/^version=//;p }')
          fi
          export CANDIDATE_VERSION=${CURRENT_VERSION/-SNAPSHOT}
          MILESTONE=$(gh api repos/$GITHUB_REPOSITORY/milestones --jq 'map(select(.due_on != null and (.title | startswith(env.CANDIDATE_VERSION)))) | .[0] | .title')
          
          if [ -z $MILESTONE ]
          then
            gh run cancel ${{ github.run_id }}
            echo "::warning title=Cannot merge::No scheduled milestone for $CURRENT_VERSION version"
          else
            gh pr edit ${{ github.event.pull_request.number }} --milestone $MILESTONE
            echo mergeEnabled=true >> $GITHUB_OUTPUT
          fi
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Merge Dependabot pull request
        if: steps.set-milestone.outputs.mergeEnabled
        run: gh pr merge ${{ github.event.pull_request.number }} --auto --rebase
        env:
          GH_TOKEN: ${{ secrets.GH_ACTIONS_REPO_TOKEN }}
`
	springFixed = `name: Merge Dependabot PR

on: pull_request_target

run-name: Merge Dependabot PR ${{ github.ref_name }}

permissions: write-all

jobs:
  merge-dependabot-pr:
    runs-on: ubuntu-latest
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    steps:

      - uses: actions/checkout@v4
        with:
          show-progress: false
          ref: ${{ github.event.pull_request.head.sha }}

      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: 17

      - name: Set Milestone to Dependabot Pull Request
        id: set-milestone
        run: |
          if test -f pom.xml
          then
            CURRENT_VERSION=$(mvn help:evaluate -Dexpression="project.version" -q -DforceStdout)
          else
            CURRENT_VERSION=$(cat gradle.properties | sed -n '/^version=/ { s/^version=//;p }')
          fi
          export CANDIDATE_VERSION=${CURRENT_VERSION/-SNAPSHOT}
          MILESTONE=$(gh api repos/$GITHUB_REPOSITORY/milestones --jq 'map(select(.due_on != null and (.title | startswith(env.CANDIDATE_VERSION)))) | .[0] | .title')
          
          if [ -z $MILESTONE ]
          then
            gh run cancel ${{ github.run_id }}
            echo "::warning title=Cannot merge::No scheduled milestone for $CURRENT_VERSION version"
          else
            gh pr edit ${{ github.event.pull_request.number }} --milestone $MILESTONE
            echo mergeEnabled=true >> $GITHUB_OUTPUT
          fi
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Merge Dependabot pull request
        if: steps.set-milestone.outputs.mergeEnabled
        run: gh pr merge ${{ github.event.pull_request.number }} --auto --rebase
        env:
          GH_TOKEN: ${{ secrets.GH_ACTIONS_REPO_TOKEN }}
`
	trpcWorkflow = `# https://stackoverflow.com/q/70664840/590396
name: Dependabot auto-approve
on: pull_request_target

permissions:
  contents: write
  pull-requests: write

jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: ${{ github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]' }}
    steps:
      - name: Approve a PR
        run: gh pr review --approve "$PR_URL"
        env:
          PR_URL: ${{github.event.pull_request.html_url}}
          GITHUB_TOKEN: ${{secrets.TRPC_GITHUB_TOKEN}}

      - name: Enable auto-merge for Dependabot PRs
        run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: ${{github.event.pull_request.html_url}}
          GITHUB_TOKEN: ${{secrets.TRPC_GITHUB_TOKEN}}
`
	trpcFixed = `# https://stackoverflow.com/q/70664840/590396
name: Dependabot auto-approve
on: pull_request_target

permissions:
  contents: write
  pull-requests: write

jobs:
  dependabot:
    runs-on: ubuntu-latest
    if: ${{ github.event.pull_request.user.login == 'dependabot[bot]' || github.event.pull_request.user.login == 'renovate[bot]' }}
    steps:
      - name: Approve a PR
        run: gh pr review --approve "$PR_URL"
        env:
          PR_URL: ${{github.event.pull_request.html_url}}
          GITHUB_TOKEN: ${{secrets.TRPC_GITHUB_TOKEN}}

      - name: Enable auto-merge for Dependabot PRs
        run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: ${{github.event.pull_request.html_url}}
          GITHUB_TOKEN: ${{secrets.TRPC_GITHUB_TOKEN}}
`
	hazmatBot = `# bot-conditions.yml
#
# what:
# workflows that check github.actor are susceptible to spoofing/impersonation,
# since github.actor refers to the last actor (i.e. in the git history of a
# branch) while the branch itself may contain attacker-controlled code.
#
# how:
# confusion between github.actor and other actor identities in a workflow trigger.

on: pull_request_target

permissions: {}

jobs:
  hackme:
    runs-on: ubuntu-latest
    if: github.actor == 'dependabot[bot]'
    steps:
      - name: vulnerable-1
        run: echo hello
        if: ${{ github.actor == 'dependabot[bot]' }}

      - name: vulnerable-2
        run: echo hello
        if: ${{ github.actor == 'dependabot[bot]' && github.repository == 'example/example' }}

      - name: vulnerable-3
        run: echo hello
        if: github.actor == 'renovate[bot]'

      - name: not-vulnerable-4
        run: echo hello
        if: github.actor == 'notabot'
`
)

// TestBotConditionsIncidents: the two workflows report
// bot-conditions.dependabot, with the fix the projects made; their fixes
// report nothing. trpc's renovate[bot] is not inconclusive: the if lets
// the attacker in by Dependabot already.
func TestBotConditionsIncidents(t *testing.T) {
	for _, c := range []struct {
		name, src string
		n         int
	}{
		{"spring-security", springWorkflow, 1},
		{"spring-security fixed", springFixed, 0},
		{"trpc", trpcWorkflow, 1},
		{"trpc fixed", trpcFixed, 0},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{BotConditions}, wfFile(c.src), nil)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.n || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
			t.Errorf("%s: %v %+v", c.name, kindsOf(rep), rep.FindingsWith(lint.CertaintyInconclusive))
			continue
		}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Fix == nil || !strings.Contains(f.Fix.Title, "github.event.pull_request.user.login") {
				t.Errorf("%s: fix %+v, no fix %+v", c.name, f.Fix, f.NoFix)
			}
		}
	}
}

// TestHazmat: in bot-conditions.yml the job's if and vulnerable-1 and -2
// report, vulnerable-3 (renovate[bot]) is inconclusive, not-vulnerable-4
// nothing. unsound-contains.yml runs on push, pull_request and
// workflow_dispatch, none an attacker's privileged event: nothing
// (vulnerable-1 is the undetected form writer-value, vulnerable-3
// not-attacker-event).
func TestHazmat(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{BotConditions}, wfFile(hazmatBot), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 3 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 {
		t.Errorf("bot-conditions.yml: %v %+v", kindsOf(rep), rep.FindingsWith(lint.CertaintyInconclusive))
	}
	rep, _, _ = checkRules(t, []lint.Rule{UnsoundContains}, wfFile(hazmatContains), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || slices.ContainsFunc(rep.FindingsWith(lint.CertaintyInconclusive), func(lint.Finding) bool { return true }) {
		t.Errorf("unsound-contains.yml: %v %+v", kindsOf(rep), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

var hazmatContains = `# unsound-contains.yml
#
# what: unsound usage of the ` + "`" + `contains` + "`" + ` function.
#
# how: the ` + "`" + `contains` + "`" + ` function is used to check if a string (or list) contains
# a substring (or element). users will often use this function to check if a
# ref is contained in a trusted list of refs, but will do so via
# a substring check instead of a list inclusion check.

on:
  push:
  pull_request:
  workflow_dispatch:
    inputs:
      some_value:
        required: true

permissions: {}

jobs:
  hackme:
    runs-on: ubuntu-latest
    steps:
      - name: vulnerable-1
        run: echo hello
        if: ${{ contains('refs/heads/main refs/heads/develop', github.ref) }}

      - name: vulnerable-2
        run: echo hello
        if: ${{ contains('main,develop', env.GITHUB_REF_NAME) }}

      - name: vulnerable-3
        run: echo hello
        if: contains('main,prod', github.ref_name) || contains('longusername anotherlongusername', github.actor) == true

      - name: probably-not-vulnerable-but-still-bad
        run: echo hello
        if: contains('runner1,runner2', runner.name)

      - name: not-vulnerable
        run: echo hello
        if: contains(some.context.*.foo, github.ref_name)
`

package agent

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// laterOf are the later steps of the step at of the one job of src, as
// lines "<name> on=<events> secrets=<names>[+token][+all] code=<n> git=<n>".
func laterOf(t *testing.T, src string, at int) []string {
	t.Helper()
	w, _ := workflow.Parse(cst.Parse([]byte(src)))
	j := w.Jobs.Value.Entries[0].Value.Value
	steps := j.Steps.Value.Items
	a, ok := Of(steps[at])
	if !ok {
		t.Fatalf("step %d is no agent step", at)
	}
	var lines []string
	for _, l := range LaterSteps(attacker.Outsider, w, &j, steps, at, a, taint.EventsOf(w, job.Privileged()), nil, nil) {
		var on []string
		for _, e := range l.On {
			if !slices.Contains(on, e.Name().String()) {
				on = append(on, e.Name().String())
			}
		}
		s := l.Name + " on=" + strings.Join(on, ",") + " secrets=" + strings.Join(l.Secrets.Names, ",")
		if l.Secrets.Token {
			s += "+token"
		}
		if l.Secrets.All {
			s += "+all"
		}
		lines = append(lines, s+" code="+strconv.Itoa(len(l.CodeRuns))+" git="+strconv.Itoa(len(l.GitRuns)))
	}
	return lines
}

// TestLaterSteps: the steps after the agent and the background one beside
// it, with what each holds more than the agent: not the job's env, nor
// the agent's, nor the token a checkout left before it; codex's key, which
// goes to a proxy, is more. The code they run stops at the checkout that
// cleans; git does not.
func TestLaterSteps(t *testing.T) {
	src := `on:
  issues: {types: [opened]}
  issue_comment:
env:
  WF: ${{ secrets.WF }}
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      JOB: ${{ secrets.JOB }}
    steps:
      - uses: actions/checkout@v4
      - name: bg
        background: true
        run: sleep 60
        env: {BG: "${{ secrets.BG }}"}
      - id: agent
        uses: openai/codex-action@v1
        with: {openai-api-key: "${{ secrets.OPENAI }}", sandbox: danger-full-access}
        env: {AGENT: "${{ secrets.AGENT }}"}
      - name: same
        run: echo "${{ secrets.AGENT }} ${{ secrets.job }} ${{ secrets.wf }}"
      - name: openai
        run: curl -H "${{ secrets.OPENAI }}" x
      - name: comment only
        if: github.event_name == 'issue_comment'
        run: deploy
        env: {NPM: "${{ secrets.NPM }}", T: "${{ github.token }}"}
      - name: test
        run: npm test
      - uses: actions/checkout@v4
      - name: after-clean
        run: |
          npm test
          git commit -m x
`
	want := []string{
		"bg on=issue_comment,issues secrets=BG code=0 git=0",
		"same on=issue_comment,issues secrets= code=0 git=0",
		"openai on=issue_comment,issues secrets=OPENAI code=0 git=0",
		"comment only on=issue_comment secrets=NPM code=0 git=0",
		"test on=issue_comment,issues secrets= code=1 git=0",
		"steps[7] on=issue_comment,issues secrets= code=0 git=0",
		"after-clean on=issue_comment,issues secrets= code=0 git=1",
	}
	if got := laterOf(t, src, 2); !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestLaterStepsToken: ai-inference holds the job's token by its default;
// a checkout with persist-credentials false leaves none; a checkout's PAT
// is held; none after the last step; toJSON(secrets) is all.
func TestLaterStepsToken(t *testing.T) {
	src := `on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {persist-credentials: false}
      - uses: actions/checkout@v4
        with: {token: "${{ secrets.PAT }}", path: other}
      - uses: actions/ai-inference@v2
        with: {prompt: p}
      - run: gh issue comment 1 -b x
        env: {GH_TOKEN: "${{ github.token }}", P: "${{ secrets.PAT }}", A: "${{ toJSON(secrets) }}"}
`
	if got, want := laterOf(t, src, 2), []string{"steps[3] on=issues secrets=+all code=0 git=0"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	last := "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: openai/codex-action@v1\n"
	if got := laterOf(t, last, 0); len(got) != 0 {
		t.Errorf("last: %q", got)
	}
	notTrue := "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n        with: {persist-credentials: 'no'}\n      - uses: openai/codex-action@v1\n      - run: x\n        env: {T: \"${{ github.token }}\"}\n"
	if got, want := laterOf(t, notTrue, 1), []string{"steps[2] on=issues secrets=+token code=0 git=0"}; !slices.Equal(got, want) {
		t.Errorf("persist-credentials no: got %q, want %q", got, want)
	}
	noPersist := "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n        with: {persist-credentials: false}\n      - uses: openai/codex-action@v1\n      - run: x\n        env: {T: \"${{ github.token }}\"}\n"
	if got, want := laterOf(t, noPersist, 1), []string{"steps[2] on=issues secrets=+token code=0 git=0"}; !slices.Equal(got, want) {
		t.Errorf("no persist: got %q, want %q", got, want)
	}
	// a checkout that fails on its path writes no token
	refused := "on: issues\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        continue-on-error: true\n        with: {path: \"${{ runner.temp }}/x\"}\n      - uses: openai/codex-action@v1\n      - run: x\n        env: {T: \"${{ github.token }}\"}\n"
	if got, want := laterOf(t, refused, 1), []string{"steps[2] on=issues secrets=+token code=0 git=0"}; !slices.Equal(got, want) {
		t.Errorf("refused: got %q, want %q", got, want)
	}
}

// TestLaterStepsWorkingDirectory: codex's working-directory is the root of
// the code its edits reach.
func TestLaterStepsWorkingDirectory(t *testing.T) {
	src := "on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: openai/codex-action@v1\n        with: {working-directory: sub}\n      - run: npm test\n      - run: bash sub/x.sh\n"
	want := []string{"steps[1] on=issues secrets= code=0 git=0", "steps[2] on=issues secrets= code=1 git=0"}
	if got := laterOf(t, src, 0); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestLaterStepsContainerEnv: the agent runs in the job's container and
// holds its env; not the env of a service, which only the service's
// container has.
func TestLaterStepsContainerEnv(t *testing.T) {
	src := `on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    container:
      image: node:20
      env: {X: "${{ secrets.X }}"}
    services:
      db:
        image: postgres
        env: {Y: "${{ secrets.Y }}"}
    steps:
      - uses: openai/codex-action@v1
      - run: deploy
        env: {X: "${{ secrets.X }}", Y: "${{ secrets.Y }}"}
`
	if got, want := laterOf(t, src, 0), []string{"steps[1] on=issues secrets=Y code=0 git=0"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestLaterStepsParallel: the steps of a parallel group with the agent run
// beside it; those after the group, after it.
func TestLaterStepsParallel(t *testing.T) {
	src := `on: issues
jobs:
  a:
    runs-on: x
    steps:
      - parallel:
          - uses: openai/codex-action@v1
          - run: deploy
            env: {K: "${{ secrets.K }}"}
      - run: npm test
`
	want := []string{"steps[0].parallel[1] on=issues secrets=K code=0 git=0", "steps[1] on=issues secrets= code=1 git=0"}
	if got := laterOf(t, src, 0); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestLaterStepsEveryRun: on the events of everyRunOn, where a variable or
// a secret the attacker writes reaches the agent in a run anyone starts,
// a later step counts when its if lets the event through by the event
// alone (an if on the actor does not keep a run of anyone out); with no
// such events, the later steps are as before.
func TestLaterStepsEveryRun(t *testing.T) {
	src := "on: {issues: {types: [assigned]}, schedule: [{cron: '0 0 * * *'}]}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with: {prompt: \"${{ vars.P }}\"}\n      - if: github.event_name == 'schedule'\n        run: ./a\n      - if: github.actor == 'x'\n        run: ./b\n"
	w, _ := workflow.Parse(cst.Parse([]byte(src)))
	j := w.Jobs.Value.Entries[0].Value.Value
	steps := j.Steps.Value.Items
	a, ok := Of(steps[0])
	if !ok {
		t.Fatal("no agent step")
	}
	everyRun := taint.EventsOf(w, []workflow.EventName{workflow.EventNameIssues, workflow.EventNameSchedule})
	on := func(everyRunOn []analysis.EventActivity) []string {
		var out []string
		for _, l := range LaterSteps(attacker.TableOf(analysis.BarrierPasses{}.With(analysis.BarrierVariableValue)), w, &j, steps, 0, a, nil, everyRunOn, nil) {
			var names []string
			for _, e := range l.On {
				if !slices.Contains(names, e.Name().String()) {
					names = append(names, e.Name().String())
				}
			}
			slices.Sort(names)
			out = append(out, l.Name+" on="+strings.Join(names, ","))
		}
		return out
	}
	if got, want := on(everyRun), []string{"steps[1] on=schedule", "steps[2] on=issues,schedule"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := on(nil), []string{"steps[1] on=", "steps[2] on="}; !slices.Equal(got, want) {
		t.Errorf("no events: got %q, want %q", got, want)
	}
}

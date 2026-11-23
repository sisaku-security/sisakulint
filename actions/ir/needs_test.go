package ir

import (
	"testing"
)

// skippedBuild is a workflow on pull_request_target whose job build does
// not run (if: false), followed by more jobs.
const skippedBuild = "on: pull_request_target\njobs:\n  build:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"

// TestIfSiteNeedsSkipped: the if of a job that GitHub skips, as a job it
// needs is skipped, is read on no event (attacker.JobIfs); a job whose if
// calls always() runs after the skip.
func TestIfSiteNeedsSkipped(t *testing.T) {
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"github.event.pull_request.user.login == 'dependabot[bot]'", false},
		{"${{ always() && github.event.pull_request.user.login == 'dependabot[bot]' }}", true},
	} {
		x := newIR(t, skippedBuild+"  test:\n    needs: build\n    if: "+c.cond+"\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
		var got bool
		for _, s := range x.allIfSites() {
			got = got || len(s.attackerOn) > 0
		}
		if got != c.want {
			t.Errorf("%s: an if site on some event %v, want %v", c.cond, got, c.want)
		}
	}
}

// TestAgentStepNeedsResult: an agent step in a job whose if waits for the
// failure of a job it needs, with no status function, runs on no event.
func TestAgentStepNeedsResult(t *testing.T) {
	src := "on: issue_comment\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n  test:\n    needs: build\n    if: needs.build.result == 'failure'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: ${{ github.event.comment.body }}\n"
	steps := newIR(t, src).allAgentSteps()
	if len(steps) != 1 {
		t.Fatalf("%d steps", len(steps))
	}
	if len(steps[0].attackerOn) != 0 || len(steps[0].actorOn) != 0 {
		t.Errorf("attackerOn %v, actorOn %v, want none", steps[0].attackerOn, steps[0].actorOn)
	}
}

// TestCacheSaveOnCallerNeeds: a called workflow's job saves to the cache
// on no event of a caller whose job that calls it needs a job that does
// not run: the if of the caller's job is read in the caller's workflow.
func TestCacheSaveOnCallerNeeds(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    cache-mode: write\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
	for _, c := range []struct {
		cond string
		want bool
	}{
		{"", false},
		{"    if: always()\n", true},
	} {
		caller := skippedBuild + "  call:\n    needs: build\n" + c.cond + "    uses: ./.github/workflows/called.yml\n"
		x := labeledIR(t, ".github/workflows/called.yml", freeConfig,
			[2]string{".github/workflows/called.yml", called},
			[2]string{".github/workflows/ci.yml", caller})
		e, _ := x.workflow.Jobs.Value.Lookup("j")
		j := e.Value.Value
		if got := len(x.cacheSaveOn(&j)) > 0; got != c.want {
			t.Errorf("caller %q: saves on some event %v, want %v", c.cond, got, c.want)
		}
	}
}

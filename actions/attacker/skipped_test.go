package attacker

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// TestAfterSkipped: the if of a job that calls a status function is false
// when every job that the job depends on is skipped in the run and the if
// is false there (failure() false, success() false with needs, always()
// true); an if that may be true then, or a job with a job before it that
// may run, is not false.
func TestAfterSkipped(t *testing.T) {
	const steps = "    runs-on: u\n    steps:\n      - run: x\n"
	const skippedChain = "  a:\n    if: false\n" + steps + "  b:\n    needs: a\n" + steps
	prt := analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	push := analysis.MustEventActivity(workflow.EventNamePush, workflow.ActivityTypeUnset)
	for _, c := range []struct {
		name, on, jobs string
		e              analysis.EventActivity
		false_         bool
	}{
		{"failure after a skipped chain", "pull_request_target", skippedChain + "  test:\n    needs: b\n    if: failure()\n" + steps, prt, true},
		{"failure after a skipped job", "pull_request_target", skippedChain + "  test:\n    needs: a\n    if: failure()\n" + steps, prt, true},
		{"success or failure", "pull_request_target", skippedChain + "  test:\n    needs: b\n    if: success() || failure()\n" + steps, prt, true},
		{"failure with no needs", "pull_request_target", "  test:\n    if: failure()\n" + steps, prt, true},
		{"failure in a called workflow", "workflow_call", skippedChain + "  test:\n    needs: b\n    if: failure()\n" + steps, prt, true},
		{"always", "pull_request_target", skippedChain + "  test:\n    needs: b\n    if: always()\n" + steps, prt, false},
		{"not cancelled", "pull_request_target", skippedChain + "  test:\n    needs: b\n    if: ${{ !cancelled() }}\n" + steps, prt, false},
		{"cancelled", "pull_request_target", skippedChain + "  test:\n    needs: b\n    if: cancelled()\n" + steps, prt, false},
		{"always and the result", "pull_request_target", skippedChain + "  test:\n    needs: b\n    if: always() && needs.b.result == 'success'\n" + steps, prt, false},
		{"a job before that may run", "pull_request_target", skippedChain + "  c:\n" + steps + "  test:\n    needs: [b, c]\n    if: failure()\n" + steps, prt, false},
		{"a job before with always that runs", "pull_request_target", "  a:\n    if: false\n" + steps + "  b:\n    needs: a\n    if: always()\n" + steps + "  test:\n    needs: b\n    if: failure()\n" + steps, prt, false},
		{"success or failure with no needs", "pull_request_target", "  test:\n    if: success() || failure()\n" + steps, prt, false},
		{"not success with no needs", "pull_request_target", "  test:\n    if: ${{ !success() }}\n" + steps, prt, false},
		{"a cycle", "pull_request_target", "  a:\n    needs: test\n    if: false\n" + steps + "  test:\n    needs: a\n    if: failure()\n" + steps, prt, false},
		{"a need that names no job", "pull_request_target", "  test:\n    needs: [gone]\n    if: failure()\n" + steps, prt, false},
		{"skipped on push only, read on push", "[push, pull_request_target]", "  a:\n    if: github.event_name != 'push'\n" + steps + "  test:\n    needs: a\n    if: failure()\n" + steps, push, true},
		{"skipped on push only, read on pull_request_target", "[push, pull_request_target]", "  a:\n    if: github.event_name != 'push'\n" + steps + "  test:\n    needs: a\n    if: failure()\n" + steps, prt, false},
	} {
		w, j := workflowOf(t, "on: "+c.on+"\njobs:\n"+c.jobs)
		got := EventOnly(JobIf(w, &j), c.e)
		if (got == expr.TruthFalse) != c.false_ {
			t.Errorf("%s: EventOnly = %v, want false %v", c.name, got, c.false_)
		}
	}
}

// TestAfterSkippedReaders: the reading holds wherever the if of a job is
// read with its workflow (Table.Kept), and not for the if of a step or a
// job read with no workflow; EventNameOnly reads the jobs before by the
// event name, and NarrowsAnyEvent with no event; a job whose needs the
// model does not read is not read so.
func TestAfterSkippedReaders(t *testing.T) {
	const steps = "    runs-on: u\n    steps:\n      - run: x\n"
	prt := analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	w, j := workflowOf(t, "on: pull_request_target\njobs:\n  a:\n    if: false\n"+steps+"  b:\n    needs: a\n"+steps+"  test:\n    needs: b\n    if: failure()\n"+steps)
	if Outsider.Kept(JobIf(w, &j), prt) {
		t.Error("Kept: the job after a skipped chain is kept")
	}
	if StepIf(nil, nil, j.If).truth(eventOf(prt), eventLookup(prt), nil) == expr.TruthFalse {
		t.Error("StepIf: failure() is false")
	}
	if Outsider.JobCodeTruth(j.If, nil, prt, JobStateUnknown) == expr.TruthFalse {
		t.Error("JobCodeTruth: failure() is false")
	}
	w, j = workflowOf(t, "on: [push, pull_request_target]\njobs:\n  a:\n    if: github.event_name == 'push'\n"+steps+"  test:\n    needs: a\n    if: failure()\n"+steps)
	if got := EventNameOnly(JobIf(w, &j), workflow.EventNamePush); got == expr.TruthFalse {
		t.Errorf("EventNameOnly on push: %v, want not false: the job a may run and fail on push", got)
	}
	if got := EventNameOnly(JobIf(w, &j), workflow.EventNamePullRequestTarget); got != expr.TruthFalse {
		t.Errorf("EventNameOnly on pull_request_target: %v, want false", got)
	}
	w, j = workflowOf(t, "on: pull_request_target\njobs:\n  a:\n    if: github.event_name == 'pull_request_target'\n"+steps+"  test:\n    needs: a\n    if: failure() || github.head_ref == 'main'\n"+steps)
	if Outsider.NarrowingOf(JobIf(w, &j)).NarrowsAnyEvent(pathOf(t, "github.head_ref")) {
		t.Error("NarrowsAnyEvent: github.head_ref is narrowed, but the job a may run and fail, and then the job test runs with any github.head_ref")
	}
	call := analysis.MustEventActivity(workflow.EventNameWorkflowCall, workflow.ActivityTypeUnset)
	w, j = workflowOf(t, "on: workflow_call\njobs:\n  a:\n    if: github.event_name == 'pull_request_target'\n"+steps+"  test:\n    needs: a\n    if: failure()\n"+steps)
	if got := EventOnly(JobIf(w, &j), call); got == expr.TruthFalse {
		t.Errorf("a called run, the job a reads the event: %v, want not false: the event of the caller may be pull_request_target", got)
	}
	if got := EventNameOnly(JobIf(w, &j), workflow.EventNameWorkflowCall); got == expr.TruthFalse {
		t.Errorf("a called run by the event name, the job a reads the event: %v, want not false", got)
	}
	for _, cond := range []string{"github.event_name == 'pull_request_target'", "github.event_name != 'workflow_call'"} {
		w, j = workflowOf(t, "on: workflow_call\njobs:\n  test:\n    if: "+cond+"\n"+steps)
		if got := EventOnly(JobIf(w, &j), call); got != expr.TruthUnknown {
			t.Errorf("a called run, if %s: %v, want unknown: github.event_name is the caller's", cond, got)
		}
	}
	w, j = workflowOf(t, "on: pull_request_target\njobs:\n  test:\n    needs: {x: 1}\n    if: failure()\n"+steps)
	if got := EventOnly(JobIf(w, &j), prt); got == expr.TruthFalse {
		t.Errorf("needs that the model does not read: %v, want not false", got)
	}
}

// TestAfterSkippedLadder: a ladder of jobs whose ifs call failure(), each
// rung depending on both jobs of the rung before, after a job whose if is
// false, is read on every event of workflow_call in time that grows with
// the jobs, not with the paths through them.
func TestAfterSkippedLadder(t *testing.T) {
	const rungs = 30
	var b strings.Builder
	b.WriteString("on: workflow_call\njobs:\n  root:\n    if: false\n    runs-on: u\n    steps:\n      - run: x\n")
	for i := range rungs {
		for _, side := range []string{"a", "b"} {
			fmt.Fprintf(&b, "  j%d%s:\n", i, side)
			if i == 0 {
				b.WriteString("    needs: root\n")
			} else {
				fmt.Fprintf(&b, "    needs: [j%da, j%db]\n", i-1, i-1)
			}
			b.WriteString("    if: failure()\n    runs-on: u\n    steps:\n      - run: x\n")
		}
	}
	fmt.Fprintf(&b, "  test:\n    needs: [j%da, j%db]\n    if: failure()\n    runs-on: u\n    steps:\n      - run: x\n", rungs-1, rungs-1)
	w, j := workflowOf(t, b.String())
	for _, n := range workflow.EventNames() {
		if n == workflow.EventNameUnset {
			continue
		}
		types := workflow.ActivityTypesOf(n)
		if len(types) == 0 {
			types = []workflow.ActivityType{workflow.ActivityTypeUnset}
		}
		for _, a := range types {
			e := analysis.MustEventActivity(n, a)
			for _, p := range JobIfs(w, &j) {
				if got := EventOnly(p, e); got != expr.TruthFalse {
					t.Fatalf("%v: %v, want false", e, got)
				}
			}
		}
	}
}

// TestAfterSkippedBots: after a job whose if is false, failure() is false,
// so a job whose if is failure() or a comparison of the actor with a bot
// runs only in the run of that bot: the comparison lets the bot in
// (OtherBots, DependabotBypasses), where with failure() not known it did
// not decide whether the job runs. DependabotBypasses, SubstringBypasses
// and LabelTruth, which set the value of a comparison or of the labels by
// an override, read the if after skipped jobs with that value too.
func TestAfterSkippedBots(t *testing.T) {
	const steps = "    runs-on: u\n    steps:\n      - run: x\n"
	syn := []analysis.EventActivity{analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)}
	src := func(cond string) string {
		return "on: pull_request_target\njobs:\n  a:\n    if: false\n" + steps + "  test:\n    needs: a\n    if: " + cond + "\n" + steps
	}
	w, j := workflowOf(t, src("failure() || github.actor == 'renovate[bot]'"))
	if got := OtherBots(JobIf(w, &j), syn); len(got) != 1 {
		t.Errorf("failure() or renovate: %d other bots, want 1", len(got))
	}
	for _, cond := range []string{"github.actor == 'dependabot[bot]' || (failure() && github.actor != 'dependabot[bot]')", "github.actor == 'dependabot[bot]' || failure()", "contains('dependabot[bot]', github.actor) || failure()"} {
		w, j = workflowOf(t, src(cond))
		if got := DependabotBypasses(JobIf(w, &j), syn); len(got) != 1 {
			t.Errorf("%s: %d dependabot bypasses, want 1", cond, len(got))
		}
	}
	w, j = workflowOf(t, src("contains('octocat-admin', github.actor) || failure()"))
	if got := SubstringBypasses(JobIf(w, &j), syn); len(got) != 1 {
		t.Errorf("a part of a name or failure(): %d substring bypasses, want 1", len(got))
	}
	// a reading that gives the value of a node by an override (the labels of
	// LabelTruth) reads the if after skipped jobs with it too
	labeled := analysis.MustEventActivity(workflow.EventNamePullRequestTarget, workflow.ActivityTypeLabeled)
	w, j = workflowOf(t, src("failure() || contains(github.event.pull_request.labels.*.name, 'ok')"))
	if got := Outsider.LabelTruth(JobIf(w, &j), labeled, "other", []string{"other"}); got != expr.TruthFalse {
		t.Errorf("failure() or the label ok, labeled other: %v, want false", got)
	}
	if got := Outsider.LabelTruth(JobIf(w, &j), labeled, "ok", []string{"ok"}); got == expr.TruthFalse {
		t.Errorf("failure() or the label ok, labeled ok: %v, want not false", got)
	}
}

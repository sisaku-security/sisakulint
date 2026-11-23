package attacker

import (
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// stepIfOn is the if cond, written as a double-quoted YAML string, of the
// one step of a workflow whose on is on; with no cond the step has no if.
func stepIfOn(t *testing.T, on, cond string) workflow.Field[workflow.If] {
	t.Helper()
	src := "on: " + on + "\njobs:\n  a:\n    runs-on: u\n    steps:\n      - run: x\n"
	if cond != "" {
		src += "        if: \"" + cond + "\"\n"
	}
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	if w == nil {
		t.Fatalf("no workflow of %q", src)
	}
	e, _ := w.Jobs.Value.Lookup("a")
	return e.Value.Value.Steps.Value.Items[0].If
}

type truthCase struct {
	cond string
	want expr.Truth
}

func checkCodeTruth(t *testing.T, s JobState, cases []truthCase) {
	t.Helper()
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	for _, c := range cases {
		if got := Outsider.CodeTruth(StepIf(nil, nil, stepIfOn(t, "pull_request_target", c.cond)), prt, s); got != c.want {
			t.Errorf("%s, %q: got %v, want %v", s, c.cond, got, c.want)
		}
	}
}

// TestCodeTruthFailed: after a step failed, success() and cancelled() are
// false, failure() and always() true, and an if with no status function
// is false (success() && is added); a folded literal is read as its
// string.
func TestCodeTruthFailed(t *testing.T) {
	checkCodeTruth(t, JobStateFailed, []truthCase{
		{"", expr.TruthFalse},
		{"success()", expr.TruthFalse},
		{"${{ 'success()' }}", expr.TruthFalse},
		{"'always()'", expr.TruthFalse},
		{"cancelled()", expr.TruthFalse},
		{"(failure() && github.event.pull_request.head.repo.full_name == github.repository) || (success() && github.event.pull_request.head.repo.fork)", expr.TruthFalse},
		{"github.event.pull_request.head.repo.fork", expr.TruthFalse},
		{"failure()", expr.TruthTrue},
		{"always()", expr.TruthTrue},
		{"${{ always() }}", expr.TruthTrue},
		{"always ()", expr.TruthTrue},
		{"${{ 'always()' }}", expr.TruthTrue},
		{"!cancelled()", expr.TruthTrue},
		{"a ${{ always() }}", expr.TruthTrue},
		{"a ${{ github.actor }}", expr.TruthFalse},
		{"failure() && github.event.pull_request.head.repo.fork", expr.TruthUnknown},
	})
}

// TestCodeTruthCancelled: in a cancelled run, cancelled() and always() are
// true, failure() and success() false.
func TestCodeTruthCancelled(t *testing.T) {
	checkCodeTruth(t, JobStateCancelled, []truthCase{
		{"cancelled()", expr.TruthTrue},
		{"always()", expr.TruthTrue},
		{"failure()", expr.TruthFalse},
		{"success()", expr.TruthFalse},
		{"", expr.TruthFalse},
	})
}

// TestCodeTruthSucceeded: with no failure and no cancel, success() and
// always() are true, failure() and cancelled() false, and an if that calls
// no status function is read as written.
func TestCodeTruthSucceeded(t *testing.T) {
	checkCodeTruth(t, JobStateSucceeded, []truthCase{
		{"", expr.TruthTrue},
		{"success()", expr.TruthTrue},
		{"always()", expr.TruthTrue},
		{"failure()", expr.TruthFalse},
		{"cancelled()", expr.TruthFalse},
		{"success() || cancelled()", expr.TruthTrue},
		{"github.event.pull_request.head.repo.full_name == github.repository", expr.TruthFalse},
		{"github.event.pull_request.head.repo.fork", expr.TruthUnknown},
	})
}

// TestCodeTruthUnknown: with the job's state not known, every status
// function is not known; a folded literal is read as its string.
func TestCodeTruthUnknown(t *testing.T) {
	checkCodeTruth(t, JobStateUnknown, []truthCase{
		{"", expr.TruthTrue},
		{"github.event.pull_request.head.repo.full_name == github.repository", expr.TruthFalse},
		{"github.event.pull_request.head.repo.fork", expr.TruthUnknown},
		{"${{ 'github.event.pull_request.head.repo.full_name == github.repository' }}", expr.TruthFalse},
		{"always()", expr.TruthUnknown},
		{"a ${{ github.actor }}", expr.TruthTrue},
		{"'false'", expr.TruthTrue}, // a string, not folded
	})
}

func TestActorTruth(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	if got := Outsider.ActorTruth(StepIf(nil, nil, stepIfOn(t, "pull_request_target", "always()")), prt, JobStateFailed); got != expr.TruthTrue {
		t.Errorf("always() after a failure: got %v", got)
	}
	if got := Outsider.ActorTruth(StepIf(nil, nil, stepIfOn(t, "pull_request_target", "")), prt, JobStateFailed); got != expr.TruthFalse {
		t.Errorf("no if after a failure: got %v", got)
	}
}

// TestCodeTruthEventOnly: an event without runs is read by github.event_name
// and github.event.action, with the job's state.
func TestCodeTruthEventOnly(t *testing.T) {
	push := ev(workflow.EventNamePush, workflow.ActivityTypeUnset)
	for _, c := range []struct {
		cond string
		s    JobState
		want expr.Truth
	}{
		{"", JobStateFailed, expr.TruthFalse},
		{"always()", JobStateFailed, expr.TruthTrue},
		{"github.event_name == 'push'", JobStateUnknown, expr.TruthTrue},
	} {
		if got := Outsider.CodeTruth(StepIf(nil, nil, stepIfOn(t, "push", c.cond)), push, c.s); got != c.want {
			t.Errorf("%s, %q: got %v, want %v", c.s, c.cond, got, c.want)
		}
	}
}

// TestKeptCodeAgreesWithCodeTruth: KeptCode is CodeTruth with the job's
// state not known, not false, also for an if of exactly ${{ 'x' }}.
func TestKeptCodeAgreesWithCodeTruth(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	for _, cond := range []string{"", "github.event.pull_request.head.repo.full_name == github.repository", "github.event.pull_request.head.repo.fork", "always()", "a ${{ github.actor }}", "github.event.pull_request.user.login == 'octocat'", "${{ 'github.event.pull_request.head.repo.full_name == github.repository' }}"} {
		c := stepIfOn(t, "pull_request_target", cond)
		if kept, truth := Outsider.KeptCode(StepIf(nil, nil, c), prt), Outsider.CodeTruth(StepIf(nil, nil, c), prt, JobStateUnknown); kept != (truth != expr.TruthFalse) {
			t.Errorf("%q: KeptCode %v, CodeTruth %v", cond, kept, truth)
		}
	}
}

// TestCodeTruthJobStatus: job.status is the status of the job that the
// state tells (success, failure or cancelled); an if that calls no status
// function has success() && added.
func TestCodeTruthJobStatus(t *testing.T) {
	checkCodeTruth(t, JobStateFailed, []truthCase{
		{"${{ always() && job.status == 'failure' }}", expr.TruthTrue},
		{"job.status == 'failure'", expr.TruthFalse},
	})
	checkCodeTruth(t, JobStateSucceeded, []truthCase{
		{"${{ always() && job.status == 'failure' }}", expr.TruthFalse},
		{"job.status == 'success'", expr.TruthTrue},
	})
	checkCodeTruth(t, JobStateCancelled, []truthCase{
		{"${{ always() && job.status == 'cancelled' }}", expr.TruthTrue},
	})
	checkCodeTruth(t, JobStateUnknown, []truthCase{
		{"${{ always() && job.status == 'failure' }}", expr.TruthUnknown},
	})
}

// jobIfOn is the if cond, written as a double-quoted YAML string, of the
// job c of a workflow on pull_request_target whose jobs are build (with the
// continue-on-error coe, none when empty) and c, which needs build; and the
// job build.
func jobIfOn(t *testing.T, cond, coe string) (workflow.Field[workflow.If], workflow.Job) {
	t.Helper()
	src := "on: pull_request_target\njobs:\n  build:\n    runs-on: u\n"
	if coe != "" {
		src += "    continue-on-error: " + coe + "\n"
	}
	src += "    steps:\n      - run: x\n  c:\n    needs: build\n    if: \"" + cond + "\"\n    runs-on: u\n    steps:\n      - run: x\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	if w == nil {
		t.Fatalf("no workflow of %q", src)
	}
	b, _ := w.Jobs.Value.Lookup("build")
	c, _ := w.Jobs.Value.Lookup("c")
	return c.Value.Value.If, b.Value.Value
}

// TestJobCodeTruthNeedsResult: the if of a job reads needs.<id>.result of
// a job it needs directly: success when every job it depends on succeeded,
// failure after a failure when the job fails; not for a job it does not
// need.
func TestJobCodeTruthNeedsResult(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	for _, c := range []struct {
		cond, coe string
		fails     bool
		s         JobState
		want      expr.Truth
	}{
		{"needs.build.result == 'failure'", "", false, JobStateSucceeded, expr.TruthFalse},
		{"needs.build.result == 'success'", "", false, JobStateSucceeded, expr.TruthTrue},
		{"needs['build'].result == 'success'", "", false, JobStateSucceeded, expr.TruthTrue},
		{"needs.BUILD.result == 'success'", "", false, JobStateSucceeded, expr.TruthTrue},
		// a job whose continue-on-error is true and that failed has the result success (observed on 2026-11-16)
		{"needs.build.result == 'success'", "true", false, JobStateSucceeded, expr.TruthTrue},
		{"needs.build.result == 'success'", "${{ vars.C }}", false, JobStateSucceeded, expr.TruthTrue},
		{"needs.build.result == 'success'", "false", false, JobStateSucceeded, expr.TruthTrue},
		{"needs.other.result == 'failure'", "", false, JobStateSucceeded, expr.TruthUnknown},
		{"${{ always() && needs.build.result == 'failure' }}", "", true, JobStateFailed, expr.TruthTrue},
		{"${{ always() && needs.build.result == 'failure' }}", "", false, JobStateFailed, expr.TruthUnknown},
		{"${{ always() && needs.build.result == 'failure' }}", "", true, JobStateUnknown, expr.TruthUnknown},
	} {
		cond, build := jobIfOn(t, c.cond, c.coe)
		needs := []Need{{Job: build, Fails: c.fails}}
		if got := Outsider.JobCodeTruth(cond, needs, prt, c.s); got != c.want {
			t.Errorf("JobCodeTruth %s, %q, continue-on-error %q, fails %v: got %v, want %v", c.s, c.cond, c.coe, c.fails, got, c.want)
		}
		if got := Outsider.JobActorTruth(cond, needs, prt, c.s); got != c.want {
			t.Errorf("JobActorTruth %s, %q, continue-on-error %q, fails %v: got %v, want %v", c.s, c.cond, c.coe, c.fails, got, c.want)
		}
	}
	// CodeTruth does not read needs
	cond, _ := jobIfOn(t, "needs.build.result == 'failure'", "")
	if got := Outsider.CodeTruth(StepIf(nil, nil, cond), prt, JobStateSucceeded); got != expr.TruthUnknown {
		t.Errorf("CodeTruth: got %v, want %v", got, expr.TruthUnknown)
	}
}

// TestJobCodeTruthNeedsResultNoStatus: an if of a job that calls no status
// function is read only when every job it depends on directly succeeded,
// so needs.<id>.result of such a job is success, and needs.*.result is
// success for each, whether the job surely runs or not; an if that calls
// one reads needs.*.result as not known.
func TestJobCodeTruthNeedsResultNoStatus(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	for _, c := range []struct {
		cond        string
		runs, fails bool
		none        bool // the job has no needs
		s           JobState
		want        expr.Truth
	}{
		{"needs.build.result == 'failure'", false, false, false, JobStateSucceeded, expr.TruthFalse},
		{"needs.Build.result == 'success'", false, false, false, JobStateSucceeded, expr.TruthTrue},
		{"contains(needs.*.result, 'failure')", false, false, false, JobStateSucceeded, expr.TruthFalse},
		{"contains(needs.*.result, 'success')", false, false, false, JobStateSucceeded, expr.TruthTrue},
		{"contains(needs.*.result, 'success')", false, false, true, JobStateSucceeded, expr.TruthFalse},
		{"${{ always() && contains(needs.*.result, 'skipped') }}", true, false, false, JobStateSucceeded, expr.TruthUnknown},
		{"${{ always() && contains(needs.*.result, 'failure') }}", true, true, false, JobStateFailed, expr.TruthUnknown},
		{"${{ always() && needs.build.result == 'failure' }}", true, false, false, JobStateSucceeded, expr.TruthFalse},
		{"${{ always() && needs.build.result == 'failure' }}", false, false, false, JobStateSucceeded, expr.TruthUnknown},
		// success() && X is true only when success() is true, as an if with no status function is
		{"${{ success() && needs.build.result == 'failure' }}", false, false, false, JobStateSucceeded, expr.TruthFalse},
		{"${{ success() && contains(needs.*.result, 'failure') }}", false, false, false, JobStateSucceeded, expr.TruthFalse},
	} {
		cond, build := jobIfOn(t, c.cond, "")
		needs := []Need{{Job: build, Fails: c.fails, SurelyRuns: c.runs}}
		if c.none {
			needs = nil
		}
		if got := Outsider.JobCodeTruth(cond, needs, prt, c.s); got != c.want {
			t.Errorf("JobCodeTruth %s, %q, surely runs %v, no needs %v: got %v, want %v", c.s, c.cond, c.runs, c.none, got, c.want)
		}
		if got := Outsider.JobActorTruth(cond, needs, prt, c.s); got != c.want {
			t.Errorf("JobActorTruth %s, %q, surely runs %v, no needs %v: got %v, want %v", c.s, c.cond, c.runs, c.none, got, c.want)
		}
	}
	// the if of a step does not read needs.*.result
	cond, _ := jobIfOn(t, "contains(needs.*.result, 'failure')", "")
	if got := Outsider.CodeTruth(StepIf(nil, nil, cond), prt, JobStateSucceeded); got != expr.TruthUnknown {
		t.Errorf("CodeTruth: got %v, want %v", got, expr.TruthUnknown)
	}
}

// TestLabelTruthJobIfNeedsResult: the if of a job that waits for a label
// reads the needs context of the job as JobCodeTruth reads it in a job
// whose state is not known.
func TestLabelTruthJobIfNeedsResult(t *testing.T) {
	_, pre := jobIfOn(t, "x", "")
	pre.ID = jobIDOf(t, "pre")
	needs := []Need{{Job: pre}}
	for _, c := range []struct {
		cond string
		want expr.Truth
	}{
		{"github.event.label.name == 'safe-to-test' && needs.pre.result == 'failure'", expr.TruthFalse},
		{"github.event.label.name == 'safe-to-test' && needs.pre.result == 'success'", expr.TruthTrue},
		{"contains(github.event.pull_request.labels.*.name, 'safe-to-test') && contains(needs.*.result, 'failure')", expr.TruthFalse},
		{"${{ always() && github.event.label.name == 'safe-to-test' && needs.pre.result == 'failure' }}", expr.TruthUnknown},
	} {
		c0, e := labeledIf(t, c.cond)
		job := PlacedIf{c: c0, job: &jobIf{needs: needs}}
		if got := Outsider.LabelTruth(job, e, "safe-to-test", []string{"safe-to-test"}); got != c.want {
			t.Errorf("LabelTruth of a job's if %q: got %v, want %v", c.cond, got, c.want)
		}
		if got := Outsider.LabelTruth(StepIf(nil, nil, c0), e, "safe-to-test", []string{"safe-to-test"}); c.want == expr.TruthFalse && got == expr.TruthFalse {
			t.Errorf("LabelTruth of a step's if %q reads needs: got %v", c.cond, got)
		}
		if got := Outsider.Truth(job, e, RunOwn); c.want == expr.TruthFalse && got != expr.TruthFalse {
			t.Errorf("Truth of a job's if %q: got %v, want %v", c.cond, got, expr.TruthFalse)
		}
	}
}

// jobIDOf is the ID of a job named id.
func jobIDOf(t *testing.T, id string) workflow.String {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte("on: push\njobs:\n  "+id+":\n    runs-on: u\n    steps:\n      - run: x\n"), cst.ModeGitHub))
	return w.Jobs.Value.Entries[0].Value.Value.ID
}

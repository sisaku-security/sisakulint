package attacker

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// workflowOf is the workflow src and its job test.
func workflowOf(t *testing.T, src string) (*workflow.Workflow, workflow.Job) {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	e, ok := w.Jobs.Value.Lookup("test")
	if !ok {
		t.Fatalf("no job test in %q", src)
	}
	return w, e.Value.Value
}

func TestJobIfs(t *testing.T) {
	const build = "  build:\n    if: false\n    runs-on: u\n    steps:\n      - run: x\n"
	for _, c := range []struct {
		name, jobs string
		want       []string
	}{
		{"no if", build + "  test:\n    needs: build\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test", "build"}},
		{"always", build + "  test:\n    needs: build\n    if: always()\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test"}},
		{"success and", build + "  test:\n    needs: build\n    if: success() && github.event_name == 'push'\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test", "build"}},
		{"two steps", build + "  mid:\n    needs: build\n    runs-on: u\n    steps:\n      - run: x\n  test:\n    needs: mid\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test", "mid", "build"}},
		{"two steps, always in the middle", build + "  mid:\n    needs: build\n    if: always()\n    runs-on: u\n    steps:\n      - run: x\n  test:\n    needs: mid\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test", "mid"}},
		{"cycle", "  build:\n    needs: test\n    runs-on: u\n    steps:\n      - run: x\n  test:\n    needs: build\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test", "build"}},
		{"no such job", "  test:\n    needs: [nothing]\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test"}},
		{"case", build + "  test:\n    needs: Build\n    runs-on: u\n    steps:\n      - run: x\n", []string{"test", "build"}},
	} {
		w, j := workflowOf(t, "on: push\njobs:\n"+c.jobs)
		var got []string
		for _, n := range NeedJobs(w, &j) {
			got = append(got, n.ID.AsString())
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: NeedJobs %v, want %v", c.name, got, c.want)
		}
		if n := len(JobIfs(w, &j)); n != len(c.want) {
			t.Errorf("%s: %d JobIfs, want %d", c.name, n, len(c.want))
		}
	}
	_, j := workflowOf(t, "on: push\njobs:\n"+build+"  test:\n    needs: build\n    runs-on: u\n    steps:\n      - run: x\n")
	if got := NeedJobs(nil, &j); len(got) != 1 || got[0].ID.AsString() != "test" {
		t.Errorf("NeedJobs with no workflow: %v, want test alone", got)
	}
}

// TestPlacedIfReadsNeeds: the if of a job reads needs.<id>.result and
// needs.*.result of the jobs it depends on directly; the if of a step
// does not.
func TestPlacedIfReadsNeeds(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	title := []expr.PathElem{{Name: "github"}, {Name: "event"}, {Name: "pull_request"}, {Name: "title"}}
	for _, c := range []struct {
		cond     string
		job      bool // false: the job's if is false in every run
		step     bool // false: the step's if is false in every run
		hasNeeds bool
	}{
		{"needs.build.result == 'failure'", false, true, true},
		{"needs.build.result == 'success'", true, true, true},
		{"contains(needs.*.result, 'failure')", false, true, true},
		{"${{ always() && contains(needs.*.result, 'failure') }}", true, true, true},
		{"${{ success() && needs.build.result == 'failure' }}", false, true, true},
		// no needs: needs.*.result is an empty array
		{"contains(needs.*.result, 'success')", false, true, false},
	} {
		src := "on: pull_request_target\njobs:\n  build:\n    runs-on: u\n    steps:\n      - run: x\n  test:\n"
		if c.hasNeeds {
			src += "    needs: build\n"
		}
		src += "    if: " + c.cond + "\n    runs-on: u\n    steps:\n      - run: x\n"
		w, j := workflowOf(t, src)
		job, step := JobIf(w, &j), StepIf(nil, nil, j.If)
		for _, r := range []struct {
			name string
			p    PlacedIf
			want bool
		}{{"job", job, c.job}, {"step", step, c.step}} {
			if got := Outsider.Kept(r.p, prt); got != r.want {
				t.Errorf("Kept of the %s's if %q: got %v, want %v", r.name, c.cond, got, r.want)
			}
			if got := Outsider.KeptCode(r.p, prt); got != r.want {
				t.Errorf("KeptCode of the %s's if %q: got %v, want %v", r.name, c.cond, got, r.want)
			}
			if got := Outsider.KeptActor(r.p, prt); got != r.want {
				t.Errorf("KeptActor of the %s's if %q: got %v, want %v", r.name, c.cond, got, r.want)
			}
			if got := Outsider.KeptValue(r.p, prt, title, "x"); got != r.want {
				t.Errorf("KeptValue of the %s's if %q: got %v, want %v", r.name, c.cond, got, r.want)
			}
			if got := EventOnly(r.p, prt) != expr.TruthFalse; got != r.want {
				t.Errorf("EventOnly of the %s's if %q: not false %v, want %v", r.name, c.cond, got, r.want)
			}
			if !r.want && Outsider.KeptOthers(r.p, prt, title) {
				t.Errorf("KeptOthers of the %s's if %q: true, want false", r.name, c.cond)
			}
		}
	}
	// with no workflow, the needs of the job are not known: read as a step's
	_, j := workflowOf(t, "on: pull_request_target\njobs:\n  test:\n    if: contains(needs.*.result, 'success')\n    runs-on: u\n    steps:\n      - run: x\n")
	if !Outsider.Kept(JobIf(nil, &j), prt) {
		t.Error("Kept of JobIf with no workflow: false, want true")
	}
}

// TestNeedJobsIfForms: the job gate, which the job label needs, is
// followed while the if of label is true only when success() is true,
// read by the syntax (always () is always()).
func TestNeedJobsIfForms(t *testing.T) {
	for _, c := range []struct {
		name, labelIf string
		withGate      bool
	}{
		{"no if", "", true},
		{"always()", "${{ always() }}", false},
		{"always ()", "${{ always () }}", false},
		{"ALWAYS()", "ALWAYS()", false},
		{"failure() or", "failure() || github.event_name == 'push'", false},
		{"success() and", "success() && github.event_name == 'push'", true},
		{"a string with always()", "${{ !contains(github.event.pull_request.title, 'always()') }}", true},
		{"a context named success", "steps.success.outputs.x == 'y'", true},
		{"a syntax error", "${{ always( }}", true},
		{"always() in a mixed if", "${{ always() }} && true", false},
		{"always() in a folded string", "${{ 'always()' }}", false},
		{"a folded string with no status function", "${{ 'github.event_name == ''push''' }}", true},
		// a string literal with no ${{ }} is an expression of a string, which
		// calls no function
		{"a string literal with always()", "'always()'", true},
		{"a mixed if with no status function", "${{ github.event_name }} == push", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := "on: pull_request_target\njobs:\n  gate:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n  test:\n    needs: gate\n"
			if c.labelIf != "" {
				src += "    if: \"" + c.labelIf + "\"\n"
			}
			src += "    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
			w, j := workflowOf(t, src)
			got := len(NeedJobs(w, &j)) == 2
			if got != c.withGate {
				t.Errorf("gate followed: %v, want %v", got, c.withGate)
			}
		})
	}
}

// TestEventNameOnly: an if read with github.event_name alone; the if of a
// job also reads the results of the jobs it depends on directly.
func TestEventNameOnly(t *testing.T) {
	for _, c := range []struct {
		cond string // the step's if, as written after "if: "; empty for none
		e    workflow.EventName
		want bool // not false
	}{
		{"", workflow.EventNamePush, true},
		{"github.event_name != 'push'", workflow.EventNamePush, false},
		{"github.event_name != 'push'", workflow.EventNamePullRequest, true},
		{"${{ github.event_name == 'push' }}", workflow.EventNamePullRequest, false},
		{"${{ github.event_name == 'push' }}", workflow.EventNamePush, true},
		{"github.ref == 'refs/heads/main'", workflow.EventNamePush, true},
		{"github.event_name == 'push' && github.ref == 'refs/heads/main'", workflow.EventNamePullRequest, false},
		{"always() && github.event_name == 'push'", workflow.EventNamePullRequest, false},
		{"\"${{ github.event_name }} == 'push'\"", workflow.EventNamePullRequest, true}, // text around: a string, always true
	} {
		src := "on: push\njobs:\n  test:\n    runs-on: x\n    steps:\n      - run: a\n"
		if c.cond != "" {
			src += "        if: " + c.cond + "\n"
		}
		_, j := workflowOf(t, src)
		s := j.Steps.Value.Items[0]
		if got := EventNameOnly(StepIf(nil, nil, s.If), c.e) != expr.TruthFalse; got != c.want {
			t.Errorf("%q on %v: %v, want %v", c.cond, c.e, got, c.want)
		}
	}
	w, j := workflowOf(t, "on: push\njobs:\n  build:\n    runs-on: x\n    steps:\n      - run: a\n  test:\n    needs: build\n    if: needs.build.result == 'failure'\n    runs-on: x\n    steps:\n      - run: a\n")
	if got := EventNameOnly(JobIf(w, &j), workflow.EventNamePush); got != expr.TruthFalse {
		t.Errorf("the job's if: %v, want false", got)
	}
	if got := EventNameOnly(StepIf(nil, nil, j.If), workflow.EventNamePush); got == expr.TruthFalse {
		t.Errorf("the same if as a step's: false, want not false")
	}
}

// TestPlacedIfComparisons: the readers of the comparisons of an if read
// the if of a job with the results of the jobs it depends on directly.
func TestPlacedIfComparisons(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	headRef := []expr.PathElem{{Name: "github"}, {Name: "head_ref"}}
	src := func(cond string) string {
		return "on: pull_request_target\njobs:\n  build:\n    runs-on: u\n    steps:\n      - run: x\n  test:\n    needs: build\n    if: " + cond + "\n    runs-on: u\n    steps:\n      - run: x\n"
	}
	w, j := workflowOf(t, src("${{ needs.build.result == 'failure' || github.head_ref == 'release' }}"))
	if !Outsider.NarrowingOf(JobIf(w, &j)).Narrows(prt, headRef) {
		t.Error("the job's if: does not narrow github.head_ref")
	}
	if Outsider.NarrowingOf(StepIf(nil, nil, j.If)).Narrows(prt, headRef) {
		t.Error("the same if as a step's: narrows github.head_ref")
	}
	// a run of Dependabot pushes to its pull request (synchronize)
	syn := []analysis.EventActivity{ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeSynchronize)}
	w, j = workflowOf(t, src("${{ needs.build.result == 'failure' || github.actor == 'dependabot[bot]' }}"))
	if got := DependabotBypasses(JobIf(w, &j), syn); len(got) != 1 {
		t.Errorf("the job's if: %d bypasses, want 1", len(got))
	}
	if got := DependabotBypasses(StepIf(nil, nil, j.If), syn); len(got) != 0 {
		t.Errorf("the same if as a step's: %d bypasses, want 0", len(got))
	}
}

// TestStepIfReadsNeeds: the if of a step of a job whose if is true only
// when success() is true reads needs.<id>.result of the jobs the job
// depends on directly as success, in every JobState; the if of a step of
// any other job, or of a step whose job is not given, does not.
func TestStepIfReadsNeeds(t *testing.T) {
	prt := ev(workflow.EventNamePullRequestTarget, workflow.ActivityTypeOpened)
	headRef := []expr.PathElem{{Name: "github"}, {Name: "head_ref"}}
	src := func(jobIf, needs, stepIf string) string {
		s := "on: pull_request_target\njobs:\n  build:\n    runs-on: u\n    steps:\n      - run: x\n  test:\n"
		if needs != "" {
			s += "    needs: " + needs + "\n"
		}
		if jobIf != "" {
			s += "    if: " + jobIf + "\n"
		}
		return s + "    runs-on: u\n    steps:\n      - if: " + stepIf + "\n        run: x\n"
	}
	for _, c := range []struct {
		name, jobIf, needs, stepIf string
		false_                     bool // the step's if is false in every run
	}{
		{"no if, failure result", "", "build", "needs.build.result == 'failure'", true},
		{"no if, success result", "", "build", "needs.build.result == 'success'", false},
		{"no if, star failure", "", "build", "contains(needs.*.result, 'failure')", true},
		{"no if, star success", "", "build", "${{ !contains(needs.*.result, 'success') }}", true},
		{"no if, case of the ID", "", "Build", "needs.BUILD.result != 'success'", true},
		{"success and", "success() && github.event_name == 'pull_request_target'", "build", "needs.build.result == 'failure'", true},
		{"after a failed step", "", "build", "failure() && needs.build.result == 'failure'", true},
		{"no needs, star success", "", "", "contains(needs.*.result, 'success')", true},
		{"always()", "always()", "build", "needs.build.result == 'failure'", false},
		{"success() or failure()", "success() || failure()", "build", "needs.build.result == 'failure'", false},
		// a step reads the state of the steps before it, not the jobs before
		// the job (afterSkipped is not read for a step)
		{"failure() of a step of a job with no needs", "", "", "failure()", false},
	} {
		w, j := workflowOf(t, src(c.jobIf, c.needs, c.stepIf))
		p := StepIf(w, &j, j.Steps.Value.Items[0].If)
		if got := !Outsider.Kept(p, prt); got != c.false_ {
			t.Errorf("%s: Kept is false %v, want %v", c.name, got, c.false_)
		}
		if got := EventOnly(p, prt) == expr.TruthFalse; got != c.false_ {
			t.Errorf("%s: EventOnly is false %v, want %v", c.name, got, c.false_)
		}
		if got := EventNameOnly(p, workflow.EventNamePullRequestTarget) == expr.TruthFalse; got != c.false_ {
			t.Errorf("%s: EventNameOnly is false %v, want %v", c.name, got, c.false_)
		}
		for _, s := range []JobState{JobStateUnknown, JobStateSucceeded, JobStateFailed} {
			if c.stepIf == "failure()" || !c.false_ && s == JobStateFailed {
				continue // false by the state alone: success() && is added to an if that calls no status function
			}
			if got := Outsider.CodeTruth(p, prt, s) == expr.TruthFalse; got != c.false_ {
				t.Errorf("%s: CodeTruth in %v is false %v, want %v", c.name, s, got, c.false_)
			}
		}
		// with no workflow or no job, needs is not read
		for _, q := range []PlacedIf{StepIf(nil, &j, j.Steps.Value.Items[0].If), StepIf(w, nil, j.Steps.Value.Items[0].If)} {
			if c.false_ && !Outsider.Kept(q, prt) {
				t.Errorf("%s: Kept with no workflow or job: false, want true", c.name)
			}
		}
	}
	w, j := workflowOf(t, src("", "build", "${{ needs.build.result == 'failure' || github.head_ref == 'release' }}"))
	if !Outsider.NarrowingOf(StepIf(w, &j, j.Steps.Value.Items[0].If)).Narrows(prt, headRef) {
		t.Error("the step's if: does not narrow github.head_ref")
	}
	w, j = workflowOf(t, src("always()", "build", "${{ needs.build.result == 'failure' || github.head_ref == 'release' }}"))
	if Outsider.NarrowingOf(StepIf(w, &j, j.Steps.Value.Items[0].If)).Narrows(prt, headRef) {
		t.Error("the step's if in a job whose if is always(): narrows github.head_ref")
	}
}

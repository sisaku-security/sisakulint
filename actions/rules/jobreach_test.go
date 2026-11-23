package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// unrunJobs are the rewrites of TestUnrunJobsReadAlike: the job that each
// job of the example with no needs then needs (zzpre, which runs, zzskip,
// whose if is false, or none), and the if of such a job. GitHub runs none
// of the jobs of the example in any of them: an if that calls no status
// function is read only when every job its job needs succeeded, and a job
// is skipped when a job it needs is skipped; failure() is false when no job
// before fails, and success() is false after a skipped job.
var unrunJobs = []struct{ name, need, job string }{
	{"needs result", "zzpre", "needs.zzpre.result == 'failure'"},
	{"if false", "zzpre", "false"},
	{"needed job skipped", "zzskip", "true"},
	{"failure after skipped", "zzskip", "failure()"},
	{"success or failure after skipped", "zzskip", "success() || failure()"},
	{"failure without needs", "", "failure()"},
	{"if false without needs", "", "false"},
}

// unrunBase is the index of the rewrite of unrunJobs that the rewrite i is
// compared with: the one whose if is false, with needs when the rewrite i
// adds needs, else without. A rewrite that adds needs changes what the
// rules read of the needs (the outputs of a job before, for one), so it is
// compared only with one that adds needs too.
func unrunBase(i int) int {
	for b, u := range unrunJobs {
		if u.job == "false" && (u.need == "") == (unrunJobs[i].need == "") {
			return b
		}
	}
	panic("no rewrite with the if false")
}

// TestUnrunJobsReadAlike: each example of a workflow of one file, of every
// rule and quality rule, rewritten so that GitHub runs none of its jobs in
// each way of unrunJobs, gives the same findings and inconclusive places as
// the rewrite whose if is false (unrunBase). The jobs the rewrites add,
// zzpre and zzskip, are the same in each: zzpre runs and zzskip does not.
// The rules read whether a job runs by the ifs a run of the job goes
// through (attacker.JobIfs), so a job that the result of a job it needs
// stops, one that a skipped job it needs stops, and one whose if calls a
// status function that is false after skipped jobs, read as one whose if
// is false.
func TestUnrunJobsReadAlike(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	seen := map[string]bool{}
	n := 0
	for _, c := range sharedChecks(t).Of() {
		e := c.Example
		if e.InputKind != lint.InputKindWorkflow || len(e.Others) != 0 {
			continue
		}
		key := c.Rule.String() + " " + e.Name.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		sel, err := lint.ParseSelector(c.Rule.String())
		if err != nil {
			t.Fatal(err)
		}
		one, err := reg.Select(lint.Only(sel), lint.FactSources{})
		if err != nil {
			t.Fatal(err)
		}
		var got [][]string
		for _, u := range unrunJobs {
			text, err := rewriteUnrun(e.Text, u.need, u.job)
			if err != nil {
				t.Errorf("%s: %s: %v", key, u.name, err)
				got = nil
				break
			}
			x := e
			x.Text = text
			run, err := one.RunExample(ctx, x, nil)
			if err != nil {
				t.Errorf("%s: %s: %v", key, u.name, err)
				got = nil
				break
			}
			got = append(got, placesOf(run.Report, text))
		}
		if len(got) != len(unrunJobs) {
			continue
		}
		n++
		for i, u := range unrunJobs {
			b := unrunBase(i)
			if i != b && !slices.Equal(got[i], got[b]) {
				t.Errorf("%s: %s gives\n  %s\nwhere %s gives\n  %s", key, u.name, strings.Join(got[i], "\n  "), unrunJobs[b].name, strings.Join(got[b], "\n  "))
			}
		}
	}
	if n == 0 {
		t.Fatal("no example rewritten")
	}
	t.Logf("%d examples rewritten", n)
}

// rewriteUnrun is the workflow src with the jobs zzpre, which runs, and
// zzskip, whose if is false, added after its jobs, and each job of src with
// no needs made to need the job need (none when need is empty), with the
// if job. A job of src with needs whose if may be true after a job before
// it fails (attacker.TrueOnlyOnSuccess is false) gets the if job too: zzpre,
// which runs, may fail, and the job would run after it.
func rewriteUnrun(src, need, job string) (string, error) {
	tree := cst.ParseMode([]byte(src), cst.ModeGitHub)
	w, _ := workflow.Parse(tree)
	if w == nil || w.Jobs.Status != workflow.Present {
		return "", fmt.Errorf("no jobs")
	}
	var ed edit.Editor
	var edits []edit.Edit
	for _, ent := range w.Jobs.Value.Entries {
		if ent.Value.Status != workflow.Present {
			return "", fmt.Errorf("job %s is not a mapping", ent.Key.AsString())
		}
		j := ent.Value.Value
		if j.Needs.Status != workflow.Absent {
			if !attacker.TrueOnlyOnSuccess(j.If) {
				x, err := ed.SetValue(j.If.Value.Base.Node, edit.Str(job))
				if err != nil {
					return "", fmt.Errorf("the if of %s: %w", ent.Key.AsString(), err)
				}
				edits = append(edits, x)
			}
			continue
		}
		var ins edit.Map
		if need != "" {
			ins = append(ins, edit.Pair{Key: "needs", Value: edit.Str(need)})
		}
		if j.If.Status == workflow.Present {
			x, err := ed.SetValue(j.If.Value.Base.Node, edit.Str(job))
			if err != nil {
				return "", fmt.Errorf("the if of %s: %w", ent.Key.AsString(), err)
			}
			edits = append(edits, x)
		} else {
			ins = append(ins, edit.Pair{Key: "if", Value: edit.Str(job)})
		}
		if len(ins) == 0 {
			continue
		}
		x, err := ed.Insert(j.Base.Node, edit.First(), ins)
		if err != nil {
			return "", fmt.Errorf("the needs of %s: %w", ent.Key.AsString(), err)
		}
		edits = append(edits, x)
	}
	added := func(cond string) edit.Map {
		return edit.Map{
			{Key: "if", Value: edit.Str(cond)},
			{Key: "runs-on", Value: edit.Str("ubuntu-latest")},
			{Key: "steps", Value: edit.Seq{edit.Map{{Key: "run", Value: edit.Str("echo")}}}},
		}
	}
	x, err := ed.Insert(w.Jobs.Value.Base.Node, edit.Last(), edit.Map{{Key: "zzpre", Value: added("true")}, {Key: "zzskip", Value: added("false")}})
	if err != nil {
		return "", fmt.Errorf("zzpre: %w", err)
	}
	edits = append(edits, x)
	res, err := edit.Apply(tree, edits)
	if err != nil {
		return "", err
	}
	return string(res.Tree.Bytes()), nil
}

// placesOf are the findings, the findings of quality rules and the
// inconclusive places of rep, each as its rule or kind and its line in text: the rewrites differ in the bytes of a
// line, not in the lines.
func placesOf(rep lint.Report, text string) []string {
	line := func(off int) int { return strings.Count(text[:min(off, len(text))], "\n") + 1 }
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		out = append(out, fmt.Sprintf("finding %s %s line %d", f.Rule, f.Args.KindID(), line(f.Location.Span.Start)))
	}
	for _, f := range rep.QualityFindings {
		out = append(out, fmt.Sprintf("quality finding %s %s line %d", f.Rule, f.Args.KindID(), line(f.Location.Span.Start)))
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, fmt.Sprintf("inconclusive %s %s line %d", g.Rule, g.InconclusiveKind, line(g.Location.Span.Start)))
	}
	slices.Sort(out)
	return out
}

// unrunSteps are the ifs that TestUnrunStepsReadAlike gives to the steps of
// the jobs of the example with no needs, which then need zzpre, which runs.
// GitHub runs such a job only after zzpre succeeded, so in its steps
// needs.zzpre.result is success, and GitHub runs none of the steps in any
// of them. The last, whose if is false, is the one the others are compared
// with.
var unrunSteps = []string{
	"needs.zzpre.result == 'failure'",
	"contains(needs.*.result, 'failure')",
	"false",
}

// TestUnrunStepsReadAlike: each example of a workflow of one file, of every
// rule and quality rule, rewritten so that GitHub runs none of the steps of
// its jobs with no needs in each way of unrunSteps, gives the same findings
// and inconclusive places as the rewrite whose if is false. The rules read
// the if of a step with the results of the jobs its job depends on
// (attacker.StepIf), so a step that the result of a job that its job needs
// stops reads as one whose if is false. A rule that does not read the if of
// a step gives the same findings in each.
func TestUnrunStepsReadAlike(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	seen := map[string]bool{}
	n := 0
	for _, c := range sharedChecks(t).Of() {
		e := c.Example
		if e.InputKind != lint.InputKindWorkflow || len(e.Others) != 0 {
			continue
		}
		key := c.Rule.String() + " " + e.Name.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		sel, err := lint.ParseSelector(c.Rule.String())
		if err != nil {
			t.Fatal(err)
		}
		one, err := reg.Select(lint.Only(sel), lint.FactSources{})
		if err != nil {
			t.Fatal(err)
		}
		var got [][]string
		for _, cond := range unrunSteps {
			text, err := rewriteUnrunSteps(e.Text, cond)
			if err != nil {
				t.Errorf("%s: %s: %v", key, cond, err)
				got = nil
				break
			}
			x := e
			x.Text = text
			run, err := one.RunExample(ctx, x, nil)
			if err != nil {
				t.Errorf("%s: %s: %v", key, cond, err)
				got = nil
				break
			}
			got = append(got, placesOf(run.Report, text))
		}
		if len(got) != len(unrunSteps) {
			continue
		}
		n++
		b := len(unrunSteps) - 1
		for i, cond := range unrunSteps[:b] {
			if !slices.Equal(got[i], got[b]) {
				t.Errorf("%s: %s gives\n  %s\nwhere %s gives\n  %s", key, cond, strings.Join(got[i], "\n  "), unrunSteps[b], strings.Join(got[b], "\n  "))
			}
		}
	}
	if n == 0 {
		t.Fatal("no example rewritten")
	}
	t.Logf("%d examples rewritten", n)
}

// rewriteUnrunSteps is the workflow src with the job zzpre, which runs,
// added after its jobs, and each job of src with no needs and with steps
// made to need zzpre, with its if, when it has one, made true, and with the
// if cond on each of its steps.
func rewriteUnrunSteps(src, cond string) (string, error) {
	tree := cst.ParseMode([]byte(src), cst.ModeGitHub)
	w, _ := workflow.Parse(tree)
	if w == nil || w.Jobs.Status != workflow.Present {
		return "", fmt.Errorf("no jobs")
	}
	var ed edit.Editor
	var edits []edit.Edit
	for _, ent := range w.Jobs.Value.Entries {
		if ent.Value.Status != workflow.Present {
			return "", fmt.Errorf("job %s is not a mapping", ent.Key.AsString())
		}
		j := ent.Value.Value
		if j.Needs.Status != workflow.Absent || j.Steps.Status != workflow.Present {
			continue
		}
		ins := edit.Map{{Key: "needs", Value: edit.Str("zzpre")}}
		if j.If.Status == workflow.Present {
			x, err := ed.SetValue(j.If.Value.Base.Node, edit.Str("true"))
			if err != nil {
				return "", fmt.Errorf("the if of %s: %w", ent.Key.AsString(), err)
			}
			edits = append(edits, x)
		}
		x, err := ed.Insert(j.Base.Node, edit.First(), ins)
		if err != nil {
			return "", fmt.Errorf("the needs of %s: %w", ent.Key.AsString(), err)
		}
		edits = append(edits, x)
		for k, s := range j.Steps.Value.Items {
			var x edit.Edit
			var err error
			if s.If.Status == workflow.Present {
				x, err = ed.SetValue(s.If.Value.Base.Node, edit.Str(cond))
			} else {
				x, err = ed.Insert(s.Base.Node, edit.First(), edit.Map{{Key: "if", Value: edit.Str(cond)}})
			}
			if err != nil {
				return "", fmt.Errorf("the if of the step %d of %s: %w", k, ent.Key.AsString(), err)
			}
			edits = append(edits, x)
		}
	}
	x, err := ed.Insert(w.Jobs.Value.Base.Node, edit.Last(), edit.Map{{Key: "zzpre", Value: edit.Map{
		{Key: "runs-on", Value: edit.Str("ubuntu-latest")},
		{Key: "steps", Value: edit.Seq{edit.Map{{Key: "run", Value: edit.Str("echo")}}}},
	}}})
	if err != nil {
		return "", fmt.Errorf("zzpre: %w", err)
	}
	edits = append(edits, x)
	res, err := edit.Apply(tree, edits)
	if err != nil {
		return "", err
	}
	return string(res.Tree.Bytes()), nil
}

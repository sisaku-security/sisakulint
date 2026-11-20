package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// unrunJobs are the three rewrites of TestUnrunJobsReadAlike: the job that
// each job of the example with no needs then needs (zzpre, which runs, or
// zzskip, whose if is false), and the if of such a job. GitHub runs none of
// the jobs of the example in any of them: an if that calls no status
// function is read only when every job its job needs succeeded, and a job
// is skipped when a job it needs is skipped.
var unrunJobs = []struct{ name, need, job string }{
	{"needs result", "zzpre", "needs.zzpre.result == 'failure'"},
	{"if false", "zzpre", "false"},
	{"needed job skipped", "zzskip", "true"},
}

// TestUnrunJobsReadAlike: each example of a workflow of one file, of every
// rule and quality rule, rewritten so that GitHub runs none of its jobs in
// three ways (unrunJobs), gives the same findings and inconclusive places
// in the three. The jobs the rewrites add, zzpre and zzskip, are the same
// in the three: zzpre runs and zzskip does not. The rules read whether a
// job runs by the ifs a run of the job goes through (attacker.JobIfs), so
// a job that the result of a job it needs stops, and one that a skipped
// job it needs stops, read as one whose if is false.
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
			if i != 1 && !slices.Equal(got[i], got[1]) {
				t.Errorf("%s: %s gives\n  %s\nwhere %s gives\n  %s", key, u.name, strings.Join(got[i], "\n  "), unrunJobs[1].name, strings.Join(got[1], "\n  "))
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
// no needs made to need the job need, with the if job.
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
			continue
		}
		ins := edit.Map{{Key: "needs", Value: edit.Str(need)}}
		if j.If.Status == workflow.Present {
			x, err := ed.SetValue(j.If.Value.Base.Node, edit.Str(job))
			if err != nil {
				return "", fmt.Errorf("the if of %s: %w", ent.Key.AsString(), err)
			}
			edits = append(edits, x)
		} else {
			ins = append(ins, edit.Pair{Key: "if", Value: edit.Str(job)})
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

package workflow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// TestExpressionExperiments reads the files of the experiments, copied
// under testdata/observed: a file GitHub rejects for the names of its ${{ }}
// has diagnostics, and a file GitHub read has none. GitHub read all the
// files of the experiments of the types of expressions, which have none;
// their names are kept apart, since they repeat the names of the files of
// the other experiments.
func TestExpressionExperiments(t *testing.T) {
	rejected := map[string]bool{}
	for _, n := range strings.Fields("x01 x02 x03 x05 x07 x08 x09 x11 x12 x14 x20 x24 x26 x27") {
		rejected["workflows/"+n] = true
	}
	for _, n := range strings.Fields("a17 a18 z03 z06 z07 z08 z09 z10 z12 z13 z14 z15 z16") {
		rejected["actions/"+n] = true
	}
	workflows, err := filepath.Glob("testdata/observed/expression*/*/.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	actions, err := filepath.Glob("testdata/observed/expression*/*/.github/actions/*/action.yml.txt")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	check := func(f, key string, diags []Diagnostic) {
		if strings.Contains(f, "/expression-types") {
			key = "types:" + key
		}
		seen[key] = true
		if rejected[key] != (len(diags) > 0) {
			t.Errorf("%s: diagnostics %v, want them: %v", f, diags, rejected[key])
		}
	}
	for _, f := range workflows {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, diags := Parse(cst.ParseMode(src, cst.ModeGitHub))
		check(f, "workflows/"+strings.TrimSuffix(filepath.Base(f), ".yml"), diags)
	}
	for _, f := range actions {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, diags := ParseActionMetadata(cst.ParseMode(src, cst.ModeGitHub))
		check(f, "actions/"+filepath.Base(filepath.Dir(f)), diags)
	}
	for k := range rejected {
		if !seen[k] {
			t.Errorf("%s: no such file", k)
		}
	}
	if len(workflows) == 0 || len(actions) == 0 {
		t.Errorf("%d workflows, %d actions", len(workflows), len(actions))
	}
}

// TestParallelExperiments reads the files of the runs of parallel steps
// observed on GitHub. GitHub rejected p3 (a group in a
// group), p4 (wait for an unknown id), q1 (wait-all: false), q3 (an empty
// group), q4 (cancel of an unknown id), r03 and r04 (the id of a later
// step), r09 to r11 (wait, wait-all and cancel in a group), r12 (wait for
// __run) and r13 and r14 (the step's own id), which have diagnostics. It
// ran the others, which have none: p1, p2, p5 (background in a group), q2
// (wait-all: true), r00 (the control), r01 and r02 (a name in another
// case), r05 and r06 (an earlier step not in the background), r07 and r08
// (an earlier step of a group).
func TestParallelExperiments(t *testing.T) {
	rejected := map[string]bool{}
	for _, n := range strings.Fields("p1 p2 p5 q2 r00 r01 r02 r05 r06 r07 r08") {
		rejected[n] = false
	}
	for _, n := range strings.Fields("p3 p4 q1 q3 q4 r03 r04 r09 r10 r11 r12 r13 r14") {
		rejected[n] = true
	}
	files, err := filepath.Glob("testdata/observed/parallel*/*/.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, diags := Parse(cst.ParseMode(src, cst.ModeGitHub))
		n, _, _ := strings.Cut(filepath.Base(f), "-")
		want, ok := rejected[n]
		if !ok {
			t.Errorf("%s: not an experiment of the test", f)
		}
		seen[n] = true
		if want != (len(diags) > 0) {
			t.Errorf("%s: diagnostics %v, want them: %v", f, diags, want)
		}
	}
	if len(seen) != len(rejected) {
		t.Errorf("read %v, want %d files", seen, len(rejected))
	}
}

// TestJobKeyExperiments reads the files of the runs of job keys observed
// on GitHub: GitHub folds a job key that is exactly
// ${{ 'a' }} to the job id a (a need of a finds the job), and
// rejected k3, whose need names no job; k0 is the control.
func TestJobKeyExperiments(t *testing.T) {
	rejected := map[string]bool{"k0": false, "k1": false, "k2": false, "k3": true}
	files, err := filepath.Glob("testdata/observed/job-key-expr/*/.github/workflows/*.yml")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		_, diags := Parse(cst.ParseMode(src, cst.ModeGitHub))
		n, _, _ := strings.Cut(filepath.Base(f), "-")
		want, ok := rejected[n]
		if !ok {
			t.Errorf("%s: not an experiment of the test", f)
		}
		seen[n] = true
		if want != (len(diags) > 0) {
			t.Errorf("%s: diagnostics %v, want them: %v", f, diags, want)
		}
	}
	if len(seen) != len(rejected) {
		t.Errorf("read %v, want %d files", seen, len(rejected))
	}
}

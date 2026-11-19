package rules

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// condFindings are the quality findings of cond on fsys, as
// "<input>: <condition> [<status functions>]", sorted.
func condFindings(t *testing.T, fsys fstest.MapFS) []string {
	t.Helper()
	var out []string
	for _, f := range qualityReportFS(t, CondID, fsys, storeOf(t)).QualityFindings {
		a, ok := f.Args.(CondMixedText)
		if !ok {
			t.Fatalf("args %T", f.Args)
		}
		var fs []string
		for _, s := range a.StatusFunctions {
			b, _ := s.MarshalJSON()
			fs = append(fs, strings.Trim(string(b), `"`))
		}
		out = append(out, fmt.Sprintf("%s: %s [%s]", f.Location.File.Input, a.Condition, strings.Join(fs, " ")))
	}
	slices.Sort(out)
	return out
}

func checkCond(t *testing.T, name string, fsys fstest.MapFS, want []string) {
	t.Helper()
	slices.Sort(want)
	if got := condFindings(t, fsys); !slices.Equal(got, want) {
		t.Errorf("%s: got\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestCondObserved runs the workflow of an experiment, copied under
// testdata/observed: the ifs whose
// steps ran whatever their expressions gave (c1 to c3 after a failure, t3)
// have a finding; c4 and the ifs with white space around one ${{ }} (t1,
// t2), which GitHub read as expressions, do not.
func TestCondObserved(t *testing.T) {
	b, err := os.ReadFile("testdata/observed/validity-quality/2/.github/workflows/q1-cond.yml")
	if err != nil {
		t.Fatal(err)
	}
	const w = ".github/workflows/q1-cond.yml"
	checkCond(t, "q1-cond", fstest.MapFS{w: {Data: b}}, []string{
		w + ": ${{ false }} && ${{ false }} []",
		w + ": ${{ always() }} && ${{ false }} [always]",
		w + ": always() && ${{ false }} []",
		w + ": x ${{ false }} []",
	})
}

// TestCondUpstream runs the conditions of upstream's conditionalrule_test.go
// (sisakulint 17c2d82, lines 117 to 157) as ifs of steps: those with text
// outside their ${{ }} have a finding, which upstream's rule gave to none
// of them.
func TestCondUpstream(t *testing.T) {
	conds := []string{
		"${{ github.event_name == 'push' }}",
		"${{ github.event.repository.owner.id }} == ${{ github.event.sender.id }}",
		"${{ steps.disk.outputs.status }} == 'success' && !canceled()",
		"${{ env.PACKAGED_STATUS }} == 'success' && !canceled()",
		"(!canceled())",
		"${{ success() }}",
		"${{ always() }}",
		"${{ steps.test.outputs.result }} != 'failure'",
		"${{ steps.a.outputs.done }} || ${{ steps.b.outputs.done }}",
	}
	var b strings.Builder
	b.WriteString("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n")
	for _, c := range conds {
		fmt.Fprintf(&b, "      - if: %q\n        run: echo\n", c)
	}
	const w = ".github/workflows/w.yml"
	checkCond(t, "upstream", fstest.MapFS{w: {Data: []byte(b.String())}}, []string{
		w + ": ${{ github.event.repository.owner.id }} == ${{ github.event.sender.id }} []",
		w + ": ${{ steps.disk.outputs.status }} == 'success' && !canceled() []",
		w + ": ${{ env.PACKAGED_STATUS }} == 'success' && !canceled() []",
		w + ": ${{ steps.test.outputs.result }} != 'failure' []",
		w + ": ${{ steps.a.outputs.done }} || ${{ steps.b.outputs.done }} []",
	})
}

// TestCondWhiteSpace: a workflow's if drops the white
// space around one ${{ }}, an action.yml's does not.
func TestCondWhiteSpace(t *testing.T) {
	checkCond(t, "white space", fstest.MapFS{
		".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    if: \" ${{ false }}\"\n    steps:\n      - if: |\n          ${{ false }}\n        run: echo\n")},
		"a/action.yml":            {Data: []byte("name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - if: \" ${{ false }}\"\n      shell: bash\n      run: echo\n")},
	}, []string{"a/action.yml:  ${{ false }} []"})
}

package taint

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// variableCodesOf are the VariableCodes of the runs of the workflow src,
// each as its variable, reading, verdict and events (or inconclusive kind).
func variableCodesOf(t *testing.T, src string) []string {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	var out []string
	for _, s := range Analyze(w, nil).Sinks {
		for _, v := range s.VariableCodes {
			got := fmt.Sprintf("%s %s %v", v.Var, v.Reading.Arg(), v.Ref.Verdict)
			switch v.Ref.Verdict {
			case analysis.Controlled:
				var evs []string
				for _, e := range v.Ref.ControlledOn {
					if n := fmt.Sprint(e.Name()); !slices.Contains(evs, n) {
						evs = append(evs, n)
					}
				}
				got += " " + strings.Join(evs, ",")
			case analysis.Inconclusive:
				got += " " + v.Ref.InconclusiveKind.String()
			}
			out = append(out, got)
		}
	}
	return out
}

// stepWorkflow is a workflow on the events on whose one step has the env
// env and the run run, with the job's env jobEnv and the workflow's wfEnv
// (YAML of the lines of a mapping, "" for none).
func stepWorkflow(on, wfEnv, jobEnv, env, run, shell string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "on: %s\n", on)
	if wfEnv != "" {
		fmt.Fprintf(&b, "env:\n  %s\n", wfEnv)
	}
	b.WriteString("jobs:\n  j:\n    runs-on: ubuntu-latest\n")
	if jobEnv != "" {
		fmt.Fprintf(&b, "    env:\n      %s\n", jobEnv)
	}
	b.WriteString("    steps:\n      - id: s\n        run: echo x\n      - ")
	if env != "" {
		fmt.Fprintf(&b, "env:\n          %s\n        ", env)
	}
	if shell != "" {
		fmt.Fprintf(&b, "shell: %s\n        ", shell)
	}
	fmt.Fprintf(&b, "run: %s\n", run)
	return b.String()
}

func TestVariableCodes(t *testing.T) {
	title := "ISSUE_TITLE: ${{ github.event.issue.title }}"
	for _, c := range []struct {
		name                        string
		on, wfEnv, jobEnv, env, run string
		shell                       string
		want                        []string
	}{
		{name: "step env", on: "issues", env: title, run: `eval "echo $ISSUE_TITLE"`,
			want: []string{"ISSUE_TITLE code-argument Controlled issues"}},
		{name: "job env", on: "issues", jobEnv: title, run: `eval "echo $ISSUE_TITLE"`, want: []string{"ISSUE_TITLE code-argument Controlled"}},
		{name: "workflow env", on: "issues", wfEnv: title, run: `eval "echo $ISSUE_TITLE"`, want: []string{"ISSUE_TITLE code-argument Controlled"}},
		{name: "step env over job env", on: "issues", jobEnv: title, env: "ISSUE_TITLE: x", run: `eval "echo $ISSUE_TITLE"`},
		{name: "case of the key", on: "issues", env: "issue_title: ${{ github.event.issue.title }}", run: `eval "echo $ISSUE_TITLE"`},
		{name: "assigned before", on: "issues", env: title, run: `ISSUE_TITLE=x; eval "$ISSUE_TITLE"`},
		{name: "read before", on: "issues", env: title, run: `read -r ISSUE_TITLE <<< x; eval "$ISSUE_TITLE"`},
		{name: "read in a loop", on: "issues", env: title, run: `while read -r ISSUE_TITLE; do eval "$ISSUE_TITLE"; done < f`},
		{name: "for", on: "issues", env: title, run: `for ISSUE_TITLE in a; do eval "$ISSUE_TITLE"; done`},
		{name: "mapfile", on: "issues", env: title, run: `mapfile -t ISSUE_TITLE < f; eval "$ISSUE_TITLE"`},
		{name: "data", on: "issues", env: title, run: `echo "$ISSUE_TITLE"`},
		{name: "sh", on: "issues", env: title, run: `eval "echo $ISSUE_TITLE"`, shell: "sh"},
		{name: "part of the value", on: "issues", env: `ISSUE_TITLE: "x ${{ github.event.issue.title }}"`, run: `eval "echo $ISSUE_TITLE"`, want: []string{"ISSUE_TITLE code-argument Controlled"}},
		{name: "runner variable", on: "pull_request_target", run: `eval "git checkout $GITHUB_HEAD_REF"`, want: []string{"GITHUB_HEAD_REF code-argument Controlled"}},
		{name: "runner variable as the command word", on: "pull_request_target", run: `$GITHUB_HEAD_REF`},
		{name: "command word on free text", on: "issues", env: title, run: `$ISSUE_TITLE`, want: []string{"ISSUE_TITLE command-word Controlled"}},
		{name: "output of a step", on: "issues", env: "ISSUE_TITLE: ${{ steps.s.outputs.y }}", run: `eval "$ISSUE_TITLE"`, want: []string{"ISSUE_TITLE code-argument Inconclusive step-output-run"}},
		{name: "bare name in arithmetic", on: "issues", env: title, run: `(( ISSUE_TITLE + 1 ))`, want: []string{"ISSUE_TITLE arithmetic Controlled"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := variableCodesOf(t, stepWorkflow(c.on, c.wfEnv, c.jobEnv, c.env, "'"+strings.ReplaceAll(c.run, "'", "''")+"'", c.shell))
			if len(got) != len(c.want) {
				t.Fatalf("VariableCodes = %q, want %q", got, c.want)
			}
			for i := range got {
				if !strings.HasPrefix(got[i], c.want[i]) {
					t.Errorf("VariableCodes[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}

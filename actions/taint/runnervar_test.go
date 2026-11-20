package taint

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// observedRunnerVariables are the 46 names for which GitHub-hosted runners
// gave the step the runner's value, not the value an env of the job or of
// the step wrote, as the observation listed them.
var observedRunnerVariables = strings.Fields(`GITHUB_ACTION GITHUB_ACTIONS GITHUB_ACTION_REF GITHUB_ACTION_REPOSITORY GITHUB_ACTOR GITHUB_ACTOR_ID GITHUB_API_URL GITHUB_ARTIFACTS GITHUB_ARTIFACTS_LIST GITHUB_BASE_REF GITHUB_ENV GITHUB_EVENT_NAME GITHUB_EVENT_PATH GITHUB_GRAPHQL_URL GITHUB_HEAD_REF GITHUB_JOB GITHUB_OUTPUT GITHUB_PATH GITHUB_REF GITHUB_REF_NAME GITHUB_REF_PROTECTED GITHUB_REF_TYPE GITHUB_REPOSITORY GITHUB_REPOSITORY_ID GITHUB_REPOSITORY_OWNER GITHUB_REPOSITORY_OWNER_ID GITHUB_RETENTION_DAYS GITHUB_RUN_ATTEMPT GITHUB_RUN_ID GITHUB_RUN_NUMBER GITHUB_SERVER_URL GITHUB_SHA GITHUB_STATE GITHUB_STEP_SUMMARY GITHUB_TRIGGERING_ACTOR GITHUB_WORKFLOW GITHUB_WORKFLOW_REF GITHUB_WORKFLOW_SHA GITHUB_WORKSPACE RUNNER_ARCH RUNNER_ENVIRONMENT RUNNER_NAME RUNNER_OS RUNNER_TEMP RUNNER_TOOL_CACHE RUNNER_WORKSPACE`)

func TestRunnerVariable(t *testing.T) {
	for _, c := range []struct {
		name    string
		windows bool
		want    string // the context, "" for none
	}{
		{"GITHUB_SHA", false, "github.sha"},
		{"GITHUB_HEAD_REF", true, "github.head_ref"},
		{"RUNNER_TEMP", false, "runner.temp"},
		{"GITHUB_ACTIONS", false, "true"},
		{"github_sha", false, ""},
		{"github_sha", true, "github.sha"},
		{"Github_Head_Ref", true, "github.head_ref"},
		// the runner does not write these
		{"CI", true, ""},
		{"GITHUB_TOKEN", false, ""},
		{"GITHUB_ACTION_PATH", false, ""},
		{"RUNNER_DEBUG", false, ""},
		{"HOME", false, ""},
	} {
		v, ok := RunnerVariable(c.name, c.windows)
		got := ""
		if ok {
			got = v.String()
		}
		if got != c.want {
			t.Errorf("RunnerVariable(%q, %v) = %q, want %q", c.name, c.windows, got, c.want)
		}
	}
	var table []string
	for _, n := range observedRunnerVariables {
		if _, ok := RunnerVariable(n, false); ok {
			table = append(table, n)
		}
	}
	if !slices.Equal(table, observedRunnerVariables) {
		t.Errorf("the names the table has of the observed runner variables: %v", table)
	}
}

// jobOf is the first job of a workflow whose job j runs on runsOn.
func jobOf(t *testing.T, runsOn string) *workflow.Job {
	t.Helper()
	src := "on: push\njobs:\n  j:\n    runs-on: " + runsOn + "\n    steps:\n      - run: echo\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	j := w.Jobs.Value.Entries[0].Value.Value
	return &j
}

func TestWindowsRunner(t *testing.T) {
	for _, c := range []struct {
		runsOn string
		want   bool
	}{
		{"windows-latest", true},
		{"windows-2022", true},
		{"[self-hosted, Windows]", true},
		{"ubuntu-latest", false},
		{"${{ matrix.os }}", false},
		{"[self-hosted, linux]", false},
	} {
		if got := WindowsRunner(jobOf(t, c.runsOn)); got != c.want {
			t.Errorf("WindowsRunner(runs-on: %s) = %v, want %v", c.runsOn, got, c.want)
		}
	}
	if WindowsRunner(nil) {
		t.Error("WindowsRunner(nil) = true, want false")
	}
}

// TestRunnerVariableRead holds the reading of a variable the runner writes:
// its context, whatever env writes, in the case the runner's OS decides.
func TestRunnerVariableRead(t *testing.T) {
	wf := func(on, runsOn, env, run string) string {
		return "on: " + on + "\njobs:\n  j:\n    runs-on: " + runsOn + "\n    steps:\n      - shell: bash\n        env:\n          X: x\n" + env + "        run: " + run + "\n"
	}
	tar := `tar -xf a.tar f "$GITHUB_HEAD_REF"`
	if got, want := arguments(t, wf("pull_request_target", "ubuntu-latest", "", tar), false), []string{`tar 4 Option $GITHUB_HEAD_REF github.head_ref head quoted`}; !slices.Equal(got, want) {
		t.Errorf("$GITHUB_HEAD_REF without env on pull_request_target: %q, want %q", got, want)
	}
	if got := arguments(t, wf("push", "ubuntu-latest", "", tar), false); len(got) != 0 {
		t.Errorf("$GITHUB_HEAD_REF on push: %q, want none", got)
	}
	// a step of an action.yml
	act := "name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: tar -xf a.tar f \"$GITHUB_HEAD_REF\"\n"
	if got := arguments(t, act, true); len(got) != 1 || !strings.Contains(got[0], "github.head_ref") {
		t.Errorf("$GITHUB_HEAD_REF in an action.yml: %q, want the argument of github.head_ref", got)
	}
	// an env that is a ${{ }} does not decide what the runner writes
	dyn := "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env: ${{ fromJSON(vars.E) }}\n    steps:\n      - run: tar -xf a.tar f \"$GITHUB_SHA\"\n"
	if got := arguments(t, dyn, false); len(got) != 0 {
		t.Errorf("$GITHUB_SHA under an env of ${{ }}: %q, want none", got)
	}
	// on Windows, a name in another case that no env writes was not tried
	if got := arguments(t, wf("pull_request_target", "windows-latest", "", `tar -xf a.tar f "$github_head_ref"`), false); len(got) != 0 {
		t.Errorf("$github_head_ref without env on Windows: %q, want none", got)
	}
	written := func(src string) string {
		t.Helper()
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		var out []string
		for _, s := range Analyze(w, nil).Sinks {
			text := s.Value.Text()
			for _, x := range s.EnvironmentFileWrites {
				out = append(out, fmt.Sprintf("%s %s %s", x.File, x.Side, text[x.Span.Start:x.Span.End]))
			}
		}
		return strings.Join(out, "; ")
	}
	for _, c := range []struct {
		name, runsOn, env, run, want string
	}{
		{"a name the runner writes", "ubuntu-latest", "          GITHUB_HEAD_REF: ${{ github.event.issue.title }}\n", `echo "$GITHUB_HEAD_REF" >> "$GITHUB_ENV"`, ""},
		{"another case on Linux", "ubuntu-latest", "          github_head_ref: ${{ github.event.issue.title }}\n", `echo "$github_head_ref" >> "$GITHUB_ENV"`, "GITHUB_ENV SideKey $github_head_ref"},
		{"another case on Windows", "windows-latest", "          github_head_ref: ${{ github.event.issue.title }}\n", `echo "$github_head_ref" >> "$GITHUB_ENV"`, ""},
		{"a name the runner does not write", "ubuntu-latest", "          CI: ${{ github.event.issue.title }}\n", `echo "$CI" >> "$GITHUB_ENV"`, "GITHUB_ENV SideKey $CI"},
	} {
		if got := written(wf("issues", c.runsOn, c.env, c.run)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRunnerVariableOf(t *testing.T) {
	for _, n := range observedRunnerVariables {
		v, _ := RunnerVariable(n, false)
		if v.Context == nil {
			continue // GITHUB_ACTIONS is no context's
		}
		if got, ok := RunnerVariableOf(v.Context); !ok || got != n {
			t.Errorf("RunnerVariableOf(%s) = %q, %v, want %q", v, got, ok, n)
		}
	}
	if _, ok := RunnerVariableOf([]expr.PathElem{{Name: "github"}, {Name: "token"}}); ok {
		t.Error("RunnerVariableOf(github.token) is ok, want not")
	}
}

// TestRunnerVariableSecretFlow holds the reading of the secret flow: a
// variable the runner writes carries no secret an env names, and its value
// is the context's.
func TestRunnerVariableSecretFlow(t *testing.T) {
	const token = "          T: ${{ secrets.T }}\n"
	for _, c := range []struct {
		name, env, run string
		want           []string
	}{
		{"the host of a variable the runner writes", token + "          GITHUB_HEAD_REF: ${{ github.event.issue.title }}\n",
			`curl -H "Authorization: Bearer $T" "https://$GITHUB_HEAD_REF/status"`,
			[]string{"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=named github.head_ref"}},
		{"GitHub's API URL", token + "          GITHUB_API_URL: https://mirror.example\n",
			`curl -H "Authorization: Bearer $T" "$GITHUB_API_URL/repos"`,
			[]string{"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=github"}},
		{"a secret in a variable the runner writes", "          GITHUB_SHA: ${{ secrets.T }}\n",
			`curl -H "Authorization: Bearer $GITHUB_SHA" "https://example.com/x"`,
			[]string{"curl#1 host=[] path=[] secrets=[] enterprise=false dest=literal example.com"}},
	} {
		if got := requests(t, onIssues(c.env, c.run), false); !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	// ${{ env.X }} reads the env context, which has the value written
	src := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      GITHUB_SHA: ${{ secrets.T }}\n    steps:\n      - env:\n          A: ${{ env.GITHUB_SHA }}\n        run: |\n          curl -H \"Authorization: Bearer $A\" \"https://example.com/x\"\n"
	if got, want := requests(t, src, false), []string{"curl#1 host=[] path=[] secrets=[T] enterprise=false dest=literal example.com"}; !slices.Equal(got, want) {
		t.Errorf("env.GITHUB_SHA: %q, want %q", got, want)
	}
}

// TestAuthoredCommandsOfSinks runs the workflow of an experiment, copied
// under testdata/observed: each step that
// prints a workflow command of its text has it in its sink.
func TestAuthoredCommandsOfSinks(t *testing.T) {
	b, err := os.ReadFile("testdata/observed/validity-quality/8/.github/workflows/q3-commands.yml")
	if err != nil {
		t.Fatal(err)
	}
	w, _ := workflow.Parse(cst.ParseMode(b, cst.ModeGitHub))
	var got []string
	for _, s := range Analyze(w, nil).Sinks {
		for _, c := range s.AuthoredCommands {
			got = append(got, c.Name.Command())
		}
	}
	if want := []string{"set-output", "set-output", "set-output", "save-state", "set-env", "add-path"}; !slices.Equal(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}

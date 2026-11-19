package rules

import (
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// envVarFindings are the quality findings of env-var on fsys, as
// "<input>: <kind> <name>", sorted.
func envVarFindings(t *testing.T, fsys fstest.MapFS) []string {
	t.Helper()
	var out []string
	for _, f := range qualityReportFS(t, EnvVarRuleID, fsys, storeOf(t)).QualityFindings {
		name := ""
		switch a := f.Args.(type) {
		case EnvVarEqualsSign:
			name = a.Name + " " + a.Variable
		case EnvVarRunnerOverwritten:
			name = a.Name + " " + a.RunnerValue
		default:
			t.Fatalf("args %T", f.Args)
		}
		out = append(out, f.Location.File.Input.String()+": "+strings.TrimPrefix(f.Args.KindID().String(), "env-var.")+" "+name)
	}
	slices.Sort(out)
	return out
}

func checkEnvVar(t *testing.T, name string, fsys fstest.MapFS, want []string) {
	t.Helper()
	slices.Sort(want)
	if got := envVarFindings(t, fsys); !slices.Equal(got, want) {
		t.Errorf("%s: got\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// experiment is a file of a commit of the experiments, copied under
// testdata/observed.
func experiment(t *testing.T, version, path string) *fstest.MapFile {
	t.Helper()
	b, err := os.ReadFile("testdata/observed/" + version + "/" + path)
	if err != nil {
		t.Fatal(err)
	}
	return &fstest.MapFile{Data: b}
}

// TestEnvVarObserved runs the observed forms: every name with = and the
// names the runner writes over have a finding; a name with a space, and CI,
// HOME, GITHUB_TOKEN, GITHUB_ACTION_PATH and RUNNER_DEBUG, which reached the
// step, do not.
func TestEnvVarObserved(t *testing.T) {
	const q2, a, q4, q5 = ".github/workflows/q2-env.yml", ".github/actions/envc/action.yml", ".github/workflows/q4-env2.yml", ".github/workflows/q5-env-host.yml"
	checkEnvVar(t, "names with = and names the runner writes over", fstest.MapFS{
		q2: experiment(t, "validity-quality/2", q2),
		a:  experiment(t, "validity-quality/2", a+".txt"),
		q4: experiment(t, "validity-quality/6", q4),
		q5: experiment(t, "validity-quality/5", q5),
	}, []string{
		q2 + ": equals-sign A=B A", q2 + ": equals-sign A=B A",
		a + ": equals-sign A=B A",
		q4 + ": equals-sign W=X W", q4 + ": equals-sign J=X J", q4 + ": equals-sign J=X J", q4 + ": equals-sign S=X S", q4 + ": equals-sign S=X S",
		q5 + ": equals-sign W=X W", q5 + ": equals-sign J=X J", q5 + ": equals-sign S=X S",
		q2 + ": runner-overwritten GITHUB_SHA ${{ github.sha }}", q2 + ": runner-overwritten GITHUB_WORKSPACE ${{ github.workspace }}",
		q2 + ": runner-overwritten RUNNER_TEMP ${{ runner.temp }}", q2 + ": runner-overwritten GITHUB_REF ${{ github.ref }}",
		q2 + ": runner-overwritten GITHUB_ACTIONS true",
		q2 + ": runner-overwritten GITHUB_SHA ${{ github.sha }}", q2 + ": runner-overwritten GITHUB_REF ${{ github.ref }}",
		q4 + ": runner-overwritten GITHUB_SHA ${{ github.sha }}",
	})
	const q6 = ".github/workflows/q6-default-names.yml"
	var want []string
	for _, l := range strings.Split(string(experiment(t, "validity-quality/3", q6).Data), "\n") {
		n, ok := strings.CutSuffix(strings.TrimSpace(l), ": over")
		if !ok || n == "CI" || n == "GITHUB_ACTION_PATH" || n == "RUNNER_DEBUG" {
			continue
		}
		v := "true"
		if n != "GITHUB_ACTIONS" {
			p, k, _ := strings.Cut(n, "_")
			v = "${{ " + strings.ToLower(p) + "." + strings.ToLower(k) + " }}"
		}
		want = append(want, q6+": runner-overwritten "+n+" "+v)
	}
	if len(want) != 46 {
		t.Fatalf("%d names of q6, want 46", len(want))
	}
	checkEnvVar(t, "the default names", fstest.MapFS{q6: experiment(t, "validity-quality/3", q6)}, want)
	// the jobs of other cases run on a matrix of OSes, which the rule
	// does not decide (UndetectedForm unknown-os-case); the upper case ones
	// have the 46 findings
	const q8 = ".github/workflows/q8-default-names-os.yml"
	got := envVarFindings(t, fstest.MapFS{q8: experiment(t, "validity-quality/1", q8)})
	if len(got) != 46 || slices.ContainsFunc(got, func(s string) bool {
		return strings.Contains(s, "runner-overwritten Github_") || strings.Contains(s, "runner-overwritten github_")
	}) {
		t.Errorf("the default names on a matrix of OSes: %d findings, want the 46 of the upper case: %q", len(got), got)
	}
}

// TestEnvVarCase: a name in another case is the runner's
// on Windows alone.
func TestEnvVarCase(t *testing.T) {
	job := func(runsOn string) string {
		return "on: push\njobs:\n  a:\n    runs-on: " + runsOn + "\n    env:\n      github_sha: x\n    steps:\n      - run: echo\n"
	}
	for _, c := range []struct {
		runsOn string
		want   []string
	}{
		{"windows-latest", []string{".github/workflows/w.yml: runner-overwritten github_sha ${{ github.sha }}"}},
		{"[self-hosted, Windows]", []string{".github/workflows/w.yml: runner-overwritten github_sha ${{ github.sha }}"}},
		{"ubuntu-latest", nil},
		{"${{ matrix.os }}", nil},
	} {
		checkEnvVar(t, c.runsOn, fstest.MapFS{".github/workflows/w.yml": {Data: []byte(job(c.runsOn))}}, c.want)
	}
}

// TestEnvVarExpressions: a key with a ${{ }} and an env
// that is a ${{ }} have no finding and no error.
func TestEnvVarExpressions(t *testing.T) {
	checkEnvVar(t, "expressions", fstest.MapFS{".github/workflows/w.yml": {Data: []byte(`on: push
env: ${{ fromJSON(vars.ENV) }}
jobs:
  a:
    runs-on: x
    env:
      "${{ 'A=B' }}": x
    steps:
      - run: echo
`)}}, nil)
}

// TestEnvVarUpstream runs the example workflow of
// https://github.com/sisaku-security/sisakulint/blob/17c2d82151a966e6e388a17619b060ae2919712e/docs/environmentvariablerule.md:
// the name with = has a finding, as upstream sisakulint reports. The
// names with a space or & have no finding, though upstream sisakulint
// reports the names: GitHub accepts each such name as an environment
// variable of that name.
func TestEnvVarUpstream(t *testing.T) {
	const w = ".github/workflows/w.yml"
	checkEnvVar(t, "upstream", fstest.MapFS{w: {Data: []byte(`name: CI Build

on: [push]

env:
  MY VAR: "value"
  DB=CONNECTION: "value"
  API&KEY: "secret"

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo
`)}}, []string{w + ": equals-sign DB=CONNECTION DB"})
}

// TestEnvVarSameValue: an env key that the runner writes over with the
// value written, ${{ <the same context> }} or the text true of
// GITHUB_ACTIONS, gives each step the value written; no finding.
func TestEnvVarSameValue(t *testing.T) {
	const w = ".github/workflows/w.yml"
	checkEnvVar(t, "same value", fstest.MapFS{w: {Data: []byte(`on: push
jobs:
  a:
    runs-on: ubuntu-latest
    env:
      GITHUB_REPOSITORY: ${{ github.repository }}
      GITHUB_SERVER_URL: ${{ GITHUB.SERVER_URL }}
      RUNNER_TEMP: ${{ runner.temp }}
      GITHUB_ACTIONS: "true"
      GITHUB_SHA: ${{ github.event.pull_request.head.sha }}
      GITHUB_REF: ${{ github.ref }}-x
    steps:
      - run: echo
`)}}, []string{w + ": runner-overwritten GITHUB_SHA ${{ github.sha }}", w + ": runner-overwritten GITHUB_REF ${{ github.ref }}"})
}

// TestEnvVarContainerAndDockerAction: the runner writes over
// GITHUB_SHA in the env of a job's container and in runs.env of a Docker
// container action, and runs.env A=B gives the container A=B.
func TestEnvVarContainerAndDockerAction(t *testing.T) {
	const w, a = ".github/workflows/q9-unverified.yml", ".github/actions/dockenv/action.yml"
	checkEnvVar(t, "a container and a Docker action", fstest.MapFS{
		w: experiment(t, "validity-quality/7", w),
		a: experiment(t, "validity-quality/7", a+".txt"),
	}, []string{
		w + ": runner-overwritten GITHUB_SHA ${{ github.sha }}", w + ": runner-overwritten GITHUB_REF ${{ github.ref }}",
		a + ": equals-sign A=B A", a + ": runner-overwritten GITHUB_SHA ${{ github.sha }}",
	})
}

// TestEnvVarWorkflowCase: a key of the workflow's env in another case is
// written over in a job on Windows.
func TestEnvVarWorkflowCase(t *testing.T) {
	const w = ".github/workflows/w.yml"
	checkEnvVar(t, "workflow env", fstest.MapFS{w: {Data: []byte(`on: push
env:
  github_ref: x
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo
  b:
    runs-on: windows-latest
    steps:
      - run: echo
`)}}, []string{w + ": runner-overwritten github_ref ${{ github.ref }}"})
}

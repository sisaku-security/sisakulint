package rules

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

// deprecatedCommandsFindings are the quality findings of
// deprecated-commands on fsys, as "<input>: <kind> <command>", sorted.
func deprecatedCommandsFindings(t *testing.T, fsys fstest.MapFS) []string {
	t.Helper()
	var out []string
	for _, f := range qualityReportFS(t, DeprecatedCommandsID, fsys, storeOf(t)).QualityFindings {
		command := ""
		switch a := f.Args.(type) {
		case DeprecatedCommandsDeprecatedCommand:
			command = a.Command.Command()
		case DeprecatedCommandsDisabledCommand:
			command = a.Command.Command()
		default:
			t.Fatalf("args %T", f.Args)
		}
		out = append(out, f.Location.File.Input.String()+": "+strings.TrimPrefix(f.Args.KindID().String(), "deprecated-commands.")+" "+command)
	}
	slices.Sort(out)
	return out
}

func checkDeprecatedCommands(t *testing.T, name string, fsys fstest.MapFS, want []string) {
	t.Helper()
	slices.Sort(want)
	if got := deprecatedCommandsFindings(t, fsys); !slices.Equal(got, want) {
		t.Errorf("%s: got\n%s\nwant\n%s", name, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestDeprecatedCommandsObserved runs the workflow and the action of two
// experiments, copied under testdata/observed: the steps that
// printed set-output and save-state (warnings) and set-env and add-path
// (failed steps), and the step of the composite action that printed
// set-env.
func TestDeprecatedCommandsObserved(t *testing.T) {
	const q3, a = ".github/workflows/q3-commands.yml", ".github/actions/setenv/action.yml"
	checkDeprecatedCommands(t, "E3, E5", fstest.MapFS{
		q3: experiment(t, "validity-quality/8", q3),
		a:  experiment(t, "validity-quality/4", a+".txt"),
	}, []string{
		q3 + ": deprecated-command set-output", q3 + ": deprecated-command set-output", q3 + ": deprecated-command set-output",
		q3 + ": deprecated-command save-state",
		q3 + ": disabled-command set-env", q3 + ": disabled-command add-path",
		a + ": disabled-command set-env",
	})
}

// TestDeprecatedCommandsUpstream runs the example workflow of
// https://github.com/gh-intel/sisakulint/blob/17c2d82151a966e6e388a17619b060ae2919712e/docs/deprecatedcommandsrule.md
// and the script of the test of upstream sisakulint at the same commit.
// Each of the four commands that echo prints has a finding. The script
// "::set-output name=test::value" with no echo has no finding, though
// upstream sisakulint reports the script: bash runs the script as a
// command, and the log of the step has no ::set-output line.
func TestDeprecatedCommandsUpstream(t *testing.T) {
	const w = ".github/workflows/w.yml"
	checkDeprecatedCommands(t, "upstream", fstest.MapFS{w: {Data: []byte(`name: CI Build

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set version
        id: version
        run: echo "::set-output name=version::1.0.0"
      - name: Save state
        run: echo "::save-state name=build_id::12345"
      - name: Set environment
        run: echo "::set-env name=MY_VAR::my_value"
      - name: Add to path
        run: echo "::add-path::/custom/bin"
      - name: Use outputs
        run: echo "Version: ${{ steps.version.outputs.version }}"
      - run: ::set-output name=test::value
`)}}, []string{
		w + ": deprecated-command set-output", w + ": deprecated-command save-state",
		w + ": disabled-command set-env", w + ": disabled-command add-path",
	})
}

// TestDeprecatedCommandsOneRun: the commands of one run are findings of
// their own, with fingerprints of their own.
func TestDeprecatedCommandsOneRun(t *testing.T) {
	const w = ".github/workflows/w.yml"
	checkDeprecatedCommands(t, "one run", fstest.MapFS{w: {Data: []byte(`on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "::set-output name=a::1"
          echo "::set-output name=b::2"
          echo "::add-path::/opt/bin"
`)}}, []string{w + ": deprecated-command set-output", w + ": deprecated-command set-output", w + ": disabled-command add-path"})
}

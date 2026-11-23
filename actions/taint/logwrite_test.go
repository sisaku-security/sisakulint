package taint

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// flagsOf are, for each run of the workflow file, its step's name (or the
// job's id when it has none) and its UnsecureFlag.
func flagsOf(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := workflow.Parse(cst.ParseMode(b, cst.ModeGitHub))
	var out []string
	for _, s := range Analyze(w, nil).Sinks {
		name := s.Job.ID.AsString()
		if s.Step.Name.Status == workflow.Present {
			name = s.Step.Name.Value.AsString()
		}
		f := s.UnsecureFlag
		out = append(out, fmt.Sprintf("%s %v %v", name, f.State, f.Place))
	}
	return out
}

// TestUnsecureFlag: the jobs of runs observed on GitHub, and the test data
// of zizmor's insecure-commands, copied in testdata/zizmor.
func TestUnsecureFlag(t *testing.T) {
	for _, c := range []struct {
		file string
		want []string
	}{
		{e1Dir + "secret-in-log/3/.github/workflows/l2-commands.yml", []string{
			"print UnsecureOn FlagPlaceJob", "after UnsecureOn FlagPlaceJob",
			"flagged UnsecureOn FlagPlaceStep", "unflagged UnsecureOff FlagPlaceUnset", "after UnsecureOff FlagPlaceUnset",
			"upper UnsecureOn FlagPlaceStep", "one UnsecureOff FlagPlaceUnset", "spaced UnsecureOn FlagPlaceStep",
			"viaenvfile UnsecureOff FlagPlaceUnset", "afterenvfile UnsecureOn FlagPlaceGitHubEnv", "after UnsecureOn FlagPlaceGitHubEnv",
		}},
		{e1Dir + "secret-in-log/3/.github/workflows/l3-wfenv.yml", []string{"wf UnsecureOn FlagPlaceWorkflow", "wf UnsecureOn FlagPlaceWorkflow"}},
		{"testdata/zizmor/crates/zizmor/tests/integration/test-data/insecure-commands/issue-839-repro.yml", []string{
			"some-dangerous-job UnsecureOn FlagPlaceJob", "env-via-matrix UnsecureExpression FlagPlaceStep",
			"this-is-ok-1 UnsecureOff FlagPlaceUnset", "this-is-ok-2 UnsecureOff FlagPlaceUnset", "this-is-ok-3 UnsecureOff FlagPlaceUnset",
		}},
	} {
		t.Run(filepath.Base(c.file), func(t *testing.T) {
			if got := flagsOf(t, c.file); !slices.Equal(got, c.want) {
				t.Errorf("%s:\n got %q\nwant %q", c.file, got, c.want)
			}
		})
	}
}

// logRefs are the LogWrites of the runs of src, as the text of each.
func logRefs(t *testing.T, src string) []string {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	var out []string
	for _, s := range Analyze(w, nil).Sinks {
		text := Masked(s.Value)
		for _, l := range s.LogWrites {
			r, at := l.Env, text[l.Span.Start:l.Span.End]
			if l.RefIndex >= 0 {
				r, at = s.Refs[l.RefIndex], "H"
			}
			out = append(out, fmt.Sprintf("%s %v %v", at, len(r.Commands) > 0, len(r.CommandsUndecided) > 0))
		}
	}
	return out
}

func TestLogWrites(t *testing.T) {
	head := "on: [issues, fork]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n      TITLE: ${{ github.event.issue.title }}\n      DESCRIPTION: ${{ github.event.forkee.description }}\n    steps:\n"
	for _, c := range []struct {
		name, steps string
		want        []string
	}{
		{"echo", "      - run: |\n          echo \"$TITLE\"\n          echo \"${{ github.event.issue.title }}\"\n          echo \"$TITLE\" > f\n          echo \"$DESCRIPTION\"\n      - run: echo next\n", []string{"$TITLE true false", "H true false", "$DESCRIPTION false true"}},
		{"last step", "      - run: echo \"$TITLE\"\n", nil},
		{"echo -e", "      - run: echo -e \"$TITLE\"\n      - run: echo next\n", []string{"$TITLE true false"}},
		{"tee", "      - run: echo \"$TITLE\" | tee -a out.txt\n      - run: echo next\n", []string{"$TITLE true false"}},
		{"subst", "      - run: echo \"$(echo \"$TITLE\")\"\n      - run: echo next\n", []string{"$TITLE true false"}},
		// what a coproc prints goes to a pipe the shell reads, not to the log
		{"coproc pipe", "      - run: coproc echo \"$TITLE\" | cat\n      - run: echo next\n", nil},
		{"coproc subst", "      - run: echo \"$(coproc echo \"$TITLE\")\"\n      - run: echo next\n", nil},
		{"coproc stderr", "      - run: coproc { echo \"$TITLE\" >&2; }\n      - run: echo next\n", []string{"$TITLE true false"}},
		{"assigned", "      - run: |\n          TITLE=safe\n          echo \"$TITLE\"\n      - run: echo next\n", nil},
		{"length", "      - run: echo \"${#TITLE}\"\n      - run: echo next\n", nil},
		// the word of :-
		{"default word", "      - run: echo \"::set-env name=A::${X:-$TITLE}\"\n      - run: echo next\n", []string{"$TITLE true false"}},
		{"attributes", "      - run: echo \"${TITLE@a}\"\n      - run: echo next\n", nil},
		{"xtrace", "      - run: |\n          set -x\n          git log --grep \"$TITLE\" > f\n      - run: echo next\n", []string{"$TITLE true false"}},
		{"shell -x", "      - shell: bash -x {0}\n        run: git log --grep \"$TITLE\" > f\n      - run: echo next\n", []string{"$TITLE true false"}},
		{"shell -e", "      - shell: bash -e {0}\n        run: git log --grep \"$TITLE\" > f\n      - run: echo next\n", nil},
		{"shell -x, set +x", "      - shell: bash -x {0}\n        run: |\n          set +x\n          git log --grep \"$TITLE\" > f\n      - run: echo next\n", nil},
		// an echo whose output another command reads
		{"pipe to a filter", "      - run: |\n          if echo \"$TITLE\" | grep -q skip; then exit 0; fi\n          echo \"$TITLE\" | sha256sum\n          echo \"len $(echo \"$TITLE\" | wc -c)\"\n          wc -c <<< \"$(echo \"$TITLE\")\"\n      - run: echo next\n", nil},
		// what reaches the last command through the pipes (shell.PipeSources)
		{"pipe to a file", "      - run: echo \"$TITLE\" > f | cat\n      - run: echo next\n", nil},
		{"cat not reading the pipe", "      - run: echo \"$TITLE\" | cat < /dev/null\n      - run: echo next\n", nil},
		{"two cats", "      - run: echo \"$TITLE\" | cat | cat\n      - run: echo next\n", []string{"$TITLE true false"}},
		{"if body and cat", "      - run: |\n          if true; then echo \"$TITLE\"; fi\n          echo \"$TITLE\" | cat | tee x\n      - run: echo next\n", []string{"$TITLE true false", "$TITLE true false"}},
	} {
		if got := logRefs(t, head+c.steps); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestLogWritesPageName: the name of a wiki page made on the web interface
// holds add-path but no command that takes a property, as seen on
// 2026-11-06; a page pushed by git keeps its blanks, so whether the name
// holds one is not known. A key of a page that the schema does not
// describe may hold any command.
func TestLogWritesPageName(t *testing.T) {
	gollum := []analysis.EventActivity{analysis.MustEventActivity(workflow.EventNameGollum, workflow.ActivityTypeUnset)}
	for _, c := range []struct {
		ref                      string
		dash, cmds, undec, paths []analysis.EventActivity
	}{
		{"github.event.pages[0].page_name", gollum, nil, gollum, gollum},
		{"github.event.pages[0][github.event.pages[0].action]", gollum, gollum, nil, nil},
	} {
		src := "on: gollum\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - id: s\n        env:\n          V: ${{ " + c.ref + " }}\n        run: echo \"$V\"\n"
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		var got []ExprRef
		for _, s := range Analyze(w, nil).Sinks {
			for _, l := range s.LogWrites {
				got = append(got, l.Env)
			}
		}
		if len(got) != 1 {
			t.Fatalf("%s: %d log writes", c.ref, len(got))
		}
		r := got[0]
		if !slices.Equal(r.LeadingDash, c.dash) || !slices.Equal(r.Commands, c.cmds) || !slices.Equal(r.CommandsUndecided, c.undec) || !slices.Equal(r.PathCommands, c.paths) {
			t.Errorf("%s: %+v", c.ref, r)
		}
	}
}

// TestLogWritesStepID is where the LogWrites are found: a step with an id,
// whose outputs set-output sets, and a step whose
// flag may be on with a step after it.
func TestLogWritesStepID(t *testing.T) {
	head := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n%s    steps:\n"
	flag := "    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n"
	step := "      - %senv:\n          T: ${{ github.event.issue.title }}\n        run: echo \"$T\"\n"
	type sink struct {
		writes    int
		id, after bool
	}
	for _, c := range []struct {
		name string
		src  string
		want []sink
	}{
		{"id", fmt.Sprintf(head, "") + fmt.Sprintf(step, "id: s\n        "), []sink{{1, true, false}}},
		{"no id", fmt.Sprintf(head, "") + fmt.Sprintf(step, "") + "      - run: echo next\n", []sink{{0, false, true}, {0, false, false}}},
		{"flag, a step after", fmt.Sprintf(head, flag) + fmt.Sprintf(step, "") + "      - run: echo next\n", []sink{{1, false, true}, {0, false, false}}},
		{"flag, last", fmt.Sprintf(head, flag) + fmt.Sprintf(step, ""), []sink{{0, false, false}}},
		// GitHub rejects an id that is an expression, and the model reads none
		{"id of an expression", fmt.Sprintf(head, "") + fmt.Sprintf(step, "id: ${{ matrix.x }}\n        "), []sink{{0, false, false}}},
	} {
		w, _ := workflow.Parse(cst.ParseMode([]byte(c.src), cst.ModeGitHub))
		var got []sink
		for _, s := range Analyze(w, nil).Sinks {
			got = append(got, sink{len(s.LogWrites), s.HasStepID, s.HasStepAfter})
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	src := "name: a\ndescription: a\ninputs:\n  m:\n    required: true\nruns:\n  using: composite\n  steps:\n    - id: x\n      shell: bash\n      env:\n        T: ${{ github.event.issue.title }}\n      run: echo \"$T\"\n"
	a, _ := workflow.ParseActionMetadata(cst.ParseMode([]byte(src), cst.ModeGitHub))
	var got []sink
	for _, s := range Analyze(nil, a).Sinks {
		got = append(got, sink{len(s.LogWrites), s.HasStepID, s.HasStepAfter})
	}
	if want := []sink{{1, true, false}}; !slices.Equal(got, want) {
		t.Errorf("composite: got %v, want %v", got, want)
	}
}

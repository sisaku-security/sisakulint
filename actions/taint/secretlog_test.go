package taint

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// leakLabel is the name of the value in front of the leak at at in the
// run: the last NAME= before it on its line, or the first mNN of the line.
var (
	leakAssign = regexp.MustCompile(`([A-Za-z][A-Za-z0-9]*)=`)
	leakMark   = regexp.MustCompile(`\bm[0-9]+\b`)
)

func leakLabel(run string, at int) string {
	start := strings.LastIndexByte(run[:at], '\n') + 1
	end := strings.IndexByte(run[at:], '\n')
	if end < 0 {
		end = len(run) - at
	}
	if ms := leakAssign.FindAllStringSubmatch(run[start:at], -1); len(ms) > 0 {
		return ms[len(ms)-1][1]
	}
	return leakMark.FindString(run[start : at+end])
}

// leaksOf are the SecretLeaks of the workflow file, as "label place".
func leaksOf(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w, _ := workflow.Parse(cst.ParseMode(b, cst.ModeGitHub))
	var out []string
	for _, s := range Analyze(w, nil).Sinks {
		run := Masked(s.Value)
		for _, l := range s.SecretLeaks {
			out = append(out, leakLabel(run, l.At.Start)+" "+l.Place.String())
		}
	}
	return out
}

const e1Dir = "testdata/observed/"

// TestSecretLeaksObserved: as observed in a run, the lines the log showed, and the
// lines it masked that the rule tells (m01, m02, m14, m18, m19b, m20,
// m26 and the writes of D4 and WHOLE give nothing). m07, m08, m13, m15b,
// m17w, q2 and r2 the runner masked as an encoding the rule does not tell
// (FalsePositiveForm masked-encoding); m20= showed the second line, which
// the rule takes as masked (UndetectedForm multi-line-mask).
func TestSecretLeaksObserved(t *testing.T) {
	for _, c := range []struct {
		file string
		want []string
	}{
		{e1Dir + "secret-in-log/3/.github/workflows/l1-mask.yml", []string{
			"m03 LogPlaceStandardOutputOrError", "m04 LogPlaceStandardOutputOrError", "m05 LogPlaceStandardOutputOrError", "m06 LogPlaceStandardOutputOrError",
			"m07 LogPlaceStandardOutputOrError", "m08 LogPlaceStandardOutputOrError", "m09 LogPlaceStandardOutputOrError", "m10 LogPlaceStandardOutputOrError",
			"m11 LogPlaceStandardOutputOrError", "m12 LogPlaceStandardOutputOrError", "m13 LogPlaceStandardOutputOrError", "m15b LogPlaceStandardOutputOrError",
			"m17 LogPlaceStandardOutputOrError", "m17w LogPlaceStandardOutputOrError", "m19a LogPlaceStandardOutputOrError", "D3 LogPlaceXtrace",
			"m27 LogPlaceStandardOutputOrError",
			"DER LogPlaceGitHubEnv",
			"m22 LogPlaceStandardOutputOrError", "m23 LogPlaceStepHeader",
			"m24d LogPlaceStepHeader",
		}},
		{e1Dir + "secret-in-log/2/.github/workflows/l4-cross.yml", []string{
			"DERB LogPlaceGitHubEnv", "q1 LogPlaceStandardOutputOrError", "q2 LogPlaceStandardOutputOrError", "r1 LogPlaceStandardOutputOrError", "r2 LogPlaceStandardOutputOrError",
			"n22 LogPlaceStandardOutputOrError", "n23 LogPlaceStepHeader",
			"n24 LogPlaceStepHeader",
		}},
	} {
		if got := leaksOf(t, c.file); !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.file, got, c.want)
		}
	}
}

func TestSecretLeaksForms(t *testing.T) {
	head := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      S: ${{ secrets.S }}\n    steps:\n"
	for _, c := range []struct {
		name, steps string
		want        []string
	}{
		{"summary", "      - run: echo \"t=${S:1}\" >> \"$GITHUB_STEP_SUMMARY\"\n", []string{"t LogPlaceJobSummary"}},
		{"stderr", "      - run: echo \"t=${S:1}\" >&2\n", []string{"t LogPlaceStandardOutputOrError"}},
		// what a function a pipe's command calls prints is what the pipe
		// carries
		{"function to cat", "      - run: |\n          f() { echo \"t=${S:1}\"; }\n          f | cat\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"function |& cat", "      - run: |\n          f() { echo \"t=${S:1}\" >&2; }\n          f |& cat\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"function writes a file", "      - run: |\n          f() { printf '%s' \"$S\" | base64 -d > p; echo done; }\n          x=$(f)\n          echo \"$x\"\n", nil},
		// the redirects of the definition and of the call
		{"definition to /dev/null", "      - run: |\n          f() { echo \"t=${S:1}\"; } >/dev/null\n          x=$(f)\n          echo \"$x\"\n", nil},
		{"call 2>/dev/null", "      - run: |\n          f() { echo \"t=${S:1}\" >&2; }\n          x=$(f 2>/dev/null)\n          echo \"$x\"\n", nil},
		{"call 2>/dev/null to cat", "      - run: |\n          f() { echo \"t=${S:1}\" >&2; }\n          f 2>/dev/null | cat\n", nil},
		{"call 2>&1 to cat", "      - run: |\n          f() { echo \"t=${S:1}\" >&2; }\n          f 2>&1 | cat\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"nested calls to cat", "      - run: |\n" + nestedCalls(12) + "          f1 | cat\n", []string{"t LogPlaceStandardOutputOrError"}},
		// the reading of descriptors reads the outputs
		{"exec 2>&1 in a substitution", "      - run: |\n          x=$(exec 2>&1; echo \"t=${S:1}\" >&2)\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		{"exec 2>&1 in a body", "      - run: |\n          f() { exec 2>&1; echo \"t=${S:1}\" >&2; }\n          f | cat\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"exec >/dev/null in a substitution", "      - run: |\n          x=$(exec >/dev/null; echo \"t=${S:1}\")\n          echo \"$x\"\n", nil},
		{"echo to stderr in a substitution", "      - run: |\n          x=$(echo \"t=${S:1}\" >&2)\n          echo \"$x\"\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"stderr to the output in nested substitutions", "      - run: |\n          x=$(exec 2>&1; echo \"[$(echo \"t=${S:1}\" >&2)]\")\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		{"stderr to the log in nested substitutions", "      - run: |\n          x=$(echo \"[$(echo \"t=${S:1}\" >&2)]\")\n          echo \"$x\"\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"return in a substitution in a body", "      - run: |\n          f() { x=$(return; echo \"t=${S:1}\"); echo \"$x\"; }\n          f\n", nil},
		{"break in a substitution in a loop", "      - run: |\n          for i in 1; do x=$(break; echo \"t=${S:1}\"); echo \"$x\"; done\n", nil},
		{"recursion through a substitution", "      - run: |\n          f() { if [ \"$1\" -gt 0 ]; then echo \"$(f $(($1-1)))\"; fi; echo \"t=${S:1}\"; }\n          f 2 | cat\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"recursion through a filter", "      - run: |\n          f() { if [ \"$1\" = 1 ]; then x=$(f 0 | sed s/S/Z/); echo \"$x\"; else echo \"$S\"; fi; }\n          f 1\n", []string{"x LogPlaceStandardOutputOrError"}},
		{"descriptor 3 to the output", "      - run: |\n          x=$({ echo \"t=${S:1}\" >&3; } 3>&1 >/dev/null)\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		// a $( ) that writes to the output of the $( ) around it
		{"stderr to the output around, through a variable", "      - run: |\n          x=$(exec 2>&1; y=$(echo \"t=${S:1}\" >&2); echo \"$y\")\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		{"descriptor 3 to the output around, through a variable", "      - run: |\n          x=$(exec 3>&1; y=$(echo \"t=${S:1}\" >&3); echo \"$y\")\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		{"a group to the output around, through a variable", "      - run: |\n          x=$( { y=$(echo \"t=${S:1}\" >&2); echo \"$y\"; } 2>&1 )\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		// break 2 past the loop of a $( ) ends the $( )
		{"break 2 in a substitution in a loop", "      - run: |\n          for i in 1; do y=$(for j in 1; do break 2; done; echo \"t=${S:1}\"); echo \"[$y]\"; done\n", nil},
		// a break in the body of a function called in a $( ) does not end the
		// $( ): bash reads it as an error
		{"break in a body called in a substitution", "      - run: |\n          f() { break; }\n          for i in 1; do x=$(f; echo \"t=${S:1}\"); echo \"[$x]\"; done\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"break first in a body called in a substitution", "      - run: |\n          f() { break; echo \"t=${S:1}\"; }\n          for i in 1; do x=$(f); echo \"[$x]\"; done\n", []string{"x LogPlaceStandardOutputOrError"}},
		// a $( ) that writes to the pipe of a pipeline around it
		{"stderr to a pipe around", "      - run: |\n          f() { y=$(echo \"t=${S:1}\" >&2); echo \"[$y]\"; }\n          x=$( { f; } 2>&1 | cat )\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		{"descriptor 3 to a pipe around, to a digest", "      - run: |\n          { x=$(echo \"t=${S:1}\" >&3); } 3>&1 | sha256sum\n", nil},
		{"descriptor 3 to a pipe around, in a body, to a count", "      - run: |\n          f() { x=$(echo \"t=${S:1}\" >&3); }\n          f 3>&1 | wc -c\n", nil},
		{"descriptor 3 to a pipe around, to cat", "      - run: |\n          x=$( { y=$(echo \"t=${S:1}\" >&3); } 3>&1 | cat )\n          echo \"$x\"\n", []string{" LogPlaceStandardOutputOrError"}},
		// a descriptor of a writer copied from the standard output before its
		// redirect to the job summary: bash prints the value to the log, not
		// to the summary
		{"descriptor 4 of a writer to the log", "      - run: |\n          f() { y=$(echo \"t=${S:1}\" >&4); echo \"${#y}\"; }\n          f x 4>&1 >>\"$GITHUB_STEP_SUMMARY\"\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"return before echo", "      - run: |\n          f() { return; echo \"t=${S:1}\"; }\n          f | cat\n", nil},
		{"masked after", "      - run: |\n          f() { echo \"$v\"; }\n          v=\"${S:1}\"\n          curl -s \"https://example.com/?q=$(f)\" >/dev/null 2>&1\n          echo \"::add-mask::$v\"\n          f | cat\n", nil},
		{"nested calls with input", "      - run: |\n" + nestedCallsIn(12) + "          printf '%s' \"${S:1}\" | f1 | cat\n", []string{"t LogPlaceStandardOutputOrError", " LogPlaceStandardOutputOrError"}},
		{"recursive functions to cat", "      - run: |\n          f() { g; g; echo \"t=${S:1}\"; }\n          g() { f; f; }\n          f | cat\n", []string{"t LogPlaceStandardOutputOrError"}},
		// the message of :?, which bash prints on the standard error
		{"message of :?", "      - run: echo \"${X:?${S:1}}\"\n", []string{" LogPlaceStandardOutputOrError"}},
		{"word of :- printed", "      - run: echo \"${X:-${S:1}}\"\n", []string{" LogPlaceStandardOutputOrError"}},
		{"file", "      - run: echo \"t=${S:1}\" > out.txt\n", nil},
		{"last step env", "      - run: echo \"t=${S:1}\" >> \"$GITHUB_ENV\"\n", nil},
		{"set -eux", "      - run: |\n          set -eux\n          t=${S:1}\n", []string{"t LogPlaceXtrace"}},
		{"set +x", "      - run: |\n          set -x\n          set +x\n          t=${S:1}\n", nil},
		// a shell: with -x starts with the trace on
		{"shell -x", "      - shell: bash -x {0}\n        run: t=${S:1}\n", []string{"t LogPlaceXtrace"}},
		{"shell -x, set +x", "      - shell: bash -x {0}\n        run: |\n          set +x\n          t=${S:1}\n", nil},
		{"shell -x +x", "      - shell: bash -x +x {0}\n        run: t=${S:1}\n", nil},
		{"shell sh -x", "      - shell: sh -x {0}\n        run: t=${S:1}\n", []string{"t LogPlaceXtrace"}},
		{"shell -x, subshell", "      - shell: bash -x {0}\n        run: ( t=${S:1} )\n", []string{"t LogPlaceXtrace"}},
		{"shell -e", "      - shell: bash -e {0}\n        run: t=${S:1}\n", nil},
		{"set -eo xtrace", "      - run: |\n          set -eo xtrace\n          t=${S:1}\n", []string{"t LogPlaceXtrace"}},
		{"subshell", "      - run: |\n          ( set -x; true )\n          t=${S:1}\n", nil},
		{"in a subshell", "      - run: ( set -x; t=${S:1} )\n", []string{"t LogPlaceXtrace"}},
		// a coproc runs in a subshell whose standard output is a pipe to the shell
		{"coproc", "      - run: |\n          coproc { set -x; true; }\n          t=${S:1}\n", nil},
		{"in a coproc", "      - run: coproc { set -x; t=${S:1}; }\n", []string{"t LogPlaceXtrace"}},
		// a call after an element of an array
		{"call after an element", "      - run: |\n          f() { t=${S:1}; }\n          set -x\n          a[0]=x f\n", []string{"t LogPlaceXtrace"}},
		{"echo in a coproc", "      - run: coproc echo \"t=${S:1}\"\n", nil},
		{"coproc piped", "      - run: coproc echo \"t=${S:1}\" | cat\n", nil},
		{"coproc in a substitution", "      - run: echo \"$(coproc echo \"t=${S:1}\")\"\n", nil},
		// what a function defined outside reads when a subshell calls it
		// after an assignment
		{"called in the subshell", "      - run: |\n          f() { echo \"t=$t\"; }\n          ( t=${S:1}; f )\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"used in the subshell", "      - run: ( t=${S:1}; echo \"t=$t\" )\n", []string{"t LogPlaceStandardOutputOrError"}},
		{"traced in the name of a coproc", "      - run: |\n          set -x\n          coproc \"$(t=${S:1})\" { :; }\n", []string{"t LogPlaceXtrace"}},
		// bash traces the commands of a substitution in a heredoc's body and
		// in a redirect's target
		{"traced in a heredoc's body", "      - run: |\n          set -x\n          cat <<EOF\n          $(t=${S:1})\n          EOF\n", []string{"t LogPlaceXtrace"}},
		{"traced in a subshell's redirect", "      - run: |\n          set -x\n          ( : ) > \"$(t=${S:1}; echo f)\"\n", []string{"t LogPlaceXtrace"}},
		// a function's body runs where it is called, with the trace there
		{"traced in a function called after set -x", "      - run: |\n          f() { t=${S:1}; }\n          set -x\n          f\n", []string{"t LogPlaceXtrace"}},
		{"set -x in a function kept after the call", "      - run: |\n          f() { set -x; }\n          f\n          t=${S:1}\n", []string{"t LogPlaceXtrace"}},
		{"function not called", "      - run: |\n          set -x\n          f() { t=${S:1}; }\n", nil},
		{"coproc assigned", "      - run: |\n          R=$(coproc echo \"t=${S:1}\"; sleep 1)\n          echo \"r=$R\"\n", nil},
		{"if body", "      - run: |\n          if true; then set -x; fi\n          t=${S:1}\n", []string{"t LogPlaceXtrace"}},
		{"heredoc", "      - run: |\n          base64 <<EOF\n          $S\n          EOF\n", []string{" LogPlaceStandardOutputOrError"}},
		{"curl response", "      - run: |\n          R=$(curl -H \"Authorization: $S\" https://x)\n          echo \"r=$R\"\n", nil},
		{"masked before", "      - run: |\n          D=${S:2}\n          echo \"::add-mask::$D\"\n          echo \"d=$D\"\n", nil},
		{"masked other value", "      - run: |\n          D=${S:2}\n          echo \"::add-mask::$D\"\n          D=${S:3}\n          echo \"d=$D\"\n", []string{"d LogPlaceStandardOutputOrError"}},
	} {
		dir := t.TempDir()
		p := dir + "/w.yml"
		if err := os.WriteFile(p, []byte(head+c.steps), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := leaksOf(t, p); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPrintedOutputs(t *testing.T) {
	b, err := os.ReadFile(e1Dir + "secret-in-log/2/.github/workflows/l4-cross.yml")
	if err != nil {
		t.Fatal(err)
	}
	w, _ := workflow.Parse(cst.ParseMode(b, cst.ModeGitHub))
	var got []string
	for _, p := range PrintedOutputs(nil, calls.Node{}, w, nil) {
		got = append(got, p.Value.Text()+" "+p.Secret.Name+" "+p.Secret.Transform.String())
	}
	if want := []string{"${{ steps.w.outputs.o }} PROBE_B substring"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	src := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      d: ${{ steps.w.outputs.o }}
    env:
      S: ${{ secrets.S }}
    steps:
      - id: w
        run: echo "o=${S:1}" >> "$GITHUB_OUTPUT"
  b:
    needs: a
    runs-on: ubuntu-latest
    env:
      D: ${{ needs.a.outputs.d }}
    steps:
      - name: use ${{ needs.a.outputs.d }}
        uses: actions/github-script@v7
        with:
          x: ${{ needs.a.outputs.d }}
`
	w, _ = workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	got = nil
	for _, p := range PrintedOutputs(nil, calls.Node{}, w, nil) {
		got = append(got, p.Value.Text())
	}
	if want := []string{"use ${{ needs.a.outputs.d }}", "${{ needs.a.outputs.d }}", "${{ needs.a.outputs.d }}"}; len(got) != len(want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestSecretLeaksOnceMisread: forms of a secret made into a value and
// printed that SecretLeak once read wrongly, each with what it reads now.
func TestSecretLeaksOnceMisread(t *testing.T) {
	head := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      S: ${{ secrets.S }}\n    steps:\n"
	for _, c := range []struct {
		name, steps string
		want        []string
	}{
		// a function's output goes where the call sends it
		{"call to null", "      - run: |\n          f() { echo \"$1\"; }\n          f \"${S:0:4}\" > /dev/null\n", nil},
		{"call in subst", "      - run: |\n          f() { echo \"$1\"; }\n          V=$(f \"${S:0:4}\")\n", nil},
		{"call", "      - run: |\n          f() { echo \"$1\"; }\n          f \"${S:0:4}\"\n", []string{" LogPlaceStandardOutputOrError"}},
		// the words of a filter are its program, not its input
		{"sed -i", "      - run: sed -i \"s/__TOKEN__/$S/g\" config.yml\n", nil},
		{"grep -q", "      - run: |\n          if echo \"$S\" | grep -q '^ghp_'; then echo ok; fi\n", nil},
		{"jq --arg", "      - run: jq -n --arg t \"$S\" '{t: $t}'\n", nil},
		// the devices of the current descriptors
		{"stdout in subst", "      - run: Y=$(echo \"${S:0:4}\" > /dev/stdout)\n", nil},
		{"stderr to file", "      - run: |\n          exec 2>err.log\n          echo \"${S:0:4}\" > /dev/stderr\n", nil},
		// tee writes what it reads
		{"tee", "      - run: echo \"t=${S:0:4}\" | tee -a \"$GITHUB_STEP_SUMMARY\"\n", []string{"t LogPlaceStandardOutputOrError", "t LogPlaceJobSummary"}},
		// a value registered in the step before a later step
		{"mask after write", "      - run: |\n          D=${S:2}\n          echo \"D=$D\" >> \"$GITHUB_ENV\"\n          echo \"::add-mask::$D\"\n      - run: echo \"d=$D\"\n", nil},
		// a step of the same parallel group is not after
		{"parallel", "      - parallel:\n          - run: echo \"D=${S:2}\" >> \"$GITHUB_ENV\"\n          - run: echo x\n", nil},
		// set -- -x sets the parameters, not the trace
		{"set --", "      - run: |\n          set -- -x\n          t=${S:1}\n", nil},
		// the corpus (bytedance__UI-TARS-desktop release-ui-tars.yml): base64 -o
		// writes to the file
		{"base64 -o", "      - run: |\n          echo -n \"$S\" | base64 --decode -o cert.p12\n          echo -n \"$S\" | base64 -d --output=cert.p12\n", nil},
		// ::add-mask:: of a part registers the part
		{"mask of a part", "      - run: |\n          D=${S:2}\n          echo \"::add-mask::${D:0:4}\"\n          echo \"::add-mask::${#D}\"\n          echo \"d=$D\"\n", []string{"d LogPlaceStandardOutputOrError"}},
	} {
		dir := t.TempDir()
		p := dir + "/w.yml"
		if err := os.WriteFile(p, []byte(head+c.steps), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := leaksOf(t, p); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestRecursiveFunctionBounded: a function that calls
// itself is read in a time bounded by the calls, not exponential. The time
// is compared with ACTIONS_SCALE=1 only, as it depends on the machine; the
// leak is checked in every run.
func TestRecursiveFunctionBounded(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      S: ${{ secrets.S }}\n    steps:\n      - run: |\n          f() { echo \"${1:0:2}\"; f \"$1\"; f \"$1\"; f \"$1\"; f \"$1\"; }\n          f \"$S\"\n"
	start := time.Now()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	n := 0
	for _, s := range Analyze(w, nil).Sinks {
		n += len(s.SecretLeaks)
	}
	if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > 2*time.Second || n != 1 {
		t.Errorf("%d leaks in %v", n, d)
	}
}

// TestSecretLeaksPathShell: a custom shell that names bash by a path is
// read only on a runner known to have the path (ShellInvocationOf); on
// self-hosted the run is not read, which the declaration other-shell of
// secret-in-log names.
func TestSecretLeaksPathShell(t *testing.T) {
	for _, c := range []struct {
		label string
		want  []string
	}{
		{"ubuntu-latest", []string{"t LogPlaceXtrace"}},
		{"self-hosted", nil},
	} {
		src := "on: push\njobs:\n  j:\n    runs-on: " + c.label + "\n    env:\n      S: ${{ secrets.S }}\n    steps:\n      - shell: /bin/bash -x {0}\n        run: t=${S:1}\n"
		p := t.TempDir() + "/w.yml"
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := leaksOf(t, p); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.label, got, c.want)
		}
	}
}

// nestedCalls are n functions f1 to fn, each calling the next four times,
// the last printing a value made from the secret S.
func nestedCalls(n int) string {
	var b strings.Builder
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "          f%d() { f%d; f%d; f%d; f%d; }\n", i, i+1, i+1, i+1, i+1)
	}
	fmt.Fprintf(&b, "          f%d() { echo \"t=${S:1}\"; }\n", n)
	return b.String()
}

// nestedCallsIn is nestedCalls whose last function also writes its input.
func nestedCallsIn(n int) string {
	return strings.Replace(nestedCalls(n), fmt.Sprintf("f%d() { echo", n), fmt.Sprintf("f%d() { cat; echo", n), 1)
}

// TestSecretFlowTime: the readings of outputs of functions whose bodies nest
// $( ) end in time: within 2 seconds, about twice the time main took for the
// whole CLI on the longest of them (1.087 seconds, with the machine busy,
// 2026-11-16; the time of the chain alone was 0.418 seconds on a machine not
// busy).
func TestSecretFlowTime(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 runs it")
	}
	var many strings.Builder
	for i := range 200 {
		fmt.Fprintf(&many, "echo \"a%d$(f1)\"\n", i)
	}
	for _, c := range []struct {
		name, run string
		limit     time.Duration // 2 seconds when zero
	}{
		{"chain", substitutionChain(22, `echo "t=${S:1}"`) + "f1 | cat", 0},
		{"chain with a recursion", substitutionChain(22, `echo "$(f1)"; echo "t=${S:1}"`) + "f1 | cat", 0},
		{"200 lines of a chain with a recursion", substitutionChain(22, `echo "$(f1)"; echo "t=${S:1}"`) + many.String(), 0},
		// answers cut short are kept, and read again from the memo
		{"a chain of 18 calls of three arguments", argChain(18) + `a1 "$S"`, 0},
		{"a value of the output of calls past the limit, quadrupled ten times", quadrupled(14, 11), 0},
		// 12 functions that call each other through $( ), read at 20 lines;
		// within three times the 2.0 seconds main took for the whole CLI on a
		// busy machine
		{"12 functions calling each other through $( ), 20 lines", mutualCalls(12, 20), 6 * time.Second},
	} {
		start := time.Now()
		outputCalls(t, c.run)
		limit := c.limit
		if limit == 0 {
			limit = 2 * time.Second
		}
		if d := time.Since(start); d > limit {
			t.Errorf("%s: %v", c.name, d)
		}
	}
}

// argChain are n functions a1 to an, each but the last calling the next with
// its first argument three times, the last printing a value made from it.
func argChain(n int) string {
	var b strings.Builder
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "a%d() { a%d \"$1$1$1\"; }\n", i, i+1)
	}
	fmt.Fprintf(&b, "a%d() { echo \"${1:1}\"; }\n", n)
	return b.String()
}

// quadrupled are n functions b1 to bn, each but the last calling the next
// twice, the last printing a value made from S; v1 is the output of b1, and
// each of v2 to vm is the one before four times; vm is printed.
func quadrupled(n, m int) string {
	var b strings.Builder
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "b%d() { b%[2]d; b%[2]d; }\n", i, i+1)
	}
	fmt.Fprintf(&b, "b%d() { echo \"${S:1}\"; }\nv1=$(b1)\n", n)
	for i := 2; i <= m; i++ {
		fmt.Fprintf(&b, "v%d=\"$v%[2]d$v%[2]d$v%[2]d$v%[2]d\"\n", i, i-1)
	}
	fmt.Fprintf(&b, "echo \"$v%d\"\n", m)
	return b.String()
}

// TestSecretLeaksMemoCuts: an answer read again from the memo carries the
// cuts of its read, so that what reads it does not keep an answer a cut made
// as one no cut made: bash prints the base64 of what f prints, which holds
// the secret.
func TestSecretLeaksMemoCuts(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      S: ${{ secrets.S }}\n    steps:\n      - run: |\n" + indent(`h() { if [ "$1" -lt 3 ]; then f $(($1+1)) | cat; f $(($1+1)); fi; echo "::add-mask::${S:1}"; }
f() { if [ "$1" -lt 3 ]; then echo "$(h $(($1+1)))"; w=$(f $(($1+1)) | base64); echo "$w"; fi; }
g() { h 0; }
g`) + "\n"
	p := t.TempDir() + "/w.yml"
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := leaksOf(t, p); !slices.Contains(got, "w LogPlaceStandardOutputOrError") {
		t.Errorf("got %q, want the base64 of w among them", got)
	}
}

// mutualCalls are n functions f1 to fn, each but the last printing the $( )
// of every one of them, and setting xi to the $( ) of the next and printing
// it, the last printing a value made from S; m lines pipe one of them to
// cat.
func mutualCalls(n, m int) string {
	var subs, b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&subs, "$(f%d)", i)
	}
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "f%[1]d() { echo \"%[2]s\"; x%[1]d=$(f%[3]d); echo \"$x%[1]d\"; }\n", i, subs.String(), i+1)
	}
	fmt.Fprintf(&b, "f%d() { echo \"t=${S:1}\"; }\n", n)
	for j := range m {
		fmt.Fprintf(&b, "f%d | cat\n", j%n+1)
	}
	return b.String()
}

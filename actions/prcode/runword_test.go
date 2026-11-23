package prcode

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// firstWords are the words of the first simple command of the run of the
// first step of src's first job.
func firstWords(t *testing.T, src string, inComposite bool) []runWord {
	t.Helper()
	w := mustWorkflow(t, src)
	j := w.Jobs.Value.Entries[0].Value.Value
	x := j.Steps.Value.Items[0]
	masked := taint.Masked(x.Run.Value)
	sc := taint.ReadScript(nil, x.Run.Value).Script
	var out []runWord
	done := false
	walkFirst(sc, func(ws []runWord) {
		if !done {
			out, done = ws, true
		}
	}, x.Run.Value, masked, inComposite)
	return out
}

func TestWordOf(t *testing.T) {
	for _, c := range []struct {
		run         string
		composite   bool
		base        wordBase
		path        string
		open, known bool
	}{
		{"bash $RUNNER_TEMP/a/x.sh", false, wordRunnerTemp, "a/x.sh", false, true},
		{"bash ${RUNNER_TEMP}x/run.sh", false, wordBeside, "", false, true},
		{"bash ${{ runner.temp }}/${{ inputs.x }}", false, wordRunnerTemp, "", true, true},
		{"bash x$RUNNER_TEMP/y", false, wordWorkspace, "x", true, true},
		{"bash ${{ inputs.dir }}/x.sh", false, wordAnywhere, "", true, true},
		{"bash $GITHUB_WORKSPACE/x.sh", false, wordWorkspace, "x.sh", false, true},
		{"bash ${GITHUB_WORKSPACE}x/y.sh", false, wordBeside, "", false, true},
		{"bash ${{ github.action_path }}/x.sh", false, wordAnywhere, "", true, true},
		{"bash ${{ github.action_path }}/x.sh", true, wordAnywhere, "", true, true},
		{"bash $RUNNER_TEMP/../r/r/x.sh", false, wordAnywhere, "../r/r/x.sh", false, true},
		{"bash ./pr/${{ inputs.f }}", false, wordWorkspace, "./pr/", true, true},
		{"bash $HOME/x.sh", false, wordWorkspace, "", false, false},
		{`bash "${{ runner.temp }}/a b.sh"`, false, wordRunnerTemp, "a b.sh", false, true},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: '" + c.run + "'\n"
		if c.run[len(c.run)-1] == '"' {
			src = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          " + c.run + "\n"
		}
		ws := firstWords(t, src, c.composite)
		if len(ws) < 2 {
			t.Errorf("%s: words %v", c.run, ws)
			continue
		}
		w := ws[1]
		if w.base != c.base || w.known != c.known || c.known && (w.path != c.path || w.open != c.open) {
			t.Errorf("%s (composite %v): %+v; want base %v path %q open %v known %v", c.run, c.composite, w, c.base, c.path, c.open, c.known)
		}
	}
}

// TestCodeRunsWords is the reading of the words of the runs: the
// ${{ }} by their syntax, open words, and the wrappers.
func TestCodeRunsWords(t *testing.T) {
	for _, c := range []struct {
		name  string
		at    Placement
		after string
		runs  []string
	}{
		{"expression dir under pr", ws("pr"), "      - run: bash ${{ inputs.dir }}/x.sh\n", []string{"bash ${{ inputs.dir }}/x.sh"}},
		{"dot slash expression under pr", ws("pr"), "      - run: bash ./${{ inputs.f }}\n", []string{"bash ./${{ inputs.f }}"}},
		{"runner.temp in the middle under x", ws("x"), "      - run: bash x$RUNNER_TEMP/y\n", []string{"bash x$RUNNER_TEMP/y"}},
		{"runner.temp in the middle under .", ws("."), "      - run: bash x$RUNNER_TEMP/y\n", []string{"bash x$RUNNER_TEMP/y"}},
		{"runner.temp in the middle not under dist", ws("dist"), "      - run: bash x$RUNNER_TEMP/y\n", nil},
		{"GITHUB_WORKSPACE", ws("."), "      - run: bash $GITHUB_WORKSPACE/x.sh\n", []string{"bash $GITHUB_WORKSPACE/x.sh"}},
		{"GITHUB_WORKSPACE sibling", ws("."), "      - run: bash ${GITHUB_WORKSPACE}x/y.sh\n", nil},
		{"RUNNER_TEMP sibling", rt("."), "      - run: bash ${RUNNER_TEMP}x/run.sh\n", nil},
		{"runner.temp then expression", rt("a"), "      - run: bash ${{ runner.temp }}/${{ inputs.x }}\n", []string{"bash ${{ runner.temp }}/${{ inputs.x }}"}},
		{"timeout with an expression", ws("."), "      - run: timeout ${{ inputs.t }} npm test\n", []string{"timeout ${{ inputs.t }} npm test"}},
		{"env with an expression", ws("."), "      - run: env FOO=${{ secrets.X }} npm test\n", []string{"env FOO=${{ secrets.X }} npm test"}},
		{"sudo with an expression", ws("."), "      - run: sudo -u ${{ inputs.u }} npm ci\n", []string{"sudo -u ${{ inputs.u }} npm ci"}},
		{"command is an expression", ws("."), "      - run: ${{ steps.py.outputs.python-path }} -V\n", nil},
		// outside a composite action github.action_path is empty, and the
		// absolute path that is left may be anywhere
		{"action_path in a workflow", rt("a"), "      - run: bash ${{ github.action_path }}/x.sh\n", []string{"bash ${{ github.action_path }}/x.sh"}},
		{"escape with an expression", ws("."), "      - run: bash ${{ inputs.d }}/my\\ x.sh\n", []string{"bash ${{ inputs.d }}/my\\ x.sh"}},
		{"sudo glued to runner.temp is not sudo", ws("dist"), "      - run: sudo$RUNNER_TEMP/y ./dist/x.sh\n", nil},
		{"sudo before a file of dist", ws("dist"), "      - run: sudo ./dist/x.sh\n", []string{"sudo ./dist/x.sh"}},
		{"runner.temp in the middle is a directory", ws("xy"), "      - run: bash x$RUNNER_TEMP/y\n", nil},
		{"ANSI quotes with runner.temp", rt("a"), "      - run: bash $'${{ runner.temp }}/a/x.sh'\n", []string{"bash $'${{ runner.temp }}/a/x.sh'"}},
		{"an expression with an extension may be absolute", rt("a"), "      - run: bash ${{ inputs.s }}.sh\n", []string{"bash ${{ inputs.s }}.sh"}},
		{"HOME is not read", rt("."), "      - run: bash $HOME/x.sh\n", nil},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo first\n" + c.after
		w := mustWorkflow(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		var got []string
		for _, e := range codeRuns(w, &j, j.Steps.Value.Items, workflow.OrderOf(j.Steps.Value.Items), 0, c.at, nil) {
			got = append(got, e.Text)
		}
		if !slices.Equal(got, c.runs) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.runs)
		}
	}
}

// walkFirst calls f with the words of each simple command of sc.
func walkFirst(sc *shell.Script, f func([]runWord), v workflow.String, masked string, inComposite bool) {
	shell.WalkSimple(sc.List, func(c *shell.Simple) {
		var ws []runWord
		for _, wd := range c.Words {
			ws = append(ws, wordOf(v, masked, wd, inComposite))
		}
		f(ws)
	})
}

func TestExprSpans(t *testing.T) {
	for _, c := range []struct {
		run  string
		want []runWord
	}{
		// the part is "${{ inputs.d }}/my\ x.sh": the escape is taken out
		{`bash ${{ inputs.d }}/my\ x.sh`, []runWord{{base: wordAnywhere, open: true, known: true}}},
		{`bash "${{ runner.temp }}/a\"b"`, []runWord{{base: wordRunnerTemp, path: `a"b`, known: true}}},
		{`bash x\${{ runner.temp }}/y`, []runWord{{base: wordWorkspace, path: "x", open: true, known: true}}},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          " + c.run + "\n"
		ws := firstWords(t, src, false)
		w := ws[1]
		g := c.want[0]
		if w.base != g.base || w.path != g.path || w.open != g.open || w.known != g.known {
			t.Errorf("%s: %+v; want %+v", c.run, w, g)
		}
	}
}

// TestCodeRunsPwsh is the reading of the words of pwsh.
func TestCodeRunsPwsh(t *testing.T) {
	counted := []string{
		"python ${{ runner.temp }}/a/x.py",
		`python "${{ runner.temp }}/a/x.py"`,
		"python $env:RUNNER_TEMP/a/x.py",
		"python ${env:RUNNER_TEMP}/a/x.py",
		`python ${{ runner.temp }}\a\x.py`,
		`& "$env:RUNNER_TEMP/a/x.ps1"`,
	}
	for _, c := range []struct {
		name string
		at   Placement
		run  string
		want bool
	}{
		{"single quotes do not expand", rt("a"), `python '$env:RUNNER_TEMP/a/x.py'`, false},
		{"a string at the head is an expression", rt("a"), `"$env:RUNNER_TEMP/a/x.py"`, false},
		{"a variable at the head is an expression", rt("a"), `$env:RUNNER_TEMP/a/x.py`, false},
		{"dot slash", ws("."), "python ./x.py", true},
		{"a variable in the workspace", ws("."), "python $dir/x.py", true},
		{"a variable under pr", ws("pr"), "python $dir/x.py", true},
		{"a variable dir", ws("."), "./$x/run.ps1", true},
		{"a variable is not runner.temp", rt("a"), "python $dir/x.py", false},
		{"a space in quotes", rt("a b"), `python "${{ runner.temp }}/a b/x.py"`, true},
		{"a space in quotes of env", rt("a b"), `python "$env:RUNNER_TEMP/a b/x.py"`, true},
		{"statements on a line", rt("a"), "cd x; python $env:RUNNER_TEMP/a/x.py", true},
		{"the name of env in another case", rt("a"), "python $env:Runner_Temp/a/x.py", true},
	} {
		if got := pwshRuns(t, c.at, c.run); got != c.want {
			t.Errorf("%s: %s counted %v, want %v", c.name, c.run, got, c.want)
		}
	}
	for _, r := range counted {
		if !pwshRuns(t, rt("a"), r) {
			t.Errorf("runner.temp a: %s is not counted", r)
		}
		if pwshRuns(t, ws("."), r) {
			t.Errorf("workspace: %s is counted", r)
		}
	}
}

func pwshRuns(t *testing.T, at Placement, run string) bool {
	t.Helper()
	src := "on: push\njobs:\n  a:\n    runs-on: windows-latest\n    steps:\n      - run: echo first\n      - shell: pwsh\n        run: |\n          " + run + "\n"
	w := mustWorkflow(t, src)
	j := w.Jobs.Value.Entries[0].Value.Value
	return len(codeRuns(w, &j, j.Steps.Value.Items, workflow.OrderOf(j.Steps.Value.Items), 0, at, nil)) > 0
}

// TestCodeRunsActionPath: github.action_path is empty in a step of a job,
// which leaves an absolute path that may be anywhere, and any directory in
// a step of a composite action (job nil).
func TestCodeRunsActionPath(t *testing.T) {
	w := mustWorkflow(t, "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo first\n      - run: bash ${{ github.action_path }}/x.sh\n")
	j := w.Jobs.Value.Entries[0].Value.Value
	steps := j.Steps.Value.Items
	if got := codeRuns(w, &j, steps, workflow.OrderOf(steps), 0, ws("pr"), nil); len(got) != 1 {
		t.Errorf("a job: %+v", got)
	}
	if got := codeRuns(nil, nil, steps, workflow.OrderOf(steps), 0, ws("pr"), nil); len(got) != 1 {
		t.Errorf("a composite action: %+v", got)
	}
}

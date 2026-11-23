package workflow

import (
	"slices"
	"testing"
)

func oneJob(t *testing.T, job string, want ...Code) Job {
	t.Helper()
	return oneJobAmong(t, job, "", want...)
}

// jobsXY are the jobs x and y, for a job that needs them.
const jobsXY = "  x:\n    runs-on: x\n    steps: [{run: y}]\n  y:\n    runs-on: x\n    steps: [{run: y}]\n"

// oneJobAmong reads the job a, written before others, the text of other
// jobs.
func oneJobAmong(t *testing.T, job, others string, want ...Code) Job {
	t.Helper()
	src := "on: push\njobs:\n  a:\n" + job + others
	w, diags, _ := parse(t, src)
	wantCodes(t, job, diags, want...)
	if w.Jobs.Status != Present || len(w.Jobs.Value.Entries) == 0 {
		t.Fatalf("%q: jobs %v", job, w.Jobs.Status)
	}
	return w.Jobs.Value.Entries[0].Value.Value
}

func TestJobKinds(t *testing.T) {
	for _, tt := range []struct {
		job  string
		kind JobKind
		want []Code
	}{
		{"    runs-on: x\n    steps: [{run: a}]\n", JobRunner, nil},
		{"    uses: o/r/.github/workflows/w.yml@v1\n", JobCall, nil},
		{"    uses: ./.github/workflows/w.yml\n    with: {a: 1}\n    secrets: inherit\n", JobCall, nil},
		// GitHub rejects both; the reader takes the kind
		// from the first key.
		{"    runs-on: x\n    uses: ./.github/workflows/w.yml\n    steps: [{run: a}]\n", JobRunner, []Code{UnknownKey}},
		{"    runs-on: x\n    with: {a: b}\n    steps: [{run: a}]\n", JobRunner, []Code{UnknownKey}},
		{"    uses: ./.github/workflows/w.yml\n    steps: [{run: a}]\n", JobCall, []Code{UnknownKey}},
		{"    name: x\n    needs: b\n", JobUnknown, []Code{Ambiguous}},
		{"    runs-on: x\n", JobRunner, nil},
	} {
		j := oneJob(t, tt.job, tt.want...)
		if j.Kind != tt.kind {
			t.Errorf("%q: kind %v, want %v", tt.job, j.Kind, tt.kind)
		}
	}
}

func TestJobFields(t *testing.T) {
	j := oneJobAmong(t, `    name: Build
    needs: [x, y]
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    permissions: {contents: read}
    env: {A: b}
    outputs:
      sha: ${{ steps.s.outputs.sha }}
    strategy:
      matrix: {os: [a, b]}
    steps:
      - id: s
        run: echo
`, jobsXY)
	if j.ID.Text() != "a" || j.Name.Value.Text() != "Build" || len(j.Needs.Value.Items) != 2 || j.If.Value.Form != IfBare {
		t.Errorf("job = %+v", j)
	}
	if j.Permissions.Status != Present || len(j.Permissions.Value.Scopes) != 1 {
		t.Errorf("permissions = %+v", j.Permissions)
	}
	if o, ok := j.Outputs.Value.Lookup("sha"); !ok || !o.Value.Value.IsExpr() {
		t.Errorf("outputs = %+v", j.Outputs)
	}
	if j.Matrix.Status != Present || j.Steps.Status != Present || len(j.Steps.Value.Items) != 1 || j.Steps.Value.Items[0].Kind != StepRun {
		t.Errorf("matrix %v steps %+v", j.Matrix.Status, j.Steps)
	}
	if e, _ := j.Env.Value.Lookup("A"); e.Value.Value.Text() != "b" {
		t.Errorf("env = %+v", j.Env)
	}
	// needs is one name or a sequence.
	if j := oneJobAmong(t, "    needs: x\n    runs-on: y\n", jobsXY); len(j.Needs.Value.Items) != 1 || j.Needs.Value.Items[0].Text() != "x" {
		t.Errorf("needs = %+v", j.Needs)
	}
}

func TestJobCall(t *testing.T) {
	j := oneJob(t, "    uses: o/r/.github/workflows/w.yml@v1\n    with: {n: 1}\n    secrets: {token: '${{ secrets.T }}'}\n")
	if j.Uses.Value.Kind != UsesRemote || j.Uses.Value.Ref.Text != "v1" || j.InheritSecrets {
		t.Errorf("uses = %+v", j.Uses.Value)
	}
	if s, ok := j.Secrets.Value.Lookup("token"); !ok || !s.Value.Value.IsExpr() {
		t.Errorf("secrets = %+v", j.Secrets)
	}
	if w, _ := j.With.Value.Lookup("n"); w.Value.Value.AsString() != "1" {
		t.Errorf("with = %+v", j.With)
	}
	j = oneJob(t, "    uses: ./.github/workflows/w.yml\n    secrets: inherit\n")
	if !j.InheritSecrets || j.Secrets.Status != Present {
		t.Errorf("inherit %v, secrets %v", j.InheritSecrets, j.Secrets.Status)
	}
	oneJob(t, "    uses: ./.github/workflows/w.yml\n    secrets: all\n", InvalidValue)
}

func TestJobMatrix(t *testing.T) {
	j := oneJob(t, "    runs-on: x\n    strategy:\n      matrix: ${{ fromJSON(needs.a.outputs.m) }}\n")
	if j.Matrix.Status != Dynamic || j.Matrix.Expr == nil {
		t.Errorf("matrix %v", j.Matrix.Status)
	}
	j = oneJob(t, "    runs-on: x\n    strategy: ${{ fromJSON(github.x) }}\n")
	if j.Matrix.Status != Dynamic {
		t.Errorf("matrix under a dynamic strategy: %v", j.Matrix.Status)
	}
	if j = oneJob(t, "    runs-on: x\n"); j.Matrix.Status != Absent {
		t.Errorf("matrix %v", j.Matrix.Status)
	}
}

func TestJobIDs(t *testing.T) {
	src := "on: push\njobs:\n  build:\n    runs-on: x\n  Build:\n    runs-on: x\n"
	w, diags, _ := parse(t, src)
	wantCodes(t, src, diags, DuplicateKey)
	if len(w.Jobs.Value.Entries) != 2 {
		t.Errorf("jobs %d", len(w.Jobs.Value.Entries))
	}
	// A job id is no expression.
	src = "on: push\njobs:\n  ${{ x }}:\n    runs-on: y\n"
	_, diags, _ = parse(t, src)
	wantCodes(t, src, diags, ExprNotAllowed)
}

// TestJobUsesForms: a job calls a reusable workflow; other forms of uses are
// not one.
func TestJobUsesForms(t *testing.T) {
	for _, tt := range []struct {
		uses string
		kind UsesKind
		ok   bool
	}{
		{"./.github/workflows/x.yml", UsesLocal, true},
		{"o/r/.github/workflows/x.yml@v1", UsesRemote, true},
		{"$/.github/workflows/x.yml", UsesSelf, true},
		{"docker://alpine", UsesInvalid, false},
		{"o/r@v", UsesInvalid, false},
		{"./foo", UsesInvalid, false},
		{"./.github/workflows/x.yml@v1", UsesInvalid, false},
		{"o/r/foo/x.yml@v1", UsesInvalid, false},
		// GitHub folds a literal ${{ }} and runs the call
		{"${{ './.github/workflows/x.yml' }}", UsesFolded, true},
		{"${{ 'o/r/.github/workflows/x.yml@v1' }}", UsesFolded, true},
		{"${{ './foo' }}", UsesInvalid, false},
		// GitHub refuses ., .. and empty parts in a job's uses
		{"o/r/.github/workflows/./x.yml@v1", UsesInvalid, false},
		{"o/r/.github/workflows/../workflows/x.yml@v1", UsesInvalid, false},
		{"o/r/.github//workflows/x.yml@v1", UsesInvalid, false},
		{"./.github/workflows/../workflows/x.yml", UsesInvalid, false},
		{"o//r/.github/workflows/x.yml@v1", UsesInvalid, false},
		// not tried: read as before
		{"$//.github/workflows/x.yml", UsesSelf, true},
	} {
		src := "on: push\njobs:\n  a:\n    uses: " + tt.uses + "\n"
		w, diags, _ := parse(t, src)
		j := w.Jobs.Value.Entries[0].Value.Value
		if tt.ok {
			wantCodes(t, tt.uses, diags)
		} else {
			wantCodes(t, tt.uses, diags, InvalidValue)
		}
		if j.Uses.Value.Kind != tt.kind {
			t.Errorf("%s: kind %v, want %v", tt.uses, j.Uses.Value.Kind, tt.kind)
		}
	}
}

// TestMatrixDynamicKey: a Dynamic strategy keeps its key.
func TestMatrixDynamicKey(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    strategy: ${{ fromJSON(github.x) }}\n"
	w, _, _ := parse(t, src)
	m := w.Jobs.Value.Entries[0].Value.Value.Matrix
	if m.Status != Dynamic || text(src, m.Key.ContentSpan()) != "strategy" {
		t.Errorf("matrix %v key %q", m.Status, text(src, m.Key.ContentSpan()))
	}
}

// TestRunsOnAndDefaultShell: the labels of each form of runs-on, and
// defaults.run.shell of a job and of the workflow.
func TestRunsOnAndDefaultShell(t *testing.T) {
	for _, tt := range []struct {
		runsOn string
		st     Status
		labels []string
	}{
		{"ubuntu-latest", Present, []string{"ubuntu-latest"}},
		{"[self-hosted, linux]", Present, []string{"self-hosted", "linux"}},
		{"{group: g, labels: [a]}", Present, []string{"a"}},
		{"{group: g, labels: a}", Present, []string{"a"}},
		{"{group: g}", Absent, nil},
		{"${{ matrix.os }}", Present, []string{"${{ matrix.os }}"}},
	} {
		j := oneJob(t, "    runs-on: "+tt.runsOn+"\n    steps: [{run: a}]\n")
		var got []string
		for _, l := range j.RunsOn.Value.Items {
			got = append(got, l.Text())
		}
		if j.RunsOn.Status != tt.st || !slices.Equal(got, tt.labels) {
			t.Errorf("runs-on %s: %v %q, want %v %q", tt.runsOn, j.RunsOn.Status, got, tt.st, tt.labels)
		}
	}
	for _, tt := range []struct {
		defaults string
		st       Status
		shell    string
		want     []Code
	}{
		{"{run: {shell: bash}}", Present, "bash", nil},
		{"{run: {working-directory: x}}", Absent, "", nil},
		{"${{ fromJSON(x) }}", Invalid, "", []Code{ExprNotAllowed}}, // the schema allows no ${{ }} in defaults
	} {
		j := oneJob(t, "    runs-on: x\n    defaults: "+tt.defaults+"\n    steps: [{run: a}]\n", tt.want...)
		if j.DefaultShell.Status != tt.st || j.DefaultShell.Value.Text() != tt.shell {
			t.Errorf("defaults %s: %v %q, want %v %q", tt.defaults, j.DefaultShell.Status, j.DefaultShell.Value.Text(), tt.st, tt.shell)
		}
	}
	w, diags, _ := parse(t, "on: push\ndefaults:\n  run:\n    shell: pwsh\njobs:\n  a:\n    runs-on: x\n    steps: [{run: a}]\n")
	wantCodes(t, "workflow defaults", diags)
	if w.DefaultShell.Status != Present || w.DefaultShell.Value.Text() != "pwsh" {
		t.Errorf("the workflow's defaults.run.shell: %+v", w.DefaultShell)
	}
}

// TestRunsOnAndDefaultsChecked: runs-on and defaults are typed, so their
// values are checked against the schema, as env and strategy are; before
// they were, only their ${{ }} was.
func TestRunsOnAndDefaultsChecked(t *testing.T) {
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		{"jobs:\n  a:\n    runs-on: ''\n    steps: [{run: a}]\n", []Code{InvalidValue}},
		{"jobs:\n  a:\n    runs-on: {group: g, labels: x, y: 1}\n    steps: [{run: a}]\n", []Code{UnknownKey}},
		{"jobs:\n  a:\n    runs-on: x\n    defaults:\n    steps: [{run: a}]\n", []Code{WrongKind}},
		{"jobs:\n  a:\n    runs-on: x\n    defaults: {run: {x: 1}}\n    steps: [{run: a}]\n", []Code{UnknownKey}},
		{"jobs:\n  a:\n    runs-on: x\n    defaults: {run: {shell: [bash]}}\n    steps: [{run: a}]\n", []Code{WrongKind}},
		{"jobs:\n  a:\n    runs-on: x\n    defaults: {run: {shell: '${{ vars.S }}'}}\n    steps: [{run: a}]\n", nil},
		{"defaults: {run: {shell: '${{ vars.S }}'}}\njobs:\n  a:\n    runs-on: x\n    steps: [{run: a}]\n", []Code{ExprNotAllowed}},
	} {
		src := "on: push\n" + tt.src
		_, diags, _ := parse(t, src)
		wantCodes(t, src, diags, tt.want...)
	}
}

// TestJobEnvironment: the name of a job's environment, written as a string
// or as the name of a mapping (job-environment of the schema).
func TestJobEnvironment(t *testing.T) {
	for _, tt := range []struct {
		env   string
		st    Status
		name  string
		parts bool // the name has a ${{ }}
	}{
		{"prod", Present, "prod", false},
		{"{name: prod, url: 'https://x'}", Present, "prod", false},
		{"{name: '${{ github.head_ref }}'}", Present, "${{ github.head_ref }}", true},
		{"${{ inputs.env }}", Present, "${{ inputs.env }}", true},
		{"{url: 'https://x'}", Absent, "", false},
	} {
		want := []Code(nil)
		if tt.env == "{url: 'https://x'}" {
			want = []Code{MissingKey}
		}
		j := oneJob(t, "    runs-on: x\n    environment: "+tt.env+"\n    steps: [{run: a}]\n", want...)
		if j.Environment.Status != tt.st || j.Environment.Value.Text() != tt.name || (j.Environment.Value.Parts != nil) != tt.parts {
			t.Errorf("environment %s: %v %q, want %v %q", tt.env, j.Environment.Status, j.Environment.Value.Text(), tt.st, tt.name)
		}
	}
	if j := oneJob(t, "    runs-on: x\n    steps: [{run: a}]\n"); j.Environment.Status != Absent {
		t.Errorf("no environment: %v", j.Environment.Status)
	}
}

func TestJobTimeoutMinutes(t *testing.T) {
	if j := oneJob(t, "    runs-on: x\n    timeout-minutes: 10\n    steps: [{run: y}]\n"); j.TimeoutMinutes.Status != Present || j.TimeoutMinutes.Value.Text() != "10" {
		t.Errorf("timeout-minutes = %+v", j.TimeoutMinutes)
	}
	if j := oneJob(t, "    runs-on: x\n    timeout-minutes: ${{ fromJSON(vars.T) }}\n    steps: [{run: y}]\n"); j.TimeoutMinutes.Status == Absent {
		t.Errorf("a ${{ }} is written: %+v", j.TimeoutMinutes)
	}
	if j := oneJob(t, "    runs-on: x\n    steps: [{run: y}]\n"); j.TimeoutMinutes.Status != Absent {
		t.Errorf("timeout-minutes = %+v", j.TimeoutMinutes)
	}
}

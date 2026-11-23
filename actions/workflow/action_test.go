package workflow

import (
	"os"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/expr"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// runsOK is a runs section the runner accepts, for inputs about other keys.
const runsOK = "runs:\n  using: composite\n  steps:\n    - {run: x, shell: bash}\n"

func parseAction(t *testing.T, src string) (*ActionMetadata, []Diagnostic, *cst.Tree) {
	t.Helper()
	tr := cst.ParseMode([]byte(src), cst.ModeGitHub)
	a, diags := ParseActionMetadata(tr)
	for _, d := range diags {
		if d.Span.Start < 0 || d.Span.End > len(src) || d.Span.Start > d.Span.End {
			t.Errorf("%q: diagnostic %v has a span outside the input", src, d)
		}
	}
	return a, diags, tr
}

func TestActionRoot(t *testing.T) {
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		{"name: n\ndescription: d\n" + runsOK, nil},
		// the runner ignores keys it does not know at the top.
		{"author: me\nbranding: {icon: nonsense, color: nope}\nx-anything: [1, {a: b}]\n" + runsOK, nil},
		// ConvertRuns is not reached without runs.
		{"name: n\n", []Code{MissingKey}},
		{"", []Code{MissingKey}},
		{"~\n", []Code{MissingKey}},
		// duplicates are rejected, the case ignored.
		{"description: a\ndescription: b\n" + runsOK, []Code{DuplicateKey}},
		// an expression is parsed where none is allowed, and
		// named values are unknown there.
		{"x-meta: \"${{ foo( }}\"\n" + runsOK, []Code{ExprSyntax}},
		{"name: ${{ github.ref }}\n" + runsOK, []Code{ExprNotAllowed}},
		// A workflow read as an action.
		{"on: push\n" + jobsOK, []Code{MissingKey}},
	} {
		_, diags, _ := parseAction(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
	}
}

func TestActionFields(t *testing.T) {
	src := "name: My action\ndescription: Does it\n" + runsOK
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	if a.Name.Value.Text() != "My action" || a.Description.Value.Text() != "Does it" || a.Runs.Status != Present {
		t.Errorf("action = %+v", a)
	}
	if text(src, a.Node.Span()) != src {
		t.Errorf("action node %q", text(src, a.Node.Span()))
	}
}

func TestActionInputs(t *testing.T) {
	src := "inputs:\n" +
		"  token:\n    description: The token\n    required: true\n    default: ${{ github.token }}\n    deprecationMessage: use key\n    extra: [any]\n" +
		"  Other: {}\n" + runsOK
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	f := a.Inputs
	if f.Status != Present || len(f.Value.Entries) != 2 {
		t.Fatalf("inputs %v %+v", f.Status, f.Value.Entries)
	}
	in := f.Value.Entries[0].Value.Value
	if in.Description.Value.Text() != "The token" || in.Required.Value.AsString() != "true" || in.DeprecationMessage.Value.Text() != "use key" {
		t.Errorf("input = %+v", in)
	}
	if d := in.Default.Value; in.Default.Status != Present || len(d.Parts) != 1 || !d.Parts[0].Expr {
		t.Errorf("default = %+v", in.Default)
	}
	// input names are compared ignoring the case.
	if _, ok := f.Value.Lookup("other"); !ok {
		t.Error("Other is not found as other")
	}
}

func TestActionInputProblems(t *testing.T) {
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		// a null input is no mapping.
		{"inputs:\n  x:\n" + runsOK, []Code{WrongKind}},
		{"inputs:\n" + runsOK, []Code{WrongKind}},
		// input-default-context has no steps, and the runner rejects it.
		{"inputs:\n  x: {default: \"${{ steps.a.outputs.b }}\"}\n" + runsOK, []Code{ExprSyntax}},
		// Default is a loose key of action:input, whose values allow no
		// expression.
		{"inputs:\n  x: {Default: \"${{ github.token }}\"}\n" + runsOK, []Code{ExprNotAllowed}},
		{"inputs:\n  x: {}\n  X: {}\n" + runsOK, []Code{DuplicateKey}},
	} {
		_, diags, _ := parseAction(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
	}
}

// TestActionInputKeysFold: ConvertInputs compares default and
// deprecationMessage ignoring the case.
func TestActionInputKeysFold(t *testing.T) {
	src := "inputs:\n  x: {Default: plain, DEPRECATIONMESSAGE: m}\n" + runsOK
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	in := a.Inputs.Value.Entries[0].Value.Value
	if in.Default.Value.Text() != "plain" || in.DeprecationMessage.Value.Text() != "m" {
		t.Errorf("input = %+v", in)
	}
}

func TestActionOutputs(t *testing.T) {
	src := "outputs:\n  o:\n    description: d\n    value: ${{ steps.a.outputs.b }}\n" + runsOK
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	o, ok := a.Outputs.Value.Lookup("o")
	if !ok || o.Value.Value.Description.Value.Text() != "d" || len(o.Value.Value.Value.Value.Parts) != 1 {
		t.Errorf("outputs = %+v", a.Outputs)
	}
	for _, tt := range []struct {
		src  string
		want []Code
	}{
		{"outputs:\n  o: {value: x, other: y}\n" + runsOK, []Code{UnknownKey}},
		{"outputs:\n  o:\n" + runsOK, []Code{WrongKind}},
	} {
		_, diags, _ := parseAction(t, tt.src)
		wantCodes(t, tt.src, diags, tt.want...)
	}
}

func TestRunsKinds(t *testing.T) {
	const steps = "  steps:\n    - {run: x, shell: bash}\n"
	for _, tt := range []struct {
		runs string
		kind RunsKind
		want []Code
	}{
		{"  using: composite\n" + steps, RunsComposite, nil},
		// the runner compares using without case
		{"  using: Composite\n" + steps, RunsComposite, nil},
		{"  using: \"composite\"\n" + steps, RunsComposite, nil},
		{"  using: composite\n  steps: []\n", RunsComposite, nil},
		{"  using: composite\n", RunsInvalid, []Code{Ambiguous, MissingKey}},
		{"  using: node20\n  main: m.js\n", RunsJavaScript, nil},
		{"  using: node12\n  main: m.js\n  pre: p.js\n  post: q.js\n  pre-if: always()\n", RunsJavaScript, nil},
		{"  using: NODE24\n  main: m.js\n", RunsJavaScript, nil},
		{"  using: node20\n", RunsInvalid, []Code{Ambiguous, MissingKey}},
		{"  using: docker\n  image: Dockerfile\n", RunsDockerContainer, nil},
		{"  using: docker\n  args: [a]\n", RunsInvalid, []Code{MissingKey}},
		// The keys choose node-runs, using wants an image.
		{"  using: docker\n  main: m.js\n", RunsInvalid, []Code{MissingKey}},
		{"  plugin: p\n", RunsPlugin, nil},
		{"  main: m.js\n", RunsInvalid, []Code{MissingKey}},
		// ConvertRuns compares the value as it is.
		{"  using: node14\n  main: m.js\n", RunsInvalid, []Code{InvalidValue}},
		{"  using: \" composite\"\n" + steps, RunsInvalid, []Code{InvalidValue}},
		{"  using: 20\n  main: m.js\n", RunsInvalid, []Code{InvalidValue}},
		{"  using: ${{ inputs.u }}\n" + steps, RunsInvalid, []Code{ExprNotAllowed}},
		{"  using: composite\n  foo: bar\n" + steps, RunsComposite, []Code{UnknownKey}},
		{"  using: node20\n  main: m.js\n  pre-if: ${{ always() }}\n", RunsJavaScript, []Code{ExprNotAllowed}},
		// container-runs-context and container-runs-env list inputs.
		{"  using: docker\n  image: x\n  args: [\"${{ inputs.a }}\"]\n  env: {A: \"${{ inputs.a }}\"}\n", RunsDockerContainer, nil},
	} {
		src := "runs:\n" + tt.runs
		a, diags, _ := parseAction(t, src)
		wantCodes(t, src, diags, tt.want...)
		if k := a.Runs.Value.Kind; k != tt.kind {
			t.Errorf("%q: kind %v, want %v", src, k, tt.kind)
		}
	}
	// a null runs is no mapping.
	src := "runs:\n"
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags, WrongKind)
	if a.Runs.Status != Invalid || a.Runs.Value.Kind != RunsInvalid {
		t.Errorf("runs: %v %v", a.Runs.Status, a.Runs.Value.Kind)
	}
}

func TestRunsFields(t *testing.T) {
	src := "runs:\n  using: docker\n  image: docker://alpine:3\n  entrypoint: /e\n  pre-entrypoint: /p\n  post-entrypoint: /q\n  post-if: failure()\n  args: [a, \"${{ inputs.b }}\"]\n  env: {K: v}\n"
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	r := a.Runs.Value
	if r.Using.Value.Text() != "docker" || r.Image.Value.Text() != "docker://alpine:3" || r.Entrypoint.Value.Text() != "/e" ||
		r.PreEntrypoint.Value.Text() != "/p" || r.PostEntrypoint.Value.Text() != "/q" || r.PostIf.Value.Text() != "failure()" {
		t.Errorf("runs = %+v", r)
	}
	if len(r.Args.Value.Items) != 2 || r.Args.Value.Items[1].Parts == nil {
		t.Errorf("args = %+v", r.Args)
	}
	if e, ok := r.Env.Value.Lookup("K"); !ok || e.Value.Value.Text() != "v" {
		t.Errorf("env = %+v", r.Env)
	}
	src = "runs:\n  using: node20\n  main: m.js\n  pre: p.js\n  post: q.js\n  pre-if: always()\n"
	a, _, _ = parseAction(t, src)
	if r := a.Runs.Value; r.Main.Value.Text() != "m.js" || r.Pre.Value.Text() != "p.js" || r.Post.Value.Text() != "q.js" || r.PreIf.Value.Text() != "always()" {
		t.Errorf("runs = %+v", r)
	}
	a, _, _ = parseAction(t, "runs:\n  plugin: p\n")
	if a.Runs.Value.Plugin.Value.Text() != "p" {
		t.Errorf("plugin = %+v", a.Runs.Value.Plugin)
	}
}

// actionSteps reads the runs.steps of a composite action.
func actionSteps(t *testing.T, steps string, want ...Code) []Step {
	t.Helper()
	src := "runs:\n  using: composite\n  steps:\n" + steps
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags, want...)
	f := a.Runs.Value.Steps
	if f.Status != Present {
		t.Fatalf("%q: steps %v", src, f.Status)
	}
	return f.Value.Items
}

func TestActionStepKinds(t *testing.T) {
	for _, tt := range []struct {
		src  string
		kind StepKind
		want []Code
	}{
		{"    - {run: a, shell: bash}\n", StepRun, nil},
		{"    - {uses: actions/checkout@v4}\n", StepAction, nil},
		{"    - {run: a}\n", StepRun, []Code{MissingKey}},
		// keys a workflow's step has
		{"    - {run: a, shell: bash, timeout-minutes: 1}\n", StepRun, []Code{UnknownKey}},
		{"    - {uses: ./x, working-directory: /tmp}\n", StepAction, []Code{UnknownKey}},
		{"    - {run: a, shell: bash, working-directory: /tmp, continue-on-error: true}\n", StepRun, nil},
		{"    - {wait: [a]}\n", StepInvalid, []Code{UnknownKey, Ambiguous}},
	} {
		s := actionSteps(t, tt.src, tt.want...)
		if len(s) != 1 || s[0].Kind != tt.kind {
			t.Errorf("%q: steps %+v, want kind %v", tt.src, s, tt.kind)
		}
	}
}

// TestActionCondition: the runner does not trim the text
// around the expression, so white space makes a string, which is true.
func TestActionCondition(t *testing.T) {
	for _, tt := range []struct {
		ifv  string
		form IfForm
	}{
		{"\"${{ false }}\"", IfExpr},
		{"\"false\"", IfBare},
		{"\"x ${{ false }}\"", IfMixed},
		{"\"\"", IfEmpty},
		{"\"${{ false }} \"", IfMixed},
		{"\" ${{ false }}\"", IfMixed},
		{"\"inputs.flag == 'on'\"", IfBare},
	} {
		src := "    - {run: a, shell: bash, if: " + tt.ifv + "}\n"
		s := actionSteps(t, src)
		if f := s[0].If.Value.Form; f != tt.form {
			t.Errorf("if: %s: form %v, want %v", tt.ifv, f, tt.form)
		}
	}
}

func TestActionStepValues(t *testing.T) {
	steps := "    - run: echo ${{ inputs.x }}\n      shell: bash\n" +
		"    - uses: ./.github/actions/leaf\n      with: {a: true, c: 0x1F, n: 1.50}\n" +
		"    - uses: $/.github/actions/leaf\n"
	src := "runs:\n  using: composite\n  steps:\n" + steps
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	s := a.Runs.Value.Steps.Value.Items
	run := s[0].Run.Value
	sp, exact := run.Source(run.Parts[1].Span)
	if !exact || text(src, sp) != "${{ inputs.x }}" {
		t.Errorf("run expression at %q", text(src, sp))
	}
	// ./ is the workspace, $/ the action's repository; the
	// model keeps the forms of a workflow.
	if s[1].Uses.Value.Kind != UsesLocal || s[2].Uses.Value.Kind != UsesSelf {
		t.Errorf("uses %v %v", s[1].Uses.Value.Kind, s[2].Uses.Value.Kind)
	}
	for k, want := range map[string]string{"a": "true", "c": "31", "n": "1.5"} {
		if e, ok := s[1].With.Value.Lookup(k); !ok || e.Value.Value.AsString() != want {
			t.Errorf("with.%s = %q, want %q", k, e.Value.Value.AsString(), want)
		}
	}
}

// TestActionStepsLikeWorkflow: a step reads the same in a job and in an
// action.
func TestActionStepsLikeWorkflow(t *testing.T) {
	step := "      - id: s\n        name: n\n        if: success()\n        uses: a/b@v1\n        with: {k: v}\n        env: {E: e}\n"
	w, _, _ := parse(t, "on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n"+step)
	ws := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0]
	as := actionSteps(t, strings.ReplaceAll(step, "      ", "    "))[0]
	if ws.Kind != as.Kind || ws.ID.Value.Text() != as.ID.Value.Text() || ws.Name.Value.Text() != as.Name.Value.Text() ||
		ws.If.Value.Form != as.If.Value.Form || ws.Uses.Value.Text() != as.Uses.Value.Text() || ws.Uses.Value.Ref.Text != as.Uses.Value.Ref.Text {
		t.Errorf("workflow %+v\naction %+v", ws, as)
	}
	we, _ := ws.With.Value.Lookup("k")
	ae, _ := as.With.Value.Lookup("k")
	wv, _ := ws.Env.Value.Lookup("E")
	av, _ := as.Env.Value.Lookup("E")
	if we.Value.Value.Text() != ae.Value.Value.Text() || wv.Value.Value.Text() != av.Value.Value.Text() {
		t.Errorf("with or env differ")
	}
}

// TestCompositeRegression: sisakulint skips a file with runs at the top
// (isCompositeActionFile). Its unpinned uses and the inputs in its run are
// in the model.
func TestCompositeRegression(t *testing.T) {
	src := "name: setup\ndescription: d\ninputs:\n  x: {default: a}\nruns:\n  using: composite\n  steps:\n" +
		"    - uses: actions/checkout@v4\n" +
		"    - run: echo \"${{ inputs.x }}\"\n      shell: bash\n"
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	s := a.Runs.Value.Steps.Value.Items
	u := s[0].Uses.Value
	if sp, _ := u.Source(u.Ref.Span); u.Kind != UsesRemote || text(src, sp) != "v4" {
		t.Errorf("ref at %q", text(src, sp))
	}
	run := s[1].Run.Value
	var found bool
	for _, p := range run.Parts {
		if sp, _ := run.Source(p.Span); p.Expr && text(src, sp) == "${{ inputs.x }}" {
			found = true
		}
	}
	if !found {
		t.Errorf("run parts %+v", run.Parts)
	}
}

func TestActionAliasAndFlow(t *testing.T) {
	src := "x-step: &s {run: a, shell: bash}\nx-runs: &r\n  using: composite\n  steps: [*s, *s]\nruns: *r\n"
	a, diags, _ := parseAction(t, src)
	wantCodes(t, src, diags)
	r := a.Runs.Value
	if r.Kind != RunsComposite || !r.Shared() || len(r.Steps.Value.Items) != 2 {
		t.Fatalf("runs %+v", r)
	}
	s0, s1 := r.Steps.Value.Items[0], r.Steps.Value.Items[1]
	if s0.Node != s1.Node || len(s0.Via) != 2 || s0.Via[1] == s1.Via[1] || s0.Kind != StepRun {
		t.Errorf("steps %+v %+v", s0, s1)
	}
	src = "{name: x, runs: {using: composite, steps: [{run: a, shell: bash}]}}"
	a, diags, _ = parseAction(t, src)
	wantCodes(t, src, diags)
	if a.Runs.Value.Kind != RunsComposite || len(a.Runs.Value.Steps.Value.Items) != 1 {
		t.Errorf("flow runs %+v", a.Runs.Value)
	}
}

// TestActionToolSeeds reads action.yml files of the test data of actionlint
// and zizmor, copied in testdata/actionlint and testdata/zizmor. The
// expectations are the runner's, not the tools': actionlint, for one,
// rejects node16 and a missing name, which the runner accepts.
func TestActionToolSeeds(t *testing.T) {
	const al = "testdata/actionlint/testdata/projects/"
	for _, tt := range []struct {
		file string
		kind RunsKind
		want []Code
	}{
		{al + "local_action_invalid_runners/old_node/action.yaml", RunsJavaScript, nil},
		{al + "local_action_invalid_runners/node12/action.yaml", RunsJavaScript, nil},
		{al + "local_action_invalid_runners/invalid_node_version/action.yaml", RunsInvalid, []Code{InvalidValue}},
		{al + "local_action_invalid_runners/unknown_runner/action.yaml", RunsInvalid, []Code{InvalidValue}},
		{al + "local_action_invalid_runners/missing_using/action.yaml", RunsInvalid, []Code{WrongKind}},
		{al + "local_action_invalid/no_name/action.yaml", RunsJavaScript, nil},
		{al + "local_action_invalid/no_desc/action.yaml", RunsJavaScript, nil},
		{al + "local_action_invalid/branding/action.yaml", RunsJavaScript, nil},
		{al + "local_composite_action/missing_steps/action.yaml", RunsInvalid, []Code{Ambiguous, MissingKey}},
		{al + "local_docker_action/missing_image/action.yaml", RunsInvalid, []Code{Ambiguous, MissingKey}},
		{al + "local_javascript_action/missing_main/action.yaml", RunsInvalid, []Code{Ambiguous, MissingKey}},
		{al + "local_javascript_action/ok_all_optional/action.yaml", RunsJavaScript, nil},
		{al + "local_docker_action/ok_all_keys/action.yaml", RunsDockerContainer, nil},
		{al + "yaml_anchor_in_action/action/action.yaml", RunsDockerContainer, nil},
		{"testdata/actionlint/testdata/action_metadata/input-duplicate/action.yml", RunsJavaScript, []Code{DuplicateKey}},
		{"testdata/zizmor/crates/zizmor/tests/integration/test-data/invalid/invalid-action-1/action.yml", RunsInvalid, []Code{MissingKey}},
	} {
		src, err := os.ReadFile(tt.file)
		if err != nil {
			t.Fatal(err)
		}
		a, diags, _ := parseAction(t, string(src))
		wantCodes(t, tt.file, diags, tt.want...)
		if a.Runs.Value.Kind != tt.kind {
			t.Errorf("%s: kind %v, want %v", tt.file, a.Runs.Value.Kind, tt.kind)
		}
	}
}

// TestActionRunsAndFoldedIf: runs that is never read, and an if folded
// from a string literal.
func TestActionRunsAndFoldedIf(t *testing.T) {
	// runs that is never read is no composite.
	for _, src := range []string{"", "~\n", "- a\n", "x\n"} {
		a, _, _ := parseAction(t, src)
		if a.Runs.Value.Kind != RunsInvalid {
			t.Errorf("%q: kind %v", src, a.Runs.Value.Kind)
		}
	}
	// the runner folds ${{ 'x' }}, and nothing is
	// reported. The folded string is the literal's bytes in the input, so
	// its pieces are made (TestFoldedUses).
	s := actionSteps(t, "    - {uses: \"${{ 'actions/checkout@v4' }}\"}\n")
	if u := s[0].Uses; u.Status != Present || u.Value.Kind != UsesFolded || u.Value.Folded != UsesRemote || u.Value.Ref.Text != "v4" || u.Value.AsString() != "actions/checkout@v4" {
		t.Errorf("folded uses %v %+v", u.Status, u.Value)
	}
	// ConvertToIfCondition reads the folded string as the expression.
	s = actionSteps(t, "    - {run: a, shell: bash, if: \"${{ 'false' }}\"}\n")
	c := s[0].If.Value
	if c.Form != IfBare || c.Expr == nil {
		t.Fatalf("folded if %v %+v", c.Form, c.Expr)
	}
	if l, ok := c.Expr.Tree.(*expr.Literal); !ok || l.Kind != expr.LitBool {
		t.Errorf("folded if tree %#v", c.Expr.Tree)
	}
	s = actionSteps(t, "    - {run: a, shell: bash, if: \"${{ ' ' }}\"}\n")
	if f := s[0].If.Value.Form; f != IfEmpty {
		t.Errorf("folded blank if %v", f)
	}
}

// TestParseUnchanged: Parse and ParseActionMetadata share their steps; a file with
// runs only is still no workflow.
func TestParseUnchanged(t *testing.T) {
	_, diags, _ := parse(t, runsOK)
	wantCodes(t, runsOK, diags, UnknownKey, MissingKey, MissingKey)
}

package job

import (
	"github.com/gh-intel/sisakulint/actions/attacker"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

func parse(t *testing.T, src string) *workflow.Workflow {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	if w == nil {
		t.Fatalf("not a workflow: %s", src)
	}
	return w
}

func one(t *testing.T, src string) Job {
	t.Helper()
	js := Analyze(parse(t, src), attacker.Outsider)
	if len(js) != 1 {
		t.Fatalf("%d jobs: %s", len(js), src)
	}
	return js[0]
}

func names(evs []analysis.EventActivity) string {
	var out []string
	for _, e := range evs {
		if !slices.Contains(out, e.Name().String()) {
			out = append(out, e.Name().String())
		}
	}
	return strings.Join(out, ",")
}

// TestEvents: the privileged events an attacker triggers, by the on and
// the if of the job.
func TestEvents(t *testing.T) {
	for _, c := range []struct{ on, ifs, want string }{
		{"issues", "", "issues"},
		{"[push, issues]", "", "issues"},
		{"[push, issues]", "    if: github.event_name == 'push'\n", ""},
		{"pull_request_target", "", "pull_request_target"},
		{"[pull_request, pull_request_review, pull_request_review_comment]", "", "pull_request_review,pull_request_review_comment"},
		{"pull_request_review", "    if: github.event.pull_request.head.repo.full_name != github.repository\n", ""},
		{"[issue_comment, discussion, discussion_comment, fork, workflow_run]", "", "discussion,discussion_comment,fork,issue_comment,workflow_run"},
		{"[push, merge_group, gollum, watch]", "", ""},
		{"workflow_call", "", ""},
	} {
		j := one(t, "on: "+c.on+"\njobs:\n  a:\n    runs-on: x\n"+c.ifs+"    steps:\n      - run: echo\n")
		if got := names(j.PrivilegedOn); got != c.want {
			t.Errorf("%s %q: %s, want %s", c.on, c.ifs, got, c.want)
		}
	}
}

// TestApproval is prcode's TestApproval at the job: a label when every
// event is pull_request_target labeled, else an environment written out.
func TestApproval(t *testing.T) {
	for _, c := range []struct {
		on, extra string
		want      analysis.Approval
		env       string
	}{
		{"{pull_request_target: {types: [labeled]}}", "", analysis.ApprovalLabel, ""},
		{"{pull_request_target: {types: [labeled, opened]}}", "", analysis.ApprovalNone, ""},
		{"issues", "    environment: production\n", analysis.ApprovalEnvironment, "production"},
		{"issues", "    environment: {name: production}\n", analysis.ApprovalEnvironment, "production"},
		{"issues", "    environment: ${{ inputs.e }}\n", analysis.ApprovalNone, ""},
		{"issues", "", analysis.ApprovalNone, ""},
	} {
		j := one(t, "on: "+c.on+"\njobs:\n  a:\n    runs-on: x\n"+c.extra+"    steps:\n      - run: echo\n")
		if j.Approval != c.want || j.Environment.String() != c.env {
			t.Errorf("%s %q: %v %q, want %v %q", c.on, c.extra, j.Approval, j.Environment, c.want, c.env)
		}
	}
}

// TestWrites is artifact's TestWrites, moved with writesOf.
func TestWrites(t *testing.T) {
	for _, c := range []struct {
		wf, job string
		want    analysis.TokenWrite
	}{
		{"", "", analysis.TokenWriteUnwritten},
		{"permissions: {}\n", "", analysis.TokenWriteNo},
		{"permissions: read-all\n", "", analysis.TokenWriteNo},
		{"permissions: write-all\n", "", analysis.TokenWriteYes},
		{"permissions: {contents: write}\n", "", analysis.TokenWriteYes},
		{"permissions: {contents: read, id-token: write}\n", "", analysis.TokenWriteNo},
		{"permissions: {contents: write}\n", "    permissions: {contents: read}\n", analysis.TokenWriteNo},
		{"", "    permissions: {pull-requests: write}\n", analysis.TokenWriteYes},
		{"", "    permissions: ${{ inputs.p }}\n", analysis.TokenWriteYes},
	} {
		j := one(t, "on: issues\n"+c.wf+"jobs:\n  a:\n    runs-on: x\n"+c.job+"    steps:\n      - run: echo\n")
		if j.TokenWrite != c.want {
			t.Errorf("%q %q: %v, want %v", c.wf, c.job, j.TokenWrite, c.want)
		}
	}
}

// TestSecrets: the secrets a job reads.
func TestSecrets(t *testing.T) {
	for _, c := range []struct {
		name, src string
		all       bool
		names     string
	}{
		{"step env", "    steps:\n      - run: x\n        env: {K: '${{ secrets.DEPLOY_KEY }}'}\n", false, "DEPLOY_KEY"},
		{"run", "    steps:\n      - run: echo ${{ secrets.A }} ${{ secrets['B'] }} ${{ secrets.a }}\n", false, "A,B"},
		{"with", "    steps:\n      - uses: x/y@v1\n        with: {token: '${{ secrets.PAT }}'}\n", false, "PAT"},
		{"job env", "    env: {K: '${{ secrets.K }}'}\n    steps:\n      - run: x\n", false, "K"},
		{"github token", "    steps:\n      - run: echo ${{ secrets.GITHUB_TOKEN }} ${{ secrets['github_token'] }}\n", false, ""},
		{"toJSON", "    steps:\n      - run: echo '${{ toJSON(secrets) }}'\n", true, ""},
		{"index expr", "    steps:\n      - run: echo ${{ secrets[inputs.n] }}\n", true, ""},
		{"in a call", "    steps:\n      - run: echo ${{ format('{0}', secrets.F) }}\n", false, "F"},
		{"none", "    steps:\n      - run: echo ${{ github.token }}\n", false, ""},
		{"container credentials", "    container: {image: i, credentials: {username: '${{ secrets.U }}', password: '${{ secrets.P }}'}}\n    steps:\n      - run: x\n", false, "U,P"},
		{"container credentials expr", "    container: {image: i, credentials: '${{ fromJSON(secrets.R) }}'}\n    steps:\n      - run: x\n", false, "R"},
		{"container env", "    container: {image: i, env: {E: '${{ secrets.E }}'}}\n    steps:\n      - run: x\n", false, "E"},
		{"container env expr", "    container: {image: i, env: '${{ fromJSON(secrets.M) }}'}\n    steps:\n      - run: x\n", false, "M"},
		{"service", "    services: {db: {image: i, credentials: {username: u, password: '${{ secrets.DP }}'}, env: {X: '${{ toJSON(secrets) }}'}}}\n    steps:\n      - run: x\n", true, "DP"},
		{"step keys", "    steps:\n      - run: x\n        working-directory: '${{ secrets.W }}'\n        timeout-minutes: '${{ secrets.T }}'\n        continue-on-error: '${{ secrets.C }}'\n", false, "W,T,C"},
	} {
		j := one(t, "on: issues\njobs:\n  a:\n    runs-on: x\n"+c.src)
		if j.Secrets.All != c.all || strings.Join(j.Secrets.Names, ",") != c.names {
			t.Errorf("%s: %+v, want %v %q", c.name, j.Secrets, c.all, c.names)
		}
	}
	w := one(t, "on: issues\nenv: {W: '${{ secrets.W }}'}\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: x\n")
	if strings.Join(w.Secrets.Names, ",") != "W" {
		t.Errorf("workflow env: %+v", w.Secrets)
	}
	inherit := one(t, "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets: inherit\n")
	if !inherit.Secrets.All {
		t.Errorf("inherit: %+v", inherit.Secrets)
	}
	passed := one(t, "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets: {s: '${{ secrets.S }}'}\n    with: {w: '${{ secrets.T }}'}\n")
	if strings.Join(passed.Secrets.Names, ",") != "T,S" { // with is read before secrets
		t.Errorf("passed: %+v", passed.Secrets)
	}
}

// TestRunners: the runners of runs-on.
func TestRunners(t *testing.T) {
	for _, c := range []struct {
		name, runsOn, strategy string
		self, gaps             int
	}{
		{"label", "self-hosted", "", 1, 0},
		{"list", "[self-hosted, linux, x64]", "", 1, 0},
		{"upper", "SELF-HOSTED", "", 1, 0},
		{"spaces", "' self-hosted '", "", 1, 0},
		{"list spaces", "[' self-hosted']", "", 0, 0},
		{"list unmatched", "[self-hosted, ' x']", "", 0, 0},
		{"list empty", "[self-hosted, '']", "", 0, 0},
		{"mapping spaces", "{labels: ' self-hosted '}", "", 1, 0},
		{"mapping list spaces", "{group: big, labels: [' self-hosted ']}", "", 1, 0},
		{"matrix spaces", "${{ matrix.os }}", "    strategy:\n      matrix: {os: [' self-hosted', ubuntu-latest]}\n", 0, 0},
		{"matrix unmatched one", "${{ matrix.os }}", "    strategy:\n      matrix: {os: [self-hosted, ' x']}\n", 1, 0},
		{"matrix upper", "${{ matrix.os }}", "    strategy:\n      matrix: {os: [SELF-HOSTED]}\n", 1, 0},
		{"hosted", "ubuntu-latest", "", 0, 0},
		{"custom", "[linux, gpu]", "", 0, 0},
		{"group", "{group: big}", "", 0, 0},
		{"group labels", "{group: big, labels: [self-hosted]}", "", 1, 0},
		{"matrix", "${{ matrix.os }}", "    strategy:\n      matrix: {os: [ubuntu-latest, self-hosted]}\n", 1, 0},
		{"matrix include", "${{ matrix.os }}", "    strategy:\n      matrix: {v: [1], include: [{os: self-hosted}]}\n", 1, 0},
		{"matrix unknown", "${{ matrix.os }}", "    strategy:\n      matrix: {os: '${{ fromJSON(inputs.o) }}'}\n", 0, 1},
		{"matrix missing", "${{ matrix.nope }}", "    strategy:\n      matrix: {os: [a]}\n", 0, 1},
		{"matrix expr value", "${{ matrix.os }}", "    strategy:\n      matrix: {os: ['${{ inputs.r }}']}\n", 0, 1},
		{"input", "${{ inputs.runner }}", "", 0, 1},
		{"mixed", "ubuntu-${{ matrix.v }}", "    strategy:\n      matrix: {v: [a]}\n", 0, 1},
		{"dynamic list", "${{ fromJSON(inputs.labels) }}", "", 0, 1},
	} {
		j := one(t, "on: push\njobs:\n  a:\n    runs-on: "+c.runsOn+"\n"+c.strategy+"    steps:\n      - run: echo\n")
		self := 0
		for _, r := range j.RunnerLabels {
			if r.HasSelfHostedLabel {
				self++
			}
		}
		if self != c.self || len(j.InconclusiveLabels) != c.gaps {
			t.Errorf("%s: %+v %+v; want %d self-hosted, %d gaps", c.name, j.RunnerLabels, j.InconclusiveLabels, c.self, c.gaps)
		}
	}
}

// TestAnalyzeNone: a workflow without jobs, and nil, give nothing.
func TestAnalyzeNone(t *testing.T) {
	if js := Analyze(nil, attacker.Outsider); js != nil {
		t.Errorf("%+v", js)
	}
	if js := Analyze(parse(t, "on: push\n"), attacker.Outsider); len(js) != 0 {
		t.Errorf("%+v", js)
	}
}

// TestAnalyzeInvalidJobs: a job id whose
// value is not a job, and a duplicate id, are no job.
func TestAnalyzeInvalidJobs(t *testing.T) {
	for _, src := range []string{
		"on: issues\njobs:\n  a: 1\n",
		"on: issues\njobs:\n  a: ~\n",
	} {
		if js := Analyze(parse(t, src), attacker.Outsider); len(js) != 0 {
			t.Errorf("%q: %+v", src, js)
		}
	}
	js := Analyze(parse(t, "on: issues\njobs:\n  a:\n    runs-on: x\n    steps: [{run: x}]\n  a:\n    runs-on: x\n    steps: [{run: x}]\n"), attacker.Outsider)
	if len(js) != 1 {
		t.Errorf("duplicate id: %d jobs", len(js))
	}
}

// TestSecretsCaller: the env of the caller
// workflow is not passed to the called one (reusing-workflow-configurations,
// line 63 of github/docs 87cce24ea55da664a7dd2a840297bb7608b11dc2).
func TestSecretsCaller(t *testing.T) {
	j := one(t, "on: issues\nenv: {K: '${{ secrets.K }}'}\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n")
	if j.Secrets.All || len(j.Secrets.Names) != 0 {
		t.Errorf("%+v", j.Secrets)
	}
}

// TestSecretsOutputsAndNames: outputs of the
// job and names of the steps may read secrets (contexts.md lines 102, 111).
func TestSecretsOutputsAndNames(t *testing.T) {
	j := one(t, "on: issues\njobs:\n  a:\n    runs-on: x\n    outputs: {o: '${{ secrets.O }}'}\n    steps:\n      - name: '${{ secrets.N }}'\n        run: x\n")
	if strings.Join(j.Secrets.Names, ",") != "O,N" {
		t.Errorf("%+v", j.Secrets)
	}
}

// TestRunnersOnce: two labels that take the same
// values of the matrix give each value once.
func TestRunnersOnce(t *testing.T) {
	j := one(t, "on: push\njobs:\n  a:\n    runs-on: ['${{ matrix.os }}', '${{ matrix.os }}']\n    strategy:\n      matrix: {os: [self-hosted]}\n    steps:\n      - run: echo\n")
	if len(j.RunnerLabels) != 1 {
		t.Errorf("%+v", j.RunnerLabels)
	}
}

// TestMatrixValues: a whole ${{ matrix.<name> }} takes the values written
// for the name; another value, or values not all written, are false.
func TestMatrixValues(t *testing.T) {
	for _, c := range []struct {
		value, matrix, want string
		ok                  bool
	}{
		{"${{ matrix.image }}", "{image: [a, 'b:1']}", "a,b:1", true},
		{"${{ matrix.image }}", "{v: [1], include: [{image: c}]}", "c", true},
		{"${{ matrix.nope }}", "{image: [a]}", "", false},
		{"x-${{ matrix.image }}", "{image: [a]}", "", false},
		{"${{ matrix.image }}", "{image: '${{ fromJSON(inputs.i) }}'}", "", false},
		{"${{ inputs.image }}", "{image: [a]}", "", false},
	} {
		w := parse(t, "on: push\njobs:\n  a:\n    runs-on: x\n    container: '"+c.value+"'\n    strategy:\n      matrix: "+c.matrix+"\n    steps:\n      - run: echo\n")
		j := w.Jobs.Value.Entries[0].Value.Value
		vals, ok := MatrixValues(j, j.Container.Value.Image.Value)
		var got []string
		for _, v := range vals {
			got = append(got, v.Text())
		}
		if ok != c.ok || ok && strings.Join(got, ",") != c.want {
			t.Errorf("%s %s: %v %v", c.value, c.matrix, got, ok)
		}
	}
}

// TestCalled: a workflow that only its callers
// run, and where the reusable workflow a job calls is.
func TestCalled(t *testing.T) {
	for _, c := range []struct {
		on, job string
		only    bool
		kind    analysis.CalledWorkflowKind
		repo    string
	}{
		{"workflow_call", "    runs-on: x\n    steps:\n      - run: echo\n", true, analysis.CalledWorkflowKindNone, ""},
		{"{workflow_call: {inputs: {a: {type: string}}}}", "    runs-on: x\n    steps:\n      - run: echo\n", true, analysis.CalledWorkflowKindNone, ""},
		{"[workflow_call, push]", "    runs-on: x\n    steps:\n      - run: echo\n", false, analysis.CalledWorkflowKindNone, ""},
		{"push", "    uses: ./.github/workflows/b.yml\n    secrets: inherit\n", false, analysis.CalledWorkflowKindLocal, ""},
		{"push", "    uses: $/.github/workflows/b.yml\n    secrets: inherit\n", false, analysis.CalledWorkflowKindLocal, ""},
		{"push", "    uses: Octo/Shared/.github/workflows/b.yml@v1\n    secrets: inherit\n", false, analysis.CalledWorkflowKindRemote, "octo/shared"},
		{"push", "    uses: foo\n    secrets: inherit\n", false, analysis.CalledWorkflowKindNone, ""},
		{"push", "    uses: ${{ './.github/workflows/b.yml' }}\n    secrets: inherit\n", false, analysis.CalledWorkflowKindLocal, ""}, // GitHub folds it
		{"push", "    uses: ${{ 'Octo/Shared/.github/workflows/b.yml@v1' }}\n    secrets: inherit\n", false, analysis.CalledWorkflowKindRemote, "octo/shared"},
		{"", "    runs-on: x\n    steps:\n      - run: echo\n", true, analysis.CalledWorkflowKindNone, ""},
		{"{}", "    runs-on: x\n    steps:\n      - run: echo\n", true, analysis.CalledWorkflowKindNone, ""}, // GitHub runs no job of on: {}
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n" + c.job
		if c.on == "" {
			src = "jobs:\n  a:\n" + c.job // no on: the model reports it, GitHub runs nothing
		}
		j := one(t, src)
		if j.CalledOnly != c.only || j.CalledKind != c.kind || j.CalledRepo.String() != c.repo {
			t.Errorf("%s %q: %v %v %q, want %v %v %q", c.on, c.job, j.CalledOnly, j.CalledKind, j.CalledRepo, c.only, c.kind, c.repo)
		}
	}
}

package ir

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/internal/callerstest"
	"github.com/gh-intel/sisakulint/actions/labeler"
	"github.com/gh-intel/sisakulint/actions/taint"
)

const (
	labelerYML = "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ secrets.PAT }}\n"
	freeConfig = "safe-to-test:\n  - changed-files:\n      - any-glob-to-any-file: ['site/**']\n"
)

// labeledIR is the IR of the input name among files, a repository that
// has .github/labeler.yml config, read with its callers and its labelers.
func labeledIR(t *testing.T, name, config string, files ...[2]string) *IR {
	t.Helper()
	g := callerstest.Graph(t, true, false, files...)
	c := taint.NewCallers(g)
	root := fstest.MapFS{".github/labeler.yml": {Data: []byte(config)}}
	var fs []calls.File
	for _, f := range files {
		root[f[0]] = &fstest.MapFile{Data: []byte(f[1])}
		if x, ok := g.File(calls.InputNode(facts.MustCleanInputPath(f[0]))); ok {
			fs = append(fs, x)
		}
	}
	tab := labeler.Read(fs, root, func(facts.InputPath) bool { return false })
	f, ok := g.File(calls.InputNode(facts.MustCleanInputPath(name)))
	if !ok {
		t.Fatalf("no %s", name)
	}
	return New(f.Name.String(), f.Tree, f.Workflow, f.Action).WithCallers(func() *taint.Callers { return c }).WithLabelers(func() *labeler.Table { return tab })
}

func labeledWorkflow(ifs, steps string) string {
	return "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  build:\n" + ifs + "    runs-on: ubuntu-latest\n    steps:\n" + steps
}

const headCheckout = "      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: npm ci\n"

var free = []analysis.AutomaticLabel{analysis.AutomaticLabelFree}

func TestAutomaticLabel(t *testing.T) {
	for _, c := range []struct {
		name, ifs, config string
		want              []analysis.AutomaticLabel
	}{
		{"the label", "    if: github.event.label.name == 'safe-to-test'\n", freeConfig, free},
		{"no if", "", freeConfig, free},
		{"another label", "    if: github.event.label.name == 'other'\n", freeConfig, nil},
		{"paths", "    if: github.event.label.name == 'safe-to-test'\n", "safe-to-test:\n  - changed-files:\n      - all-globs-to-all-files: ['site/**']\n", []analysis.AutomaticLabel{analysis.AutomaticLabelPaths}},
		{"a label set", "    if: contains(github.event.pull_request.labels.*.name, 'safe-to-test') && contains(github.event.pull_request.labels.*.name, 'docs')\n", freeConfig + "docs:\n  - head-branch: ['^d']\n", []analysis.AutomaticLabel{analysis.AutomaticLabelLabelSet}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := labeledIR(t, ".github/workflows/build.yml", c.config,
				[2]string{".github/workflows/labeler.yml", labelerYML},
				[2]string{".github/workflows/build.yml", labeledWorkflow(c.ifs, headCheckout)})
			jobs, sites := x.allJobs(), x.allCheckoutSites()
			if len(jobs) != 1 || len(sites) != 1 {
				t.Fatalf("%d jobs, %d sites", len(jobs), len(sites))
			}
			for _, a := range []AutomaticApproval{jobs[0].automaticApproval, sites[0].automaticApproval} {
				if !slices.Equal(a.AutomaticLabels, c.want) {
					t.Errorf("got %v, want %v", a.AutomaticLabels, c.want)
				}
			}
			if a := sites[0].automaticApproval; len(c.want) > 0 && (a.At.InputName() != ".github/workflows/labeler.yml" || a.Token != labeler.TokenSourceAccount) {
				t.Errorf("the labeler: %+v", a)
			}
		})
	}
}

func TestAutomaticLabelNoLabeler(t *testing.T) {
	x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
		[2]string{".github/workflows/build.yml", labeledWorkflow("", headCheckout)})
	if a := x.allCheckoutSites()[0].automaticApproval; len(a.AutomaticLabels) != 0 {
		t.Errorf("got %v, want none", a.AutomaticLabels)
	}
}

func TestAutomaticLabelCaller(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	for _, c := range []struct {
		label string
		want  []analysis.AutomaticLabel
	}{{"safe-to-test", free}, {"other", nil}} {
		caller := labeledWorkflow("    if: github.event.label.name == '"+c.label+"'\n", "")
		caller = caller[:len(caller)-len("    runs-on: ubuntu-latest\n    steps:\n")] + "    uses: ./.github/workflows/called.yml\n"
		x := labeledIR(t, ".github/workflows/called.yml", freeConfig,
			[2]string{".github/workflows/labeler.yml", labelerYML},
			[2]string{".github/workflows/called.yml", called},
			[2]string{".github/workflows/ci.yml", caller})
		sites := x.allCheckoutSites()
		if len(sites) != 1 || !slices.Equal(sites[0].automaticApproval.AutomaticLabels, c.want) {
			t.Errorf("caller if %s: got %+v, want %v", c.label, sites, c.want)
		}
	}
}

// TestAutomaticLabelCallerStepNeeds: the if of the step of the caller's
// job that runs a composite action reads the results of the jobs the job
// needs (attacker.StepIf). A step of a workflow names ./x in the checked
// out tree, so the call is not resolved (calls.Call.Resolved) and other
// callers may run the action past no if: the worst case lets the attacker
// in whatever the label, as the taint rules read the action on every event.
func TestAutomaticLabelCallerStepNeeds(t *testing.T) {
	action := "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4.2.2\n      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n    - run: npm ci\n      shell: bash\n"
	for _, c := range []struct {
		label string
		want  []analysis.AutomaticLabel
	}{{"safe-to-test", free}, {"other", free}} {
		caller := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  pre:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n  build:\n    needs: pre\n    runs-on: ubuntu-latest\n    steps:\n      - if: needs.pre.result == 'failure' || github.event.label.name == '" + c.label + "'\n        uses: ./x\n"
		x := labeledIR(t, "x/action.yml", freeConfig,
			[2]string{".github/workflows/labeler.yml", labelerYML},
			[2]string{"x/action.yml", action},
			[2]string{".github/workflows/ci.yml", caller})
		sites := x.allCheckoutSites()
		if len(sites) != 1 || !slices.Equal(sites[0].automaticApproval.AutomaticLabels, c.want) {
			t.Errorf("the step's if with the label %s: got %+v, want %v", c.label, sites, c.want)
		}
	}
}

func TestAutomaticLabelNeeds(t *testing.T) {
	for _, c := range []struct {
		label string
		want  []analysis.AutomaticLabel
	}{{"safe-to-test", free}, {"other", nil}} {
		src := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  gate:\n    if: github.event.label.name == '" + c.label + "'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n  build:\n    needs: gate\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
		x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
			[2]string{".github/workflows/labeler.yml", labelerYML},
			[2]string{".github/workflows/build.yml", src})
		sites := x.allCheckoutSites()
		if len(sites) != 1 || !slices.Equal(sites[0].automaticApproval.AutomaticLabels, c.want) {
			t.Errorf("needs a job whose if is %s: got %v, want %v", c.label, sites[0].automaticApproval.AutomaticLabels, c.want)
		}
	}
	always := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  gate:\n    if: github.event.label.name == 'other'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n  build:\n    needs: gate\n    if: always()\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/build.yml", always})
	if got := x.allCheckoutSites()[0].automaticApproval.AutomaticLabels; !slices.Equal(got, free) {
		t.Errorf("if: always() runs after a skipped job: got %v, want free", got)
	}
}

func TestAutomaticLabelEnvironment(t *testing.T) {
	src := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  build:\n    environment: prod\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/build.yml", src})
	if a := x.allJobs()[0].automaticApproval; !slices.Equal(a.AutomaticLabels, free) || a.Environment.String() != "prod" {
		t.Errorf("got %+v, want free with the environment prod", a)
	}
}

func TestAutomaticLabelMixedEvents(t *testing.T) {
	src := "on:\n  pull_request_target:\n    types: [opened, labeled]\njobs:\n  review:\n    if: github.event.action == 'labeled' && github.event.label.name == 'safe-to-test'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          prompt: Review the pull request\n"
	x := labeledIR(t, ".github/workflows/review.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/review.yml", src})
	steps := x.allAgentSteps()
	if len(steps) != 1 || !slices.Equal(steps[0].automaticApproval.AutomaticLabels, free) {
		t.Errorf("got %+v, want free", steps)
	}
}

func TestAutomaticLabelNeedsCycle(t *testing.T) {
	src := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  a:\n    needs: b\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo a\n  b:\n    needs: a\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/build.yml", src})
	if sites := x.allCheckoutSites(); len(sites) != 1 {
		t.Fatalf("got %d sites", len(sites))
	}
	// a job that needs every job before it: the ifs are read once each
	var b strings.Builder
	b.WriteString("on:\n  pull_request_target:\n    types: [labeled]\njobs:\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "  j%d:\n", i)
		if i > 0 {
			b.WriteString("    needs: [")
			for k := 0; k < i; k++ {
				if k > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, "j%d", k)
			}
			b.WriteString("]\n")
		}
		b.WriteString("    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n")
	}
	b.WriteString("  build:\n    needs: [j29]\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout)
	x = labeledIR(t, ".github/workflows/build.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/build.yml", b.String()})
	if sites := x.allCheckoutSites(); len(sites) != 1 || !slices.Equal(sites[0].automaticApproval.AutomaticLabels, free) {
		t.Fatalf("got %+v", sites)
	}
}

func TestAutomaticLabelCallerEvents(t *testing.T) {
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	labeled := labeledWorkflow("    if: github.event.label.name == 'other'\n", "")
	labeled = labeled[:len(labeled)-len("    runs-on: ubuntu-latest\n    steps:\n")] + "    uses: ./.github/workflows/called.yml\n"
	push := "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n"
	x := labeledIR(t, ".github/workflows/called.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/a.yml", labeled},
		[2]string{".github/workflows/b.yml", push})
	if sites := x.allCheckoutSites(); len(sites) != 1 || len(sites[0].automaticApproval.AutomaticLabels) != 0 {
		t.Errorf("a caller on labeled whose if refuses the label, and a caller on push: got %+v, want none", sites[0].automaticApproval)
	}
}

func TestAutomaticLabelPrefersAccount(t *testing.T) {
	app := "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - id: app\n        uses: actions/create-github-app-token@v2\n        with:\n          app-id: ${{ vars.ID }}\n          private-key: ${{ secrets.KEY }}\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ steps.app.outputs.token }}\n"
	x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
		[2]string{".github/workflows/a-app.yml", app},
		[2]string{".github/workflows/b-pat.yml", labelerYML},
		[2]string{".github/workflows/build.yml", labeledWorkflow("", headCheckout)})
	if a := x.allCheckoutSites()[0].automaticApproval; a.Token != labeler.TokenSourceAccount || a.At.InputName() != ".github/workflows/b-pat.yml" {
		t.Errorf("got %v at %s, want the labeler of the personal access token", a.Token, a.At.InputName())
	}
}

func TestAutomaticLabelIfSite(t *testing.T) {
	src := labeledWorkflow("    if: contains('safe-to-test', github.event.label.name)\n", headCheckout)
	x := labeledIR(t, ".github/workflows/build.yml", freeConfig+"test:\n  - head-branch: ['^t']\n",
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/build.yml", src})
	sites := x.allIfSites()
	if len(sites) != 1 {
		t.Fatalf("got %d if sites", len(sites))
	}
	a := sites[0].automaticApproval
	var names []string
	for _, n := range a.LabelNames {
		names = append(names, n.String())
	}
	if !slices.Equal(a.AutomaticLabels, free) || !slices.Equal(names, []string{"safe-to-test", "test"}) {
		t.Errorf("got %v %v, want free with safe-to-test and test", a.AutomaticLabels, names)
	}
}

func TestAutomaticLabelBypass(t *testing.T) {
	src := labeledWorkflow("    if: contains('safe-to-test', github.event.label.name)\n", headCheckout)
	for _, c := range []struct {
		config string
		want   int
	}{
		{"test:\n  - head-branch: ['^t']\n", 1},
		{freeConfig + "test:\n  - head-branch: ['^t']\n", 0},
	} {
		x := labeledIR(t, ".github/workflows/build.yml", c.config,
			[2]string{".github/workflows/labeler.yml", labelerYML},
			[2]string{".github/workflows/build.yml", src})
		if got := len(x.allIfSites()[0].substringBypasses); got != c.want {
			t.Errorf("%q: got %d bypasses, want %d", c.config, got, c.want)
		}
	}
}

// TestAutomaticLabelMayNotRun: a labeler step that may not run lets the
// attacker in only undecided, and not at all when its labels do not pass
// the if; a Step that surely runs with a label that passes the if decides.
func TestAutomaticLabelMayNotRun(t *testing.T) {
	const labelerStep = "      - uses: actions/labeler@v5\n"
	failure := strings.Replace(labelerYML, labelerStep, labelerStep+"        if: failure()\n", 1)
	guard := "      - uses: actions/checkout@v4\n        if: github.event.action == 'synchronize'\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	head := "      - uses: actions/checkout@v4.2.2\n        if: github.event.action == 'opened'\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n"
	mixed := strings.Replace(failure, labelerStep, guard+head+labelerStep, 1)
	always := strings.Replace(labelerYML, labelerStep, labelerStep+"        if: always()\n", 1)
	both := always + strings.TrimPrefix(failure, "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n")
	unknown := []analysis.AutomaticLabel{analysis.AutomaticLabelUnknown}
	for _, c := range []struct {
		name, labeler, ifs string
		want               []analysis.AutomaticLabel
	}{
		{"failure(), the label", failure, "    if: github.event.label.name == 'safe-to-test'\n", unknown},
		{"failure(), another label", failure, "    if: github.event.label.name == 'other'\n", nil},
		{"the base on one event, the head on another, the label", mixed, "    if: github.event.label.name == 'safe-to-test'\n", free},
		{"the base on one event, the head on another, another label", mixed, "    if: github.event.label.name == 'other'\n", unknown},
		{"always() and failure()", both, "    if: github.event.label.name == 'safe-to-test'\n", free},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
				[2]string{".github/workflows/labeler.yml", c.labeler},
				[2]string{".github/workflows/build.yml", labeledWorkflow(c.ifs, headCheckout)})
			jobs, sites := x.allJobs(), x.allCheckoutSites()
			if len(jobs) != 1 || len(sites) != 1 {
				t.Fatalf("%d jobs, %d sites", len(jobs), len(sites))
			}
			for _, a := range []AutomaticApproval{jobs[0].automaticApproval, sites[0].automaticApproval} {
				if !slices.Equal(a.AutomaticLabels, c.want) {
					t.Errorf("got %v, want %v", a.AutomaticLabels, c.want)
				}
			}
			if c.labeler == mixed {
				steps := x.labelersOf().Steps()
				if len(steps) != 2 || steps[0].Step.Base.Node != steps[1].Step.Base.Node || sites[0].automaticApproval.At.base.Node != steps[0].Step.Base.Node {
					t.Errorf("the labeler: got %d steps and %+v, want two readings of the one step", len(steps), sites[0].automaticApproval.At)
				}
			}
			if c.labeler == both {
				steps := x.labelersOf().Steps()
				if len(steps) != 2 || sites[0].automaticApproval.At.base.Node != steps[0].Step.Base.Node {
					t.Errorf("the labeler: got %+v, want the step with always()", sites[0].automaticApproval.At)
				}
			}
		})
	}
}

// TestAutomaticLabelNeedsResult: the if of a job that waits for the label
// reads needs.<id>.result and needs.*.result of the jobs the job depends on
// directly as success when the if calls no status function, as GitHub reads
// such an if only when every one of those jobs succeeded.
func TestAutomaticLabelNeedsResult(t *testing.T) {
	const pre = "  pre:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
	workflowWith := func(cond string) string {
		return "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n" + pre + "  build:\n    needs: pre\n    if: " + cond + "\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	}
	for _, c := range []struct {
		cond string
		want []analysis.AutomaticLabel
	}{
		{"github.event.label.name == 'safe-to-test' && needs.pre.result == 'failure'", nil},
		{"github.event.label.name == 'safe-to-test' && needs.pre.result == 'success'", free},
		{"contains(github.event.pull_request.labels.*.name, 'safe-to-test') && contains(needs.*.result, 'failure')", nil},
		{"${{ always() && github.event.label.name == 'safe-to-test' && needs.pre.result == 'failure' }}", free},
		{"${{ success() && github.event.label.name == 'safe-to-test' && needs.pre.result == 'failure' }}", nil},
	} {
		x := labeledIR(t, ".github/workflows/build.yml", freeConfig,
			[2]string{".github/workflows/labeler.yml", labelerYML},
			[2]string{".github/workflows/build.yml", workflowWith(c.cond)})
		sites := x.allCheckoutSites()
		if c.want == nil {
			// the job does not run on the event (attacker.JobIfs): no site
			if len(sites) != 0 {
				t.Errorf("%s: got %+v, want no site", c.cond, sites)
			}
			continue
		}
		if len(sites) != 1 || !slices.Equal(sites[0].automaticApproval.AutomaticLabels, c.want) {
			t.Errorf("%s: got %+v, want %v", c.cond, sites, c.want)
		}
	}
	// the if site of the job reads the needs of the job
	x := labeledIR(t, ".github/workflows/build.yml", freeConfig+"test:\n  - head-branch: ['^t']\n",
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/build.yml", workflowWith("contains('safe-to-test', github.event.label.name) && needs.pre.result == 'failure'")})
	ifSites := x.allIfSites()
	if len(ifSites) != 0 {
		t.Errorf("if site: got %+v, want none (the job does not run on any event)", ifSites)
	}
	// a job that the job waiting for the label depends on reads its own needs
	gated := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n" + pre + "  gate:\n    needs: pre\n    if: needs.pre.result == 'failure'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n  build:\n    needs: gate\n    if: github.event.label.name == 'safe-to-test'\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	x = labeledIR(t, ".github/workflows/build.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/build.yml", gated})
	if sites := x.allCheckoutSites(); len(sites) != 0 {
		t.Errorf("a gate that needs pre: got %+v, want no site (build needs gate, which does not run)", sites)
	}
	// a job that calls a reusable workflow reads the needs of the job
	called := "on:\n  workflow_call:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + headCheckout
	caller := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n" + pre + "  call:\n    needs: pre\n    if: github.event.label.name == 'safe-to-test' && needs.pre.result == 'failure'\n    uses: ./.github/workflows/called.yml\n"
	x = labeledIR(t, ".github/workflows/called.yml", freeConfig,
		[2]string{".github/workflows/labeler.yml", labelerYML},
		[2]string{".github/workflows/called.yml", called},
		[2]string{".github/workflows/ci.yml", caller})
	if sites := x.allCheckoutSites(); len(sites) != 0 {
		t.Errorf("caller: got %+v, want no site (the job that calls the workflow does not run)", sites)
	}
}

// TestAutomaticLabelCalledLabeler: actions/labeler in a reusable workflow
// or a composite action that a workflow on pull_request_target calls lets
// the attacker in as the labeler of a job does.
func TestAutomaticLabelCalledLabeler(t *testing.T) {
	labelerStep := "      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ secrets.PAT }}\n"
	for _, c := range []struct {
		name   string
		at     string
		labels [][2]string
	}{
		{"job", ".github/workflows/labeler.yml", [][2]string{{".github/workflows/labeler.yml", labelerYML}}},
		{"reusable", ".github/workflows/label.yml", [][2]string{
			{".github/workflows/labeler.yml", "on: pull_request_target\njobs:\n  label:\n    uses: ./.github/workflows/label.yml\n    secrets: inherit\n"},
			{".github/workflows/label.yml", "on: workflow_call\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n" + labelerStep}}},
		{"composite", ".github/actions/label/action.yml", [][2]string{
			{".github/workflows/labeler.yml", "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: ./.github/actions/label\n"},
			{".github/actions/label/action.yml", "runs:\n  using: composite\n  steps:\n" + strings.ReplaceAll(labelerStep, "      ", "    ")}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			files := append(slices.Clone(c.labels), [2]string{".github/workflows/build.yml", labeledWorkflow("    if: github.event.label.name == 'safe-to-test'\n", headCheckout)})
			x := labeledIR(t, ".github/workflows/build.yml", freeConfig, files...)
			sites := x.allCheckoutSites()
			if len(sites) != 1 {
				t.Fatalf("%d sites", len(sites))
			}
			a := sites[0].automaticApproval
			if !slices.Equal(a.AutomaticLabels, free) || a.At.InputName() != c.at || a.Token != labeler.TokenSourceAccount {
				t.Errorf("got %+v", a)
			}
		})
	}
}

package labeler

import (
	"fmt"
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/prcode"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

const freeConfig = "safe-to-test:\n  - changed-files:\n      - any-glob-to-any-file: ['site/**']\n"

// labelerWorkflow is a workflow on pull_request_target whose one job runs
// the steps before and then actions/labeler@ref with the inputs with.
func labelerWorkflow(ref, before, with string) string {
	var b strings.Builder
	b.WriteString("on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n")
	b.WriteString(before)
	b.WriteString("      - uses: actions/labeler@" + ref + "\n")
	if with != "" {
		b.WriteString("        with:\n" + with)
	}
	return b.String()
}

// stepsIn reads the steps of the workflow src, named
// .github/workflows/labeler.yml, in a repository of the files root.
func stepsIn(t *testing.T, src string, root fstest.MapFS, excluded ...string) []Step {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	name := facts.MustCleanInputPath(".github/workflows/labeler.yml")
	return stepsOf(attacker.Outsider, name, w, root, func(p facts.InputPath) bool {
		for _, e := range excluded {
			if p.String() == e {
				return true
			}
		}
		return false
	})
}

func defaultRoot() fstest.MapFS {
	return fstest.MapFS{".github/labeler.yml": {Data: []byte(freeConfig)}}
}

func TestStepToken(t *testing.T) {
	for _, c := range []struct {
		name, ref, with string
		counted         bool
		want            TokenSource
	}{
		{"no token, v5", "v5", "", false, 0},
		{"no token, v3", "v3", "", false, 0},
		{"the GITHUB_TOKEN", "v5", "          repo-token: ${{ secrets.GITHUB_TOKEN }}\n", false, 0},
		{"github.token", "v5", "          repo-token: ${{ github.token }}\n", false, 0},
		{"a secret", "v5", "          repo-token: ${{ secrets.PAT }}\n", true, TokenSourceAccount},
		{"an env", "v5", "          repo-token: ${{ env.T }}\n", true, TokenSourceUnknown},
		{"a secret by an index", "v5", "          repo-token: ${{ secrets['LABELER_PAT'] }}\n", true, TokenSourceAccount},
		{"a secret with spaces", "v5", "          repo-token: ${{ secrets . LABELER_PAT }}\n", true, TokenSourceAccount},
		{"a secret named after the GITHUB_TOKEN", "v5", "          repo-token: ${{ secrets.GITHUB_TOKEN_PAT }}\n", true, TokenSourceAccount},
		{"github.token by an index", "v5", "          repo-token: ${{ github['token'] }}\n", false, 0},
		{"github.token with spaces", "v5", "          repo-token: ${{ github . token }}\n", false, 0},
		{"a secret named by an expression", "v5", "          repo-token: ${{ secrets[inputs.name] }}\n", true, TokenSourceUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := stepsIn(t, labelerWorkflow(c.ref, "", c.with), defaultRoot())
			if !c.counted {
				if len(got) != 0 {
					t.Fatalf("got %v, want no step", got)
				}
				return
			}
			if len(got) != 1 || got[0].Token != c.want {
				t.Fatalf("got %v, want one step with %v", got, c.want)
			}
		})
	}
	app := "      - id: app\n        uses: actions/create-github-app-token@v2\n        with:\n          app-id: ${{ vars.APP_ID }}\n          private-key: ${{ secrets.KEY }}\n"
	got := stepsIn(t, labelerWorkflow("v5", app, "          repo-token: ${{ steps.app.outputs.token }}\n"), defaultRoot())
	if len(got) != 1 || got[0].Token != TokenSourceApp {
		t.Errorf("a token of an app: got %v", got)
	}
	got = stepsIn(t, labelerWorkflow("v5", app, "          repo-token: ${{ steps . APP . outputs['token'] }}\n"), defaultRoot())
	if len(got) != 1 || got[0].Token != TokenSourceApp {
		t.Errorf("a token of an app, spelled with spaces and an index: got %v", got)
	}
	for _, with := range []string{"          repo-token: ${{ secrets.LABELER_PAT }}\n", "          repo-token: ${{ secrets['LABELER_PAT'] }}\n", "          repo-token: ${{ secrets.GITHUB_TOKEN_PAT }}\n"} {
		if got := stepsIn(t, labelerWorkflow("v5", "", with), defaultRoot()); len(got) != 1 || got[0].Unknown {
			t.Errorf("%s: got %+v, want a step that is not Unknown", with, got)
		}
	}
	for _, with := range []string{"          repo-token: ${{ secrets[inputs.name] }}\n", "          repo-token: ${{ fromJSON(toJSON(secrets)).PAT }}\n", "          repo-token: ${{ secrets.PAT || github['token'] }}\n"} {
		if got := stepsIn(t, labelerWorkflow("v5", "", with), defaultRoot()); len(got) != 1 || !got[0].Unknown {
			t.Errorf("%s: got %+v, want Unknown: the token may be the GITHUB_TOKEN", with, got)
		}
	}
}

func TestStepConfig(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	got := stepsIn(t, labelerWorkflow("v5", "", pat), defaultRoot())
	if len(got) != 1 || got[0].Unknown || got[0].AnyLabel {
		t.Fatalf("the default configuration: got %v", got)
	}
	if r := got[0].Labels["safe-to-test"]; r != freeReach {
		t.Errorf("safe-to-test: got %v, want free", r)
	}
	yaml := fstest.MapFS{".github/labeler.yaml": {Data: []byte(freeConfig)}}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat+"          configuration-path: .github/labeler.yaml\n"), yaml); len(got) != 1 || got[0].Labels["safe-to-test"] != freeReach {
		t.Errorf("configuration-path .yaml: got %v", got)
	}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat+"          configuration-path: ${{ vars.P }}\n"), defaultRoot()); len(got) != 1 || !got[0].Unknown {
		t.Errorf("configuration-path with a ${{ }}: got %v, want Unknown", got)
	}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat), fstest.MapFS{}); len(got) != 0 {
		t.Errorf("no configuration: got %v, want no step (the labeler fails)", got)
	}
	big := fstest.MapFS{".github/labeler.yml": {Data: []byte(freeConfig + strings.Repeat("#", 1<<20))}}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat), big); len(got) != 1 || !got[0].Unknown {
		t.Errorf("a configuration over 1 MiB: got %v, want Unknown", got)
	}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat), defaultRoot(), ".github/labeler.yml"); len(got) != 1 || !got[0].Unknown {
		t.Errorf("an excluded configuration: got %v, want Unknown", got)
	}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat), fstest.MapFS{".github/labeler.yml": {Data: []byte("l: [\n")}}); len(got) != 1 || len(got[0].Labels) != 0 || got[0].Unknown {
		t.Errorf("a configuration that does not read: got %v, want a step with no labels", got)
	}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat), fstest.MapFS{".github/labeler.yml": {Data: []byte("b: &b\n  - head-branch: x\nl: *b\n")}}); len(got) != 1 || !got[0].Unknown {
		t.Errorf("an alias: got %v, want Unknown", got)
	}
}

func TestConfigPathSpelling(t *testing.T) {
	got := stepsIn(t, labelerWorkflow("v5", "", "          repo-token: ${{ secrets.PAT }}\n          configuration-path: ./.github/labeler.yml\n"), defaultRoot())
	if len(got) != 1 || got[0].Labels["safe-to-test"] != freeReach {
		t.Errorf("./.github/labeler.yml: got %v", got)
	}
}

func TestStepAttackerConfig(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	head := "      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n"
	for _, c := range []struct {
		name, ref, before   string
		counted, any, unkwn bool
	}{
		{"the head before v5", "v5", head, true, true, false},
		{"the head in a directory", "v5", head + "          path: pr\n", true, false, false},
		{"the head before v4.2.0, which reads the API", "v4.2.0", head, true, false, false},
		{"a checkout with the guard fails", "v5", "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", false, false, false},
		{"a path with a ${{ }}", "v5", head + "          path: ${{ vars.D }}\n", true, false, true},
		{"the base", "v5", "      - uses: actions/checkout@v4.2.2\n", true, false, false},
		// a checkout that fails on its path brings no tree, and stops the job
		// before an actions/labeler with no status function
		{"a checkout into runner.temp", "v5", head + "          path: ${{ runner.temp }}/pr\n", false, false, false},
		{"a checkout of the base into runner.temp", "v5", "      - uses: actions/checkout@v4.2.2\n        with:\n          path: ${{ runner.temp }}/pr\n", false, false, false},
		{"a checkout into runner.temp with continue-on-error", "v5", strings.Replace(head, "      - uses", "      - continue-on-error: true\n        uses", 1) + "          path: ${{ runner.temp }}/pr\n", true, false, false},
		{"an absolute path", "v5", head + "          path: /tmp/x\n", true, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := stepsIn(t, labelerWorkflow(c.ref, c.before, pat), defaultRoot())
			if !c.counted {
				if len(got) != 0 {
					t.Fatalf("got %v, want no step", got)
				}
				return
			}
			if len(got) != 1 || got[0].AnyLabel != c.any || got[0].Unknown != c.unkwn {
				t.Fatalf("got %v, want AnyLabel %v, Unknown %v", got, c.any, c.unkwn)
			}
		})
	}
}

func TestStepPRNumber(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	if got := stepsIn(t, labelerWorkflow("v5", "", pat+"          pr-number: ${{ github.event.pull_request.number }}\n"), defaultRoot()); len(got) != 1 || got[0].Unknown {
		t.Errorf("the number of the pull request: got %v", got)
	}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat+"          pr-number: ${{ github['event'] . number }}\n"), defaultRoot()); len(got) != 1 || got[0].Unknown {
		t.Errorf("the number of the pull request, spelled with an index: got %v", got)
	}
	if got := stepsIn(t, labelerWorkflow("v5", "", pat+"          pr-number: 42\n"), defaultRoot()); len(got) != 1 || !got[0].Unknown {
		t.Errorf("another number: got %v, want Unknown", got)
	}
	if got := stepsIn(t, labelerWorkflow("v4.2.0", "", pat+"          pr-number: 42\n"), defaultRoot()); len(got) != 1 || got[0].Unknown {
		t.Errorf("v4.2.0 has no pr-number: got %v, want the step as without it", got)
	}
}

func TestStepUnknownRelease(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	// v3 and v4 add a label of the form of v5 to every pull request; v5 to
	// v7 add it with a file under site/; 2.2.0 throws on it.
	if got := stepsIn(t, labelerWorkflow("main", "", pat), defaultRoot()); len(got) != 1 || !got[0].Unknown {
		t.Errorf("a branch and a configuration of v5: got %v, want Unknown", got)
	}
	// 2.2.0 throws on an object; v3 to v7 add the label to the pull
	// request of the attacker.
	same := fstest.MapFS{".github/labeler.yml": {Data: []byte("l:\n  - head-branch: ['^x']\n  - changed-files:\n      - any-glob-to-any-file: ['a']\n")}}
	got := stepsIn(t, labelerWorkflow("v8", "", pat), same)
	if len(got) != 1 || !got[0].Unknown {
		t.Errorf("v8: got %v, want Unknown (2.2.0 throws, v3 and v4 add the label)", got)
	}
}

func TestStepEvents(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	pr := strings.Replace(labelerWorkflow("v5", "", pat), "on: pull_request_target", "on: pull_request", 1)
	if got := stepsIn(t, pr, defaultRoot()); len(got) != 0 {
		t.Errorf("on pull_request: got %v, want no step", got)
	}
	labeled := strings.Replace(labelerWorkflow("v5", "", pat), "on: pull_request_target", "on:\n  pull_request_target:\n    types: [labeled]", 1)
	if got := stepsIn(t, labeled, defaultRoot()); len(got) != 0 {
		t.Errorf("on labeled, which the attacker does not trigger: got %v, want no step", got)
	}
	notFork := strings.Replace(labelerWorkflow("v5", "", pat), "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    if: github.event.pull_request.head.repo.full_name == github.repository\n", 1)
	if got := stepsIn(t, notFork, defaultRoot()); len(got) != 0 {
		t.Errorf("a job that leaves out forks: got %v, want no step", got)
	}
}

func TestStepGuards(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	head := "      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n"
	guarded := "      - uses: actions/checkout@v6\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	for _, c := range []struct {
		name, before, with  string
		counted, any, unkwn bool
	}{
		{"continue-on-error false after a checkout that fails", strings.Replace(guarded, "      - uses", "      - continue-on-error: false\n        uses", 1), pat, false, false, false},
		{"continue-on-error with a ${{ }}", strings.Replace(guarded, "      - uses", "      - continue-on-error: ${{ vars.C }}\n        uses", 1), pat, true, false, true},
		{"continue-on-error true", strings.Replace(guarded, "      - uses", "      - continue-on-error: true\n        uses", 1), pat, true, false, false},
		{"a checkout of a value not known", "      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ steps.x.outputs.ref }}\n", pat, true, false, true},
		{"the head in pr and the configuration there", head + "          path: pr\n", pat + "          configuration-path: pr/.github/labeler.yml\n", true, true, false},
		{"the GITHUB_TOKEN or a secret", "", "          repo-token: ${{ secrets.GITHUB_TOKEN || secrets.PAT }}\n", true, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := defaultRoot()
			root["pr/.github/labeler.yml"] = root[".github/labeler.yml"]
			got := stepsIn(t, labelerWorkflow("v5", c.before, c.with), root)
			if !c.counted {
				if len(got) != 0 {
					t.Fatalf("got %v, want no step", got)
				}
				return
			}
			if len(got) != 1 || got[0].AnyLabel != c.any || got[0].Unknown != c.unkwn {
				t.Fatalf("got %+v, want AnyLabel %v, Unknown %v", got, c.any, c.unkwn)
			}
		})
	}
	got := stepsIn(t, labelerWorkflow("v5", "", "          repo-token: ${{ secrets.GITHUB_TOKEN || secrets.PAT }}\n"), defaultRoot())
	if len(got) != 1 || got[0].Token != TokenSourceUnknown {
		t.Errorf("a token of two secrets: got %+v, want TokenSourceUnknown", got)
	}
	env := strings.Replace(labelerWorkflow("v5", "", pat), "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    environment: labeling\n", 1)
	if got := stepsIn(t, env, defaultRoot()); len(got) != 1 || !got[0].Unknown {
		t.Errorf("a labeler in an environment, which may have required reviewers: got %+v, want Unknown", got)
	}
}

// withIf puts the if cond, as a double-quoted YAML string, on the first
// step of src that runs uses (a line "      - uses: <uses>").
func withIf(src, uses, cond string) string {
	line := "      - uses: " + uses + "\n"
	return strings.Replace(src, line, line+"        if: \""+cond+"\"\n", 1)
}

// stepWant is one Step that stepsIn reads: AnyLabel, Unknown and
// MayNotRun. A Step with no AnyLabel and no Unknown has the label of the
// configuration of the base.
type stepWant struct{ any, unkwn, may bool }

var (
	baseStep    = []stepWant{{}}
	baseMayStep = []stepWant{{may: true}}
	anyStep     = []stepWant{{any: true}}
	anyMayStep  = []stepWant{{any: true, may: true}}
	unknownStep = []stepWant{{unkwn: true}}
)

// checkSteps compares the steps got with want, in order.
func checkSteps(t *testing.T, got []Step, want []stepWant) {
	t.Helper()
	if len(got) != len(want) {
		var sum []stepWant
		for _, g := range got {
			sum = append(sum, stepWant{any: g.AnyLabel, unkwn: g.Unknown, may: g.MayNotRun})
		}
		t.Fatalf("got %+v, want %+v", sum, want)
	}
	for i, w := range want {
		g := got[i]
		if g.AnyLabel != w.any || g.Unknown != w.unkwn || g.MayNotRun != w.may {
			t.Errorf("step %d: got AnyLabel %v, Unknown %v, MayNotRun %v, want %+v", i, g.AnyLabel, g.Unknown, g.MayNotRun, w)
		}
		if !w.any && !w.unkwn && g.Labels["safe-to-test"] != freeReach {
			t.Errorf("step %d: safe-to-test: got %v, want the label of the configuration of the base", i, g.Labels["safe-to-test"])
		}
	}
}

// TestStepAfterFailure: a checkout before actions/labeler that fails on the
// pull request of the attacker stops the job only for an actions/labeler
// whose if does not run after a failure; the if of each step is read in
// its syntax tree, for each event of actions/labeler. An actions/labeler
// that does not run in a job that succeeded runs only when the attacker
// can make a step before it fail: unless a checkout before it surely
// fails, the step may not run (MayNotRun), and keeps the labels it adds
// when it runs.
func TestStepAfterFailure(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	head := "      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n"
	guarded := "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	unplaced := head + "          path: ${{ runner.temp }}/pr\n"
	continued := strings.Replace(guarded, "      - uses", "      - continue-on-error: true\n        uses", 1)
	inPR := head + "          path: pr\n"
	const fork = "github.event.pull_request.head.repo.fork"
	const sameRepo = "github.event.pull_request.head.repo.full_name == github.repository"
	const sync = "github.event.action == 'synchronize'"
	for _, c := range []struct {
		name, ref, before, cond string // cond is the if of actions/labeler; empty for none; ref empty for v5
		want                    []stepWant
	}{
		{"always()", "", guarded, "always()", baseStep},
		{"${{ always() }}", "", guarded, "${{ always() }}", baseStep},
		{"failure()", "", guarded, "failure()", baseStep},
		{"!cancelled()", "", guarded, "${{ !cancelled() }}", baseStep},
		{"success()", "", guarded, "success()", nil},
		{"success() folded", "", guarded, "${{ 'success()' }}", nil},
		{"no if", "", guarded, "", nil},
		{"cancelled()", "", guarded, "cancelled()", unknownStep},
		{"success() or cancelled()", "", guarded, "success() || cancelled()", unknownStep},
		{"always() after a checkout that fails on its path", "", unplaced, "always()", baseStep},
		{"a checkout that may be skipped, no if", "", withIf(guarded, "actions/checkout@v4", fork), "", unknownStep},
		{"a checkout that may be skipped, always()", "", withIf(guarded, "actions/checkout@v4", fork), "always()", baseStep},
		{"a checkout skipped for the attacker", "", withIf(guarded, "actions/checkout@v4", sameRepo), "", baseStep},
		{"a checkout skipped for the attacker, folded", "", withIf(guarded, "actions/checkout@v4", "${{ '"+sameRepo+"' }}"), "", baseStep},
		{"a checkout skipped on opened", "", withIf(guarded, "actions/checkout@v4", sync), "", baseStep},
		{"a checkout with no status function after a failure", "", guarded + head, "always()", baseStep},
		{"a checkout after a failure that may not be", "", withIf(guarded, "actions/checkout@v4", fork) + head, "always()", anyStep},
		{"cancelled() with no checkout", "", "", "cancelled()", unknownStep},
		{"cancelled() on one event and the base on another", "", withIf(head, "actions/checkout@v4.2.2", sync), "${{ cancelled() || github.event.action == 'opened' }}", unknownStep},
		{"an if that no state of the job passes", "", "", "success() && failure()", nil},
		{"an event that is not known and an event of the base", "", withIf(head, "actions/checkout@v4.2.2", sync) + "          path: ${{ vars.D }}\n", "", unknownStep},
		// an actions/labeler that does not run in a job that succeeded
		{"failure() with no step before", "", "", "failure()", baseMayStep},
		{"failure() after a step that the rule does not read", "", "      - run: echo hi\n", "failure()", baseMayStep},
		{"failure() folded", "", "", "${{ 'failure()' }}", baseMayStep},
		{"failure() after continue-on-error", "", continued, "failure()", baseMayStep},
		{"failure() after the head that has the configuration", "", head, "failure()", anyMayStep},
		{"failure() after the head, a release that reads the API", "v4.2.0", head, "failure()", baseMayStep},
		{"failure() after a checkout that may be skipped and the head", "", withIf(guarded, "actions/checkout@v4", fork) + head, "failure()", anyMayStep},
		{"failure() after the head and a checkout that fails", "", head + guarded, "failure()", anyStep},
		{"!success()", "", "", "${{ !success() }}", baseMayStep},
		{"failure() or cancelled()", "", "", "failure() || cancelled()", baseMayStep},
		{"failure() or a value of the attacker", "", "", "${{ failure() || contains(github.event.pull_request.title, 'x') }}", baseStep},
		{"failure() on one event, the head on another", "", withIf(guarded, "actions/checkout@v4", sync) + withIf(head, "actions/checkout@v4.2.2", "github.event.action == 'opened'"), "failure()", []stepWant{{}, {any: true, may: true}}},
		{"failure() after a checkout that fails on synchronize", "", withIf(guarded, "actions/checkout@v4", sync), "failure()", baseStep},
		{"failure() on one event, the head on another, a release that reads the API", "v4.2.0", withIf(guarded, "actions/checkout@v4", sync) + withIf(head, "actions/checkout@v4.2.2", "github.event.action == 'opened'"), "failure()", baseStep},
		{"failure() or opened", "", "", "${{ failure() || github.event.action == 'opened' }}", baseStep},
		{"a mixed if with failure()", "", "", "x ${{ failure() }}", baseStep},
		{"job.status of failure, which success() && makes false", "", "", "job.status == 'failure'", nil},
		{"always() and job.status of failure", "", "", "${{ always() && job.status == 'failure' }}", baseMayStep},
		// a step that runs the code of the attacker, which the attacker may make fail (P2a)
		{"failure() after the head and a step that runs the code", "", head + "      - run: npm test\n", "failure()", anyStep},
		{"failure() after the head in pr and a step that runs the code", "", inPR + "      - run: ./pr/build.sh\n", "failure()", baseStep},
		{"failure() after a step that runs the code with continue-on-error", "", inPR + "      - continue-on-error: true\n        run: ./pr/build.sh\n", "failure()", baseMayStep},
		{"failure() after a step that runs pr before the checkout of pr", "", "      - run: ./pr/build.sh\n" + inPR, "failure()", baseMayStep},
		{"failure() after a step that runs pr after a checkout that may be skipped", "", withIf(inPR, "actions/checkout@v4.2.2", fork) + "      - run: ./pr/build.sh\n", "failure()", baseMayStep},
		{"failure() after a step that runs the code and the head", "", inPR + "      - run: ./pr/build.sh\n" + head, "failure()", []stepWant{{}, {any: true, may: true}}},
		// a command ended by & runs the code of the attacker, and the exit code of the step does not wait for it
		{"failure() after a command of the code ended by &", "", inPR + "      - run: ./pr/build.sh &\n", "failure()", baseMayStep},
		{"failure() after a command of the code ended by & and one that is not", "", inPR + "      - run: |\n          ./pr/build.sh &\n          ./pr/test.sh\n", "failure()", baseStep},
		// a command that a wrapper runs as another user: read as one that the attacker can make fail, also where its failure does not end the step (the false positive form labeler-other-user)
		{"failure() after a command of the code run as another user", "", inPR + "      - run: sudo -u nobody ./pr/build.sh || true\n", "failure()", baseStep},
		{"failure() after a command of the code run as root", "", inPR + "      - run: sudo ./pr/build.sh\n", "failure()", baseStep},
		{"failure() after a command of the code run as another user where errexit holds", "", inPR + "      - run: sudo -u nobody ./pr/build.sh\n", "failure()", baseStep},
		// a background step fails the job at the next wait or wait-all that includes it
		{"failure() after a background step that runs the code", "", inPR + "      - background: true\n        run: ./pr/build.sh\n", "failure()", baseMayStep},
		{"failure() after a background step that runs the code and a wait-all", "", inPR + "      - background: true\n        run: ./pr/build.sh\n      - wait-all: true\n", "failure()", baseStep},
		{"failure() after a background step that runs the code and a wait for it", "", inPR + "      - id: b\n        background: true\n        run: ./pr/build.sh\n      - wait: [b]\n", "failure()", baseStep},
		{"no if after a background checkout that fails", "", strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1), "", baseStep},
		{"failure() after a background checkout that fails", "", strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1), "failure()", baseMayStep},
		{"no if after a background checkout that fails and a wait-all", "", strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1) + "      - wait-all: true\n", "", nil},
		{"no if after a background checkout of the head", "", strings.Replace(head, "      - uses", "      - background: true\n        uses", 1), "", unknownStep},
		{"no if after a background checkout of the head into a directory without the configuration", "", strings.Replace(inPR, "      - uses", "      - background: true\n        uses", 1), "", baseStep},
		// the failure of a step of a parallel group or of a background step fails the job at the end of the group, or at the wait or wait-all that waits for the step
		{"failure() after a group of a checkout that fails and the head", "", "      - parallel:\n          - uses: actions/checkout@v4\n            with:\n              ref: ${{ github.event.pull_request.head.sha }}\n          - uses: actions/checkout@v4.2.2\n            with:\n              ref: ${{ github.event.pull_request.head.sha }}\n              allow-unsafe-pr-checkout: true\n", "failure()", anyStep},
		{"failure() after a group of the head and a checkout that fails", "", "      - parallel:\n          - uses: actions/checkout@v4.2.2\n            with:\n              ref: ${{ github.event.pull_request.head.sha }}\n              allow-unsafe-pr-checkout: true\n          - uses: actions/checkout@v4\n            with:\n              ref: ${{ github.event.pull_request.head.sha }}\n", "failure()", anyStep},
		{"failure() after a background checkout that fails, the head and a wait-all", "", strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1) + head + "      - wait-all: true\n", "failure()", anyStep},
		{"no if after a background checkout that fails and a wait-all with continue-on-error", "", strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1) + "      - wait-all: true\n        continue-on-error: true\n", "", baseStep},
		{"no if after a background checkout that fails and a wait-all with continue-on-error of a ${{ }}", "", strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1) + "      - wait-all: true\n        continue-on-error: ${{ vars.C }}\n", "", unknownStep},
		// the head with failure() runs only after a failure before the head, which the rule does not know of: its configuration is in a reading that may not run
		{"failure() after a background checkout that fails, the head with failure() and a wait-all", "", strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1) + withIf(head, "actions/checkout@v4.2.2", "failure()") + "      - wait-all: true\n", "failure()", []stepWant{{}, {any: true, may: true}}},
		{"failure() after a background step that runs the code and a wait-all with continue-on-error", "", inPR + "      - background: true\n        run: ./pr/build.sh\n      - wait-all: true\n        continue-on-error: true\n", "failure()", baseMayStep},
		// a failure that reaches s is known, and the attacker makes a step that runs the code fail before that failure, so a checkout with failure() between them runs
		{"failure() after the code in pr, a background checkout that fails, a step that runs the code, the head with failure() and a wait-all", "", inPR + strings.Replace(guarded, "      - uses", "      - background: true\n        uses", 1) + "      - run: ./pr/build.sh\n" + withIf(head, "actions/checkout@v4.2.2", "failure()") + "      - wait-all: true\n", "failure()", anyStep},
		// the attacker makes a step that runs the code fail, so a checkout with failure() after it runs, for an actions/labeler that runs after a failure too
		{"always() after a step that runs the code and the head with failure()", "", inPR + "      - run: ./pr/build.sh\n" + withIf(head, "actions/checkout@v4.2.2", "failure()"), "always()", anyStep},
		{"!cancelled() after a step that runs the code and the head with failure()", "", inPR + "      - run: ./pr/build.sh\n" + withIf(head, "actions/checkout@v4.2.2", "failure()"), "${{ !cancelled() }}", anyStep},
		{"no if after the head with failure()", "", withIf(head, "actions/checkout@v4.2.2", "failure()"), "", baseStep},
		// a checkout that runs only after a failure or a cancel, before an actions/labeler that runs in a cancelled run: the attacker may cancel the run, which the rule does not know of
		{"!failure() after the head with cancelled()", "", withIf(head, "actions/checkout@v4.2.2", "cancelled()"), "${{ !failure() }}", []stepWant{{}, {any: true, may: true}}},
		{"success() or cancelled() after the head with cancelled()", "", withIf(head, "actions/checkout@v4.2.2", "cancelled()"), "success() || cancelled()", []stepWant{{}, {any: true, may: true}}},
		// the head with failure() before !failure(): the head runs only after a failure, which skips !failure() unless the run is cancelled
		{"!failure() after the head with failure()", "", withIf(head, "actions/checkout@v4.2.2", "failure()"), "${{ !failure() }}", []stepWant{{}, {any: true, may: true}}},
		// a failure that fails the job only after s does nothing to s
		{"no if after a background checkout that fails, with an if not decided", "", strings.Replace(withIf(guarded, "actions/checkout@v4", "${{ contains(github.event.pull_request.title, 'x') }}"), "      - uses", "      - background: true\n        uses", 1), "", baseStep},
		{"no if after a background checkout that fails, with continue-on-error of a ${{ }}", "", strings.Replace(guarded, "      - uses", "      - background: true\n        continue-on-error: ${{ vars.C }}\n        uses", 1), "", baseStep},
		// a checkout whose if is true in a job that succeeded and in a job that failed surely runs
		{"failure() after a checkout that fails with always()", "", withIf(guarded, "actions/checkout@v4", "always()"), "failure()", baseStep},
		{"no if after a checkout that fails with always()", "", withIf(guarded, "actions/checkout@v4", "always()"), "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			ref := c.ref
			if ref == "" {
				ref = "v5"
			}
			src := labelerWorkflow(ref, c.before, pat)
			if c.cond != "" {
				src = withIf(src, "actions/labeler@"+ref, c.cond)
			}
			checkSteps(t, stepsIn(t, src, defaultRoot()), c.want)
		})
	}
	env := strings.Replace(withIf(labelerWorkflow("v5", "", pat), "actions/labeler@v5", "failure()"), "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    environment: labeling\n", 1)
	checkSteps(t, stepsIn(t, env, defaultRoot()), []stepWant{{unkwn: true, may: true}})
	jobToken := withIf(labelerWorkflow("v5", "", "          repo-token: ${{ secrets.GITHUB_TOKEN || secrets.PAT }}\n"), "actions/labeler@v5", "failure()")
	checkSteps(t, stepsIn(t, jobToken, defaultRoot()), []stepWant{{unkwn: true, may: true}})
}

// TestStepJobAfterFailure: an if of the job of actions/labeler, or of a job
// that the job depends on through needs, that is false when every job
// that the job depends on succeeded makes the labeler step one that may
// not run; each if is read on its own, and a checkout that stops the job
// still stops the job.
func TestStepJobAfterFailure(t *testing.T) {
	pat := "          repo-token: ${{ secrets.PAT }}\n"
	guarded := "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	const build = "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
	const gate = "  gate:\n    needs: build\n    if: failure()\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
	const buildGuard = "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	const testHead = "  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n      - run: npm test\n"
	const testHeadBG = "  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n      - background: true\n        run: npm test\n"
	for _, c := range []struct {
		name, jobs, job, before, cond string // jobs before the job of actions/labeler; job is its needs and if; cond is the if of actions/labeler
		want                          []stepWant
	}{
		{"failure() after build", build, "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		// failure() of a job with no needs is false: no job before it fails, so the job never runs
		{"failure() with no needs", "", "    if: failure()\n", "", "", nil},
		{"cancelled() after build", build, "    needs: build\n    if: cancelled()\n", "", "", baseMayStep},
		{"no if after a gate with failure()", build + gate, "    needs: gate\n", "", "", baseMayStep},
		{"always() after build", build, "    needs: build\n    if: always()\n", "", "", baseStep},
		// success() and failure() are never true together, so the job never runs
		{"success() and failure()", "", "    if: success() && failure()\n", "", "", nil},
		{"failure() after build and a checkout that fails", build, "    needs: build\n    if: failure()\n", guarded, "", nil},
		{"failure() after build, failure() of the step", build, "    needs: build\n    if: failure()\n", "", "failure()", baseMayStep},
		// a job that the job depends on, which fails on the pull request of the attacker or which the attacker can make fail
		{"failure() after a build that fails", buildGuard, "    needs: build\n    if: failure()\n", "", "", baseStep},
		{"failure() after a test that runs the code", testHead, "    needs: test\n    if: failure()\n", "", "", baseStep},
		{"failure() after a build whose checkout has continue-on-error", strings.Replace(buildGuard, "      - uses", "      - continue-on-error: true\n        uses", 1), "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		{"failure() after a build with continue-on-error", strings.Replace(buildGuard, "    runs-on:", "    continue-on-error: true\n    runs-on:", 1), "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		{"failure() after a build that may be skipped", strings.Replace(buildGuard, "    runs-on:", "    if: github.event.pull_request.head.repo.fork\n    runs-on:", 1), "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		{"failure() after a job after a build that fails", buildGuard + "  mid:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", "    needs: mid\n    if: failure()\n", "", "", baseStep},
		{"cancelled() after a build that fails", buildGuard, "    needs: build\n    if: cancelled()\n", "", "", baseMayStep},
		// the failure of build skips label, which needs gate and has no status function
		{"no if after a gate with failure() after a build that fails", buildGuard + gate, "    needs: gate\n", "", "", baseMayStep},
		{"failure() after a build after an always() job after a job skipped for the attacker", "  z:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n  y:\n    needs: z\n    if: always()\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n" + strings.Replace(buildGuard, "    runs-on:", "    needs: y\n    runs-on:", 1), "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		{"failure() after a build with success() or failure() after a job skipped for the attacker", "  z:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n" + strings.Replace(buildGuard, "    runs-on:", "    needs: z\n    if: success() || failure()\n    runs-on:", 1), "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		{"failure() after a build whose checkout has success()", strings.Replace(buildGuard, "      - uses: actions/checkout@v4\n", "      - uses: actions/checkout@v4\n        if: success()\n", 1), "    needs: build\n    if: failure()\n", "", "", baseStep},
		{"failure() after a build with continue-on-error false", strings.Replace(buildGuard, "    runs-on:", "    continue-on-error: false\n    runs-on:", 1), "    needs: build\n    if: failure()\n", "", "", baseStep},
		{"failure() after a job that calls a reusable workflow", "  build:\n    uses: ./.github/workflows/build.yml\n", "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		{"failure() after a build whose background step runs the code before a wait-all with continue-on-error", testHeadBG + "      - wait-all: true\n        continue-on-error: true\n", "    needs: test\n    if: failure()\n", "", "", baseMayStep},
		{"failure() after a build whose background checkout fails and no step waits for", strings.Replace(buildGuard, "      - uses", "      - background: true\n        uses", 1), "    needs: build\n    if: failure()\n", "", "", baseStep},
		{"failure() after a build in an environment", strings.Replace(buildGuard, "    runs-on:", "    environment: prod\n    runs-on:", 1), "    needs: build\n    if: failure()\n", "", "", baseMayStep},
		{"failure() and the result of another job", "  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n" + strings.Replace(buildGuard, "  build:", "  build2:", 1), "    needs: [build, build2]\n    if: failure() && needs.build.result == 'failure'\n", "", "", baseMayStep},
		// needs.<id>.result of a job that the job depends on directly: success when every job it depends on succeeded, failure for a job that fails; an if with no status function is read only when every job it depends on succeeded
		{"the result of build is failure, with no status function", build, "    needs: build\n    if: needs.build.result == 'failure'\n", "", "", nil},
		{"the result of build is skipped, with no status function", build, "    needs: build\n    if: needs.build.result == 'skipped'\n", "", "", nil},
		{"the result of build with continue-on-error is failure", strings.Replace(build, "    runs-on:", "    continue-on-error: true\n    runs-on:", 1), "    needs: build\n    if: needs.build.result == 'failure'\n", "", "", nil},
		{"always() and the result of a test that runs the code is failure", testHead, "    needs: test\n    if: ${{ always() && needs.test.result == 'failure' }}\n", "", "", baseStep},
		{"always() and the result of build is failure", build, "    needs: build\n    if: ${{ always() && needs.build.result == 'failure' }}\n", "", "", baseMayStep},
		// a job that the job depends on and that may be skipped: its result is not known, and the job runs as main reads it
		{"always() and the result of a build that may be skipped is skipped", "  build:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", "    needs: build\n    if: ${{ always() && needs.build.result == 'skipped' }}\n", "", "", baseStep},
		{"a gate whose if is the result of build after the label", build + "  gate:\n    needs: build\n    if: needs.build.result == 'failure'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", "    needs: gate\n", "", "", nil},
		// needs.*.result, the results of the jobs that the job depends on directly: success for each in an if with no status function, not known in an if that calls one
		{"the results include failure, with no status function", build, "    needs: build\n    if: contains(needs.*.result, 'failure')\n", "", "", nil},
		{"the results include failure, with no status function, needs as a list", build, "    needs: [build]\n    if: contains(needs.*.result, 'failure')\n", "", "", nil},
		{"success() and the result of build is failure", build, "    needs: build\n    if: ${{ success() && needs.build.result == 'failure' }}\n", "", "", nil},
		{"the results by an index of a star include failure, with no status function", build, "    needs: build\n    if: contains(needs[*].result, 'failure')\n", "", "", nil},
		{"the results include failure, with a need that is not a job", build, "    needs: [build, gone]\n    if: contains(needs.*.result, 'failure')\n", "", "", nil},
		{"the result of a build that may be skipped is failure, with no status function", "  build:\n    if: vars.BUILD == 'true'\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", "    needs: build\n    if: needs.build.result == 'failure'\n", "", "", nil},
		{"always() and the results include skipped after a test that runs the code", testHead + "  build:\n    needs: test\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", "    needs: build\n    if: ${{ always() && contains(needs.*.result, 'skipped') }}\n", "", "", baseStep},
		// a job whose if is true only when success() is true is skipped when a job it needs is skipped (attacker.NeedJobs)
		{"success() and the event after a build that never runs", "  build:\n    if: false\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n", "    needs: build\n    if: success() && github.event_name == 'pull_request_target'\n", "", "", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := strings.Replace(labelerWorkflow("v5", c.before, pat), "jobs:\n  label:\n", "jobs:\n"+c.jobs+"  label:\n"+c.job, 1)
			if c.cond != "" {
				src = withIf(src, "actions/labeler@v5", c.cond)
			}
			checkSteps(t, stepsIn(t, src, defaultRoot()), c.want)
		})
	}
}

// TestStepJobAncestors: the jobs that a job depends on are read once each,
// so a ladder of jobs that each depend on both jobs of the rung before is
// read in time that grows with the jobs and the needs, not with the paths
// through the needs (2 to the power of the rungs).
func TestStepJobAncestors(t *testing.T) {
	const rungs = 25
	var b strings.Builder
	for i := range rungs {
		for _, side := range []string{"a", "b"} {
			b.WriteString(fmt.Sprintf("  j%d%s:\n", i, side))
			if i > 0 {
				b.WriteString(fmt.Sprintf("    needs: [j%da, j%db]\n", i-1, i-1))
			}
			b.WriteString("    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n")
		}
	}
	job := fmt.Sprintf("    needs: [j%da, j%db]\n    if: failure()\n", rungs-1, rungs-1)
	src := strings.Replace(labelerWorkflow("v5", "", "          repo-token: ${{ secrets.PAT }}\n"), "jobs:\n  label:\n", "jobs:\n"+b.String()+"  label:\n"+job, 1)
	checkSteps(t, stepsIn(t, src, defaultRoot()), baseMayStep)
}

func TestStepNeedsAndFallback(t *testing.T) {
	needs := strings.Replace(labelerWorkflow("v5", "", "          repo-token: ${{ secrets.PAT }}\n"), "jobs:\n  label:\n", "jobs:\n  gate:\n    if: github.event.pull_request.head.repo.full_name == github.repository\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n  label:\n    needs: gate\n", 1)
	if got := stepsIn(t, needs, defaultRoot()); len(got) != 0 {
		t.Errorf("a labeler that needs a job the attacker does not pass: got %v, want no step", got)
	}
	for _, cond := range []string{"${{ always () }}", "ALWAYS()"} {
		spaced := strings.Replace(needs, "    needs: gate\n", "    needs: gate\n    if: \""+cond+"\"\n", 1)
		if got := stepsIn(t, spaced, defaultRoot()); len(got) != 1 {
			t.Errorf("%s: a labeler whose if calls a status function runs when the job it needs is skipped: got %d steps, want 1", cond, len(got))
		}
	}
	text := strings.Replace(needs, "    needs: gate\n", "    needs: gate\n    if: \"${{ !contains(github.event.pull_request.title, 'always()') }}\"\n", 1)
	if got := stepsIn(t, text, defaultRoot()); len(got) != 0 {
		t.Errorf("a string with always() is no status function: got %d steps, want none", len(got))
	}
	fallback := labelerWorkflow("v5", "", "          repo-token: ${{ secrets.PAT || github.token }}\n")
	if got := stepsIn(t, fallback, defaultRoot()); len(got) != 1 || !got[0].Unknown {
		t.Errorf("a secret that falls back to the GITHUB_TOKEN: got %+v, want Unknown", got)
	}
}

// TestStepCheckoutInTable: the ifs of the checkouts before actions/labeler
// are read in the same attacker run table as the steps of actions/labeler:
// a checkout that only a member passes runs
// when the attacker gets past that check.
func TestStepCheckoutInTable(t *testing.T) {
	head := "      - uses: actions/checkout@v4.2.2\n        if: github.event.pull_request.author_association == 'MEMBER'\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n"
	src := labelerWorkflow("v5", head, "          repo-token: ${{ secrets.PAT }}\n")
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	name := facts.MustCleanInputPath(".github/workflows/labeler.yml")
	none := func(facts.InputPath) bool { return false }
	if got := stepsOf(attacker.Outsider, name, w, defaultRoot(), none); len(got) != 1 || got[0].AnyLabel {
		t.Errorf("an outsider: got %+v, want the configuration of the base", got)
	}
	member := attacker.TableOf(analysis.BarrierPasses{}.With(analysis.BarrierAssociationMember))
	if got := stepsOf(member, name, w, defaultRoot(), none); len(got) != 1 || !got[0].AnyLabel {
		t.Errorf("an attacker who is a member: got %+v, want AnyLabel", got)
	}
}

// TestConfigOnBranchCount: each step that runs the code of the attacker
// adds one reading, where the attacker makes that step fail; a job that
// has failed does not branch again, so n such steps give n + 1 readings.
func TestConfigOnBranchCount(t *testing.T) {
	const n = 12
	var b strings.Builder
	b.WriteString("      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: pr\n")
	for i := range n {
		b.WriteString("      - if: always()\n        run: ./pr/step" + string(rune('a'+i)) + ".sh\n")
	}
	src := withIf(labelerWorkflow("v5", b.String(), "          repo-token: ${{ secrets.PAT }}\n"), "actions/labeler@v5", "failure()")
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	at := attacker.Outsider
	sites := prcode.AnalyzeIn(taint.NewCallersIn(calls.New(nil, false, false, facts.Repo{}), at), calls.Node{}, w, nil, nil)
	steps := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items
	s := steps[len(steps)-1]
	e := taint.EventsOn(w, attackerEvents)[0]
	got := configOn(facts.MustCleanInputPath(".github/labeler.yml"), s, steps[:len(steps)-1], sites, at, e, nil, nil)
	if len(got) != n+1 {
		t.Errorf("got %d readings, want %d", len(got), n+1)
	}
}

// TestConfigOnBranchCountMay: a checkout with failure() that writes the
// configuration splits off one reading that may not run, and a step that
// runs the code of the attacker adds one reading where the attacker makes
// the step fail; neither branches again inside the other, so n pairs of
// them give at most 2n + 1 readings.
func TestConfigOnBranchCountMay(t *testing.T) {
	const n = 30
	var b strings.Builder
	b.WriteString("      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: pr\n")
	for i := range n {
		b.WriteString("      - uses: actions/checkout@v4.2.2\n        if: failure()\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: .github\n")
		b.WriteString(fmt.Sprintf("      - run: ./pr/build%d.sh\n", i))
	}
	src := withIf(labelerWorkflow("v5", b.String(), "          repo-token: ${{ secrets.PAT }}\n"), "actions/labeler@v5", "failure()")
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	at := attacker.Outsider
	sites := prcode.AnalyzeIn(taint.NewCallersIn(calls.New(nil, false, false, facts.Repo{}), at), calls.Node{}, w, nil, nil)
	steps := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items
	e := taint.EventsOn(w, attackerEvents)[0]
	got := configOn(facts.MustCleanInputPath(".github/labeler.yml"), steps[len(steps)-1], steps[:len(steps)-1], sites, at, e, nil, nil)
	if len(got) > 2*n+1 {
		t.Errorf("got %d readings, want at most %d", len(got), 2*n+1)
	}
}

// TestConfigOnBranchCountBackground: a step that runs the code of the
// attacker in the background fails the job only at the wait-all, so a
// checkout with failure() after the step is still read in a job whose
// state is not known; a reading where the attacker makes the step fail
// does not split off more readings, so n pairs give at most 2n + 1
// readings.
func TestConfigOnBranchCountBackground(t *testing.T) {
	const n = 30
	var b strings.Builder
	b.WriteString("      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: pr\n")
	for i := range n {
		b.WriteString(fmt.Sprintf("      - background: true\n        run: ./pr/build%d.sh\n", i))
		b.WriteString("      - uses: actions/checkout@v4.2.2\n        if: failure()\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: .github\n")
	}
	b.WriteString("      - wait-all: true\n")
	src := withIf(labelerWorkflow("v5", b.String(), "          repo-token: ${{ secrets.PAT }}\n"), "actions/labeler@v5", "failure()")
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	at := attacker.Outsider
	sites := prcode.AnalyzeIn(taint.NewCallersIn(calls.New(nil, false, false, facts.Repo{}), at), calls.Node{}, w, nil, nil)
	steps := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items
	e := taint.EventsOn(w, attackerEvents)[0]
	got := configOn(facts.MustCleanInputPath(".github/labeler.yml"), steps[len(steps)-1], steps[:len(steps)-1], sites, at, e, nil, nil)
	if len(got) > 2*n+1 {
		t.Errorf("got %d readings, want at most %d", len(got), 2*n+1)
	}
}

// TestConfigOnBranchCountKnownFailure: a background checkout that fails
// fails the job only at the wait-all, so a failure that reaches s is known
// from the start; each step that runs the code of the attacker before the
// wait-all still adds one reading where the attacker makes the step fail
// earlier, and a checkout with failure() splits off one reading that may
// not run, so n pairs give at most 2n + 1 readings.
func TestConfigOnBranchCountKnownFailure(t *testing.T) {
	const n = 30
	var b strings.Builder
	b.WriteString("      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: pr\n")
	b.WriteString("      - background: true\n        uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")
	for i := range n {
		b.WriteString(fmt.Sprintf("      - run: ./pr/build%d.sh\n", i))
		b.WriteString("      - uses: actions/checkout@v4.2.2\n        if: failure()\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          allow-unsafe-pr-checkout: true\n          path: .github\n")
	}
	b.WriteString("      - wait-all: true\n")
	src := withIf(labelerWorkflow("v5", b.String(), "          repo-token: ${{ secrets.PAT }}\n"), "actions/labeler@v5", "failure()")
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	at := attacker.Outsider
	sites := prcode.AnalyzeIn(taint.NewCallersIn(calls.New(nil, false, false, facts.Repo{}), at), calls.Node{}, w, nil, nil)
	steps := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items
	e := taint.EventsOn(w, attackerEvents)[0]
	got := configOn(facts.MustCleanInputPath(".github/labeler.yml"), steps[len(steps)-1], steps[:len(steps)-1], sites, at, e, nil, nil)
	if len(got) > 2*n+1 {
		t.Errorf("got %d readings, want at most %d", len(got), 2*n+1)
	}
	if !slices.Contains(got, readingWritten) {
		t.Errorf("got %v, want a reading where the attacker writes the configuration and s runs", got)
	}
}

package rules

import (
	"fmt"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// dispatchReport runs rule alone on the workflows files (name to text), and
// gives the kinds of its findings and of its inconclusive places.
func dispatchReport(t *testing.T, rule lint.Rule, files map[string]string) (findings []lint.FindingKindID, places []string) {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, text := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(text)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	rep := runAlone(t, rule, in)
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		places = append(places, g.InconclusiveKind.String())
	}
	return kindsOf(rep), places
}

// TestCheckoutDispatch: untrusted-checkout reports an input of
// workflow_dispatch in a checkout's ref as input-dispatch before it reads
// the approval, which a run of workflow_dispatch does not have, and
// untrusted-checkout-toctou leaves the input to it.
func TestCheckoutDispatch(t *testing.T) {
	const steps = "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v1\n        with:\n          ref: ${{ %s }}\n      - run: npm ci\n"
	job := func(on, extra, ref string) map[string]string {
		return map[string]string{".github/workflows/w.yml": "on: " + on + "\njobs:\n  a:\n" + extra + fmt.Sprintf(steps, ref)}
	}
	called := "on:\n  workflow_call:\n    inputs: {ref: {type: string}}\n  workflow_dispatch:\n    inputs: {ref: {}}\njobs:\n  a:\n" + fmt.Sprintf(steps, "inputs.ref")
	caller := "on: pull_request_target\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      ref: ${{ github.event.pull_request.head.sha }}\n"
	for _, c := range []struct {
		name     string
		rule     lint.Rule
		files    map[string]string
		findings []lint.FindingKindID
		places   []string
	}{
		{"label and dispatch", UntrustedCheckout, job("{pull_request_target: {types: [labeled]}, workflow_dispatch: {inputs: {ref: {}}}}", "", "inputs.ref"), nil, []string{"input-dispatch"}},
		{"label and dispatch, toctou", UntrustedCheckoutToctou, job("{pull_request_target: {types: [labeled]}, workflow_dispatch: {inputs: {ref: {}}}}", "", "inputs.ref"), nil, nil},
		{"environment", UntrustedCheckout, job("{workflow_dispatch: {inputs: {ref: {}}}}", "    environment: prod\n", "inputs.ref"), nil, []string{"input-dispatch"}},
		{"environment, toctou", UntrustedCheckoutToctou, job("{workflow_dispatch: {inputs: {ref: {}}}}", "    environment: prod\n", "inputs.ref"), nil, nil},
		{"mixed", UntrustedCheckout, job("{pull_request_target: {}, workflow_dispatch: {inputs: {ref: {}}}}", "", "inputs.ref || github.event.pull_request.head.sha"), []lint.FindingKindID{kindUntrustedCheckoutExecuted}, []string{"input-dispatch"}},
		{"called from a pull request", UntrustedCheckout, map[string]string{".github/workflows/called.yml": called, ".github/workflows/caller.yml": caller}, nil, []string{"checkout-ref-unknown", "input-dispatch"}},
	} {
		findings, places := dispatchReport(t, c.rule, c.files)
		slices.Sort(places)
		if !slices.Equal(findings, c.findings) || !slices.Equal(places, c.places) {
			t.Errorf("%s: findings %v, places %v; want %v, %v", c.name, findings, places, c.findings, c.places)
		}
	}
}

// TestDownloadDispatch: artifact-poisoning reports an input of
// workflow_dispatch that chooses the run of a download as input-dispatch,
// before it reads the approval.
func TestDownloadDispatch(t *testing.T) {
	const steps = "    runs-on: ubuntu-latest\n    steps:\n      - uses: dawidd6/action-download-artifact@v6\n        with: {run_id: '${{ %s }}', name: out, path: out}\n      - run: ./out/publish.sh\n"
	job := func(on, extra, run string) map[string]string {
		return map[string]string{".github/workflows/w.yml": "on: " + on + "\njobs:\n  a:\n" + extra + fmt.Sprintf(steps, run)}
	}
	called := "on:\n  workflow_call:\n    inputs: {run: {type: string}}\n  workflow_dispatch:\n    inputs: {run: {}}\njobs:\n  a:\n" + fmt.Sprintf(steps, "inputs.run")
	caller := "on: pull_request_target\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      run: ${{ github.event.pull_request.number }}\n"
	for _, c := range []struct {
		name     string
		files    map[string]string
		places   []string
		findings []lint.FindingKindID
	}{
		// on pull_request_target the input is empty, and the release
		// searches the runs of the workflow, which takes the run of a
		// review of a pull request from a fork
		{"label and dispatch", job("{pull_request_target: {types: [labeled]}, workflow_dispatch: {inputs: {run: {}}}}", "", "inputs.run"), []string{"input-dispatch"}, []lint.FindingKindID{kindArtifactPoisoningExecuted}},
		{"environment", job("{workflow_dispatch: {inputs: {run: {}}}}", "    environment: prod\n", "inputs.run"), []string{"input-dispatch"}, nil},
		// the caller gives the input on its events: no search
		{"called from a pull request", map[string]string{".github/workflows/called.yml": called, ".github/workflows/caller.yml": caller}, []string{"download-input-unknown", "input-dispatch"}, nil},
	} {
		findings, places := dispatchReport(t, ArtifactPoisoning, c.files)
		slices.Sort(places)
		if !slices.Equal(findings, c.findings) || !slices.Equal(places, c.places) {
			t.Errorf("%s: findings %v, places %v; want %v, %v", c.name, findings, places, c.findings, c.places)
		}
	}
}

// TestAgentDispatch: the rules of an agent's step report input-dispatch for
// a prompt with an input of workflow_dispatch on a run of
// workflow_dispatch, and reach-unknown as before for a prompt without one
// and for repository_dispatch.
func TestAgentDispatch(t *testing.T) {
	// the sandbox danger-full-access for unsafe-sandbox, the default for
	// execution-order, which counts npm test after it
	const step = "jobs:\n  a:\n    runs-on: ubuntu-latest\n%s    steps:\n      - uses: actions/checkout@v4\n      - uses: openai/codex-action@v1\n        with:\n          openai-api-key: ${{ secrets.OPENAI_API_KEY }}\n          prompt: %q\n%s      - run: npm test\n"
	sandbox := ""
	wf := func(on, extra, prompt string) map[string]string {
		return map[string]string{".github/workflows/w.yml": "on: " + on + "\n" + fmt.Sprintf(step, extra, prompt, sandbox)}
	}
	dispatch := "{workflow_dispatch: {inputs: {task: {}}}}"
	for _, rule := range []lint.Rule{AIActionUnsafeSandbox, AIActionExecutionOrder} {
		sandbox = ""
		if rule == AIActionUnsafeSandbox {
			sandbox = "          sandbox: danger-full-access\n"
		}
		for _, c := range []struct {
			name  string
			files map[string]string
			want  string
		}{
			{"input", wf(dispatch, "", "Do ${{ inputs.task }}"), "input-dispatch"},
			{"event input", wf(dispatch, "", "Do ${{ github.event.inputs.task }}"), "input-dispatch"},
			{"no input", wf(dispatch, "", "Fix the open issues"), "reach-unknown"},
			{"job if", wf(dispatch, "    if: github.event_name != 'workflow_dispatch'\n", "Do ${{ inputs.task }}"), "reach-unknown"},
			{"repository_dispatch", wf("repository_dispatch", "", "Do ${{ github.event.client_payload.task }}"), "reach-unknown"},
		} {
			findings, places := dispatchReport(t, rule, c.files)
			if len(findings) != 0 || len(places) == 0 || slices.ContainsFunc(places, func(p string) bool { return p != c.want }) {
				t.Errorf("%s, %s: findings %v, places %v; want %s", c.name, rule.Meta().ID, findings, places, c.want)
			}
		}
	}
	sandbox = ""
	// prompt-injection: input-dispatch on a run of workflow_dispatch only
	for _, c := range []struct {
		name   string
		files  map[string]string
		places []string
	}{
		{"input", wf(dispatch, "", "Do ${{ inputs.task }}"), []string{"input-dispatch"}},
		{"job if", wf(dispatch, "    if: github.event_name != 'workflow_dispatch'\n", "Do ${{ inputs.task }}"), nil},
	} {
		findings, places := dispatchReport(t, AIActionPromptInjection, c.files)
		if len(findings) != 0 || !slices.Equal(places, c.places) {
			t.Errorf("prompt-injection, %s: findings %v, places %v; want %v", c.name, findings, places, c.places)
		}
	}
}

// TestCacheDispatch: cache-poisoning reports, in a job that can save on
// workflow_dispatch, a key, a path or a checkout that an input of
// workflow_dispatch decides as input-dispatch, before it reads the
// approval; a job whose cache-mode saves nothing, or whose values no input
// decides, has none.
func TestCacheDispatch(t *testing.T) {
	const dispatch = "on: {workflow_dispatch: {inputs: {x: {}}}}\n"
	wf := func(src string) map[string]string { return map[string]string{".github/workflows/w.yml": src} }
	const save = "      - uses: actions/cache/save@v4\n        with: {path: build, key: 'build-${{ inputs.x }}'}\n"
	const checkout = "      - uses: actions/checkout@v4\n        with: {ref: '${{ inputs.x }}'}\n"
	for _, c := range []struct {
		name, src string
		places    []string
		findings  []lint.FindingKindID
	}{
		{"key", dispatch + "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + save, []string{"input-dispatch"}, nil},
		{"cache-mode read", dispatch + "jobs:\n  j:\n    runs-on: ubuntu-latest\n    cache-mode: read\n    steps:\n" + save, nil, nil},
		{"job if", dispatch + "jobs:\n  j:\n    runs-on: ubuntu-latest\n    if: github.event_name != 'workflow_dispatch'\n    steps:\n" + save, nil, nil},
		{"saved checkout", dispatch + "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + checkout + "      - uses: actions/cache/save@v4\n        with: {path: ., key: tree}\n", []string{"input-dispatch"}, nil},
		{"code run", dispatch + "jobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + checkout + "      - run: npm ci\n", []string{"input-dispatch"}, nil},
		{"checkout, cache-mode read", dispatch + "jobs:\n  j:\n    runs-on: ubuntu-latest\n    cache-mode: read\n    steps:\n" + checkout + "      - run: npm ci\n", nil, nil},
		{"label and dispatch", "on: {pull_request_target: {types: [labeled]}, workflow_dispatch: {inputs: {x: {}}}}\ncache-mode: write\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + save, []string{"input-dispatch"}, nil},
		{"issues and dispatch", "on: {issues: {}, workflow_dispatch: {inputs: {x: {}}}}\ncache-mode: write\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + save, []string{"input-dispatch"}, []lint.FindingKindID{kindCachePoisoningWritableJob}},
	} {
		findings, places := dispatchReport(t, CachePoisoning, wf(c.src))
		if !slices.Equal(findings, c.findings) || !slices.Equal(places, c.places) {
			t.Errorf("%s: findings %v, places %v; want %v, %v", c.name, findings, places, c.findings, c.places)
		}
	}
}

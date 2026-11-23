package rules

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// The forms in this file are reports against the upstream sisakulint: each
// is a minimal workflow on which the upstream linter reported a finding that
// does not hold, missed a form that it should report, or gave a fix that
// broke the workflow. The rules here read
// the form the other way, and the tests keep them from taking up the
// upstream reading. Each row says what the upstream linter did and why the
// rules here do otherwise.

// runEveryRule runs every rule and every quality rule on files.
func runEveryRule(t *testing.T, files map[string]string, r facts.Resolver) lint.Report {
	t.Helper()
	fsys := fstest.MapFS{}
	for n, s := range files {
		fsys[n] = &fstest.MapFile{Data: []byte(s)}
	}
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		r = &refs{}
	}
	rep := lint.Run(context.Background(), in, reg, r)
	for _, e := range rep.Errors {
		t.Errorf("internal error: %+v", e)
	}
	return rep
}

// reportedKinds is the IDs of the kinds of the findings and of the quality
// findings of rep.
func reportedKinds(rep lint.Report) []string {
	var ks []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		ks = append(ks, f.Args.KindID().String())
	}
	for _, f := range rep.QualityFindings {
		ks = append(ks, f.Args.KindID().String())
	}
	return ks
}

const upstreamSHA = "0123456789abcdef0123456789abcdef01234567"

func TestUpstreamDefectForms(t *testing.T) {
	wf := func(src string) map[string]string { return map[string]string{".github/workflows/w.yml": src} }
	for _, c := range []struct {
		name   string
		files  map[string]string
		want   []string // kinds that must be reported
		absent []string // kinds, or rules (an ID without a dot: every kind of the rule), that must not be reported
	}{
		// upstream: critical, for a checkout and a relative destination. Here
		// only a download of the artifact of an attacker's run is reported, and
		// the artifact of a job of the same run is not one.
		{"an artifact of a needs job of the same run", wf(`on: push
jobs:
  produce:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@` + upstreamSHA + `
        with: {name: data, path: results/*.json}
  consume:
    needs: produce
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + upstreamSHA + `
      - uses: actions/download-artifact@` + upstreamSHA + `
        with: {name: data, path: results}
      - run: jq . results/result.json
`), nil, []string{"artifact-poisoning"}},
		// upstream: a similar account name passes the exact comparison. On
		// pull_request a run of Dependabot gets no more than the run of the
		// author of the pull request, so nothing is reported.
		{"an exact comparison with dependabot[bot] on pull_request", wf(`on: pull_request
jobs:
  bot:
    if: github.actor == 'dependabot[bot]'
    runs-on: ubuntu-latest
    steps:
      - run: echo trusted
`), nil, []string{"bot-conditions"}},
		// upstream: pull requests restore the cache. A job that only push and
		// workflow_dispatch run is not a writer of an attacker.
		{"a cache on push and workflow_dispatch only", wf(`on:
  push: {branches: [main]}
  workflow_dispatch:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@` + upstreamSHA + `
        with: {cache: npm}
`), nil, upstreamCachePoisoningKinds},
		// upstream: pull requests write the cache though the if keeps the job
		// to push. The cache of a run of pull_request is in the scope of the
		// merge ref, which the default branch does not read.
		{"a cache of a job kept to push", wf(`on: [push, pull_request]
jobs:
  cache:
    if: github.event_name == 'push'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@` + upstreamSHA + `
        with: {path: .cache, key: fixed}
`), nil, upstreamCachePoisoningKinds},
		// upstream: the cache of the pull_request workflow poisons the one of
		// push on the default branch, under the same key.
		{"one key in a pull_request workflow and a push workflow", map[string]string{
			".github/workflows/pr.yml":   "on: pull_request\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache@" + upstreamSHA + "\n        with: {path: .cache, key: fixed}\n",
			".github/workflows/push.yml": "on: {push: {branches: [main]}}\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache@" + upstreamSHA + "\n        with: {path: .cache, key: fixed}\n",
		}, nil, upstreamCachePoisoningKinds},
		// upstream: the workflow has no mitigation, though permissions is
		// empty. The job has no token that writes and reads no secret.
		{"permissions: {} on issue_comment", wf(`on: issue_comment
permissions: {}
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - run: echo read-only
`), nil, []string{"dangerous-triggers"}},
		// upstream: a reusable workflow of another repository is not a
		// dependency that Dependabot updates.
		{"a reusable workflow of another repository and no Dependabot", wf(`on: push
jobs:
  call:
    uses: OWNER/WORKFLOWS/.github/workflows/callee.yml@` + upstreamSHA + `
`), []string{"dependabot-github-actions.no-update-tool"}, nil},
		// upstream: a step under if: ${{ false }} is missing a timeout. The
		// quality rule reads the timeout-minutes of the job only.
		{"a step that never runs in a job with a timeout", wf(`on: push
jobs:
  test:
    timeout-minutes: 30
    runs-on: ubuntu-latest
    steps:
      - if: ${{ false }}
        run: sleep 600
`), nil, []string{"missing-timeout-minutes"}},
		// upstream: the folded if is a string, always true. A folded scalar
		// without ${{ }} is an expression, as one line is.
		{"a folded if of two lines", wf(`on: push
jobs:
  test:
    if: >-
      github.event_name == 'push' &&
      github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - run: echo ok
`), nil, []string{"cond"}},
		// upstream: the composite action of the repository is not read. The
		// rules read every action.yml, and the inputs its caller gives.
		{"a composite action of the repository", map[string]string{
			".github/workflows/w.yml":           "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: ./.github/actions/helper\n        with: {value: \"${{ github.event.issue.title }}\"}\n",
			".github/actions/helper/action.yml": "inputs: {value: {}}\nruns:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ${{ inputs.value }}\n",
		}, []string{"code-injection.controlled"}, nil},
		// upstream: secret-in-log, for expansions that print no part of the
		// secret, for a print sent to a file, and for the result of a command
		// given the secret as an argument.
		{"an expansion that prints whether the secret is set", wf(`on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env: {TOKEN: "${{ secrets.EXAMPLE_TOKEN }}"}
        run: echo "configured=${TOKEN:+YES}"
`), nil, upstreamSecretInLogKinds},
		{"a print of the secret sent to a file", wf(`on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env: {TOKEN: "${{ secrets.EXAMPLE_TOKEN }}"}
        run: printf '%s' "$TOKEN" > credential.txt
`), nil, upstreamSecretInLogKinds},
		{"a field of the result of a command given the secret", wf(`on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env: {RESOURCE_ID: "${{ secrets.EXAMPLE_TOKEN }}"}
        run: |
          STATUS=$(example-cli get --resource "$RESOURCE_ID" --query status)
          echo "status=$STATUS"
`), nil, upstreamSecretInLogKinds},
		// upstream: $/ is an external owner/repository@ref. It is the
		// repository of the workflow at the commit that runs.
		{"a $/ action", map[string]string{
			".github/workflows/w.yml":           "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: $/.github/actions/helper\n",
			".github/actions/helper/action.yml": "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo ok\n",
		}, nil, []string{"commit-sha"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := runEveryRule(t, c.files, nil)
			for _, in := range rep.Inputs {
				if in.State != lint.InputStateRead || len(in.Diagnostics) != 0 {
					t.Errorf("%s: state %v, diagnostics %+v; want read without any", in.Name, in.State, in.Diagnostics)
				}
			}
			got := reportedKinds(rep)
			for _, k := range c.want {
				if !slices.Contains(got, k) {
					t.Errorf("%s is not reported; got %v", k, got)
				}
			}
			for _, k := range c.absent {
				if slices.ContainsFunc(got, func(g string) bool { return g == k || !strings.Contains(k, ".") && strings.HasPrefix(g, k+".") }) {
					t.Errorf("%s is reported; got %v", k, got)
				}
			}
		})
	}
}

var (
	upstreamCachePoisoningKinds = []string{"cache-poisoning"}
	upstreamSecretInLogKinds    = []string{"secret-in-log"}
)

// TestUpstreamDefectInputs: inputs that the upstream linter read wrongly are
// read as GitHub reads them, with the diagnostics GitHub gives.
func TestUpstreamDefectInputs(t *testing.T) {
	for _, c := range []struct {
		name    string
		files   map[string]string
		invalid bool
		absent  []string
	}{
		// upstream: the fix phase alone refused on: workflow_call as a scalar.
		{"on: workflow_call as a scalar", map[string]string{
			".github/workflows/caller.yml": "on: push\njobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n",
			".github/workflows/callee.yml": "on: workflow_call\njobs:\n  test: {runs-on: ubuntu-latest, steps: [{run: echo ok}]}\n",
		}, false, nil},
		// upstream: a quoted 'true' given to an input of type string is a
		// boolean. YAML reads a quoted scalar as a string.
		{"a quoted true given to a string input", map[string]string{
			".github/workflows/caller.yml": "on: push\njobs:\n  call:\n    uses: ./.github/workflows/callee.yml\n    with: {value: 'true'}\n",
			".github/workflows/callee.yml": "on:\n  workflow_call:\n    inputs:\n      value: {type: string}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps: [{run: echo ok}]\n",
		}, false, nil},
		// upstream: a file of only a comment gets a finding of permissions as
		// well as the syntax error. The file is invalid, and no rule reports
		// on it.
		{"a workflow of only a comment", map[string]string{
			".github/workflows/w.yml": "# disabled\n",
		}, true, []string{"permissions.unwritten", "permissions.write-all"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep := runEveryRule(t, c.files, nil)
			for _, in := range rep.Inputs {
				if bad := in.State == lint.InputStateInvalid; bad != c.invalid {
					t.Errorf("%s: invalid %v, want %v (diagnostics %+v)", in.Name, bad, c.invalid, in.Diagnostics)
				}
				if !c.invalid && len(in.Diagnostics) != 0 {
					t.Errorf("%s: diagnostics %+v", in.Name, in.Diagnostics)
				}
			}
			got := reportedKinds(rep)
			for _, k := range c.absent {
				if slices.Contains(got, k) {
					t.Errorf("%s is reported; got %v", k, got)
				}
			}
		})
	}
}

// TestUpstreamDefectNoFix: the upstream fix moved a value of a word list of
// for to env and wrote the variable outside quotes, where the shell splits
// it into words. The rule reports the place and gives no fix: outside
// quotes, the words of for and select are the list the loop goes over, and
// one quoted word, which the fix would write, means another thing.
func TestUpstreamDefectNoFix(t *testing.T) {
	src := injStep(`for file in ${{ github.event.pull_request.title }}; do echo "$file"; done`)
	src = strings.Replace(src, "on: issues", "on: pull_request_target", 1)
	got, notes := injFixed(t, src, lint.SafetyReview)
	if got != src {
		t.Errorf("changed:\n%s", got)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "cannot tell") {
		t.Errorf("notes %v, want one that the rule cannot tell how the shell reads the place", notes)
	}
}

// definitions answers workflow.definition for the refs of one path, and
// records the refs asked.
type definitions struct {
	mu      sync.Mutex
	content map[string]string // by ref
	asked   []string
}

func (d *definitions) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	w, ok := q.(facts.WorkflowDefinition)
	if !ok {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not asked"}
	}
	d.mu.Lock()
	d.asked = append(d.asked, w.Ref)
	d.mu.Unlock()
	src, ok := d.content[w.Ref]
	if !ok {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "no such ref"}
	}
	sha, _ := facts.ParseSHA(w.Ref)
	v, err := json.Marshal(facts.WorkflowFile{Commit: sha, Content: src})
	if err != nil {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: err.Error()}
	}
	return facts.RawAnswer{State: facts.StateFound, Value: v}
}

// TestUpstreamDefectTwoRefs: the upstream recursive scan read one path of a
// reusable workflow once, whatever its ref. Each ref of the path is asked,
// and the answer of each ref is read: each of the two contents names an
// action of its own by a tag, and commit-sha reports both.
func TestUpstreamDefectTwoRefs(t *testing.T) {
	a, b := strings.Repeat("1", 40), strings.Repeat("2", 40)
	d := &definitions{content: map[string]string{
		a: "on: workflow_call\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example/first@v1\n",
		b: "on: workflow_call\njobs:\n  c:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: example/second@v2\n",
	}}
	rep := runEveryRule(t, map[string]string{".github/workflows/w.yml": "on: push\njobs:\n  first:\n    uses: owner/workflows/.github/workflows/check.yml@" + a + "\n  second:\n    uses: owner/workflows/.github/workflows/check.yml@" + b + "\n"}, d)
	for _, ref := range []string{a, b} {
		if !slices.Contains(d.asked, ref) {
			t.Errorf("the ref %s is not asked; asked %v", ref, d.asked)
		}
	}
	var unpinned []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Args.KindID().String() == "commit-sha.unpinned" {
			unpinned = append(unpinned, f.Detected())
		}
	}
	for _, uses := range []string{"example/first@v1", "example/second@v2"} {
		if !slices.ContainsFunc(unpinned, func(d string) bool { return strings.Contains(d, uses) }) {
			t.Errorf("no commit-sha.unpinned for %s; got %v", uses, unpinned)
		}
	}
}

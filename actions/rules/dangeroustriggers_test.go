package rules

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// exposureFacts answers the facts of the rules of jobs: whether the default
// token writes, whether an environment approves, whether the repository is
// public.
type exposureFacts struct{ writes, protected, public *bool }

func (e exposureFacts) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	var v *bool
	switch q.(type) {
	case facts.RepoDefaultTokenWrite:
		v = e.writes
	case facts.RepoEnvironmentProtected:
		v = e.protected
	case facts.RepoPublic:
		v = e.public
	}
	if v == nil {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
	}
	b, _ := json.Marshal(*v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

const (
	writeCond = `{"query":{"kind":"repo.default-token-write"},"eq":true}`
	envCond   = `{"query":{"kind":"repo.environment-protected","environment":"production"},"eq":false}`
	readKey   = "      - run: ./deploy\n        env: {K: '${{ secrets.DEPLOY_KEY }}'}\n"
)

func exposedJob(on, perms, extra, steps string) string {
	return "on: " + on + "\n" + perms + "jobs:\n  a:\n    runs-on: ubuntu-latest\n" + extra + "    steps:\n" + steps
}

// TestDangerousTriggers: the kinds of dangerous-triggers by the event and
// the permissions.
func TestDangerousTriggers(t *testing.T) {
	type want struct{ kind, cond string }
	for _, c := range []struct {
		name, src string
		want      []want
	}{
		{"written write", exposedJob("issues", "permissions: {issues: write}\n", "", "      - run: echo\n"), []want{{"dangerous-triggers.token-write", ""}}},
		{"unwritten", exposedJob("issues", "", "", "      - run: echo\n"), []want{{"dangerous-triggers.token-write", writeCond}}},
		{"read only", exposedJob("issues", "permissions: {contents: read}\n", "", "      - run: echo\n"), nil},
		{"secrets", exposedJob("issue_comment", "permissions: {}\n", "", readKey), []want{{"dangerous-triggers.secrets", ""}}},
		{"both", exposedJob("pull_request_target", "permissions: write-all\n", "", readKey), []want{{"dangerous-triggers.token-write", ""}, {"dangerous-triggers.secrets", ""}}},
		{"environment", exposedJob("issues", "", "    environment: production\n", readKey),
			[]want{{"dangerous-triggers.token-write", `{"all":[` + envCond + `,` + writeCond + `]}`}, {"dangerous-triggers.secrets", envCond}}},
		{"label", exposedJob("{pull_request_target: {types: [labeled]}}", "permissions: write-all\n", "", readKey), nil},
		{"push", exposedJob("push", "permissions: write-all\n", "", readKey), nil},
		{"pull_request", exposedJob("pull_request", "permissions: write-all\n", "", readKey), nil},
		{"if push", exposedJob("[push, issues]", "permissions: write-all\n", "    if: github.event_name == 'push'\n", readKey), nil},
		{"called", exposedJob("workflow_call", "permissions: write-all\n", "", readKey), nil},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{DangerousTriggers}, wfFile(c.src), exposureFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != len(c.want) {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		got := map[string]string{}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got[f.Args.KindID().String()] = condJSON(t, f)
		}
		for _, w := range c.want {
			if cond, ok := got[w.kind]; !ok || cond != w.cond {
				t.Errorf("%s: %v; want %s %s", c.name, got, w.kind, w.cond)
			}
		}
	}
}

// TestDangerousTriggersCaller: a job that calls a reusable workflow on an
// attacker's event exposes what it passes.
func TestDangerousTriggersCaller(t *testing.T) {
	src := "on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/c.yml\n    secrets: inherit\n"
	rep, _, _ := checkRules(t, []lint.Rule{DangerousTriggers}, wfFile(src), exposureFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	if a, ok := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.(DangerousTriggersSecrets); !ok || len(a.Secrets) != 1 || a.Secrets[0] != "*" {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args)
	}
}

// TestDangerousTriggersNoJobs: no finding on a workflow with no jobs, nor
// on an action.yml.
func TestDangerousTriggersNoJobs(t *testing.T) {
	files := map[string]string{
		".github/workflows/w.yml": "on: issues\n",
		"action.yml":              "name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - run: echo ${{ secrets.X }}\n      shell: bash\n",
	}
	for _, r := range []lint.Rule{DangerousTriggers, SelfHostedRunner} {
		rep, _, _ := checkRules(t, []lint.Rule{r}, files, exposureFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
			t.Errorf("%s: %+v %+v", r.Meta().ID, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
		}
	}
}

// TestDangerousTriggersIncidents: the jobs of the incidents the Meta cites.
func TestDangerousTriggersIncidents(t *testing.T) {
	for _, c := range []struct {
		name, src string
		kinds     []string
	}{
		// spotbugs-2024, spotbugs/sonar-findbugs 5d472785be2a561e287f4f5059a95a9cc05487fb
		// .github/workflows/sonarqube.yml:1-29,59-71, cut to the
		// job and what it reads
		{"spotbugs-2024", "on:\n  push:\n    branches: [master]\n  pull_request_target:\n    branches: [master]\n  release:\n    types: [created]\npermissions:\n  checks: write\n  contents: read\n  pull-requests: write\n  statuses: read\njobs:\n  build:\n    if: github.repository == 'spotbugs/sonar-findbugs'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n          ref: ${{ steps.condval.outputs.value }}\n      - name: Build\n        run: ./mvnw verify sonar:sonar -Dsonar.token=$SONAR_TOKEN\n        env:\n          GITHUB_TOKEN: ${{ secrets.PAT_TO_FORK }}\n          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}\n",
			[]string{"dangerous-triggers.secrets", "dangerous-triggers.token-write"}},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{DangerousTriggers}, wfFile(c.src), exposureFacts{writes: ptr(true)})
		var got []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got = append(got, f.Args.KindID().String())
		}
		slices.Sort(got)
		if !slices.Equal(got, c.kinds) {
			t.Errorf("%s: %v, want %v", c.name, got, c.kinds)
		}
	}
}

// TestDangerousTriggersInheritReads: a job that calls a reusable workflow of
// the inputs reads what the jobs of the called workflow read. The workflows
// are those of the runs observed for secret-exposure
// (testdata/observed/secret-exposure/5, with on: issues in place of on:
// push), and the forms of two runs of 2026-11-06, written here.
func TestDangerousTriggersInheritReads(t *testing.T) {
	read := func(p string) string {
		b, err := os.ReadFile("testdata/observed/secret-exposure/5/.github/workflows/" + p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	files := map[string]string{
		".github/workflows/s3-callers.yml":    strings.Replace(read("s3-callers.yml"), "on: push", "on: issues", 1),
		".github/workflows/called-tojson.yml": read("called-tojson.yml"),
		".github/workflows/called-plain.yml":  read("called-plain.yml"),
		".github/workflows/e11.yml":           "on: issues\npermissions: {}\njobs:\n  named-unread:\n    uses: ./.github/workflows/called-ab.yml\n    secrets:\n      PROBE_A: ${{ secrets.PROBE_A }}\n      PROBE_B: ${{ secrets.PROBE_B }}\n  nested-named-unread:\n    uses: ./.github/workflows/mid.yml\n    secrets: inherit\n",
		".github/workflows/called-ab.yml":     "on:\n  workflow_call:\n    secrets:\n      PROBE_A:\n        required: false\n      PROBE_B:\n        required: false\npermissions: {}\njobs:\n  called:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          X: ${{ secrets.PROBE_A }}\n        run: \"true\"\n",
		".github/workflows/mid.yml":           "on:\n  workflow_call:\npermissions: {}\njobs:\n  middle:\n    uses: ./.github/workflows/inner.yml\n    secrets:\n      K: ${{ secrets.PROBE_B }}\n",
		".github/workflows/inner.yml":         "on:\n  workflow_call:\n    secrets:\n      K:\n        required: false\npermissions: {}\njobs:\n  inner:\n    runs-on: ubuntu-latest\n    steps:\n      - run: \"true\"\n",
	}
	rep, _, _ := checkRules(t, []lint.Rule{DangerousTriggers}, files, exposureFacts{})
	var got []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if a, ok := f.Args.(DangerousTriggersSecrets); ok {
			got = append(got, f.Location.File.Input.String()+" "+strings.Join(a.Secrets, ","))
		}
	}
	slices.Sort(got)
	// named-tojson and named-plain get the one passed, inherit-plain the one
	// read, inherit-tojson every one; named-unread of e11 the one read, and
	// nested-named-unread of e13 none
	want := []string{
		".github/workflows/e11.yml PROBE_A",
		".github/workflows/s3-callers.yml *",
		".github/workflows/s3-callers.yml PROBE_A",
		".github/workflows/s3-callers.yml PROBE_A",
		".github/workflows/s3-callers.yml PROBE_A",
	}
	if !slices.Equal(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}

// TestDangerousTriggersNestedUnknown fixes the nested form of the false
// positive inherit-unread, whose example is the direct form: the job calls
// a workflow of the inputs that calls, in turn, a workflow that is not
// among the inputs; the rule takes the job to read every secret.
func TestDangerousTriggersNestedUnknown(t *testing.T) {
	files := map[string]string{
		".github/workflows/ci.yml":  "on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/mid.yml\n    secrets: inherit\n",
		".github/workflows/mid.yml": "on:\n  workflow_call:\npermissions: {}\njobs:\n  m:\n    uses: ./.github/workflows/inner.yml\n    secrets: inherit\n",
	}
	rep, _, _ := checkRules(t, []lint.Rule{DangerousTriggers}, files, exposureFacts{})
	var got []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if a, ok := f.Args.(DangerousTriggersSecrets); ok {
			got = append(got, f.Location.File.Input.String()+" "+strings.Join(a.Secrets, ","))
		}
	}
	if !slices.Equal(got, []string{".github/workflows/ci.yml *"}) {
		t.Errorf("%q", got)
	}
}

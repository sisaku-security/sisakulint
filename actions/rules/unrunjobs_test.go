package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestUnrunJobsWorkflowEnv: a read of the secrets without a name in the env
// of the workflow is read by every job: with one job of two that GitHub
// skips in every run, secret-exposure reports it; with both skipped, it
// does not.
func TestUnrunJobsWorkflowEnv(t *testing.T) {
	const job = "    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
	for _, c := range []struct {
		name string
		src  string
		want int
	}{
		{"one job skipped", "on: push\nenv:\n  ALL: ${{ toJSON(secrets) }}\njobs:\n  a:\n    if: false\n" + job + "  b:\n" + job, 1},
		{"every job skipped", "on: push\nenv:\n  ALL: ${{ toJSON(secrets) }}\njobs:\n  a:\n    if: false\n" + job + "  b:\n    if: false\n" + job, 0},
	} {
		refs, _ := referencesOf(t, wfFile(c.src))
		if len(refs) != c.want {
			t.Errorf("%s: %d findings, want %d", c.name, len(refs), c.want)
		}
	}
}

// TestAllowedActionsSkippedJob: in a job that GitHub skips in every run, a
// uses that the setting does not allow still stops the run
// (allowed-actions.unstarted-run), and a uses by a tag fails no job
// (allowed-actions.unpinned-action).
func TestAllowedActionsSkippedJob(t *testing.T) {
	files := map[string]string{".github/workflows/w.yml": "on: push\njobs:\n  a:\n    if: false\n    runs-on: x\n    steps:\n      - uses: x/other@v1\n"}
	got, _ := allowedActionsRun(t, files, "o/r", settingFacts(t, "o/r", selectedNone))
	if want := []string{".github/workflows/w.yml allowed-actions.unstarted-run x/other@v1"}; !slices.Equal(got, want) {
		t.Errorf("not allowed: got %q, want %q", got, want)
	}
	pinning := `{"allowed_actions":"all","sha_pinning_required":true}`
	if got, _ := allowedActionsRun(t, files, "o/r", settingFacts(t, "o/r", pinning)); len(got) != 0 {
		t.Errorf("pinning required: got %q, want none", got)
	}
	files[".github/workflows/w.yml"] = strings.Replace(files[".github/workflows/w.yml"], "    if: false\n", "", 1)
	if got, _ := allowedActionsRun(t, files, "o/r", settingFacts(t, "o/r", pinning)); len(got) != 1 {
		t.Errorf("pinning required, the job runs: got %q, want one", got)
	}
}

// alwaysSkippedFields are the fields always-skipped of the summaries.
var alwaysSkippedFields = []ir.SummaryField{ir.FieldUsesAlwaysSkipped, ir.FieldCompositeCallAlwaysSkipped, ir.FieldImageSiteAlwaysSkipped, ir.FieldLeftCredentialAlwaysSkipped, ir.FieldUploadAlwaysSkipped, ir.FieldJobAlwaysSkipped, ir.FieldSinkAlwaysSkipped, ir.FieldPrintedOutputAlwaysSkipped, ir.FieldSecretsContextReadAlwaysSkipped, ir.FieldSecretPartAlwaysSkipped}

// TestUnrunJobsNoFindings: each true positive example of one workflow file
// of a rule whose view reads always-skipped, rewritten so that GitHub runs
// none of its jobs (unrunJobs), gives no finding and no inconclusive place
// in the lines of its jobs.
func TestUnrunJobsNoFindings(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	reads := map[lint.RuleID]bool{}
	for _, r := range All() {
		reads[r.Meta().ID] = slices.ContainsFunc(r.Meta().ViewFields, func(f ir.SummaryField) bool { return slices.Contains(alwaysSkippedFields, f) })
	}
	ctx := context.Background()
	seen := map[string]bool{}
	n := 0
	for _, c := range sharedChecks(t).Of() {
		e := c.Example
		if !reads[c.Rule] || c.What != lint.ExampleTruePositive || e.InputKind != lint.InputKindWorkflow || len(e.Others) != 0 {
			continue
		}
		key := c.Rule.String() + " " + e.Name.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		sel, err := lint.ParseSelector(c.Rule.String())
		if err != nil {
			t.Fatal(err)
		}
		one, err := reg.Select(lint.Only(sel), lint.FactSources{})
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range unrunJobs {
			text, err := rewriteUnrun(e.Text, u.need, u.job)
			if err != nil {
				t.Errorf("%s: %s: %v", key, u.name, err)
				continue
			}
			x := e
			x.Text = text
			run, err := one.RunExample(ctx, x, nil)
			if err != nil {
				t.Errorf("%s: %s: %v", key, u.name, err)
				continue
			}
			n++
			first := strings.Count(text[:strings.Index(text, "\njobs:")+1], "\n") + 1 // the line of jobs:
			last := strings.Count(text[:strings.Index(text, "zzpre:")], "\n") + 1     // the line of the job zzpre
			for _, p := range placesOf(run.Report, text) {
				var l int
				fmt.Sscanf(p[strings.LastIndex(p, " line ")+len(" line "):], "%d", &l)
				if first < l && l < last {
					t.Errorf("%s: %s: %s", key, u.name, p)
				}
			}
		}
	}
	if n == 0 {
		t.Fatal("no example rewritten")
	}
	t.Logf("%d rewrites", n)
}

// TestUnrunJobsFileRules: credentials and self-hosted-runner report a job
// that GitHub skips in every run: the password is read in the file, and
// the runs-on says that the repository has the runner, which the workflow
// of a pull request from a fork names.
func TestUnrunJobsFileRules(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    if: false\n    runs-on: [self-hosted, linux]\n    container:\n      image: ghcr.io/o/i:1\n      credentials:\n        username: u\n        password: hunter2\n    steps:\n      - run: echo\n"
	rep, _, _ := checkRules(t, []lint.Rule{Credentials, SelfHostedRunner}, wfFile(src), nil)
	var got []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		got = append(got, f.Rule.String())
	}
	if !slices.Contains(got, CredentialsID.String()) || !slices.Contains(got, SelfHostedRunnerID.String()) {
		t.Errorf("findings of %q, want credentials and self-hosted-runner", got)
	}
}

// TestSecretsInheritSkippedCalledJob: secrets-inherit does not report a
// call with secrets: inherit whose called workflow reads the secrets
// without a name only in a job that GitHub skips in every run: GitHub
// passes that job's runner no secret.
func TestSecretsInheritSkippedCalledJob(t *testing.T) {
	const caller = "on: push\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n"
	called := "on: workflow_call\njobs:\n  x:\n    if: false\n    runs-on: ubuntu-latest\n    env:\n      ALL: ${{ toJSON(secrets) }}\n    steps:\n      - run: echo\n  y:\n    runs-on: ubuntu-latest\n    env:\n      A: ${{ secrets.A }}\n    steps:\n      - run: echo\n"
	for _, c := range []struct {
		name   string
		called string
		want   int
	}{
		{"read in a skipped job", called, 0},
		{"read in a job that runs", strings.Replace(called, "    if: false\n", "", 1), 1},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{SecretsInherit}, map[string]string{".github/workflows/ci.yml": caller, ".github/workflows/called.yml": c.called}, nil)
		if n := len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)); n != c.want {
			t.Errorf("%s: %d findings, want %d", c.name, n, c.want)
		}
	}
}

// TestNeverRunStep: a run step whose if is false runs nothing, so neither
// untrusted-checkout nor unmasked-secret-exposure reports it; without the
// if, both do.
func TestNeverRunStep(t *testing.T) {
	const checkout = "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + coOld + "\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - if: false\n        run: npm install\n"
	const secret = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - if: false\n        env:\n          V: ${{ fromJSON(secrets.AZ).clientId }}\n        run: echo \"$V\"\n"
	for _, c := range []struct {
		src  string
		kind string
	}{
		{checkout, "untrusted-checkout.executed"},
		{secret, "unmasked-secret-exposure.public"},
		{secret, "unmasked-secret-exposure.private"},
	} {
		kinds := func(src string) []string {
			rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout, UnmaskedSecretExposure}, wfFile(src), exposureFacts{})
			var out []string
			for _, f := range rep.Findings {
				out = append(out, f.KindText())
			}
			return out
		}
		if got := kinds(c.src); slices.Contains(got, c.kind) {
			t.Errorf("if: false: got %q, want no %s", got, c.kind)
		}
		if got := kinds(strings.Replace(c.src, "if: false\n        ", "", 1)); !slices.Contains(got, c.kind) {
			t.Errorf("no if: got %q, want %s", got, c.kind)
		}
	}
}

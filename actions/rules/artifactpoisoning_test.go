package rules

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// downloadFacts answers the facts of artifact-poisoning: the
// environment's protection, the default token, a pinned commit, whether a
// download's files run. A field left nil is not known.
type downloadFacts struct {
	protected, defaultWrite, contains, executed *bool
}

func (d downloadFacts) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	var v *bool
	switch q.(type) {
	case facts.RepoEnvironmentProtected:
		v = d.protected
	case facts.RepoDefaultTokenWrite:
		v = d.defaultWrite
	case facts.GitCommitContains:
		v = d.contains
	case facts.DownloadExecuted:
		v = d.executed
	}
	if v == nil {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
	}
	b, _ := json.Marshal(*v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

const (
	apOn        = "{workflow_run: {workflows: [ci], types: [completed]}}"
	apWith      = "{run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}'}"
	apRead      = "    permissions: {actions: read}\n"
	apExecutedQ = `{"query":{"kind":"download.executed","input_path":".github/workflows/w.yml","step":"jobs.a.steps[0]"},"eq":true}`
	apDefaultQ  = `{"query":{"kind":"repo.default-token-write"},"eq":true}`
)

// TestArtifactPoisoning: the kinds of artifact-poisoning on the forms of a
// download, row by row.
func TestArtifactPoisoning(t *testing.T) {
	for _, c := range []struct {
		name, on, jobExtra, uses, with, after string
		kind                                  string // "" for none
		cond                                  string
	}{
		{"executed", apOn, apRead, "actions/download-artifact@v4", apWith, "      - run: npm ci\n", "artifact-poisoning.executed", ""},
		{"not seen to run", apOn, apRead, "actions/download-artifact@v4", apWith, "      - run: echo done\n", "artifact-poisoning.download", apExecutedQ},
		{"permissions unwritten", apOn, "", "actions/download-artifact@v4", apWith, "      - run: npm ci\n", "artifact-poisoning.executed", apDefaultQ},
		{"no actions scope", apOn, "    permissions: {contents: read}\n", "actions/download-artifact@v4", apWith, "      - run: npm ci\n", "", ""},
		{"a PAT", apOn, "    permissions: {contents: read}\n", "actions/download-artifact@v4", "{run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ secrets.PAT }}'}", "      - run: npm ci\n", "artifact-poisoning.executed", ""},
		{"no token", apOn, apRead, "actions/download-artifact@v4", "{run-id: '${{ github.event.workflow_run.id }}'}", "      - run: npm ci\n", "", ""},
		{"runner.temp, not run", apOn, apRead, "actions/download-artifact@v4", "{run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}', path: '${{ runner.temp }}/a'}", "      - run: npm ci\n", "", ""},
		{"runner.temp, run", apOn, apRead, "actions/download-artifact@v4", "{run-id: '${{ github.event.workflow_run.id }}', github-token: '${{ github.token }}', path: '${{ runner.temp }}/a'}", "      - run: bash $RUNNER_TEMP/a/x.sh\n", "artifact-poisoning.executed", ""},
		{"no checkout needed", apOn, apRead, "actions/download-artifact@v4", apWith, "      - run: ./deploy.sh\n", "artifact-poisoning.executed", ""},
		{"environment", apOn, apRead + "    environment: prod\n", "actions/download-artifact@v4", apWith, "      - run: npm ci\n", "artifact-poisoning.executed", unprotectQ},
		{"push", "push", apRead, "actions/download-artifact@v4", apWith, "      - run: npm ci\n", "", ""},
		{"v3", apOn, apRead, "actions/download-artifact@v3", apWith, "      - run: npm ci\n", "", ""},
		{"dawidd6 v3, no with", apOn, apRead, "dawidd6/action-download-artifact@v3", "", "      - run: npm ci\n", "artifact-poisoning.executed", ""},
		{"actions/download-artifact, no with", apOn, apRead, "actions/download-artifact@v4", "", "      - run: npm ci\n", "", ""},
		// a search of forks' runs holds on any event
		{"dawidd6 v3 on push", "push", apRead, "dawidd6/action-download-artifact@v3", "{workflow: build.yml}", "      - run: npm ci\n", "artifact-poisoning.executed", ""},
		// with allow_forks false, the search takes the run of a review of a
		// pull request from a fork
		{"dawidd6 v6 on push", "push", apRead, "dawidd6/action-download-artifact@v6", "{workflow: build.yml}", "      - run: npm ci\n", "artifact-poisoning.executed", ""},
		// run_id github.event.workflow_run.id is
		// never empty on workflow_run, so no search drops the environment
		{"dawidd6 run_id, environment", apOn, apRead + "    environment: prod\n", "dawidd6/action-download-artifact@v6", "{run_id: '${{ github.event.workflow_run.id }}'}", "      - run: npm ci\n", "artifact-poisoning.executed", unprotectQ},
		// a commit in no table: every version searches, so no git.commit-contains
		{"dawidd6 a commit in no table", "push", apRead, "dawidd6/action-download-artifact@1234567890abcdef1234567890abcdef12345678", "{name: out}", "      - run: npm ci\n", "artifact-poisoning.executed", ""},
		// the false positive form search-filter: the rule does not read commit
		{"dawidd6 commit github.sha on push", "push", apRead, "dawidd6/action-download-artifact@v20", "{commit: '${{ github.sha }}'}", "      - run: npm ci\n", "artifact-poisoning.executed", ""},
		{"label", "{pull_request_target: {types: [labeled]}}", apRead, "dawidd6/action-download-artifact@v6", "{repo: '${{ github.event.pull_request.head.repo.full_name }}'}", "      - run: npm ci\n", "artifact-poisoning.executed", ""}, // a search is not approved
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + c.jobExtra + "    steps:\n      - uses: " + c.uses + "\n"
		if c.with != "" {
			src += "        with: " + c.with + "\n"
		}
		src += c.after
		rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(src), downloadFacts{})
		if c.kind == "" {
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
				t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
			continue
		}
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
		if f.Args.KindID().String() != c.kind || condJSON(t, f) != c.cond {
			t.Errorf("%s: %s %s; want %s %s", c.name, f.Args.KindID(), condJSON(t, f), c.kind, c.cond)
		}
	}
}

// TestArtifactPoisoningUnknownFacts: with no answer the finding is
// conditional; when the files downloaded are read as data, there is none.
func TestArtifactPoisoningUnknownFacts(t *testing.T) {
	src := "on: " + apOn + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + apRead + "    steps:\n      - uses: actions/download-artifact@v4\n        with: " + apWith + "\n      - run: echo done\n"
	rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(src), downloadFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConditional {
		t.Errorf("not known: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _, _ = checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(src), downloadFacts{executed: ptr(false)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("read as data: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestArtifactPoisoningIncidents holds the workflows of the incidents of
// artifact-poisoning, each cut to the download and what runs after it.
// The advisories GHSL-2024-125 and GHSA-5xr6-xhww-33m4 are examples of
// examples/true-positive/artifact-poisoning.
func TestArtifactPoisoningIncidents(t *testing.T) {
	for _, c := range []struct {
		name, src, kind string
	}{
		// Legit Security, "a manually triggered workflow that pulls the last
		// built image from the 'build.yml' workflow and publishes it"
		{"Legit workflow_dispatch", "on: workflow_dispatch\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: dawidd6/action-download-artifact@v2\n        with:\n          workflow: build.yml\n          name: image\n      - run: make publish\n", "artifact-poisoning.executed"},
		// CodeQL, actions/ql/src/Security/CWE-829/ArtifactPoisoningCritical.md
		// (f7617abe602d4763cd08c6a57b6a6bc347e7e325), Incorrect Usage: v2
		// searches forks' runs of this workflow, whose file a pull request
		// can change; sh cmd.sh runs the cmd.sh of the workspace, which the
		// artifact overrides ("an attacker will be able to override the
		// contents of cmd.sh", the qhelp)
		{"CodeQL Incorrect Usage", "name: Insecure Workflow\non:\n  workflow_run:\n    workflows: [\"Prev\"]\n    types:\n      - completed\njobs:\n  Download:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n      - uses: dawidd6/action-download-artifact@v2\n        with:\n          name: pr_number\n      - name: Run command\n        run: |\n          sh cmd.sh\n", "artifact-poisoning.executed"},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(c.src), downloadFacts{})
		var kinds []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			kinds = append(kinds, f.Args.KindID().String())
		}
		if !slices.Equal(kinds, []string{c.kind}) {
			t.Errorf("%s: %v", c.name, kinds)
		}
	}
}

// TestArtifactPoisoningFix: the fix of a download with no path puts the files
// under runner.temp, and the finding closes; a written path gets no fix.
func TestArtifactPoisoningFix(t *testing.T) {
	src := "on: " + apOn + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + apRead + "    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n      - run: npm ci\n"
	out := applied(t, ArtifactPoisoning, src, downloadFacts{}, lint.SafetyReview)
	if !strings.Contains(out, "          path: ${{ runner.temp }}/artifacts\n") {
		t.Fatalf("not fixed:\n%s", out)
	}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(out), downloadFacts{}); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("after the fix: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	withPath := strings.Replace(src, "          github-token: ${{ github.token }}\n", "          github-token: ${{ github.token }}\n          path: dist\n", 1) + "      - run: bash dist/x.sh\n"
	rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(withPath), downloadFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix.Reason != ir.NoFixReasonManual {
		t.Errorf("a path: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestArtifactPoisoningZipSlipAndApprovals: a release with the zip-slip
// gets no fix, and an approval or a token not known does not hide a search
// of forks' runs.
func TestArtifactPoisoningZipSlipAndApprovals(t *testing.T) {
	// a release with the zip-slip, or a commit in no table, gets no fix:
	// runner.temp does not keep its files out of the workspace
	for _, uses := range []string{"actions/download-artifact@v4.1.0", "actions/download-artifact@0123456789abcdef0123456789abcdef01234567"} {
		src := "on: " + apOn + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n" + apRead + "    steps:\n      - uses: " + uses + "\n        with: " + apWith + "\n      - run: echo done\n"
		rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(src), downloadFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix.Reason != ir.NoFixReasonManual {
			t.Errorf("no fix of %s: %+v", uses, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
	for _, c := range []struct {
		name, src, kind, cond string
	}{
		// a token not known does not hide a search of forks' runs
		{"token not known", "on: workflow_dispatch\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: dawidd6/action-download-artifact@v3\n        with:\n          workflow: build.yml\n          github_token: ${{ inputs.tok }}\n      - run: make\n", "artifact-poisoning.executed", ""},
		// an approval does not cover a search: the newest fork's run is
		// taken after it
		{"approval by a label", "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: dawidd6/action-download-artifact@v3\n        with:\n          workflow: build.yml\n      - run: ./x.sh\n", "artifact-poisoning.executed", apDefaultQ},
		{"approval by an environment", "on: push\npermissions: {actions: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    environment: prod\n    steps:\n      - uses: dawidd6/action-download-artifact@v6\n        with:\n          workflow: build.yml\n          allow_forks: true\n      - run: make\n", "artifact-poisoning.executed", ""},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(c.src), downloadFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != c.kind || condJSON(t, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]) != c.cond {
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
				t.Errorf("%s: %s %s", c.name, f.Args.KindID(), condJSON(t, f))
			}
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) == 0 {
				t.Errorf("%s: none", c.name)
			}
		}
	}
}

// TestArtifactPoisoningThreatEvents holds the threat of the rule to its
// behavior: the kinds
// rest on download-event, not privileged-event; the actor takes every event,
// as a search of runs takes the attacker's on any event; and the kinds keep
// repo.pull-request-target-allowed.
func TestArtifactPoisoningThreatEvents(t *testing.T) {
	m := ArtifactPoisoning.Meta()
	for _, k := range m.FindingKinds {
		if !slices.Contains(k.Preconditions, downloadEvent) || slices.Contains(k.Preconditions, privilegedEvent) {
			t.Errorf("%s: preconditions %v, want download-event and no privileged-event", k.ID, k.Preconditions)
		}
		if !slices.Contains(k.FactKinds, facts.KindRepoPullRequestTargetAllowed) {
			t.Errorf("%s: no repo.pull-request-target-allowed", k.ID)
		}
	}
	i := slices.IndexFunc(m.Threat.Preconditions, func(p lint.Precondition) bool { return p.ID == downloadEvent })
	if i < 0 {
		t.Fatal("no precondition download-event")
	}
	if p := m.Threat.Preconditions[i]; len(p.Observed) == 0 || !slices.Contains(p.Cites, dawidd6Search) {
		t.Errorf("download-event: observed %d, cites %v", len(p.Observed), p.Cites)
	}
	if len(m.Threat.Actors) != 1 {
		t.Fatalf("actors %d, want 1", len(m.Threat.Actors))
	}
	a := m.Threat.Actors[0]
	got, want := slices.Clone(a.Events), workflow.EventNames()
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("events %v, want every event %v", got, want)
	}
	attacker := append(job.Privileged(), workflow.EventNameGollum, workflow.EventNameWatch,
		workflow.EventNamePullRequest) // pull_request for now, as for the review events
	for _, e := range a.Events {
		want := lint.RunStarterOther
		if slices.Contains(attacker, e) {
			want = lint.RunStarterAttacker
		}
		if a.RunStarters[e] != want {
			t.Errorf("run starter of %s: %v, want %v", e, a.RunStarters[e], want)
		}
	}
}

// TestArtifactPoisoningSameRun: a download of the current run in a job
// that needs a job which checks out the pull request's code and uploads
// is a finding, which names that job and points at its checkout and
// upload.
func TestArtifactPoisoningSameRun(t *testing.T) {
	const build = "  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          persist-credentials: false\n      - run: make\n      - uses: actions/upload-artifact@v4\n        with: {name: out, path: out}\n"
	for _, c := range []struct {
		name, download, after, kind string
	}{
		{"executed", "actions/download-artifact@v4", "      - run: ./run.sh\n", "artifact-poisoning.executed"},
		{"v3 not seen to run", "actions/download-artifact@v3", "      - run: echo done\n", "artifact-poisoning.download"},
	} {
		src := "on: pull_request_target\njobs:\n" + build + "  deploy:\n    needs: build\n    runs-on: ubuntu-latest\n    permissions: {contents: write}\n    steps:\n      - uses: " + c.download + "\n        with: {name: out}\n" + c.after
		rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(src), downloadFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Errorf("%s: %d findings %+v", c.name, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			continue
		}
		f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
		args, _ := json.Marshal(f.Args)
		if f.Args.KindID().String() != c.kind || !strings.Contains(string(args), `"pr_run_ref":"jobs.build"`) {
			t.Errorf("%s: %s %s", c.name, f.Args.KindID(), args)
		}
		var notes []string
		for _, r := range f.Evidence {
			notes = append(notes, r.Note)
		}
		if !slices.Contains(notes, "checks out the pull request's code (jobs.build)") || !slices.Contains(notes, "uploads the artifact (jobs.build)") {
			t.Errorf("%s: evidence %q", c.name, notes)
		}
	}
}

// TestArtifactPoisoningSameRunGuard: the guard of actions/checkout fails
// the checkout of the code of a pull request on pull_request_target, so a
// major tag from v2 uploads nothing of the pull request, and a commit in no
// table holds unless the commit has the guard.
func TestArtifactPoisoningSameRunGuard(t *testing.T) {
	src := func(ref string) string {
		return "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@" + ref + "\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make\n      - uses: actions/upload-artifact@v4\n        with: {name: out, path: out}\n  deploy:\n    needs: build\n    runs-on: ubuntu-latest\n    permissions: {contents: write}\n    steps:\n      - uses: actions/download-artifact@v4\n        with: {name: out}\n      - run: ./run.sh\n"
	}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(src("v4")), downloadFacts{}); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("v4: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, wfFile(src("0123456789abcdef0123456789abcdef01234567")), downloadFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || !strings.Contains(condJSON(t, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]), "git.commit-contains") {
		t.Errorf("a commit in no table: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestArtifactPoisoningSameRunComposite: an upload inside a composite
// action of the inputs, an upload of a reusable workflow of the inputs that
// a needed job calls, and actions/upload-artifact/merge of such an upload
// are uploads of the current run; a ./ action the inputs do not have is
// inconclusive.
func TestArtifactPoisoningSameRunComposite(t *testing.T) {
	deploy := "  deploy:\n    needs: NEEDS\n    runs-on: ubuntu-latest\n    permissions: {contents: write}\n    steps:\n      - uses: actions/download-artifact@v4\n        with: {name: out}\n      - run: ./run.sh\n"
	checkout := "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make\n"
	composite := map[string]string{
		".github/workflows/w.yml":       "on: pull_request_target\njobs:\n  build:\n" + checkout + "      - uses: ./.github/actions/up\n" + strings.ReplaceAll(deploy, "NEEDS", "build"),
		".github/actions/up/action.yml": "name: up\ndescription: up\nruns:\n  using: composite\n  steps:\n    - uses: actions/upload-artifact@v4\n      with: {name: out, path: out}\n",
	}
	called := map[string]string{
		".github/workflows/w.yml": "on: pull_request_target\njobs:\n  build: {uses: ./.github/workflows/b.yml}\n" + strings.ReplaceAll(deploy, "NEEDS", "build"),
		".github/workflows/b.yml": "on: workflow_call\njobs:\n  build:\n" + checkout + "      - uses: actions/upload-artifact@v4\n        with: {name: out, path: out}\n",
	}
	merge := map[string]string{
		".github/workflows/w.yml": "on: pull_request_target\njobs:\n  build:\n" + checkout + "      - uses: actions/upload-artifact@v4\n        with: {name: part-1, path: out}\n  merge:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact/merge@v4\n        with: {name: out, pattern: part-*}\n" + strings.ReplaceAll(deploy, "NEEDS", "merge"),
	}
	for name, files := range map[string]map[string]string{"composite": composite, "called": called, "merge": merge} {
		rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, files, downloadFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Errorf("%s: %+v", name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
	unmerged := map[string]string{".github/workflows/w.yml": strings.Replace(merge[".github/workflows/w.yml"], "pattern: part-*", "pattern: other-*", 1)}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, unmerged, downloadFacts{}); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 {
		t.Errorf("merge of other artifacts: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	negated := map[string]string{".github/workflows/w.yml": strings.Replace(merge[".github/workflows/w.yml"], "pattern: part-*", "pattern: '!other-*'", 1)}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, negated, downloadFacts{}); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Errorf("merge with a negated pattern: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	excluded := map[string]string{".github/workflows/w.yml": strings.Replace(merge[".github/workflows/w.yml"], "pattern: part-*", "pattern: '!part-*'", 1)}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, excluded, downloadFacts{}); len(rep.Findings) != 0 {
		t.Errorf("merge with a negated pattern that excludes the artifact: %+v", rep.Findings)
	}
	dynamic := map[string]string{".github/workflows/w.yml": strings.Replace(merge[".github/workflows/w.yml"], "pattern: part-*", "pattern: '${{ vars.P }}'", 1)}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, dynamic, downloadFacts{}); len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 {
		t.Errorf("merge with a pattern that is a ${{ }}: %+v", rep.Findings)
	}
	otherName := map[string]string{".github/workflows/w.yml": strings.Replace(strings.Replace(dynamic[".github/workflows/w.yml"], "{name: out, pattern:", "{name: merged, pattern:", 1), "        with: {name: merged, pattern: '${{ vars.P }}'}\n", "        with: {name: merged, pattern: '${{ vars.P }}'}\n      - uses: actions/upload-artifact@v4\n        with: {name: out, path: docs}\n", 1)}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, otherName, downloadFacts{}); len(rep.Findings) != 0 {
		t.Errorf("merge with an unknown pattern under another name: %+v", rep.Findings)
	}
	skipped := map[string]string{".github/workflows/w.yml": composite[".github/workflows/w.yml"], ".github/actions/up/action.yml": strings.Replace(composite[".github/actions/up/action.yml"], "    - uses: actions/upload-artifact@v4\n", "    - if: false\n      uses: actions/upload-artifact@v4\n", 1)}
	if rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, skipped, downloadFacts{}); len(rep.Findings) != 0 {
		t.Errorf("composite upload with if: false: %+v", rep.Findings)
	}
	missing := map[string]string{".github/workflows/w.yml": composite[".github/workflows/w.yml"]}
	rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, missing, downloadFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 {
		t.Errorf("missing action: %+v", rep.Findings)
	}
}

// TestArtifactPoisoningPatterns: the pattern of actions/upload-artifact/merge
// and of actions/download-artifact, read as minimatch reads it. A pattern
// that the releases of minimatch read differently makes the merge
// inconclusive, and the download take every artifact.
func TestArtifactPoisoningPatterns(t *testing.T) {
	checkout := "    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make\n      - uses: actions/upload-artifact@v4\n        with: {name: part-1, path: out}\n"
	merge := func(pattern string) map[string]string {
		return map[string]string{".github/workflows/w.yml": "on: pull_request_target\njobs:\n  build:\n" + checkout + "  merge:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/upload-artifact/merge@v4\n        with: {name: out, pattern: '" + pattern + "'}\n  deploy:\n    needs: merge\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with: {name: out}\n      - run: ./run.sh\n"}
	}
	download := func(pattern string) map[string]string {
		return map[string]string{".github/workflows/w.yml": "on: pull_request_target\njobs:\n  build:\n" + checkout + "  deploy:\n    needs: build\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with: {pattern: '" + pattern + "'}\n      - run: ./run.sh\n"}
	}
	for _, c := range []struct {
		name                   string
		files                  map[string]string
		findings, inconclusive int
	}{
		{"merge part-@(x|y)", merge("part-@(x|y)"), 0, 0},
		{"merge part-+(x)", merge("part-+(x)"), 0, 0},
		{"merge part-!(1)", merge("part-!(1)"), 0, 0},
		{"merge #part-1", merge("#part-1"), 0, 0},
		{"merge part-@(1|2)", merge("part-@(1|2)"), 1, 0},
		{"merge part-{1..3}", merge("part-{1..3}"), 1, 0},
		{"merge part-+(@(1|2))", merge("part-+(@(1|2))"), 0, 1},
		{"merge part-[[:digit:]]", merge("part-[[:digit:]]"), 0, 1},
		{"download part-*", download("part-*"), 1, 0},
		{"download part-{1,2}", download("part-{1,2}"), 1, 0},
		{"download part-[!x]*", download("part-[!x]*"), 1, 0},
		{"download !other-*", download("!other-*"), 1, 0},
		{"download part-@(1|2)", download("part-@(1|2)"), 1, 0},
		{"download !(x)*", download("!(x)*"), 1, 0},
		{"download other-{a,b}", download("other-{a,b}"), 0, 0},
		{"download part-@(x|y)", download("part-@(x|y)"), 0, 0},
		{"download part-[[:digit:]]", download("part-[[:digit:]]"), 1, 0},
		{"download part-+(@(1|2))", download("part-+(@(1|2))"), 1, 0},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{ArtifactPoisoning}, c.files, downloadFacts{})
		if got := len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)); got != c.findings {
			t.Errorf("%s: %d findings, want %d: %+v", c.name, got, c.findings, rep.Findings)
		}
		if got := len(rep.FindingsWith(lint.CertaintyInconclusive)); got != c.inconclusive {
			t.Errorf("%s: %d inconclusive, want %d: %+v", c.name, got, c.inconclusive, rep.Findings)
		}
	}
}

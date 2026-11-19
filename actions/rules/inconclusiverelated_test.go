package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// exampleReport runs rules on the example at path under examples: a file,
// put in .github/workflows, or a directory whose files are the inputs, with the answers of its file
// of facts (path without .yml, then .facts.json) when there is one.
func exampleReport(t *testing.T, path string, rules ...lint.Rule) lint.Report {
	t.Helper()
	root := filepath.Join("examples", path)
	files := map[string]string{}
	st, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if st.IsDir() {
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			files[filepath.ToSlash(rel)] = string(b)
			return err
		})
	} else {
		var b []byte
		b, err = os.ReadFile(root)
		files[".github/workflows/"+filepath.Base(root)] = string(b)
	}
	if err != nil {
		t.Fatal(err)
	}
	var r facts.Resolver = &facts.Store{}
	if b, err := os.ReadFile(strings.TrimSuffix(root, ".yml") + ".facts.json"); err == nil {
		if r, err = facts.LoadStore(b); err != nil {
			t.Fatal(err)
		}
	}
	rep, _, _ := checkRules(t, rules, files, r)
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %+v", rep.Errors)
	}
	return rep
}

// inconclusiveOf are the inconclusive findings of rep of the rule id and
// the kind k.
func inconclusiveOf(rep lint.Report, id lint.RuleID, k string) []lint.Finding {
	var out []lint.Finding
	for _, f := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if f.Rule == id && f.InconclusiveKind.String() == k {
			out = append(out, f)
		}
	}
	return out
}

// relatedNotes are the notes of the related places of f, each after the
// input or the fact the place is in.
func relatedNotes(f lint.Finding) []string {
	var out []string
	for _, r := range f.Related {
		at := r.Location.File.Input.String()
		if r.Location.File.Query != nil {
			at = "fact"
		}
		out = append(out, at+" "+r.Note)
	}
	return out
}

// hasNote is whether a related place of f has a note that starts with
// prefix, in the input in (any input or fact when in is empty).
func hasNote(f lint.Finding, in, prefix string) bool {
	for _, r := range f.Related {
		if strings.HasPrefix(r.Note, prefix) && (in == "" || r.Location.File.Input.String() == in) {
			return true
		}
	}
	return false
}

// TestCheckoutRefUnknownRelated: the inconclusive finding of a checkout
// whose ref is not known has the steps that run what the checkout brings
// in Related, and no Evidence.
func TestCheckoutRefUnknownRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/untrusted-checkout/checkout-ref-unknown.yml", UntrustedCheckout)
	gs := inconclusiveOf(rep, UntrustedCheckoutID, "checkout-ref-unknown")
	if len(gs) != 1 {
		t.Fatalf("%d inconclusive findings, want 1", len(gs))
	}
	if !hasNote(gs[0], "", "runs what the checkout brings") || len(gs[0].Evidence) != 0 {
		t.Errorf("related %v, evidence %+v: want the steps that run what the checkout brings, and no evidence", relatedNotes(gs[0]), gs[0].Evidence)
	}
}

// TestInputDispatchRelated: the inconclusive finding of a checkout whose
// ref is an input of workflow_dispatch has the steps that run what the
// checkout brings in Related.
func TestInputDispatchRelated(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, map[string]string{
		".github/workflows/w.yml": "on:\n  workflow_dispatch:\n    inputs:\n      ref: {type: string}\n  pull_request_target:\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ inputs.ref }}\n      - run: npm install\n",
	}, &facts.Store{})
	gs := inconclusiveOf(rep, UntrustedCheckoutID, "input-dispatch")
	if len(gs) != 1 || !hasNote(gs[0], ".github/workflows/w.yml", "runs what the checkout brings") {
		t.Fatalf("inconclusive findings %+v, want 1 with the step of npm install in Related", gs)
	}
}

// TestUndecidedLabelRelated: the inconclusive finding of a label that a
// labeler may add has the ref of the pull request's code, the steps that
// run it and the step of actions/labeler in Related; the step of
// actions/labeler is in another workflow, so a run that reports only that
// workflow reports the inconclusive finding.
func TestUndecidedLabelRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/untrusted-checkout/label-paths", UntrustedCheckout)
	gs := inconclusiveOf(rep, UntrustedCheckoutID, "label-paths")
	if len(gs) != 1 {
		t.Fatalf("%d inconclusive findings, want 1", len(gs))
	}
	g := gs[0]
	if !hasNote(g, ".github/workflows/labeled.yml", "names the code of the pull request") ||
		!hasNote(g, ".github/workflows/labeled.yml", "runs what the checkout brings") ||
		!hasNote(g, ".github/workflows/labeler.yml", "the step of actions/labeler that may add ") {
		t.Errorf("related %v, want the ref, the steps that run the code and the step of actions/labeler", relatedNotes(g))
	}
	if !g.In([]facts.InputPath{facts.MustCleanInputPath(".github/workflows/labeler.yml")}) {
		t.Errorf("the inconclusive finding is not of the workflow of actions/labeler")
	}
}

// TestArtipackedGapRelated: an upload whose path is not known has the
// step that leaves the credential in Related; a step whose input that
// decides whether it leaves the credential is not known has the path of
// the upload in Related.
func TestArtipackedGapRelated(t *testing.T) {
	for _, c := range []struct{ example, kind, in, note string }{
		{"inconclusive/artipacked/upload-input-unknown.yml", "upload-input-unknown", ".github/workflows/upload-input-unknown.yml", "leaves the credential in .git/config"},
		{"inconclusive/artipacked/credential-input-unknown.yml", "credential-input-unknown", ".github/workflows/credential-input-unknown.yml", "the paths that the upload puts in the artifact"},
	} {
		rep := exampleReport(t, c.example, Artipacked)
		gs := inconclusiveOf(rep, ArtipackedID, c.kind)
		if len(gs) != 1 || !hasNote(gs[0], c.in, c.note) {
			t.Errorf("%s: inconclusive findings %+v, want 1 with %q in Related", c.example, gs, c.note)
		}
	}
}

// inlineReport runs rule on the workflow wf, with no facts.
func inlineReport(t *testing.T, wf string, rule lint.Rule) lint.Report {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{rule}, map[string]string{".github/workflows/w.yml": wf}, &facts.Store{})
	return rep
}

// wantRelated checks that an inconclusive finding of the rule id and the
// kind k in rep has a related place whose note starts with note, and that
// none has Evidence.
func wantRelated(t *testing.T, rep lint.Report, id lint.RuleID, k, note string) {
	t.Helper()
	gs := inconclusiveOf(rep, id, k)
	if len(gs) == 0 {
		t.Fatalf("no inconclusive finding of %s", k)
	}
	found := false
	for _, g := range gs {
		if len(g.Evidence) != 0 {
			t.Errorf("%s: evidence %+v, want none", k, g.Evidence)
		}
		found = found || hasNote(g, "", note)
	}
	if !found {
		t.Errorf("%s: no related place with a note that starts with %q; related %v", k, note, relatedNotes(gs[0]))
	}
}

// TestAIActionPromptInjectionInconclusiveRelated: gate-expr has where the
// value comes from, as the finding has.
func TestAIActionPromptInjectionInconclusiveRelated(t *testing.T) {
	rep, _, _ := checkRules(t, []lint.Rule{AIActionPromptInjection}, map[string]string{
		".github/workflows/caller.yml": "on:\n  issues:\n    types: [opened]\njobs:\n  c:\n    uses: ./.github/workflows/called.yml\n    with:\n      t: ${{ github.event.issue.title }}\n",
		".github/workflows/called.yml": "on:\n  workflow_call:\n    inputs:\n      t: {type: string}\njobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: ${{ secrets.GITHUB_TOKEN }}\n          allowed_non_write_users: ${{ vars.AGENT_USERS }}\n          prompt: \"Triage this issue: ${{ inputs.t }}\"\n",
	}, &facts.Store{})
	wantRelated(t, rep, AIActionPromptInjectionID, "gate-expr", "a caller gives ")
}

// TestAIActionUnrestrictedTriggerInconclusiveRelated: labeler-unknown has
// the step of actions/labeler.
func TestAIActionUnrestrictedTriggerInconclusiveRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/ai-action-unrestricted-trigger/labeler-unknown", AIActionUnrestrictedTrigger)
	wantRelated(t, rep, AIActionUnrestrictedTriggerID, "labeler-unknown", "the step of actions/labeler that may add ")
}

// TestUnsecureCommandsInconclusiveRelated: structured-value has where the
// value comes from.
func TestUnsecureCommandsInconclusiveRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/unsecure-commands/structured-value.yml", UnsecureCommands)
	wantRelated(t, rep, UnsecureCommandsID, "structured-value", "$DESCRIPTION gets its value here")
}

// TestCachePoisoningInconclusiveRelated: the inconclusive places of the
// checkout of a pull request's code and its cache saves have the ref.
func TestCachePoisoningInconclusiveRelated(t *testing.T) {
	for _, k := range []string{"archive-substituted", "cache-path-unknown", "remote-unknown"} {
		rep := exampleReport(t, "inconclusive/cache-poisoning/"+k+".yml", CachePoisoning)
		wantRelated(t, rep, CachePoisoningID, k, "checks out the pull request's code")
	}
	rep := inlineReport(t, "on:\n  workflow_dispatch:\n    inputs:\n      ref: {type: string}\n  pull_request_target:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ inputs.ref }}\n      - uses: actions/cache/save@v4\n        with:\n          path: .\n          key: k\n", CachePoisoning)
	wantRelated(t, rep, CachePoisoningID, "input-dispatch", "steps[1] saves ")
}

// TestArgumentInjectionInconclusiveRelated: the places that hold a value
// an attacker may control have where the value comes from.
func TestArgumentInjectionInconclusiveRelated(t *testing.T) {
	for _, k := range []string{"undeclared-option", "value-head", "remote-program", "unverified-option"} {
		rep := exampleReport(t, "inconclusive/argument-injection/"+k+".yml", ArgumentInjection)
		wantRelated(t, rep, ArgumentInjectionID, k, "$")
	}
}

// TestArtifactPoisoningInconclusiveRelated: a download whose run, input
// or destination is not known has the places of the finding it would
// give.
func TestArtifactPoisoningInconclusiveRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/artifact-poisoning/input-dispatch.yml", ArtifactPoisoning)
	wantRelated(t, rep, ArtifactPoisoningID, "input-dispatch", "runs what the download puts")
	rep = exampleReport(t, "inconclusive/artifact-poisoning/download-input-unknown.yml", ArtifactPoisoning)
	wantRelated(t, rep, ArtifactPoisoningID, "download-input-unknown", "runs what the download puts")
	rep = exampleReport(t, "inconclusive/artifact-poisoning/download-path-unknown.yml", ArtifactPoisoning)
	wantRelated(t, rep, ArtifactPoisoningID, "download-path-unknown", "names the run of the pull request")
	for _, n := range relatedNotes(inconclusiveOf(rep, ArtifactPoisoningID, "download-path-unknown")[0]) {
		if strings.Contains(n, "runs what the download puts") {
			t.Errorf("download-path-unknown has a run: %s", n)
		}
	}
}

// TestAIActionExecutionOrderInconclusiveRelated: gate-expr and
// reach-unknown have the steps that run what the agent leaves.
func TestAIActionExecutionOrderInconclusiveRelated(t *testing.T) {
	for _, k := range []string{"gate-expr", "reach-unknown"} {
		rep := exampleReport(t, "inconclusive/ai-action-execution-order/"+k+".yml", AIActionExecutionOrder)
		wantRelated(t, rep, AIActionExecutionOrderID, k, "steps[2] runs npm test")
	}
}

// TestRequestForgeryInconclusiveRelated: a host whose value is not
// analyzed has the places of the secrets the request carries.
func TestRequestForgeryInconclusiveRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/request-forgery/env-dynamic.yml", RequestForgery)
	wantRelated(t, rep, RequestForgeryID, "env-dynamic", "the request carries DEPLOY_TOKEN here")
}

// TestSetOutputInjectionInconclusiveRelated: structured-value has where
// the value comes from.
func TestSetOutputInjectionInconclusiveRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/set-output-injection/structured-value.yml", SetOutputInjection)
	wantRelated(t, rep, SetOutputInjectionID, "structured-value", "$DESCRIPTION gets its value here")
}

// TestKnownVulnerableActionsInconclusiveRelated: archive-substituted has
// the step of the composite action that uses the action.
func TestKnownVulnerableActionsInconclusiveRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/known-vulnerable-actions/archive-substituted.yml", KnownVulnerableActions)
	wantRelated(t, rep, KnownVulnerableActionsID, "archive-substituted", "the step of the composite action ")
}

// TestSecretExfiltrationInconclusiveRelated: destination-unknown has the
// places of the secrets the request carries.
func TestSecretExfiltrationInconclusiveRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/secret-exfiltration/destination-unknown.yml", SecretExfiltration)
	wantRelated(t, rep, SecretExfiltrationID, "destination-unknown", "the request carries API_KEY here")
}

// TestAIActionExcessiveToolsInconclusiveRelated: a gate that is not
// decided has the step that lets the agent change what a permitted command
// runs, as the finding has it.
func TestAIActionExcessiveToolsInconclusiveRelated(t *testing.T) {
	rep := inlineReport(t, "on:\n  issues:\n    types: [opened]\njobs:\n  triage:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          github_token: ${{ secrets.GITHUB_TOKEN }}\n          allowed_non_write_users: ${{ vars.AGENT_USERS }}\n          prompt: \"Triage issue #${{ github.event.issue.number }}\"\n          claude_args: --allowedTools \"Edit,Bash(npm test)\"\n", AIActionExcessiveTools)
	wantRelated(t, rep, AIActionExcessiveToolsID, "gate-expr", "Edit lets the agent change what")
}

// TestAIActionUnsafeSandboxInconclusiveRelated: setting-expr, reached by a
// variable that an attacker writes, has the place of the variable.
func TestAIActionUnsafeSandboxInconclusiveRelated(t *testing.T) {
	src := strings.Replace(claudeJob("{issues: {types: [assigned]}}", ownerIf, "ubuntu-latest", "          prompt: \"${{ vars.P }}\"\n          claude_args: ${{ steps.s.outputs.args }}\n", ""),
		"    steps:\n", "    steps:\n      - id: s\n        run: echo \"args=--permission-mode bypassPermissions\" >> \"$GITHUB_OUTPUT\"\n", 1)
	found := false
	for _, f := range runBarriers(t, AIActionUnsafeSandboxID, src, analysis.BarrierPasses{}.With(analysis.BarrierVariableValue)) {
		if f.Certainty == lint.CertaintyInconclusive && f.InconclusiveKind.String() == "setting-expr" {
			found = true
			if len(f.Evidence) != 0 || !hasNote(f, "", "vars.P reaches the agent") {
				t.Errorf("related %v, evidence %+v: want the place of vars.P in Related, and no Evidence", relatedNotes(f), f.Evidence)
			}
		}
	}
	if !found {
		t.Error("no setting-expr")
	}
}

// TestLabelRelatedOfRules: the inconclusive finding of an undecided label
// of cache-poisoning and of artifact-poisoning has the step of
// actions/labeler; that of a checkout of a pull request's code that saves
// the tree to the cache also has the ref and the step that saves.
func TestLabelRelatedOfRules(t *testing.T) {
	rep := exampleReport(t, "inconclusive/cache-poisoning/label-paths", CachePoisoning)
	wantRelated(t, rep, CachePoisoningID, "label-paths", "the step of actions/labeler that may add ")
	labeled := "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  build:\n    if: github.event.label.name == 'safe-to-test'\n    runs-on: ubuntu-latest\n    cache-mode: write\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: actions/cache/save@v4\n        with:\n          path: .\n          key: k\n"
	labeler := "on: pull_request_target\npermissions: {}\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ secrets.LABELER_PAT }}\n"
	b, err := os.ReadFile("examples/inconclusive/cache-poisoning/label-paths.facts.json")
	if err != nil {
		t.Fatal(err)
	}
	store, err := facts.LoadStore(b)
	if err != nil {
		t.Fatal(err)
	}
	rep, _, _ = checkRules(t, []lint.Rule{CachePoisoning}, map[string]string{".github/workflows/labeled.yml": labeled, ".github/workflows/labeler.yml": labeler, ".github/labeler.yml": "safe-to-test:\n  - changed-files:\n      - all-globs-to-all-files: 'site/**'\n"}, store)
	wantRelated(t, rep, CachePoisoningID, "label-paths", "checks out the pull request's code")
	wantRelated(t, rep, CachePoisoningID, "label-paths", "steps[1] saves ")
	rep = exampleReport(t, "inconclusive/artifact-poisoning/label-paths", ArtifactPoisoning)
	wantRelated(t, rep, ArtifactPoisoningID, "label-paths", "the step of actions/labeler that may add ")
}

// TestSecretsInArtifactsGapRelated: an upload whose path is not known has
// the step that leaves the credential in Related; a step whose input that
// decides whether it leaves the credential is not known has the path of
// the upload.
func TestSecretsInArtifactsGapRelated(t *testing.T) {
	rep := exampleReport(t, "inconclusive/secrets-in-artifacts/upload-input-unknown.yml", SecretsInArtifacts)
	wantRelated(t, rep, SecretsInArtifactsID, "upload-input-unknown", "leaves the credential in a file of the workspace")
	rep = exampleReport(t, "inconclusive/secrets-in-artifacts/credential-input-unknown.yml", SecretsInArtifacts)
	wantRelated(t, rep, SecretsInArtifactsID, "credential-input-unknown", "the paths that the upload puts in the artifact")
}

// TestCachePoisoningDispatchNoRef: the inconclusive finding of a checkout
// whose ref has an input of workflow_dispatch does not say that the ref
// checks out the pull request's code, which the input decides.
func TestCachePoisoningDispatchNoRef(t *testing.T) {
	rep := inlineReport(t, "on:\n  workflow_dispatch:\n    inputs:\n      ref: {type: string}\n  pull_request_target:\njobs:\n  j:\n    runs-on: ubuntu-latest\n    permissions: {}\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ inputs.ref || github.event.pull_request.head.sha }}\n      - uses: actions/cache/save@v4\n        with:\n          path: .\n          key: k\n", CachePoisoning)
	for _, g := range inconclusiveOf(rep, CachePoisoningID, "input-dispatch") {
		if hasNote(g, "", "checks out the pull request's code") {
			t.Errorf("related %v: the ref is said to check out the pull request's code", relatedNotes(g))
		}
	}
	wantRelated(t, rep, CachePoisoningID, "input-dispatch", "steps[1] saves ")
}

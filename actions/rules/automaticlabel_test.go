package rules

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

const (
	labelerPAT = "on: pull_request_target\njobs:\n  label:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/labeler@v5\n        with:\n          repo-token: ${{ secrets.PAT }}\n"
	freeSafe   = "safe:\n  - head-branch: ['^x']\n"
	pathsSafe  = "safe:\n  - changed-files:\n      - all-globs-to-all-files: ['src/**']\n"
)

// TestLabelerTokenOwnerBesideOpenGate: a step that the attacker already
// starts through an open gate gets the finding of that gate alone, not a
// second one at the same place for the labeled runs.
func TestLabelerTokenOwnerBesideOpenGate(t *testing.T) {
	in := repoOf(t, map[string]string{
		".github/workflows/labeler.yml": labelerPAT,
		".github/labeler.yml":           freeSafe,
		".github/workflows/labeled.yml": "on:\n  pull_request_target:\n    types: [opened, labeled]\njobs:\n  j:\n    if: github.event.label.name == 'safe' || github.event.action == 'opened'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: Review the pull request\n",
	})
	rep := runAlone(t, AIActionUnrestrictedTrigger, in)
	if len(rep.Errors) != 0 {
		t.Fatalf("errors %+v", rep.Errors)
	}
	if got := kindsOf(rep); !slices.Equal(got, []lint.FindingKindID{kindAIActionUnrestrictedTriggerUnchecked}) {
		t.Errorf("got %v, want unchecked alone", got)
	}
}

// TestAutomaticLabelInconclusiveOnlyWhereReported: a labeled job whose label
// actions/labeler adds only on paths is inconclusive only where a free
// label would give a finding: not for a checkout of the base, a checkout
// that the guard refuses, a download of no run of the attacker, or a job
// with no token that writes and no secret.
func TestAutomaticLabelInconclusiveOnlyWhereReported(t *testing.T) {
	in := repoOf(t, map[string]string{
		".github/workflows/labeler.yml": labelerPAT,
		".github/labeler.yml":           pathsSafe,
		".github/workflows/labeled.yml": "on:\n  pull_request_target:\n    types: [labeled]\npermissions: {}\njobs:\n  base:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n  guarded:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v6\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n  download:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: x\n",
	})
	for _, r := range []lint.Rule{UntrustedCheckout, ArtifactPoisoning, DangerousTriggers} {
		rep := runAlone(t, r, in)
		var labeled []lint.Finding // the job of labeler.yml reads its token, which dangerous-triggers reports
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Location.File.Input.String() == ".github/workflows/labeled.yml" {
				labeled = append(labeled, f)
			}
		}
		if len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 || len(labeled) != 0 {
			t.Errorf("%s: inconclusive %+v, findings in labeled.yml %+v", r.Meta().ID, rep.FindingsWith(lint.CertaintyInconclusive), labeled)
		}
	}
}

// TestToctouEnvironmentWithLabeler: a job whose label actions/labeler adds
// and whose environment has required reviewers is approved by the
// reviewers, so untrusted-checkout-toctou reads its moving ref.
func TestToctouEnvironmentWithLabeler(t *testing.T) {
	in := repoOf(t, map[string]string{
		".github/workflows/labeler.yml": labelerPAT,
		".github/labeler.yml":           freeSafe,
		".github/workflows/labeled.yml": "on:\n  pull_request_target:\n    types: [labeled]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    environment: prod\n    steps:\n      - uses: actions/checkout@v4.2.2\n        with:\n          ref: ${{ github.event.pull_request.head.ref }}\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          allow-unsafe-pr-checkout: true\n      - run: npm ci\n",
	})
	store, err := facts.LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[{"query":{"kind":"repo.environment-protected","environment":"prod"},"state":"found","value":true}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rep := runWith(t, UntrustedCheckoutToctou, in, store)
	if got := kindsOf(rep); !slices.Equal(got, []lint.FindingKindID{kindUntrustedCheckoutToctouMutableRef}) {
		t.Errorf("got %v, want mutable-ref", got)
	}
}

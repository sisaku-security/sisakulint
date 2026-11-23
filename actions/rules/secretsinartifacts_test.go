package rules

import (
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestSecretsInArtifacts: the kinds of secrets-in-artifacts on uploads of
// files with secrets.
func TestSecretsInArtifacts(t *testing.T) {
	const up = "      - uses: actions/upload-artifact@v4\n        with: {path: .}\n"
	for _, c := range []struct {
		name, steps, kind string
	}{
		{"auth key", "      - uses: google-github-actions/auth@v2\n        with: {credentials_json: '${{ secrets.GCP }}'}\n" + up, "secrets-in-artifacts.lasting"},
		{"auth wif", "      - uses: google-github-actions/auth@v2\n        with: {workload_identity_provider: p}\n" + up + stepNext, "secrets-in-artifacts.job-scoped"},
		{"auth wif last", "      - uses: google-github-actions/auth@v2\n        with: {workload_identity_provider: p}\n" + up, "secrets-in-artifacts.job-scoped"},
		{"auth excluded", "      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n      - uses: actions/upload-artifact@v4\n        with:\n          path: |\n            .\n            !gha-creds-*.json\n", ""},
		{"dotnet dot", "      - uses: actions/setup-dotnet@v4\n        with: {source-url: s}\n" + up, ""},
		// @actions/glob refuses .., so path: .. fails the upload
		{"dotnet parent", "      - uses: actions/setup-dotnet@v4\n        with: {source-url: s}\n      - uses: actions/upload-artifact@v4\n        with: {path: ..}\n", ""},
		{"checkout is not this", coV4 + upHidden + stepNext, ""},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{SecretsInArtifacts}, wfFile(artifactJob("permissions: write-all\n", c.steps)), artifactFacts{})
		switch {
		case c.kind == "" && len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0:
			t.Errorf("%s: %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		case c.kind != "" && (len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != c.kind):
			t.Errorf("%s: %+v; want %s", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), c.kind)
		}
	}
}

// TestSecretsOnePerUpload: one finding for the upload however many steps
// before it leave a credential that it takes, with the first step as the
// evidence and the number of the others in the note.
func TestSecretsOnePerUpload(t *testing.T) {
	auth := "      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n"
	up := "      - uses: actions/upload-artifact@v4\n        with: {path: .}\n"
	rep, in, _ := checkRules(t, []lint.Rule{SecretsInArtifacts}, wfFile(artifactJob("", auth+auth+auth+up)), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	if !strings.Contains(textAt(t, in, f.Location), ".") || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0].Note, "2 more steps") || f.Anchor != f.Args.KindID().String() {
		t.Errorf("at %q, evidence %+v, anchor %q", textAt(t, in, f.Location), f.Evidence, f.Anchor)
	}
}

// TestSecretsKindsApart: a credential that lasts and one that works while
// the job runs, which one upload takes, are two findings of two kinds at
// the upload, with two fingerprints.
func TestSecretsKindsApart(t *testing.T) {
	lasting := "      - uses: google-github-actions/auth@v2\n        with: {credentials_json: x}\n"
	job := "      - uses: google-github-actions/auth@v2\n        with: {workload_identity_provider: x}\n"
	up := "      - uses: actions/upload-artifact@v4\n        with: {path: .}\n"
	rep, _, _ := checkRules(t, []lint.Rule{SecretsInArtifacts}, wfFile(artifactJob("", lasting+job+up)), artifactFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fingerprint == rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Fingerprint || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID() == rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Args.KindID() {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

package rules

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestUnmaskedSecretExposure: the kinds by repo.public, and the observed
// forms.
func TestUnmaskedSecretExposure(t *testing.T) {
	step := func(v string) map[string]string {
		return wfFile("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          X: \"" + v + "\"\n        run: \"true\"\n")
	}
	for _, c := range []struct {
		name   string
		files  map[string]string
		public *bool
		want   []string // kind, certainty, secrets
	}{
		{"unknown", step("${{ fromJSON(secrets.J).pass }}"), nil, []string{"unmasked-secret-exposure.public", "conditional", "J", "unmasked-secret-exposure.private", "conditional", "J"}}, // in the order of the fingerprints
		{"public", step("${{ fromJSON(secrets.J).pass }}"), ptr(true), []string{"unmasked-secret-exposure.public", "confirmed", "J"}},
		{"private", step("${{ fromJSON(secrets.J).pass }}"), ptr(false), []string{"unmasked-secret-exposure.private", "confirmed", "J"}},
		{"compared", step("${{ fromJSON(secrets.J).pass == 'x' }}"), ptr(true), nil},
		{"whole", step("${{ secrets.J }}"), ptr(true), nil},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{UnmaskedSecretExposure}, c.files, exposureFacts{public: c.public})
		var got []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			var s []string
			switch a := f.Args.(type) {
			case UnmaskedSecretExposurePublic:
				s = a.Secrets
			case UnmaskedSecretExposurePrivate:
				s = a.Secrets
			}
			got = append(got, f.Args.KindID().String(), certainty(f), strings.Join(s, ","))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestUnmaskedSecretExposureUpstream: sisakulint's example (17c2d82151a966e6e388a17619b060ae2919712e,
// script/actions/unmasked-secret-exposure.yaml). Six in vulnerable-job, as
// upstream, and one more in safe-job: its step's env has
// fromJson(secrets.CONFIG).apiKey, which the runner prints before the
// step's ::add-mask:: runs.
func TestUnmaskedSecretExposureUpstream(t *testing.T) {
	src, err := os.ReadFile("testdata/upstream/unmasked-secret-exposure.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rep, _, _ := checkRules(t, []lint.Rule{UnmaskedSecretExposure}, wfFile(string(src)), exposureFacts{public: ptr(true)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 7 {
		t.Errorf("%d findings: %+v", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestUnmaskedSecretExposureProbe: the workflows of the observed runs
// (testdata/observed/secret-exposure: the workflows
// of the runs, copied).
func TestUnmaskedSecretExposureProbe(t *testing.T) {
	dir := "testdata/observed/secret-exposure/3/.github/workflows/"
	for _, c := range []struct {
		file string
		want int
	}{
		// json: JOB_PASS, P, the run of run-user, reserialized, with-user;
		// not O (Object), C (false), nor the run of seen (no ${{ }})
		{"s1-secrets.yml", 5},
		// WORKFLOW_USER, the step's name, K, L
		{"s2-printed.yml", 4},
	} {
		src, err := os.ReadFile(dir + c.file)
		if err != nil {
			t.Fatal(err)
		}
		rep, _, _ := checkRules(t, []lint.Rule{UnmaskedSecretExposure}, wfFile(string(src)), exposureFacts{public: ptr(true)})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.want {
			t.Errorf("%s: %d findings: %+v", c.file, len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
}

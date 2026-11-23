package rules

import (
	"os"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// secretInLogFindings are the findings of secret-in-log in the workflow
// src, in a public repository, as "secret place transform" at their lines.
func secretInLogFindings(t *testing.T, src string) []string {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{SecretInLog}, wfFile(src), exposureFacts{public: ptr(true)})
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		a, ok := f.Args.(SecretInLogPublic)
		if !ok {
			t.Fatalf("a finding of %s in a public repository", f.Args.KindID())
		}
		b, _ := a.Place.MarshalJSON()
		out = append(out, a.Secret+" "+string(b)+" "+a.Transform)
	}
	return out
}

// TestSecretInLogKinds: the kinds by repo.public, as unmasked-secret-exposure.
func TestSecretInLogKinds(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          T: ${{ secrets.t }}\n        run: echo \"${T:0:4}\"\n"
	for _, c := range []struct {
		public *bool
		want   []string
	}{
		{nil, []string{"secret-in-log.public", "conditional", "secret-in-log.private", "conditional"}},
		{ptr(true), []string{"secret-in-log.public", "confirmed"}},
		{ptr(false), []string{"secret-in-log.private", "confirmed"}},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{SecretInLog}, wfFile(src), exposureFacts{public: c.public})
		var got []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got = append(got, f.Args.KindID().String(), certainty(f))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%v: got %q, want %q", c.public, got, c.want)
		}
	}
}

// TestSecretInLogProbe: the workflows of the observed runs. The lines are
// those taint's TestSecretLeaksObserved
// reads; here, one finding each, with the secret's name in upper case.
func TestSecretInLogProbe(t *testing.T) {
	dir := "testdata/observed/"
	for _, c := range []struct {
		file string
		want int
	}{
		// m03-m13, m15b, m17, m17w, m19a, D3, m27, DER, m22, m23, m24d
		{"secret-in-log/3/.github/workflows/l1-mask.yml", 21},
		// DERB, q1, q2, r1, r2, n22, n23 (run), OUT (env), n24
		{"secret-in-log/2/.github/workflows/l4-cross.yml", 9},
	} {
		src, err := os.ReadFile(dir + c.file)
		if err != nil {
			t.Fatal(err)
		}
		if got := secretInLogFindings(t, string(src)); len(got) != c.want {
			t.Errorf("%s: %d findings: %q", c.file, len(got), got)
		}
	}
}

// TestSecretInLogUpstream: sisakulint's examples
// (17c2d82151a966e6e388a17619b060ae2919712e, script/actions). Upstream
// reports the chained assignment and the direct echo of the vulnerable
// example, which the runner masks, and takes as safe the
// cross-step example of the safe one, whose $GITHUB_ENV the header of the
// next step prints before its ::add-mask:: runs.
func TestSecretInLogUpstream(t *testing.T) {
	for _, c := range []struct {
		file string
		want []string
	}{
		{"secret-in-log-vulnerable.yaml", []string{`GCP_SERVICE_ACCOUNT_KEY "github-env" jq`, `GCP_SERVICE_ACCOUNT_KEY "standard-output-or-error" jq`}},
		{"secret-in-log-safe.yaml", []string{`GCP_SERVICE_ACCOUNT_KEY "github-env" jq`}},
		{"goat-secret-in-build-log.yml", []string{`GCP_SERVICE_ACCOUNT_KEY "standard-output-or-error" jq`}},
	} {
		src, err := os.ReadFile("testdata/upstream/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		if got := secretInLogFindings(t, string(src)); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.file, got, c.want)
		}
	}
}

// TestPrintedOutputAnchorsDistinct: outputs
// printed at one key and twice in one value each get their own finding.
func TestPrintedOutputAnchorsDistinct(t *testing.T) {
	src := `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - id: a
        env: {A: "${{ secrets.A }}", B: "${{ secrets.B }}"}
        run: |
          echo "o=${A:0:2}${B:0:2}" >> "$GITHUB_OUTPUT"
          echo "p=${A:1:2}" >> "$GITHUB_OUTPUT"
      - env:
          X: ${{ steps.a.outputs.o }}
          Y: "${{ steps.a.outputs.p }} ${{ steps.a.outputs.p }}"
        run: make
`
	rep, _, _ := checkRules(t, []lint.Rule{SecretInLog}, wfFile(src), exposureFacts{public: ptr(true)})
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	var header []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if a := f.Args.(SecretInLogPublic); a.Place == analysis.LogPlaceStepHeader {
			header = append(header, a.Secret)
		}
	}
	if want := []string{"B", "A", "A", "A"}; !slices.Equal(header, want) {
		t.Errorf("step-header findings %q, want %q", header, want)
	}
}

package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// slowArgs are the args of a quality finding of the tests.
type slowArgs struct{}

func (slowArgs) KindID() lint.FindingKindID   { return lint.MustFindingKindID("test.slow") }
func (slowArgs) Detected() string             { return "slow" }
func (slowArgs) MarshalJSON() ([]byte, error) { return []byte(`{"kind_id":"test.slow"}`), nil }

// qualityReport is a report of two quality findings of one kind, the
// second conditional, and the inputs it is of.
func qualityReport(t *testing.T) (lint.Report, lint.Inputs) {
	t.Helper()
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: make\n")}})
	if err != nil {
		t.Fatal(err)
	}
	x := in.List[0]
	f := lint.QualityFinding{FindingDraft: lint.FindingDraft{Rule: lint.MustRuleID("test"), Location: lint.At(x, x.Workflow.Base), Args: slowArgs{}},
		Certainty: lint.CertaintyConfirmed, Consequence: "it runs long", Remedy: "end it"}
	g := f
	g.Certainty = lint.CertaintyConditional
	return lint.Report{Inputs: in.List, Complete: true, QualityRules: []lint.RuleID{lint.MustRuleID("test")}, QualityFindings: []lint.QualityFinding{f, g}}, in
}

func TestTextQuality(t *testing.T) {
	rep, in := qualityReport(t)
	got := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	for _, want := range []string{"quality\n", "test.slow  ×2", "2 quality findings: the bits do not count quality findings", "bits 0"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	var b bytes.Buffer
	if err := writeLines(&b, rep, in, registry(t), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), " quality test.slow: slow\n") || !strings.Contains(b.String(), " quality test.slow: slow [conditional]") {
		t.Errorf("%s", b.String())
	}
}

// TestRuleQualityOnly: --rule with a quality rule alone
// runs no rule, gives its quality findings and exits 0.
func TestRuleQualityOnly(t *testing.T) {
	dir := repo(t)
	got := run(t, args("--root", dir, "--rule", "missing-timeout-minutes"))
	if got.code != 0 || !strings.Contains(got.stdout, `"rules":[]`) || !strings.Contains(got.stdout, `"kind_id":"missing-timeout-minutes.job"`) || !strings.Contains(got.stdout, `"findings":[]`) {
		t.Errorf("exit %d, stderr %q, stdout %s", got.code, got.stderr, got.stdout)
	}
}

// TestExplainQuality: --explain takes the ID of a quality rule.
func TestExplainQuality(t *testing.T) {
	got := run(t, raw("--explain=missing-timeout-minutes"))
	if got.code != 0 || !strings.Contains(got.stdout, "quality rule") || !strings.Contains(got.stdout, "missing-timeout-minutes.job") && !strings.Contains(got.stdout, `missing\-timeout\-minutes\.job`) {
		t.Errorf("exit %d, stderr %q, stdout %s", got.code, got.stderr, got.stdout)
	}
	if got := run(t, raw("--explain=nothere")); got.code != ExitUsage || !strings.Contains(got.stderr, "missing-timeout-minutes") {
		t.Errorf("exit %d, stderr %q: the IDs named do not have the quality rules", got.code, got.stderr)
	}
}

// TestExamplesQuality: --examples=<quality rule> writes the catalog of the
// quality rule alone, as --examples=<rule> does of a rule.
func TestExamplesQuality(t *testing.T) {
	p := t.TempDir() + "/c.html"
	got := run(t, raw("--examples=missing-timeout-minutes", "--html", p))
	if got.code != 0 {
		t.Fatalf("exit %d, stderr %q", got.code, got.stderr)
	}
	page, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte(`"rule":"missing-timeout-minutes","quality":true,"meta"`)) || bytes.Contains(page, []byte(`"quality":false,"meta"`)) {
		t.Error("the catalog is not of the quality rule alone")
	}
}

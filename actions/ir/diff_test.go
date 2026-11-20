package ir

import (
	"slices"
	"strings"
	"testing"

	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// allFields are the fields of every summary type, in the order of Field.
func allFields() []SummaryField {
	var out []SummaryField
	for f := fieldUnset + 1; f < fieldCount; f++ {
		out = append(out, f)
	}
	return out
}

var usesFields = []SummaryField{FieldUsesRepo, FieldUsesRef, FieldUsesExact, FieldUsesLevel, FieldUsesUsesText}

// TestDiffFields: a ref changed is uses.ref of that summary only; uses.uses-text,
// only for the text of a finding, is not compared; a summary no field of
// fields changed is not given.
func TestDiffFields(t *testing.T) {
	before := newIR(t, usesWorkflow)
	after := newIR(t, strings.Replace(usesWorkflow, "actions/checkout@v4", "actions/checkout@v5", 1))
	got := Diff(before, after, usesFields)
	if len(got) != 1 || got[0].Key.Path() != "jobs.build.steps[0].uses" || !slices.Equal(got[0].Fields, []SummaryField{FieldUsesRef}) {
		t.Fatalf("got %+v", got)
	}
	if got := Diff(before, after, []SummaryField{FieldUsesRepo}); len(got) != 0 {
		t.Errorf("fields that did not change: %+v", got)
	}
}

// TestDiffOneSide: a summary only before, or only after,
// has every field compared changed, of those asked for; one only after
// holds no edit, as it has no place in the bytes before.
func TestDiffOneSide(t *testing.T) {
	with := newIR(t, usesWorkflow)
	without := newIR(t, strings.Replace(usesWorkflow, "  call:\n    uses: o/r/.github/workflows/w.yml@v1\n", "", 1))
	want := []SummaryField{FieldUsesRepo, FieldUsesRef, FieldUsesExact, FieldUsesLevel}
	gone := Diff(with, without, usesFields)
	if len(gone) != 1 || gone[0].Key.Path() != "jobs.call.uses" || !slices.Equal(gone[0].Fields, want) {
		t.Fatalf("gone: %+v", gone)
	}
	i := strings.Index(usesWorkflow, "@v1") + 1
	if !gone[0].Holds(edit.Edit{Span: cst.Span{Start: i, End: i + 2}}) {
		t.Error("an edit in the uses gone is not in its summary")
	}
	added := Diff(without, with, usesFields)
	if len(added) != 1 || added[0].Key.Path() != "jobs.call.uses" || !slices.Equal(added[0].Fields, want) || added[0].Holds(edit.Edit{Span: cst.Span{Start: 0, End: len(usesWorkflow)}}) {
		t.Fatalf("added: %+v", added)
	}
}

// TestDiffHolds: an edit is in a summary when the element of a handle of
// it, before the fix, has the edit's span; not when it is elsewhere.
func TestDiffHolds(t *testing.T) {
	before := newIR(t, usesWorkflow)
	after := newIR(t, strings.Replace(usesWorkflow, "actions/checkout@v4", "actions/checkout@v5", 1))
	c := Diff(before, after, []SummaryField{FieldUsesRef})[0]
	i := strings.Index(usesWorkflow, "@v4") + 1
	if !c.Holds(edit.Edit{Span: cst.Span{Start: i, End: i + 2}}) {
		t.Error("the edit of the ref is not in the summary of its uses")
	}
	j := strings.Index(usesWorkflow, "on: push")
	if c.Holds(edit.Edit{Span: cst.Span{Start: j, End: j + 2}}) {
		t.Error("an edit of on is in the summary of a uses")
	}
}

// TestDiffMakesOnlyItsTypes: only the summary types of the fields asked
// for are made, in both IRs.
func TestDiffMakesOnlyItsTypes(t *testing.T) {
	before, after := newIR(t, usesWorkflow), newIR(t, usesWorkflow)
	Diff(before, after, []SummaryField{FieldUsesRef})
	for _, x := range []*IR{before, after} {
		if x.Made(SummaryUses) != 1 || x.Made(SummarySink) != 0 || x.Made(SummaryCheckoutSite) != 0 || x.Made(SummaryStepFix) != 0 {
			t.Errorf("made uses %d, sinks %d, sites %d, fixes %d", x.Made(SummaryUses), x.Made(SummarySink), x.Made(SummaryCheckoutSite), x.Made(SummaryStepFix))
		}
	}
}

const siteAndSink = `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}" && npm ci
`

// TestDiffEditElsewhere: an edit of another line keeps every field of the
// summaries of every type (Uses, CheckoutSite and Sink).
func TestDiffEditElsewhere(t *testing.T) {
	if got := Diff(newIR(t, siteAndSink), newIR(t, "# a comment\n"+siteAndSink), allFields()); len(got) != 0 {
		t.Errorf("got %+v", got)
	}
	if n := len(newIR(t, siteAndSink).allCheckoutSites()); n != 1 {
		t.Fatalf("sites %d: the input is not what the test is for", n)
	}
	if n := len(newIR(t, siteAndSink).allSinks()); n != 1 {
		t.Fatalf("sinks %d: the input is not what the test is for", n)
	}
}

// TestDiffUpload: an edit of another line keeps the fields of Upload and
// LeftCredential; persist-credentials false on the checkout (what
// artipacked's fix changes) takes the
// LeftCredential away, every field of it, and changes
// upload.taken-credentials only. The indices are compared by place: when
// the credential of an earlier step goes, an upload that takes a later one
// changes too, which reads more rules again, not fewer.
func TestDiffUpload(t *testing.T) {
	if got := Diff(newIR(t, uploadWF), newIR(t, "# a comment\n"+uploadWF), allFields()); len(got) != 0 {
		t.Errorf("elsewhere: %+v", got)
	}
	after := strings.Replace(uploadWF, "      - uses: actions/checkout@v4\n", "      - uses: actions/checkout@v4\n        with: {persist-credentials: false}\n", 1)
	got := Diff(newIR(t, uploadWF), newIR(t, after), allFields())
	var fields [][]SummaryField
	for _, c := range got {
		fields = append(fields, c.Fields)
	}
	want := [][]SummaryField{{FieldLeftCredentialFile, FieldLeftCredentialLifetime, FieldLeftCredentialMissingCommits, FieldLeftCredentialCheckout}, {FieldUploadTakenCredentials}}
	if !slices.EqualFunc(fields, want, slices.Equal) {
		t.Errorf("persist false: %+v", got)
	}
	two := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with: {path: a}\n      - uses: actions/checkout@v4\n        with: {path: b}\n      - uses: actions/upload-artifact@v4\n        with: {path: b, include-hidden-files: true}\n      - uses: actions/upload-artifact@v4\n        with: {path: a, include-hidden-files: true}\n"
	after = strings.Replace(two, "with: {path: a}\n", "with: {path: a, persist-credentials: false}\n", 1)
	var changed []string
	for _, c := range Diff(newIR(t, two), newIR(t, after), allFields()) {
		if slices.Contains(c.Fields, FieldUploadTakenCredentials) {
			changed = append(changed, c.Key.Path())
		}
	}
	if want := []string{"jobs.a.steps[2]", "jobs.a.steps[3]"}; !slices.Equal(changed, want) {
		t.Errorf("an index that moves: %v, want %v", changed, want)
	}
}

// TestDiffJob: an edit of another line keeps the fields of Job, and
// permissions written on the job changes job.token-write only.
func TestDiffJob(t *testing.T) {
	if got := Diff(newIR(t, jobWF), newIR(t, "# a comment\n"+jobWF), allFields()); len(got) != 0 {
		t.Errorf("%+v", got)
	}
	after := strings.Replace(jobWF, "    environment: production\n", "    environment: production\n    permissions: {contents: write}\n", 1)
	got := Diff(newIR(t, jobWF), newIR(t, after), allFields())
	if len(got) != 1 || !slices.Equal(got[0].Fields, []SummaryField{FieldJobTokenWrite}) {
		t.Errorf("%+v", got)
	}
}

// TestDiffImageSite: an edit of another line keeps the fields of ImageSite
// and RegistryCredentials, and a digest written changes image-site.images
// only.
func TestDiffImageSite(t *testing.T) {
	if got := Diff(newIR(t, imageWF), newIR(t, "# a comment\n"+imageWF), allFields()); len(got) != 0 {
		t.Errorf("%+v", got)
	}
	after := strings.Replace(imageWF, "docker://alpine:3", "docker://alpine:3@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1)
	got := Diff(newIR(t, imageWF), newIR(t, after), allFields())
	if len(got) != 1 || !slices.Equal(got[0].Fields, []SummaryField{FieldImageSiteImages}) {
		t.Errorf("%+v", got)
	}
}

// TestDiffAgentStep: an edit of another line keeps the fields of
// AgentStep, and commit-sha's pin of the action changes none.
func TestDiffAgentStep(t *testing.T) {
	if got := Diff(newIR(t, agentWF), newIR(t, "# a comment\n"+agentWF), allFields()); len(got) != 0 {
		t.Errorf("elsewhere: %+v", got)
	}
	after := strings.Replace(agentWF, "anthropics/claude-code-action@v1", "anthropics/claude-code-action@6fed3ca145920b639991cb756090506e1bcaf515", 1)
	for _, c := range Diff(newIR(t, agentWF), newIR(t, after), allFields()) {
		for _, f := range c.Fields {
			if fieldSummary[f] == SummaryAgentStep {
				t.Errorf("pinned: %v changed", f)
			}
		}
	}
}

// TestDiffPromptRefs: an edit of another line keeps prompt-refs, and
// code-injection's fix of a run elsewhere changes none of them.
func TestDiffPromptRefs(t *testing.T) {
	if got := Diff(newIR(t, promptWF), newIR(t, "# a comment\n"+promptWF), allFields()); len(got) != 0 {
		t.Errorf("elsewhere: %+v", got)
	}
}

// TestDiffTools: an edit of another line keeps the grants, the undecided
// permissions and the setting references.
func TestDiffTools(t *testing.T) {
	if got := Diff(newIR(t, toolsWF), newIR(t, "# a comment\n"+toolsWF), allFields()); len(got) != 0 {
		t.Errorf("elsewhere: %+v", got)
	}
}

// TestDiffLater: an edit of another line keeps the fields of the later
// steps.
func TestDiffLater(t *testing.T) {
	if got := Diff(newIR(t, orderWF), newIR(t, "# a comment\n"+orderWF), allFields()); len(got) != 0 {
		t.Errorf("elsewhere: %+v", got)
	}
}

// TestDiffSecrets: an edit of another line keeps the fields of the reads
// of the secrets context and of the parts of secrets.
func TestDiffSecrets(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - env:\n          X: ${{ toJSON(secrets) }}\n          Y: ${{ fromJSON(secrets.J).u }}\n        run: \"true\"\n"
	if got := Diff(newIR(t, src), newIR(t, "# a comment\n"+src), allFields()); len(got) != 0 {
		t.Errorf("elsewhere: %+v", got)
	}
}

package github

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
)

// TestWorkflowDefinition: workflow.definition answers the blob of the file
// at the commit of the ref, with export-subst's placeholders as they are
// (GitHub runs the commit's file); a file the commit lacks is absent, and
// one the token cannot read, or too large, unknown.
func TestWorkflowDefinition(t *testing.T) {
	const called = "on: workflow_call\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo 'SUBST[$Format:%H$]'\n"
	f := &fake{answers: map[string]func(http.ResponseWriter){
		"/repos/o/r/commits/refs/tags/v1":                              body(200, shaA),
		"/repos/o/r/contents/.github/workflows/called.yml?ref=" + shaA: body(200, called),
		"/repos/o/r/contents/.github/workflows/none.yml?ref=" + shaA:   body(404, notFoundBody),
		"/repos/o/r/contents/.github/workflows/denied.yml?ref=" + shaA: body(403, `{"message":"Resource not accessible by integration"}`),
		"/repos/o/r/contents/.github/workflows/large.yml?ref=" + shaA:  body(200, strings.Repeat("#", maxDefinition+1)),
	}}
	r := startWith(t, f, Options{Token: "t"})
	ctx := context.Background()
	at := func(p, ref string) facts.Answer[facts.WorkflowFile] {
		path, err := facts.ParseUsesPath(p)
		if err != nil {
			t.Fatal(err)
		}
		return facts.WorkflowDefinition{Repo: mustRepo(t, "o/r"), Path: path, Ref: ref}.Ask(ctx, r)
	}
	if got := at(".github/workflows/called.yml", "v1"); got.State != facts.StateFound || got.Value.Content != called || got.Value.Commit.String() != shaA {
		t.Errorf("called: %+v", got)
	}
	if got := at(".github/workflows/none.yml", "v1"); got.State != facts.StateAbsent {
		t.Errorf("a file the commit lacks: %+v, want absent", got)
	}
	if got := at(".github/workflows/denied.yml", "v1"); got.State != facts.StateUnknown || !strings.Contains(got.Reason, "403") {
		t.Errorf("a file the token cannot read: %+v, want unknown", got)
	}
	if got := at(".github/workflows/large.yml", "v1"); got.State != facts.StateUnknown || !strings.Contains(got.Reason, "larger") {
		t.Errorf("a file too large: %+v, want unknown", got)
	}
	if got := at(".github/workflows/called.yml", "gone"); got.State == facts.StateFound {
		t.Errorf("a ref that is not there: %+v, want no answer", got)
	}
}

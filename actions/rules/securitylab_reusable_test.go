package rules

import (
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// TestAdvisoryCallerForms: each example of an advisory (# advisory:) that is
// a caller and a reusable workflow (.github/workflows/caller.yml and
// called.yml) is run with every rule in two forms: the called workflow in
// the same repository, as the example is, and in another repository that
// workflow.definition answers. Both forms give the kind of the example's
// declaration, and the same number of each kind of finding and of
// inconclusive place of the example's rule. The workflows of the advisories
// were read at the commit each example names, with gh api
// 'repos/<owner>/<repo>/contents/.github/workflows/<file>?ref=<commit>' -H
// 'Accept: application/vnd.github.raw'.
func TestAdvisoryCallerForms(t *testing.T) {
	const local, remote = "./.github/workflows/called.yml", "o/wf/.github/workflows/called.yml@v1"
	n := 0
	for _, x := range Examples() {
		e := x.Example
		if len(e.Notes.Advisories) == 0 || e.Name.String() != ".github/workflows/called.yml" || len(e.Others) != 1 || e.Others[0].Name.String() != ".github/workflows/caller.yml" {
			continue
		}
		n++
		caller := e.Others[0].Text
		if !strings.Contains(caller, local) {
			t.Errorf("%s: the caller does not call %s", x.Path, local)
			continue
		}
		decl, _, _ := strings.Cut(x.ID, ".")
		want := x.Rule.String() + "." + decl
		if x.What == lint.ExampleInconclusive {
			want = x.Rule.String() + " " + decl
		}
		var got [2]map[string]int
		for i, files := range []map[string]string{
			{".github/workflows/caller.yml": caller, ".github/workflows/called.yml": e.Text},
			{".github/workflows/caller.yml": strings.Replace(caller, local, remote, 1)},
		} {
			rep, _, _ := checkRules(t, All(), files, remoteDefs{"o/wf": e.Text})
			got[i] = map[string]int{}
			for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
				if f.Rule == x.Rule {
					got[i][f.Args.KindID().String()]++
				}
			}
			for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
				if g.Rule == x.Rule && g.InconclusiveKind.String() != "remote-callee-unknown" {
					got[i][g.Rule.String()+" "+g.InconclusiveKind.String()]++
				}
			}
			if got[i][want] == 0 {
				t.Errorf("%s, form %d: no %s in %v", x.Path, i, want, got[i])
			}
		}
		for k, c := range got[0] {
			if got[1][k] != c {
				t.Errorf("%s: %d of %s in the same repository, %d in another", x.Path, c, k, got[1][k])
			}
		}
		for k, c := range got[1] {
			if _, ok := got[0][k]; !ok {
				t.Errorf("%s: %d of %s in another repository, none in the same", x.Path, c, k)
			}
		}
	}
	if n == 0 {
		t.Error("no example of an advisory is a caller and a reusable workflow")
	}
}

package ir

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

const downloadWF = `on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ github.token }}
      - run: npm ci
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: x
`

// TestDownloadSitesAreTheProjection: each summary has what
// prcode.AnalyzeDownloads gives of its site; a download no privileged
// event reaches has none.
func TestDownloadSitesAreTheProjection(t *testing.T) {
	tree, w := parse(t, downloadWF)
	var want []prcode.DownloadSite
	for _, s := range prcode.AnalyzeDownloads(w, nil, nil) {
		if len(s.PRCodeOn) > 0 {
			want = append(want, s)
		}
	}
	got := New(".github/workflows/w.yml", tree, w, nil).allDownloadSites()
	if len(got) != len(want) || len(got) != 2 {
		t.Fatalf("got %d, want %d", len(got), len(want))
	}
	g := got[0]
	if len(g.prRunRefs) != 1 || g.prRunRefs[0].Input != analysis.DownloadInputRunID || g.prRunRefs[0].Text != "github.event.workflow_run.id" ||
		g.destination != analysis.DownloadDestinationWorkspace || len(g.codeRunSteps) != 1 || g.actionsRead != analysis.ActionsReadUnwritten || g.stepPath != want[0].Path {
		t.Errorf("%+v", g)
	}
	if g.key.Path() != "jobs.a.steps[0]" {
		t.Errorf("key %s", g.key)
	}
	if len(got[1].prRunRefs) != 0 {
		t.Errorf("no token: %+v", got[1])
	}
}

// TestRunnerTempPath: the fix inserts path into with, or with itself; a
// written path gets no fix.
func TestRunnerTempPath(t *testing.T) {
	for _, c := range []struct {
		name, with, want string
		fix              bool
	}{
		{"with", "        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n", "path: ${{ runner.temp }}/artifacts", true},
		{"no with", "", "with:\n          path: ${{ runner.temp }}/artifacts", true},
		{"a path", "        with:\n          run-id: ${{ github.event.workflow_run.id }}\n          github-token: ${{ github.token }}\n          path: dist\n", "", false},
	} {
		uses := "actions/download-artifact@v4"
		if c.name == "no with" {
			uses = "dawidd6/action-download-artifact@v3"
		}
		x := newIR(t, "on: {workflow_run: {workflows: [ci], types: [completed]}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: "+uses+"\n"+c.with+"      - run: npm ci\n")
		sites := x.allDownloadSites()
		if len(sites) != 1 {
			t.Fatalf("%s: %d sites", c.name, len(sites))
		}
		p := sites[0].runnerTempPath(x.RuleAccess())
		if (p.Fix != nil) != c.fix {
			t.Fatalf("%s: %+v", c.name, p)
		}
		if !c.fix {
			if p.NoFix == nil || p.NoFix.Reason != NoFixReasonManual {
				t.Errorf("%s: %+v", c.name, p.NoFix)
			}
			continue
		}
		res, err := edit.Apply(x.tree, p.Fix.Edits)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(res.Tree.Bytes()); !strings.Contains(got, c.want) {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, c.want)
		}
	}
}

// TestDiffDownloadSite: an edit of another line keeps the fields of
// DownloadSite, and RunnerTempPath's path changes the destination and the
// steps that run what it puts.
func TestDiffDownloadSite(t *testing.T) {
	if got := Diff(newIR(t, downloadWF), newIR(t, "# a comment\n"+downloadWF), allFields()); len(got) != 0 {
		t.Errorf("elsewhere: %+v", got)
	}
	after := strings.Replace(downloadWF, "          github-token: ${{ github.token }}\n", "          github-token: ${{ github.token }}\n          path: ${{ runner.temp }}/artifacts\n", 1)
	got := Diff(newIR(t, downloadWF), newIR(t, after), allFields())
	if len(got) != 1 || !slices.Equal(got[0].Fields, []SummaryField{FieldDownloadSiteDestination, FieldDownloadSiteCodeRunSteps}) {
		t.Errorf("runner.temp: %+v", got)
	}
}

package rules

import (
	"context"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// storeOf is a file of facts of the entries, each a JSON object of
// facts-v0.json#/$defs/entry.
func storeOf(t *testing.T, entries ...string) facts.Resolver {
	t.Helper()
	s, err := facts.LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[` + strings.Join(entries, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// qualityReportFS runs the quality rule id alone on the files of fsys,
// with r answering the facts.
func qualityReportFS(t *testing.T, id lint.RuleID, fsys fstest.MapFS, r facts.Resolver) lint.Report {
	t.Helper()
	in, err := lint.Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	all, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := lint.ParseSelector(id.String())
	if err != nil {
		t.Fatal(err)
	}
	reg, err := all.Select(lint.Only(sel), lint.FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(context.Background(), in, reg, r)
	for _, e := range rep.Errors {
		t.Errorf("internal error: %+v", e)
	}
	return rep
}

func TestArchivedUses(t *testing.T) {
	fsys := fstest.MapFS{
		".github/workflows/w.yml": {Data: []byte(`on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/create-release@v1
      - uses: actions/checkout@v5
      - uses: ./local
      - uses: docker://alpine:3
  b:
    uses: Old-Org/Workflows/.github/workflows/ci.yml@v1
`)},
		"local/action.yml": {Data: []byte("name: x\ndescription: y\nruns:\n  using: composite\n  steps:\n    - uses: actions/create-release@v1\n")},
	}
	archived := storeOf(t,
		`{"query":{"kind":"repo.archived","repo":"actions/create-release"},"state":"found","value":true}`,
		`{"query":{"kind":"repo.archived","repo":"actions/checkout"},"state":"found","value":false}`,
		`{"query":{"kind":"repo.archived","repo":"old-org/workflows"},"state":"found","value":true}`)
	rep := qualityReportFS(t, ArchivedUsesID, fsys, archived)
	var got []string
	for _, f := range rep.QualityFindings {
		if f.Certainty != lint.CertaintyConfirmed {
			t.Errorf("%s: %v", f.Detected(), f.Certainty)
		}
		got = append(got, f.Location.File.Input.String()+": "+f.Detected())
	}
	slices.Sort(got)
	want := []string{
		".github/workflows/w.yml: Old-Org/Workflows/.github/workflows/ci.yml@v1 names old-org/workflows, a repository that is archived",
		".github/workflows/w.yml: actions/create-release@v1 names actions/create-release, a repository that is archived",
		"local/action.yml: actions/create-release@v1 names actions/create-release, a repository that is archived",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// with no answer, each uses of another repository is conditional, and
	// ./local and docker:// are not asked about
	rep = qualityReportFS(t, ArchivedUsesID, fsys, storeOf(t))
	if len(rep.QualityFindings) != 4 {
		t.Fatalf("%d findings, want 4", len(rep.QualityFindings))
	}
	for _, f := range rep.QualityFindings {
		if f.Certainty != lint.CertaintyConditional {
			t.Errorf("%s: %v", f.Detected(), f.Certainty)
		}
		for _, q := range f.Condition.Queries() {
			if a, ok := q.(facts.RepoArchived); !ok || a.Repo.String() == "" {
				t.Errorf("asks %#v", q)
			}
		}
	}
}

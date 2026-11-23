package reportview

import (
	"slices"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

func TestFiles(t *testing.T) {
	quiet := "on: push\npermissions: {}\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	crlf := "on: issues\r\npermissions: {}\r\njobs:\r\n  b:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - run: echo \"${{ github.event.issue.title }}\""
	rep, in := runOn(t, map[string]string{
		".github/workflows/a.yml":     injected,
		".github/workflows/quiet.yml": quiet,
		".github/workflows/crlf.yml":  crlf,
	})
	p, err := Build(rep, in, testRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range p.Files {
		names = append(names, f.Input.String())
	}
	if want := []string{".github/workflows/a.yml", ".github/workflows/crlf.yml"}; !slices.Equal(names, want) {
		t.Fatalf("files %q, want %q", names, want)
	}
	a, c := p.Files[0], p.Files[1]
	if len(a.Lines) != 8 || a.Lines[7] != `        run: echo "${{ github.event.issue.title }}"` {
		t.Errorf("a.yml: %d lines, last %q", len(a.Lines), a.Lines[len(a.Lines)-1])
	}
	if len(c.Lines) != 7 || c.Lines[0] != "on: issues" || c.Lines[6] != `      - run: echo "${{ github.event.issue.title }}"` {
		t.Errorf("crlf.yml: %q", c.Lines)
	}
}

// A file of a place of a finding is held; a file of a fact is not.
func TestFilesOfInconclusiveAndFacts(t *testing.T) {
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte("on: push\njobs: {}\n")}})
	if err != nil {
		t.Fatal(err)
	}
	name := inputPath(t, ".github/workflows/w.yml")
	q, err := facts.EncodeQuery(facts.RepoPublic{})
	if err != nil {
		t.Fatal(err)
	}
	p := Page{Findings: []Finding{{Path: []Node{{Role: RoleFinding, Query: q}}}, {Path: []Node{{Role: RoleFinding, Input: &name, Line: 1}}}}}
	got := filesOf(p, in)
	if len(got) != 1 || got[0].Input != name || !slices.Equal(got[0].Lines, []string{"on: push", "jobs: {}"}) {
		t.Errorf("%+v", got)
	}
}

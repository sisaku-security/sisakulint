package reportview

import (
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

const uploading = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Upload
        uses: actions/upload-artifact@v4
        with:
          name: all
          path: .
      - name: Long
        run: |
          echo 1
          echo 2
          echo 3
          echo 4
          echo 5
          echo 6
          echo 7
          echo 8
          echo 9
          echo 10
          echo 11
          echo 12
          echo 13
          echo 14
`

func TestSnippet(t *testing.T) {
	in, err := lint.Enumerate(fstest.MapFS{".github/workflows/w.yml": {Data: []byte(uploading)}})
	if err != nil {
		t.Fatal(err)
	}
	job := in.List[0].Workflow.Jobs.Value.Entries[0].Value.Value
	upload := job.Steps.Value.Items[1]
	path, _ := upload.With.Value.Lookup("path")
	n, err := nodeOf(in, RoleFinding, lint.At(in.List[0], path.Value.Value.Base), "")
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, s := range n.Snippet {
		texts = append(texts, strings.TrimSpace(s.Text))
	}
	if !slices.Equal(texts, []string{"- name: Upload", "uses: actions/upload-artifact@v4", "with:", "name: all", "path: ."}) {
		t.Errorf("snippet %q", texts)
	}
	if i := slices.IndexFunc(n.Snippet, func(s SnippetLine) bool { return s.At }); i != 4 || n.Snippet[i].Line != 13 {
		t.Errorf("the line of the place in %+v", n.Snippet)
	}

	long := job.Steps.Value.Items[2]
	l := lint.AtSpan(in.List[0], long.Run.Value.Base, long.Run.Value.Base.Primary(), true)
	l.Span.Start = strings.Index(uploading, "echo 12")
	l.Span.End = l.Span.Start + len("echo 12")
	n, err = nodeOf(in, RoleFinding, l, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Snippet) > maxSnippet {
		t.Errorf("%d lines, more than %d", len(n.Snippet), maxSnippet)
	}
	if i := slices.IndexFunc(n.Snippet, func(s SnippetLine) bool { return s.At }); i < 0 || strings.TrimSpace(n.Snippet[i].Text) != "echo 12" {
		t.Errorf("the line of the place is not in %+v", n.Snippet)
	}
	if strings.TrimSpace(n.Snippet[0].Text) != "- name: Long" {
		t.Errorf("the head of the step is not first: %+v", n.Snippet[0])
	}

	perm := lint.At(in.List[0], job.Permissions.Value.Base)
	if n, err = nodeOf(in, RoleFinding, perm, ""); err != nil || n.Snippet != nil {
		t.Errorf("a place out of steps: %+v %v", n.Snippet, err)
	}
}

package lint

import (
	"testing"
	"testing/fstest"
)

func TestRunReadsLabelerConfig(t *testing.T) {
	fsys := fstest.MapFS{
		".github/labeler.yml": {Data: []byte("safe-to-test:\n  - head-branch: ['^x']\n")},
		".github/workflows/labeler.yml": {Data: []byte(`on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
        with:
          repo-token: ${{ secrets.PAT }}
`)},
	}
	whole, err := Enumerate(fsys)
	if err != nil {
		t.Fatal(err)
	}
	steps := lazyLabelers(whole)().Steps()
	if len(steps) != 1 || steps[0].Unknown || len(steps[0].Labels) != 1 {
		t.Errorf("the whole repository: got %v, want one step with the label safe-to-test", steps)
	}
	files, err := Files(fsys, []string{".github/workflows/labeler.yml"})
	if err != nil {
		t.Fatal(err)
	}
	if got := lazyLabelers(files)().Steps(); len(got) != 0 {
		t.Errorf("a file named: got %v, want no steps (the other files are not read)", got)
	}
	ex, err := ParseExclude(".github/labeler.yml")
	if err != nil {
		t.Fatal(err)
	}
	excluded, err := EnumerateExcept(fsys, []Exclude{ex})
	if err != nil {
		t.Fatal(err)
	}
	if got := lazyLabelers(excluded)().Steps(); len(got) != 1 || !got[0].Unknown {
		t.Errorf("the configuration excluded: got %v, want one step not known", got)
	}
}

package rules

import (
	"fmt"
	"slices"
	"testing"
)

func TestCacheBloat(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{"unified", `on: [push, issue_comment]
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: ~/.npm, key: "npm-${{ hashFiles('package-lock.json') }}", restore-keys: npm-}
`, "cache-bloat.partial-restore: the step may save under a new key the content of an older cache that restore-keys restored; the events on which the step may save: push"},
		{"README of actions/cache/save", `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Restore cached Prime Numbers
        id: cache-prime-numbers-restore
        uses: actions/cache/restore@v5
        with:
          key: ${{ runner.os }}-prime-numbers
          path: |
            path/to/dependencies
      - name: Always Save Prime Numbers
        if: always() && steps.cache-prime-numbers-restore.outputs.cache-hit != 'true'
        uses: actions/cache/save@v5
        with:
          key: ${{ steps.cache-prime-numbers-restore.outputs.cache-primary-key }}
          path: |
            path/to/dependencies
`, ""},
		{"upstream's advice", `on: [push, pull_request]
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache/restore@v4
        if: github.event_name != 'push'
        with: {path: p, key: "k-${{ github.sha }}", restore-keys: k-}
      - uses: actions/cache/save@v4
        if: github.event_name == 'push'
        with: {path: p, key: "k-${{ github.sha }}"}
`, ""},
		{"another path saved", `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache/restore@v4
        with: {path: a, key: "a-${{ github.sha }}", restore-keys: a-}
      - uses: actions/cache/save@v4
        with: {path: b, key: "b-${{ github.sha }}"}
`, ""},
		{"actions/cache after a restore of its path", `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache/restore@v4
        with: {path: a, key: "a-${{ github.sha }}", restore-keys: a-}
      - run: make
      - uses: actions/cache@v4
        with: {path: a, key: "a-${{ github.run_id }}"}
`, "cache-bloat.partial-restore: the step may save under a new key the content of an older cache that restore-keys restored; the events on which the step may save: push"},
		{"restore-keys of one expression", `on: workflow_dispatch
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: a, key: "a-${{ github.sha }}", restore-keys: "${{ inputs.restore-keys }}"}
`, ""},
		{"restore-keys of text and an expression", `on: workflow_dispatch
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache@v4
        with: {path: a, key: "a-${{ github.sha }}", restore-keys: "${{ runner.os }}-a-"}
`, "cache-bloat.partial-restore: the step may save under a new key the content of an older cache that restore-keys restored; the events on which the step may save: workflow_dispatch"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := qualityKinds(t, CacheBloatID, c.src)
			if (c.want == "") != (len(got) == 0) || c.want != "" && got[0] != c.want {
				t.Errorf("%v, want %q", got, c.want)
			}
		})
	}
}

// TestCacheBloatRelated: the restore beside a save is the last one before
// it of a path the save saves.
func TestCacheBloatRelated(t *testing.T) {
	src := `on: push
jobs:
  a:
    runs-on: x
    steps:
      - uses: actions/cache/restore@v4
        with: {path: x, key: "x-${{ github.sha }}", restore-keys: x-}
      - uses: actions/cache/restore@v4
        with: {path: y, key: "y-${{ github.sha }}", restore-keys: y-}
      - uses: actions/cache/restore@v4
        with: {path: x, key: "z-${{ github.sha }}", restore-keys: z-}
      - uses: actions/cache/save@v4
        with: {path: y, key: "y-${{ github.run_id }}"}
      - uses: actions/cache/save@v4
        with: {path: x, key: "x-${{ github.run_id }}"}
`
	var got []string
	for _, f := range qualityReport(t, CacheBloatID, src, nil).QualityFindings {
		var related []int
		for _, r := range f.Related {
			related = append(related, r.Location.Position().Line)
		}
		got = append(got, fmt.Sprint(f.Location.Position().Line, related))
	}
	if want := []string{"12 [8]", "14 [10]"}; !slices.Equal(got, want) {
		t.Errorf("save line [restore lines] %v, want %v", got, want)
	}
}

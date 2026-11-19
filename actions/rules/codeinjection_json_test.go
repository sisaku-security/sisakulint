package rules

import (
	"slices"
	"strings"
	"testing"
)

// toJson(...) in a quoted heredoc is left alone only where no line of it can
// be the delimiter and nothing reads the body as code; the
// rest is still reported.
func TestInjectionJSONHeredoc(t *testing.T) {
	rep, in := injection(t, wfFile(`on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat > a << '{'
          ${{ toJson(github.event.issue) }}
          {
      - run: |
          cat > b << '"x"'
          ${{ toJson(github.event.issue.title) }}
          "x"
      - run: |
          cat > c << 'END'
          ${{ github.event.issue.body }}
          END
      - run: |
          cat > d << END
          ${{ toJson(github.event.issue) }}
          END
      - run: |
          bash << 'END'
          ${{ toJson(github.event.issue) }}
          END
      - run: |
          cat > f << 'END'
          ${{ format('{0}', toJson(github.event.issue)) }}
          END
      - run: |
          cat > g << 'END'
          ${{ toJson(github.event.issue) }}
          END
`))
	want := []string{ // a, d, e and f; c; b (at sorts them)
		".github/workflows/w.yml github.event.issue",
		".github/workflows/w.yml github.event.issue",
		".github/workflows/w.yml github.event.issue",
		".github/workflows/w.yml github.event.issue",
		".github/workflows/w.yml github.event.issue.body",
		".github/workflows/w.yml github.event.issue.title",
	}
	if got := at(t, rep, in); !slices.Equal(got, want) {
		t.Fatalf("findings at\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

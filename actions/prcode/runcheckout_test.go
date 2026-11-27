package prcode

import (
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/calls"
)

// TestRunCheckouts: gh pr checkout with a literal number or a whole ${{ }}
// of the event's pull request, its events, and what runs after it in the
// same run and in the steps after it.
func TestRunCheckouts(t *testing.T) {
	for _, c := range []struct {
		on, run, after string
		ref            string // "" for no site
		events, runs   []string
	}{
		{"{issue_comment: {types: [created]}}", `gh pr checkout "${{ github.event.issue.number }}"`, "      - run: npm ci\n",
			"${{ github.event.issue.number }}", []string{"issue_comment/created"}, []string{"npm ci"}},
		{"pull_request_target", "gh pr checkout ${{ github.event.pull_request.number }} && make", "",
			"${{ github.event.pull_request.number }}", []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}, []string{"make"}},
		{"pull_request_target", "gh pr checkout --force 12", "",
			"12", []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}, nil},
		{"pull_request_target", "gh pr checkout -b x ${{ github.event.number }}\ncat README.md", "      - run: echo done\n",
			"${{ github.event.number }}", []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}, nil},
		// make before the checkout runs the base's tree
		{"pull_request_target", "make; gh pr checkout ${{ github.event.pull_request.number }}", "", "${{ github.event.pull_request.number }}", []string{"pull_request_target/opened", "pull_request_target/reopened", "pull_request_target/synchronize"}, nil},
		// the issue's number is empty on pull_request_target
		{"pull_request_target", "gh pr checkout ${{ github.event.issue.number }}", "", "", nil, nil},
		{"push", "gh pr checkout 12 && make", "", "", nil, nil},
		{"pull_request_target", "gh pr checkout ${{ github.event.pull_request.number }}-x", "", "", nil, nil},
		{"pull_request_target", "gh pr view ${{ github.event.pull_request.number }}", "", "", nil, nil},
		{"pull_request_target", "gh pr checkout \"$PR\"", "", "", nil, nil},
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          " + strings.ReplaceAll(c.run, "\n", "\n          ") + "\n" + c.after
		sites := AnalyzeRunCheckouts(nil, calls.Node{}, mustWorkflow(t, src), nil)
		if c.ref == "" {
			if len(sites) != 0 {
				t.Errorf("%q: %+v", c.run, sites)
			}
			continue
		}
		if len(sites) != 1 {
			t.Errorf("%q: %d sites", c.run, len(sites))
			continue
		}
		s := sites[0]
		var runs []string
		for _, r := range s.CodeRunSteps {
			runs = append(runs, r.Text)
		}
		if s.Ref != c.ref || !slices.Equal(eventNames(s.PRCodeOn), c.events) || !slices.Equal(runs, c.runs) {
			t.Errorf("%q: ref %q, events %v, runs %v; want %q %v %v", c.run, s.Ref, eventNames(s.PRCodeOn), runs, c.ref, c.events, c.runs)
		}
	}
}

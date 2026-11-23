package prcode

import "testing"

// TestSiteJobNeeds: a checkout in a job that GitHub does not run, as the
// result of the job it needs or the if of that job tells, brings the code
// of the pull request on no event (attacker.JobIfs).
func TestSiteJobNeeds(t *testing.T) {
	const checkout = `    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`
	for _, c := range []struct {
		name, build, test string
		want              int
	}{
		{"needs result", "", "    needs: build\n    if: needs.build.result == 'failure'\n", 0},
		{"needs skipped", "    if: false\n", "    needs: build\n", 0},
		{"always", "    if: false\n", "    needs: build\n    if: always()\n", 1},
		{"no if", "", "    needs: build\n", 1},
	} {
		src := "on: pull_request_target\njobs:\n  build:\n" + c.build + "    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n  test:\n" + c.test + checkout
		sites := Analyze(mustWorkflow(t, src), nil)
		if len(sites) != 1 {
			t.Fatalf("%s: %d sites", c.name, len(sites))
		}
		if got := len(sites[0].PRCodeOn); (got > 0) != (c.want > 0) {
			t.Errorf("%s: PRCodeOn %v", c.name, eventNames(sites[0].PRCodeOn))
		}
	}
}

package ir

import (
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
)

// TestIRRequests: a run's requests carry what taint reads of them and what
// the job's runs-on and services are; an input of an action of the table
// carries the secrets of its credential.
func TestIRRequests(t *testing.T) {
	x := newIR(t, "on: issues\njobs:\n  j:\n    runs-on: [self-hosted, linux]\n    defaults:\n      run:\n        shell: bash\n    services:\n      db:\n        image: postgres\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: |\n          curl -H \"A: $T\" \"https://${{ github.event.issue.title }}/x\"\n      - uses: octokit/request-action@v2.x\n        env:\n          GITHUB_TOKEN: ${{ github.token }}\n        with:\n          route: ${{ github.event.issue.body }}\n")
	var got []RequestSite
	for _, s := range x.allSinks() {
		got = append(got, s.requests...)
	}
	if len(got) != 1 {
		t.Fatalf("%d requests", len(got))
	}
	r := got[0]
	if r.Command != "curl" || r.Occurrence != 1 || len(r.HostRefs) != 1 || r.HostRefs[0].Path != "github.event.issue.title" ||
		len(r.Secrets) != 1 || r.Secrets[0].Name != "T" || r.Destination != analysis.DestinationNamed || r.DestinationPath != "github.event.issue.title" ||
		r.RunnerHosting != analysis.RunnerHostingSelfHosted || !slices.Equal(r.RunnerLabels, []string{"self-hosted", "linux"}) || !slices.Equal(r.ServiceNames, []string{"db"}) {
		t.Errorf("%+v", r)
	}
	as := x.allRequestActionSites()
	if len(as) != 1 || as[0].action != "octokit/request-action" || as[0].input != "route" || len(as[0].hostRefs) != 1 || len(as[0].secrets) != 1 || !as[0].secrets[0].Token ||
		as[0].runnerHosting != analysis.RunnerHostingSelfHosted {
		t.Errorf("%+v", as)
	}
}

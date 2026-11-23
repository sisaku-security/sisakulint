package taint

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// actionRequests are the RequestActionSites of src as lines: the action,
// the input, the controlled references, the secrets.
func actionRequests(t *testing.T, src string) []string {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	var out []string
	for _, r := range RequestActionSites(nil, calls.Node{}, w, nil) {
		controlled := func(rs []ExprRef) string {
			var out []string
			for _, x := range rs {
				if x.Verdict == analysis.Controlled {
					out = append(out, expr.PathString(x.Path))
				}
			}
			return strings.Join(out, ",")
		}
		var secrets []string
		for _, s := range r.Secrets {
			switch {
			case s.Whole:
				secrets = append(secrets, "*")
			case s.Token:
				secrets = append(secrets, "token")
			default:
				secrets = append(secrets, s.Name)
			}
		}
		out = append(out, fmt.Sprintf("%s %s host=[%s] path=[%s] secrets=[%s]", r.Action, r.Input, controlled(r.HostRefs), controlled(r.PathRefs), strings.Join(secrets, ",")))
	}
	return out
}

// TestRequestActionSites: the CodeQL tests of secret-exfiltration and
// request-forgery, and an action not in the table.
func TestRequestActionSites(t *testing.T) {
	sonar := "name: test\non:\n  pull_request_target:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: sonarsource/sonarcloud-github-action@master\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}\n        with:\n          args: >\n            -Dsonar.scm.revision=${{ github.event.workflow_run.head_sha }}\n            -Dsonar.pullrequest.key=${{ github.event.pull_request.title }}\n"
	if got, want := actionRequests(t, sonar), []string{"SonarSource/sonarcloud-github-action args host=[github.event.pull_request.title] path=[] secrets=[SONAR_TOKEN]"}; !slices.Equal(got, want) {
		t.Errorf("sonar: got %q, want %q", got, want)
	}
	octokit := "on: issue_comment\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: octokit/request-action@v2.x\n        with:\n          route: ${{ github.event.comment.body }}\n"
	if got, want := actionRequests(t, octokit), []string{"octokit/request-action route host=[github.event.comment.body] path=[] secrets=[]"}; !slices.Equal(got, want) {
		t.Errorf("octokit: got %q, want %q", got, want)
	}
	withToken := "on: issue_comment\njobs:\n  test:\n    runs-on: ubuntu-latest\n    env:\n      GITHUB_TOKEN: ${{ github.token }}\n    steps:\n      - uses: octokit/request-action@v2.x\n        with:\n          url: ${{ github.event.comment.body }}\n"
	if got, want := actionRequests(t, withToken), []string{"octokit/request-action url host=[github.event.comment.body] path=[] secrets=[token]"}; !slices.Equal(got, want) {
		t.Errorf("octokit url: got %q, want %q", got, want)
	}
	other := "on: issue_comment\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: octokit/graphql-action@v2.x\n        with:\n          query: ${{ github.event.comment.body }}\n"
	if got := actionRequests(t, other); len(got) != 0 {
		t.Errorf("graphql-action: %q", got)
	}
}

// octokitStep is a workflow on issues whose job has env and a step of
// octokit/request-action with with.
func octokitStep(env, with string) string {
	return "on: issues\njobs:\n  test:\n    runs-on: ubuntu-latest\n    env:\n      N: none\n" + env + "    steps:\n      - uses: octokit/request-action@v2.x\n        with:\n" + with
}

// TestRequestActionSitePlace: a value after the host of the route or the
// URL is in the path.
func TestRequestActionSitePlace(t *testing.T) {
	for _, c := range []struct{ with, want string }{
		{"          route: GET /repos/${{ github.event.issue.title }}\n", "octokit/request-action route host=[] path=[github.event.issue.title] secrets=[]"},
		{"          route: POST ${{ github.event.issue.title }}\n", "octokit/request-action route host=[github.event.issue.title] path=[] secrets=[]"},
		{"          url: https://api.example.com/${{ github.event.issue.title }}\n", "octokit/request-action url host=[] path=[github.event.issue.title] secrets=[]"},
		{"          url: https://${{ github.event.issue.title }}/x\n", "octokit/request-action url host=[github.event.issue.title] path=[] secrets=[]"},
	} {
		if got := actionRequests(t, octokitStep("", c.with)); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: got %q, want %q", c.with, got, c.want)
		}
	}
}

// TestRequestActionSiteSecrets: the credential is read through env.X, and
// the whole secrets context is one.
func TestRequestActionSiteSecrets(t *testing.T) {
	src := octokitStep("      T: ${{ secrets.S }}\n", "          url: ${{ github.event.issue.title }}\n          github_token: ${{ env.T }}\n          token: ${{ toJSON(secrets) }}\n")
	want := []string{"octokit/request-action url host=[github.event.issue.title] path=[] secrets=[S,*]"}
	if got := actionRequests(t, src); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

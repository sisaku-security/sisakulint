package rules

import (
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// forgeryReport runs request-forgery on files.
func forgeryReport(t *testing.T, files map[string]string) lint.Report {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{RequestForgery}, files, exposureFacts{})
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	return rep
}

// forgeryResults are the findings of request-forgery on files, as
// "<kind> <sender> <expr_ref>", and its inconclusive kinds.
func forgeryResults(t *testing.T, files map[string]string) []string {
	t.Helper()
	rep := forgeryReport(t, files)
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		switch a := f.Args.(type) {
		case RequestForgeryCredentialHost:
			out = append(out, "credential-host "+a.Command+" "+strings.Join(a.Secrets, ",")+" "+a.ExprRef)
		case RequestForgeryActionInput:
			out = append(out, "action-input "+a.Action+" "+a.Input+" "+strings.Join(a.Secrets, ",")+" "+a.ExprRef)
		case RequestForgeryRunnerNetwork:
			out = append(out, "runner-network "+a.Command+" "+strings.Join(a.RunnerLabels, ",")+" "+a.ExprRef)
		}
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, g.InconclusiveKind.String())
	}
	return out
}

// forgeryRun is a workflow on issues whose job runs on runsOn, with env,
// and one step of run.
func forgeryRun(runsOn, env, run string) map[string]string {
	return wfFile("on: issues\njobs:\n  j:\n    runs-on: " + runsOn + "\n    env:\n      N: none\n" + env + "    steps:\n      - run: |\n          " + strings.ReplaceAll(run, "\n", "\n          ") + "\n")
}

const issueTitle = "github.event.issue.title"

// TestRequestForgeryCodeQL: the tests of CodeQL's secret-exfiltration and
// request-forgery.
func TestRequestForgeryCodeQL(t *testing.T) {
	sonar := wfFile("name: test\non:\n  pull_request_target:\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: sonarsource/sonarcloud-github-action@master\n        env:\n          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}\n        with:\n          args: >\n            -Dsonar.scm.revision=${{ github.event.workflow_run.head_sha }}\n            -Dsonar.pullrequest.key=${{ github.event.pull_request.title }}\n")
	if got, want := forgeryResults(t, sonar), []string{"action-input SonarSource/sonarcloud-github-action args SONAR_TOKEN github.event.pull_request.title"}; !slices.Equal(got, want) {
		t.Errorf("sonar: got %q, want %q", got, want)
	}
	// the request-forgery test: no credential, on a GitHub-hosted runner
	octokit := wfFile("on: issue_comment\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: octokit/request-action@v2.x\n        with:\n          route: ${{ github.event.comment.body }}\n")
	if got := forgeryResults(t, octokit); len(got) != 0 {
		t.Errorf("octokit: %q", got)
	}
}

// TestRequestForgeryCredentialHost: a credential sent to the attacker's
// host; code-injection's fix, which moves the ${{ }} into env, leaves the
// same Fingerprint.
func TestRequestForgeryCredentialHost(t *testing.T) {
	before := forgeryRun("ubuntu-latest", "      T: ${{ secrets.T }}\n", `curl -H "A: $T" "https://${{ github.event.issue.title }}/x"`)
	after := forgeryRun("ubuntu-latest", "      T: ${{ secrets.T }}\n      X: ${{ github.event.issue.title }}\n", `curl -H "A: $T" "https://$X/x"`)
	want := []string{"credential-host curl T " + issueTitle}
	for _, files := range []map[string]string{before, after} {
		if got := forgeryResults(t, files); !slices.Equal(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	b, a := forgeryReport(t, before), forgeryReport(t, after)
	if len(b.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || len(a.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || b.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fingerprint != a.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fingerprint {
		t.Errorf("fingerprints: before %+v, after %+v", b.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), a.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	// in the path: nothing
	if got := forgeryResults(t, forgeryRun("ubuntu-latest", "      T: ${{ secrets.T }}\n", `curl -H "A: $T" "https://api.example.com/${{ github.event.issue.title }}"`)); len(got) != 0 {
		t.Errorf("path: %q", got)
	}
}

// TestRequestForgeryRunnerNetwork: a request with no credential to the
// attacker's host from a self-hosted runner; nothing from a GitHub-hosted
// one or one not known.
func TestRequestForgeryRunnerNetwork(t *testing.T) {
	run := `curl "https://${{ github.event.issue.title }}/x"`
	shell := "      N2: none\n"
	if got, want := forgeryResults(t, wfFile("on: issues\njobs:\n  j:\n    runs-on: [self-hosted, linux]\n    defaults:\n      run:\n        shell: bash\n    env:\n"+shell+"    steps:\n      - run: "+run+"\n")), []string{"runner-network curl self-hosted,linux " + issueTitle}; !slices.Equal(got, want) {
		t.Errorf("self-hosted: got %q, want %q", got, want)
	}
	if got := forgeryResults(t, forgeryRun("ubuntu-latest", "", run)); len(got) != 0 {
		t.Errorf("ubuntu-latest: %q", got)
	}
	if got := forgeryResults(t, wfFile("on: issues\njobs:\n  j:\n    runs-on: linux.2xlarge\n    defaults:\n      run:\n        shell: bash\n    steps:\n      - run: "+run+"\n")); len(got) != 0 {
		t.Errorf("custom label: %q", got)
	}
}

// TestRequestForgeryAnchorsDistinct: two requests of the same form in one
// run are two findings with two Fingerprints.
func TestRequestForgeryAnchorsDistinct(t *testing.T) {
	line := `curl -H "A: $T" "https://${{ github.event.issue.title }}/x"`
	rep := forgeryReport(t, forgeryRun("ubuntu-latest", "      T: ${{ secrets.T }}\n", line+"\n"+line))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fingerprint == rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Fingerprint {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestRequestForgeryGhToken: gh api sends GH_TOKEN only to GitHub's hosts,
// and GH_ENTERPRISE_TOKEN to any other.
func TestRequestForgeryGhToken(t *testing.T) {
	run := `gh api "$X"`
	x := "      X: ${{ github.event.issue.title }}\n"
	if got := forgeryResults(t, forgeryRun("ubuntu-latest", x+"      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n", run)); len(got) != 0 {
		t.Errorf("GH_TOKEN: %q", got)
	}
	if got, want := forgeryResults(t, forgeryRun("ubuntu-latest", x+"      GH_ENTERPRISE_TOKEN: ${{ secrets.GHE }}\n", run)), []string{"credential-host gh api GHE " + issueTitle}; !slices.Equal(got, want) {
		t.Errorf("GH_ENTERPRISE_TOKEN: got %q, want %q", got, want)
	}
}

// TestRequestForgeryNotAnalyzed: a value whose control is not analyzed, at
// the host of a request that carries a credential, is inconclusive.
func TestRequestForgeryNotAnalyzed(t *testing.T) {
	files := wfFile("on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - id: s\n        run: echo\n      - run: |\n          curl -H \"A: $T\" \"https://${{ steps.s.outputs.host }}/x\"\n")
	if got, want := forgeryResults(t, files), []string{"step-output-run"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

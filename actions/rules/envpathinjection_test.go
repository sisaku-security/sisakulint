package rules

import (
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

func pathRule(t *testing.T, src string) lint.Report {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{EnvpathInjection}, wfFile(src), nil)
	return rep
}

func TestEnvpathInjectionDetection(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{fcStep(`echo "$T" >> "$GITHUB_PATH"`), "$T"},
		{fcStep(`echo "$HOME/tools/${B}" >> "$GITHUB_PATH"`), "${B}"},
		{fcStep(`echo "${{ github.event.issue.title }}" >> "$GITHUB_PATH"`), "github.event.issue.title"},
		{fcStep(`echo "t=$T" >> "$GITHUB_ENV"`), ""},
		// a branch name is enough on $GITHUB_PATH
		{"on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.head_ref }}\" >> \"$GITHUB_PATH\"\n", "github.head_ref"},
		// the example of
		// https://github.com/gh-intel/sisakulint/blob/17c2d82151a966e6e388a17619b060ae2919712e/docs/envpathinjectioncritical.md
		// (line 69): its value ../../tmp/evil/tools is no branch name (git
		// refuses ..), but a branch name alone is a path relative to the workspace
		{"on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.head.ref }}/tools\" >> \"$GITHUB_PATH\"\n", "github.event.pull_request.head.ref"},
		// what no attacker chooses, and pull_request
		{"on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.number }}\" >> \"$GITHUB_PATH\"\n", ""},
		{"on: pull_request\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pull_request.title }}\" >> \"$GITHUB_PATH\"\n", ""},
	} {
		rep := pathRule(t, c.src)
		var got []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got = append(got, strings.SplitN(f.Detected(), " ", 2)[0])
		}
		if s := strings.Join(got, "; "); s != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.src, s, c.want)
		}
	}
}

func TestEnvpathInjectionFinding(t *testing.T) {
	rep := pathRule(t, fcStep(`echo "$T" >> "$GITHUB_PATH"`))
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
	// the kind declares no fixes: neither a fix nor a reason for none; its
	// remedy says what to do
	if f.Certainty != lint.CertaintyConfirmed || f.Fix != nil || f.NoFix != nil || !strings.Contains(f.Remedy, "fixed path") {
		t.Errorf("%+v: confirmed, with neither a fix nor a reason, and the remedy", f)
	}
	if !strings.Contains(f.Detected(), "issues") || len(f.Evidence) == 0 {
		t.Errorf("the events and the env it comes from: %s %+v", f.Detected(), f.Evidence)
	}
	wiki := pathRule(t, "on: gollum\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.pages[0].title }}\" >> \"$GITHUB_PATH\"\n")
	if len(wiki.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || wiki.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != "envpath-injection.wiki" || wiki.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Condition == nil {
		t.Errorf("gollum alone: %+v", wiki.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

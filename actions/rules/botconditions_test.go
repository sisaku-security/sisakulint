package rules

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TestBotConditions: the conditions on a bot's name that an attacker
// passes, by the event.
func TestBotConditions(t *testing.T) {
	prt := []workflow.EventName{workflow.EventNamePullRequestTarget}
	for _, c := range []struct {
		name, on, cond string
		want           []lint.FindingArgs
		inc            int
	}{
		{"actor", "pull_request_target", "github.actor == 'dependabot[bot]'", []lint.FindingArgs{BotConditionsDependabot{Path: "github.actor", Literal: "dependabot[bot]", AttackerOn: prt}}, 0},
		{"ne", "pull_request_target", "github.actor != 'dependabot[bot]'", nil, 0},
		{"push", "push", "github.actor == 'dependabot[bot]'", nil, 0},
		{"author", "pull_request_target", "github.event.pull_request.user.login == 'dependabot[bot]'", nil, 0},
		{"trpc", "pull_request_target", "${{ github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]' }}", []lint.FindingArgs{BotConditionsDependabot{Path: "github.actor", Literal: "dependabot[bot]", AttackerOn: prt}}, 0},
		{"renovate", "pull_request_target", "github.actor == 'renovate[bot]'", nil, 1},
		{"labeled only", "{pull_request_target: {types: [labeled]}}", "github.actor == 'dependabot[bot]'", nil, 0},
	} {
		src := "on: " + c.on + "\njobs:\n  a:\n    if: " + c.cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n"
		rep, _, _ := checkRules(t, []lint.Rule{BotConditions}, wfFile(src), nil)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != len(c.want) || len(rep.FindingsWith(lint.CertaintyInconclusive)) != c.inc {
			t.Errorf("%s: %+v %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
			continue
		}
		for i, w := range c.want {
			if !argsEqual(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i].Args, w) || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i].Fix == nil {
				t.Errorf("%s: %+v, want %+v with a fix", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[i].Args, w)
			}
		}
	}
}

// TestBotConditionsFolded: GitHub reads the string of an if of exactly
// ${{ '…' }} as the expression, of a job and of a step, so the comparison
// in the string is read; the fix is none, as the comparison is in a string.
func TestBotConditionsFolded(t *testing.T) {
	prt := []workflow.EventName{workflow.EventNamePullRequestTarget}
	const cond = "${{ 'github.actor == ''dependabot[bot]''' }}"
	want := BotConditionsDependabot{Path: "github.actor", Literal: "dependabot[bot]", AttackerOn: prt}
	for name, src := range map[string]string{
		"job":  "on: pull_request_target\njobs:\n  a:\n    if: " + cond + "\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo\n",
		"step": "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - if: " + cond + "\n        run: echo\n",
	} {
		rep, _, _ := checkRules(t, []lint.Rule{BotConditions}, wfFile(src), nil)
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || !argsEqual(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args, want) || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil {
			t.Errorf("%s: %+v, want %+v with no fix", name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), want)
		}
	}
}

// argsEqual compares the args of findings, whose types may hold slices.
func argsEqual(a, b lint.FindingArgs) bool { return reflect.DeepEqual(a, b) }

// TestAuthorContextCloses: the fix of bot-conditions keeps the attacker out
// of the job, so the findings of the other rules in it close too.
func TestAuthorContextCloses(t *testing.T) {
	ctx := context.Background()
	in, err := lint.Enumerate(os.DirFS(filepath.Join("testdata", "interplay", "author-context")))
	if err != nil {
		t.Fatal(err)
	}
	all, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	r := storeResolver(t, filepath.Join("testdata", "interplay", "author-context", "facts.json"))
	before := lint.Run(ctx, in, all, r())
	if !slices.Contains(kindsOf(before), kindBotConditionsDependabot) || !slices.Contains(kindsOf(before), kindDangerousTriggersTokenWrite) {
		t.Fatalf("before: %v", kindsOf(before))
	}
	s, _ := lint.ParseSelector(BotConditionsID.String())
	one, err := all.Select(lint.Only(s), lint.FactSources{})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(ctx, in, one, r())
	a, err := lint.ApplyFixes(ctx, in, one, r(), rep, lint.SafetyReview)
	if err != nil {
		t.Fatal(err)
	}
	after := lint.Run(ctx, fixedInputs(t, filepath.Join("testdata", "interplay", "author-context"), a.Files), all, r())
	for _, k := range kindsOf(after) {
		if k != kindCommitSHAUnpinned {
			t.Errorf("after the fix: %v", kindsOf(after))
			break
		}
	}
}

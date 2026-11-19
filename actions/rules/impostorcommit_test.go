package rules

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

const (
	fork = "b3154b9543ce6392fe65a19ce523c4d4adabca7b"
	tag  = "860fb3d0de1295b37890acec26add9a411d36583"
)

// commits answers git.commit-ref from a table by repo@sha (the answers
// GitHub gave for those commits), and counts what
// it is asked and how many questions it has at once. A question not in
// the table is absent.
type commits struct {
	answer map[string]facts.RawAnswer
	wait   time.Duration // each question takes this long

	mu              sync.Mutex
	asked           map[string]int
	now, mostAtOnce int
}

func (c *commits) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	g, ok := q.(facts.GitCommitRef)
	if !ok {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not a commit"}
	}
	k := g.Repo.String() + "@" + g.SHA.String()
	c.mu.Lock()
	if c.asked == nil {
		c.asked = map[string]int{}
	}
	c.asked[k]++
	c.now++
	c.mostAtOnce = max(c.mostAtOnce, c.now)
	c.mu.Unlock()
	time.Sleep(c.wait)
	c.mu.Lock()
	c.now--
	c.mu.Unlock()
	if a, ok := c.answer[k]; ok {
		return a
	}
	return facts.RawAnswer{State: facts.StateAbsent}
}

func impostor(t *testing.T, files map[string]string, r facts.Resolver) (lint.Report, lint.Inputs) {
	t.Helper()
	if r == nil {
		r = &commits{}
	}
	rep, in, _ := checkRules(t, []lint.Rule{ImpostorCommit}, files, r)
	return rep, in
}

// TestImpostorDetection: the SHAs of the steps' uses of other
// repositories, in a workflow and in a composite action, and nothing else
// of an input that has every form of uses. What the rule does not detect
// on purpose is its UndetectedForms, held by TestUndetectedForms.
func TestImpostorDetection(t *testing.T) {
	rep, in := impostor(t, map[string]string{".github/workflows/w.yml": detection, "act/action.yml": compositeAction + "    - uses: inner/action@" + fork + "\n"}, nil)
	want := []string{
		".github/workflows/w.yml 11BD71901BBE5B1630CEEA73D27597364C9AF683",
		".github/workflows/w.yml " + sha,
		".github/workflows/w.yml " + sha, // the folded string's, in the literal
		"act/action.yml " + fork,
	}
	if got := at(t, rep, in); !slices.Equal(got, want) {
		t.Errorf("findings at\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Severity != lint.SeverityHigh || f.Certainty != lint.CertaintyConfirmed || f.Rule != ImpostorCommitID {
			t.Errorf("%+v: want a confirmed finding of high severity", f)
		}
		if !strings.Contains(f.Detected(), "no branch and no tag") || f.Fix != nil || f.NoFix != nil {
			t.Errorf("%+v", f)
		}
	}
}

// TestImpostorAnswers: absent is a finding, a branch or a tag that has the
// commit is none (a commit only a tag has), and not knowing is a finding on
// the condition that no branch or tag has it (bit 2, not 1).
func TestImpostorAnswers(t *testing.T) {
	for _, c := range []struct {
		name      string
		answer    facts.RawAnswer
		findings  int
		certainty lint.Certainty
		code      uint8
	}{
		{"absent", facts.RawAnswer{State: facts.StateAbsent}, 1, lint.CertaintyConfirmed, lint.ConfirmedBit},
		{"a tag has it", resolved("refs/tags/v1"), 0, 0, 0},
		{"a branch has it", resolved("refs/heads/main"), 0, 0, 0},
		{"not known", facts.RawAnswer{State: facts.StateUnknown, Reason: "no token"}, 1, lint.CertaintyConditional, lint.UndecidedBit},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := &commits{answer: map[string]facts.RawAnswer{"actions/checkout@" + tag: c.answer}}
			rep, _ := impostor(t, map[string]string{".github/workflows/w.yml": step("actions/checkout@" + tag)}, r)
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.findings {
				t.Fatalf("findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
			}
			if c.findings == 1 {
				f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]
				if f.Certainty != c.certainty {
					t.Errorf("certainty %v, want %v", f.Certainty, c.certainty)
				}
				if c.certainty == lint.CertaintyConditional && (f.Condition == nil || len(f.Condition.Queries()) != 1 || f.Condition.Queries()[0].Kind() != facts.KindGitCommitRef) {
					t.Errorf("condition %+v", f.Condition)
				}
			}
			if got := lint.Classify(rep, lint.SeverityInfo); got != c.code {
				t.Errorf("exit bits %d, want %d", got, c.code)
			}
		})
	}
}

// TestImpostorAsksAtOnce: the questions of an input are asked at once
// before the engine evaluates the conditions one by one, 8 at a time. Each
// of the 20 questions waits 200 ms, and the test fails when fewer than 8
// questions are ever asked at the same time (a pause of the whole process
// for 200 ms while the first 8 questions start would also make fewer than
// 8). The time is compared with ACTIONS_SCALE=1 only, as the time depends
// on the machine.
func TestImpostorAsksAtOnce(t *testing.T) {
	var src strings.Builder
	src.WriteString("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n")
	for i := range 20 {
		src.WriteString("      - uses: o/r" + string(rune('a'+i)) + "@" + fork + "\n")
	}
	r := &commits{wait: 200 * time.Millisecond}
	start := time.Now()
	rep, _ := impostor(t, map[string]string{".github/workflows/w.yml": src.String()}, r)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 20 {
		t.Fatalf("findings %d", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	if r.mostAtOnce != maxAsked {
		t.Errorf("%d questions at once, want %d", r.mostAtOnce, maxAsked)
	}
	if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > 20*r.wait/2 {
		t.Errorf("took %v, as if one by one", d)
	}
}

// TestImpostorOneQuestionPerFact: the case of a
// repository or of a SHA, and a path in the repository, make no other
// fact.
func TestImpostorOneQuestionPerFact(t *testing.T) {
	r := &commits{}
	src := "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" +
		"      - uses: actions/checkout@" + fork + "\n      - uses: Actions/Checkout@" + strings.ToUpper(fork) + "\n      - uses: actions/checkout/sub@" + fork + "\n"
	impostor(t, map[string]string{".github/workflows/w.yml": src}, r)
	if r.asked["actions/checkout@"+fork] != 1 || len(r.asked) != 1 {
		t.Errorf("asked %v", r.asked)
	}
}

// TestImpostorAndCommitSHA: the two rules share the
// remote uses of the steps by whether the ref is a full SHA; no uses has a
// finding of both.
func TestImpostorAndCommitSHA(t *testing.T) {
	rep, in, _ := checkRules(t, []lint.Rule{CommitSHA, ImpostorCommit}, map[string]string{".github/workflows/w.yml": detection, "act/action.yml": compositeAction}, &commits{})
	seen := map[string]lint.RuleID{}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		k := fmt.Sprint(f.Location.File.Input, " ", f.Location.Span.Start)
		if r, ok := seen[k]; ok && r != f.Rule {
			i, _ := in.Lookup(f.Location.File.Input)
			t.Errorf("%s has a finding of both rules", i.Tree.Bytes()[f.Location.Span.Start:f.Location.Span.End])
		}
		seen[k] = f.Rule
	}
}

func TestImpostorForms(t *testing.T) {
	for _, c := range []struct{ name, src string }{
		{"quoted", step(`"actions/checkout@` + fork + `"`)},
		{"through an alias", "on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: &u actions/checkout@" + fork + "\n      - uses: *u\n"},
		{"folded", step("${{ 'actions/checkout@" + fork + "' }}")},
	} {
		t.Run(c.name, func(t *testing.T) {
			rep, in := impostor(t, map[string]string{".github/workflows/w.yml": c.src}, nil)
			if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) == 0 {
				t.Fatal("no finding")
			}
			for _, got := range at(t, rep, in) {
				if !strings.HasSuffix(got, " "+fork) {
					t.Errorf("at %q, want the SHA", got)
				}
			}
		})
	}
}

func TestImpostorRegistry(t *testing.T) {
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	m, ok := reg.Meta(ImpostorCommitID)
	if !ok || m.Severity() != lint.SeverityHigh {
		t.Fatalf("Meta = %+v, %v", m, ok)
	}
	k := m.FindingKinds[0]
	if got := k.CVSS.Vector(); got != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N" {
		t.Errorf("vector %s", got)
	}
	if !slices.Equal(k.FactKinds, []facts.Kind{facts.KindGitCommitRef}) || len(k.Fixes) != 0 || len(m.FixKinds) != 0 {
		t.Errorf("facts %v, fixes %v and %v", k.FactKinds, k.Fixes, m.FixKinds)
	}
	if k.ExploitMaturity.Value != lint.ExploitMaturityAttacked || len(k.Incidents) == 0 {
		t.Errorf("exploited %+v, incidents %v", k.ExploitMaturity, k.Incidents)
	}
}

// TestImpostorAgentkitFork: coinbase/agentkit
// 8edc60f030035f377780f421431a7ac66828253d .github/workflows/changelog.yml
// (lines 1-12 and 27-33; the other steps left out), a commit of the
// attacker's fork (mmvojwip) that pinned tj-actions/changed-files to the
// dangling commit 6e6023c0, which no branch or tag has and which
// impersonates github-actions[bot] (Unit 42,
// https://unit42.paloaltonetworks.com/github-actions-supply-chain-attack/).
// The attacker tried it there; coinbase/agentkit itself ran a malicious
// commit through a tag the attacker moved, which commit-sha reports
// (TestCommitSHAAgentkit).
func TestImpostorAgentkitFork(t *testing.T) {
	const dangling = "6e6023c01918b353229af0881232f601a4cc8365"
	const src = `name: Changelog

on: [pull_request]

jobs:
  check-changelog-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - run: printenv
      - name: Check for modified Python files in coinbase-agentkit
        if: steps.check-label.outputs.skip != 'true'
        id: changed-agent-files
        uses: tj-actions/changed-files@` + dangling + `
        with:
          files: |
            python/coinbase-agentkit/**/*.py
`
	r := &commits{answer: map[string]facts.RawAnswer{"tj-actions/changed-files@" + dangling: {State: facts.StateAbsent}}}
	rep, _ := impostor(t, wfFile(src), r)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != "impostor-commit.fork-commit" || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Certainty != lint.CertaintyConfirmed {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// TestImpostorOutside: the commit written after @ of a uses above the root
// of its repository is fetched but does not run, unless another uses goes
// into its directory.
func TestImpostorOutside(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: o/r/acts/comp@" + sha + "\n      - uses: o/r/../../../actions/github-script/v7@" + sha + "\n"
	rep, _, _ := checkRules(t, []lint.Rule{ImpostorCommit}, wfFile(src), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Errorf("findings %d, want 1 (the first step only)", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
}

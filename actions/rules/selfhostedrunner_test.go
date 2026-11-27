package rules

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"

	"github.com/gh-intel/sisakulint/actions/lint"
)

const (
	publicCond = `{"query":{"kind":"repo.public"},"eq":true}`
	forkPRCond = `{"all":[{"query":{"kind":"repo.public"},"eq":false},{"query":{"kind":"repo.allow-forking"},"eq":true},{"query":{"kind":"repo.fork-pr-run-workflows"},"eq":true}]}`
)

// forkFacts answers repo.public, repo.allow-forking and
// repo.fork-pr-run-workflows, each unknown when nil.
type forkFacts struct{ public, forking, run *bool }

func (f forkFacts) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	var v *bool
	switch q.(type) {
	case facts.RepoPublic:
		v = f.public
	case facts.RepoAllowForking:
		v = f.forking
	case facts.RepoForkPRRunWorkflows:
		v = f.run
	}
	if v == nil {
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
	}
	b, _ := json.Marshal(*v)
	return facts.RawAnswer{State: facts.StateFound, Value: b}
}

// TestSelfHostedRunner: the labels and the gaps of runs-on and of the
// matrix.
func TestSelfHostedRunner(t *testing.T) {
	for _, c := range []struct {
		name, runsOn, strategy string
		labels, gaps           int
	}{
		{"label", "self-hosted", "", 1, 0},
		{"list", "[self-hosted, linux]", "", 1, 0},
		{"hosted", "ubuntu-latest", "", 0, 0},
		{"matrix", "${{ matrix.os }}", "    strategy:\n      matrix: {os: [ubuntu-latest, self-hosted]}\n", 1, 0},
		{"matrix include", "${{ matrix.os }}", "    strategy:\n      matrix: {v: [1], include: [{os: self-hosted}]}\n", 1, 0},
		{"input", "${{ inputs.runner }}", "", 0, 1},
		{"group", "{group: big}", "", 0, 0},
		{"upper", "SELF-HOSTED", "", 1, 0},
		{"scalar spaces", "' self-hosted '", "", 1, 0},
		{"list spaces", "[' self-hosted']", "", 0, 0},
		{"list unmatched", "[self-hosted, ' x']", "", 0, 0},
		{"mapping spaces", "{labels: [' self-hosted ']}", "", 1, 0},
		{"matrix spaces", "${{ matrix.os }}", "    strategy:\n      matrix: {os: [' self-hosted']}\n", 0, 0},
	} {
		src := "on: push\njobs:\n  a:\n    runs-on: " + c.runsOn + "\n" + c.strategy + "    steps:\n      - run: echo\n"
		rep, _, _ := checkRules(t, []lint.Rule{SelfHostedRunner}, wfFile(src), exposureFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2*c.labels || len(rep.FindingsWith(lint.CertaintyInconclusive)) != c.gaps {
			t.Errorf("%s: %+v %+v", c.name, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
			continue
		}
		want := map[string]string{"self-hosted-runner.public": publicCond, "self-hosted-runner.private": forkPRCond}
		n := map[string]int{}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			k := f.Args.KindID().String()
			n[k]++
			if condJSON(t, f) != want[k] {
				t.Errorf("%s: %s %s", c.name, k, condJSON(t, f))
			}
		}
		if n["self-hosted-runner.public"] != c.labels || n["self-hosted-runner.private"] != c.labels {
			t.Errorf("%s: %v", c.name, n)
		}
	}
}

// TestSelfHostedRunnerPrivate: repo.public false drops the finding of a
// public repository, and the facts of a private or internal one decide
// that of one who may read it.
func TestSelfHostedRunnerPrivate(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: self-hosted\n    steps:\n      - run: echo\n"
	for _, c := range []struct {
		name string
		f    forkFacts
		want lint.Certainty // of self-hosted-runner.private; unset: no finding
	}{
		{"public", forkFacts{public: ptr(true), forking: ptr(true), run: ptr(true)}, lint.CertaintyUnset},
		{"forks run", forkFacts{public: ptr(false), forking: ptr(true), run: ptr(true)}, lint.CertaintyConfirmed},
		{"settings unknown", forkFacts{public: ptr(false)}, lint.CertaintyConditional},
		{"no fork", forkFacts{public: ptr(false), forking: ptr(false), run: ptr(true)}, lint.CertaintyUnset},
		{"forks do not run", forkFacts{public: ptr(false), forking: ptr(true), run: ptr(false)}, lint.CertaintyUnset},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{SelfHostedRunner}, wfFile(src), c.f)
		var got []lint.Finding
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Args.KindID().String() == "self-hosted-runner.private" {
				got = append(got, f)
			} else if *c.f.public {
				continue
			} else {
				t.Errorf("%s: %s", c.name, f.Args.KindID())
			}
		}
		switch {
		case c.want == lint.CertaintyUnset && len(got) != 0, c.want != lint.CertaintyUnset && (len(got) != 1 || got[0].Certainty != c.want):
			t.Errorf("%s: %+v", c.name, got)
		}
	}
}

// TestSelfHostedRunnerIncidents: the jobs of the incidents the Meta cites.
// pytorch-2023, pytorch/pytorch c913f3857fb6a8ff8a32174db1da1b4f808f178f
// .github/workflows/docker-builds.yml:3-5,30: a job of
// pull_request on a runner named self-hosted, which tells that the
// repository has such runners; the runner the attackers took had the
// labels of its own (the limit custom-label).
func TestSelfHostedRunnerIncidents(t *testing.T) {
	src := "on:\n  workflow_dispatch:\n  pull_request:\njobs:\n  docker-build:\n    runs-on: [self-hosted, linux.2xlarge]\n    steps:\n      - run: echo\n"
	rep, _, _ := checkRules(t, []lint.Rule{SelfHostedRunner}, wfFile(src), exposureFacts{public: ptr(true)})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID().String() != "self-hosted-runner.public" {
		t.Errorf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

// trustFacts answers repo.public true and repo.runner-label-trusted true
// for the labels of trusted, in lower case; any other fact is unknown.
type trustFacts struct{ trusted []string }

func (f trustFacts) Resolve(_ context.Context, q facts.Query) facts.RawAnswer {
	switch x := q.(type) {
	case facts.RepoPublic:
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
	case facts.RepoRunnerLabelTrusted:
		for _, l := range f.trusted {
			if x.RunnerLabel.String() == l {
				return facts.RawAnswer{State: facts.StateFound, Value: []byte("true")}
			}
		}
		return facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}
	}
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "not in the table"}
}

// TestSelfHostedRunnerTrusted: a label of runs-on that the owner declares
// trusted (repo.runner-label-trusted) drops the findings of the job, also
// for a runs-on a ${{ }} of the matrix gives; a trusted label of another
// job, or of another combination, does not.
func TestSelfHostedRunnerTrusted(t *testing.T) {
	eco := "    strategy:\n      matrix:\n        include: [{r: ubuntu-latest}, {r: eco}]\n"
	ternary := "${{ matrix.r == 'eco' && fromJSON('[\"self-hosted\",\"linux\",\"eco\"]') || matrix.r }}"
	for _, c := range []struct {
		name, runsOn, strategy string
		trusted                []string
		public                 int
	}{
		{"none trusted", "[self-hosted, linux, fast]", "", nil, 1},
		{"trusted", "[self-hosted, linux, fast]", "", []string{"fast"}, 0},
		{"trusted case", "[self-hosted, linux, FAST]", "", []string{"fast"}, 0},
		{"other trusted", "[self-hosted, linux, slow]", "", []string{"fast"}, 1},
		{"self-hosted alone", "self-hosted", "", []string{"fast"}, 1},
		{"ternary", ternary, eco, nil, 1},
		{"ternary trusted", ternary, eco, []string{"eco"}, 0},
		{"ternary other", ternary, eco, []string{"fast"}, 1},
	} {
		src := "on: pull_request\njobs:\n  a:\n    runs-on: " + c.runsOn + "\n" + c.strategy + "    steps:\n      - run: echo\n"
		rep, _, _ := checkRules(t, []lint.Rule{SelfHostedRunner}, wfFile(src), trustFacts{trusted: c.trusted})
		n := 0
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed) {
			if f.Args.KindID().String() == "self-hosted-runner.public" {
				n++
			}
		}
		if n != c.public || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
			t.Errorf("%s: %d confirmed public, want %d; %+v", c.name, n, c.public, rep.FindingsWith(lint.CertaintyInconclusive))
		}
	}
}

// TestSelfHostedRunnerExprReached: a runs-on the rule cannot read is
// undecided only while a pull request from a fork may reach a runner of
// the repository.
func TestSelfHostedRunnerExprReached(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: ${{ vars.RUNNER || 'pool' }}\n    steps:\n      - run: echo\n"
	for _, c := range []struct {
		name string
		f    forkFacts
		gaps int
	}{
		{"unknown", forkFacts{}, 1},
		{"public", forkFacts{public: ptr(true)}, 1},
		{"private, forks run", forkFacts{public: ptr(false), forking: ptr(true), run: ptr(true)}, 1},
		{"private, forks do not run", forkFacts{public: ptr(false), run: ptr(false)}, 0},
		{"private, no fork", forkFacts{public: ptr(false), forking: ptr(false)}, 0},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{SelfHostedRunner}, wfFile(src), c.f)
		if got := len(rep.FindingsWith(lint.CertaintyInconclusive)); got != c.gaps {
			t.Errorf("%s: %d inconclusive, want %d", c.name, got, c.gaps)
		}
	}
}

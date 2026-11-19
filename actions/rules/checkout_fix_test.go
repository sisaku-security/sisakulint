package rules

import (
	"context"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// applied runs rule on src with r and applies its fixes of safety; it gives
// the workflow after them (src when nothing changed).
func applied(t *testing.T, rule lint.Rule, src string, r facts.Resolver, safety lint.Safety) string {
	t.Helper()
	rep, in, reg := checkRules(t, []lint.Rule{rule}, wfFile(src), r)
	applied, err := lint.ApplyFixes(context.Background(), in, reg, r, rep, safety)
	if err != nil {
		t.Fatalf("ApplyFixes: %v", err)
	}
	out := applied.Files
	if b, ok := out[facts.MustCleanInputPath(".github/workflows/w.yml")]; ok {
		return string(b)
	}
	return src
}

const coOld = "actions/checkout@v4.2.2"

// TestUntrustedCheckoutFixWith: with has ref and repository only; it goes whole.
func TestUntrustedCheckoutFixWith(t *testing.T) {
	head := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + coOld + "\n"
	for _, c := range []struct{ name, with, want string }{
		{"ref only",
			"        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n",
			""},
		{"ref and repository",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.event.pull_request.head.ref }}\n",
			""},
		{"ref and another",
			"        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n          fetch-depth: 0\n",
			"        with:\n          fetch-depth: 0\n"},
		{"flow",
			"        with: {ref: '${{ github.event.pull_request.head.sha }}', fetch-depth: 0}\n",
			"        with: {fetch-depth: 0}\n"},
		{"comment kept",
			"        with:\n          # the PR\n          ref: ${{ github.event.pull_request.head.sha }}\n          fetch-depth: 0 # all\n",
			"        with:\n          fetch-depth: 0 # all\n"},
		{"refs/pull",
			"        with:\n          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n          path: pr\n",
			"        with:\n          path: pr\n"},
		{"fork with a literal ref",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: main\n",
			"        with:\n          ref: main\n"},
	} {
		src := head + c.with + "      - run: npm ci\n"
		want := head + c.want + "      - run: npm ci\n"
		if got := applied(t, UntrustedCheckout, src, checkoutFacts{}, lint.SafetyReview); got != want {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, want)
		}
		if got := applied(t, UntrustedCheckout, src, checkoutFacts{}, lint.SafetySafe); got != src {
			t.Errorf("%s: a review fix applied as safe:\n%s", c.name, got)
		}
	}
}

func TestUntrustedCheckoutNoFix(t *testing.T) {
	for _, with := range []string{
		"{ref: 'pr-${{ github.event.pull_request.head.sha }}'}",
		"{repository: 'x/${{ github.event.pull_request.head.repo.full_name }}'}",
	} {
		src := checkoutJob("pull_request_target", "", coOld, with, "      - run: npm ci\n")
		rep, _, _ := checkRules(t, []lint.Rule{UntrustedCheckout}, wfFile(src), checkoutFacts{})
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fix != nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix == nil || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].NoFix.Reason != ir.NoFixReasonManual {
			t.Errorf("%s: %+v", with, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
		}
	}
}

func TestToctouFix(t *testing.T) {
	const labeled = "on: {pull_request_target: {types: [labeled]}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + coOld + "\n"
	for _, c := range []struct {
		name, with, want string
		safety           lint.Safety
	}{
		{"refs/pull head",
			"        with:\n          ref: refs/pull/${{ github.event.pull_request.number }}/head\n",
			"        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", lint.SafetySafe},
		{"fork's branch",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.event.pull_request.head.ref }}\n",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.event.pull_request.head.sha }}\n", lint.SafetySafe},
		{"head_ref, any case",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ GitHub.Head_Ref }}\n",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.event.pull_request.head.sha }}\n", lint.SafetySafe},
		{"head_ref by an index",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github['head_ref'] }}\n",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.event.pull_request.head.sha }}\n", lint.SafetySafe},
		{"head.ref with spaces",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github . event . pull_request . head . ref }}\n",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.event.pull_request.head.sha }}\n", lint.SafetySafe},
		{"head_ref with a default is no branch name alone",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github['head_ref'] || 'main' }}\n",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github['head_ref'] || 'main' }}\n", lint.SafetySafe},
		{"the fork alone",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n",
			"        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.event.pull_request.head.sha }}\n", lint.SafetySafe},
		{"refs/pull merge",
			"        with:\n          ref: refs/pull/${{ github.event.pull_request.number }}/merge\n",
			"        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", lint.SafetyReview},
	} {
		src := labeled + c.with + "      - run: npm ci\n"
		want := labeled + c.want + "      - run: npm ci\n"
		if got := applied(t, UntrustedCheckoutToctou, src, checkoutFacts{}, c.safety); got != want {
			t.Errorf("%s:\n%s\nwant\n%s", c.name, got, want)
		}
		if c.safety == lint.SafetyReview {
			if got := applied(t, UntrustedCheckoutToctou, src, checkoutFacts{}, lint.SafetySafe); got != src {
				t.Errorf("%s: a review fix applied as safe", c.name)
			}
		}
	}
}

// TestToctouEnvironmentUnknown: with the environment's protection not known, both rules
// report, and only untrusted-checkout gives a fix.
func TestToctouEnvironmentUnknown(t *testing.T) {
	src := checkoutJob("pull_request_target", "    environment: prod\n", coOld, "{ref: 'refs/pull/${{ github.event.pull_request.number }}/head'}", "      - run: npm ci\n")
	rep, in, reg := checkRules(t, []lint.Rule{UntrustedCheckout, UntrustedCheckoutToctou}, wfFile(src), checkoutFacts{})
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 {
		t.Fatalf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule == UntrustedCheckoutToctouID && (f.Fix != nil || f.NoFix == nil || f.NoFix.Reason != ir.NoFixReasonFact) {
			t.Errorf("toctou: %+v", f)
		}
		if f.Rule == UntrustedCheckoutID && f.Fix == nil {
			t.Errorf("untrusted-checkout: no fix %+v", f)
		}
	}
	if _, err := lint.ApplyFixes(context.Background(), in, reg, checkoutFacts{}, rep, lint.SafetyReview); err != nil {
		t.Errorf("ApplyFixes: %v", err)
	}
	// protected: toctou's fix, safe
	r := checkoutFacts{protected: ptr(true)}
	if got := applied(t, UntrustedCheckoutToctou, src, r, lint.SafetySafe); !strings.Contains(got, "ref: '${{ github.event.pull_request.head.sha }}'") {
		t.Errorf("protected:\n%s", got)
	}
}

// TestUntrustedCheckoutFixKeepsStepPath: a file of facts that answers the first checkout keeps
// answering it after the fix of the second.
func TestUntrustedCheckoutFixKeepsStepPath(t *testing.T) {
	src := "on: pull_request_target\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + coOld + "\n        with: {ref: '${{ github.event.pull_request.head.sha }}', path: data}\n      - uses: " + coOld + "\n        with: {ref: '${{ github.event.pull_request.head.sha }}', path: code}\n      - run: ./code/build.sh\n"
	file, _ := facts.ParseInputPath(".github/workflows/w.yml")
	first, _ := facts.WorkflowStep("a", 0)
	r := stepFacts{file: file, step: first}
	got := applied(t, UntrustedCheckout, src, r, lint.SafetyReview)
	if !strings.Contains(got, "path: data}") || strings.Count(got, "head.sha") != 1 {
		t.Errorf("after the fix:\n%s", got)
	}
}

// stepFacts says the checkout at step of file is read as data, and that
// every other checkout runs.
type stepFacts struct {
	file facts.InputPath
	step facts.StepPath
}

func (s stepFacts) Resolve(ctx context.Context, q facts.Query) facts.RawAnswer {
	if e, ok := q.(facts.CheckoutExecuted); ok {
		v := e.InputPath != s.file || e.Step != s.step
		return checkoutFacts{executed: ptr(v)}.Resolve(ctx, q)
	}
	return checkoutFacts{}.Resolve(ctx, q)
}

// commit-sha pins a tag of a release with the guard; the run again after the
// fix, on a file of facts with the tag's commit, makes no new finding of
// untrusted-checkout (found in the corpus: pytorch's _binary-test-macos.yml).
func TestCheckoutAfterCommitSHAFix(t *testing.T) {
	src := checkoutJob("workflow_call", "", "actions/checkout@v5.1.0", "{ref: '${{ github.event.pull_request.head.sha }}'}", "      - run: npm ci\n")
	store, err := facts.LoadStore([]byte(`{"schema":"sisakulint/facts/v0","facts":[
{"query":{"kind":"git.ref-commit","repo":"actions/checkout","ref":"v5.1.0"},"state":"found","value":{"sha":"fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09","ref":"refs/tags/v5.1.0"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rep, in, reg := checkRules(t, []lint.Rule{CommitSHA, UntrustedCheckout}, wfFile(src), store)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Rule != CommitSHAID {
		t.Fatalf("%+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	if _, err := lint.ApplyFixes(context.Background(), in, reg, store, rep, lint.SafetySafe); err != nil {
		t.Errorf("ApplyFixes: %v", err)
	}
}

// TestFixRefusesAWeakerFinding: the case of testdata/interplay/weak-executed
// with every rule and the fixes that are safe: the pin of commit-sha makes
// the finding of untrusted-checkout conditional, and --fix refuses it (as
// the owner decided on 2026-09-29, to be looked at again if the fix is
// often refused).
func TestFixRefusesAWeakerFinding(t *testing.T) {
	dir := filepath.Join("testdata", "interplay", "weak-executed")
	in, err := lint.Enumerate(os.DirFS(dir))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(All())
	if err != nil {
		t.Fatal(err)
	}
	r := storeResolver(t, filepath.Join(dir, "facts.json"))()
	rep := lint.Run(context.Background(), in, reg, r)
	_, err = lint.ApplyFixes(context.Background(), in, reg, r, rep, lint.SafetySafe)
	if err == nil || !strings.Contains(err.Error(), "from confirmed to conditional") || !strings.Contains(err.Error(), "untrusted-checkout") {
		t.Errorf("err %v", err)
	}
}

package cli

import (
	"encoding/json"
	"github.com/gh-intel/sisakulint/actions/facts"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

type selectionJSON struct {
	Rules []struct {
		ID string `json:"id"`
	} `json:"rules"`
	Skipped  []string `json:"skipped_rules"`
	Findings []struct {
		Rule      string `json:"rule"`
		Certainty string `json:"certainty"`
	} `json:"findings"`
	Fix *struct {
		Unchecked []string `json:"unchecked_rules"`
	} `json:"fix"`
}

func selection(t *testing.T, stdout string) selectionJSON {
	t.Helper()
	var s selectionJSON
	if err := json.Unmarshal([]byte(stdout), &s); err != nil {
		t.Fatalf("%v: %s", err, stdout)
	}
	return s
}

// TestSkipRule: --skip-rule given again and with commas is the same; the
// rules skipped run not, and are in skipped_rules, beside the quality rule
// whose DefaultRun is named.
func TestSkipRule(t *testing.T) {
	dir := example(t)
	facts := dir + "/facts.json"
	all := selection(t, run(t, args("--root", dir, "--facts", facts)).stdout)
	for _, e := range []Env{
		args("--root", dir, "--facts", facts, "--skip-rule", "commit-sha", "--skip-rule", "impostor-commit"),
		args("--root", dir, "--facts", facts, "--skip-rule", "commit-sha,impostor-commit"),
	} {
		s := selection(t, run(t, e).stdout)
		if strings.Join(s.Skipped, ",") != "commit-sha,impostor-commit,missing-timeout-minutes" {
			t.Errorf("skipped_rules %v", s.Skipped)
		}
		for _, f := range s.Findings {
			if f.Rule == "commit-sha" || f.Rule == "impostor-commit" {
				t.Errorf("a finding of %s, which is skipped", f.Rule)
			}
		}
		if len(s.Rules)+len(s.Skipped) != len(all.Rules)+len(all.Skipped) {
			t.Errorf("rules %d and skipped %d, of %d and %d", len(s.Rules), len(s.Skipped), len(all.Rules), len(all.Skipped))
		}
	}
}

func TestRuleOnly(t *testing.T) {
	dir := example(t)
	got := run(t, args("--root", dir, "--facts", dir+"/facts.json", "--rule", "commit-sha"))
	s := selection(t, got.stdout)
	if len(s.Rules) != 1 || s.Rules[0].ID != "commit-sha" || got.code != 1 {
		t.Errorf("rules %v, exit %d; want commit-sha alone and bit 1", s.Rules, got.code)
	}
}

// TestSkipRuleExit: what is skipped sets no bit. labeled.yml of the example
// has one confirmed finding of untrusted-checkout-toctou and one of
// commit-sha (its README); with both rules skipped it has none, and only
// the inconclusive finding of known-vulnerable-actions (the file of facts
// does not answer the advisories of actions/checkout) sets bit 8.
func TestSkipRuleExit(t *testing.T) {
	dir := example(t)
	facts := dir + "/facts.json"
	if got := run(t, args("--root", dir, "--facts", facts, "--rule", "untrusted-checkout-toctou", ".github/workflows/labeled.yml")); got.code != 1 {
		t.Errorf("the rule alone: exit %d, want 1", got.code)
	}
	got := run(t, args("--root", dir, "--facts", facts, "--skip-rule", "untrusted-checkout-toctou,commit-sha", ".github/workflows/labeled.yml"))
	s := selection(t, got.stdout)
	inconclusive := 0
	for _, f := range s.Findings {
		if f.Certainty == "inconclusive" {
			inconclusive++
		}
	}
	if got.code != int(lint.InconclusiveBit) || len(s.Findings) != inconclusive || inconclusive == 0 {
		t.Errorf("both skipped: exit %d, %d findings, %d of the findings inconclusive; want 8, and only inconclusive findings", got.code, len(s.Findings), inconclusive)
	}
}

func TestSelectionUsage(t *testing.T) {
	dir := repo(t)
	for _, c := range []struct {
		name, why string
		env       Env
	}{
		{"an empty item", "empty", args("--root", dir, "--rule", "a,,b")},
		{"an empty value", "empty", args("--root", dir, "--skip-rule", "")},
		{"a space after a comma", "kebab-case", args("--root", dir, "--skip-rule", "commit-sha, impostor-commit")},
		{"a kind", "a kind of finding is not taken yet", args("--root", dir, "--rule", "commit-sha.unpinned")},
		{"both flags", "--rule and --skip-rule", args("--root", dir, "--rule", "commit-sha", "--skip-rule", "impostor-commit")},
		{"an unknown ID", `--skip-rule: no rule has the ID "comit-sha" (the rules are action-list, ai-action-excessive-tools, ai-action-execution-order, ai-action-prompt-injection, ai-action-unrestricted-trigger, ai-action-unsafe-sandbox, allowed-actions, archived-uses, argument-injection, artifact-poisoning, artipacked, bot-conditions, cache-bloat, cache-poisoning, code-injection,`, args("--root", dir, "--skip-rule", "comit-sha")},
		{"no rule left", "no rule is left to run", args("--root", dir, "--skip-rule", "action-list,ai-action-excessive-tools,ai-action-execution-order,ai-action-prompt-injection,ai-action-unrestricted-trigger,ai-action-unsafe-sandbox,argument-injection,artifact-poisoning,artipacked,bot-conditions,cache-poisoning,code-injection,commit-sha,credentials,dangerous-triggers,envpath-injection,envvar-injection,impostor-commit,known-vulnerable-actions,output-clobbering,permissions,request-forgery,secret-exfiltration,secret-exposure,secret-in-log,secrets-in-artifacts,secrets-inherit,self-hosted-runner,set-output-injection,unmasked-secret-exposure,unpinned-images,unsecure-commands,unsound-contains,untrusted-checkout,untrusted-checkout-toctou,archived-uses,cache-bloat,dependabot-github-actions,dependency-review-settings,deprecated-node-runtime,missing-timeout-minutes,cond,env-var,deprecated-commands,uses-path,expression,allowed-actions")},
		{"with the registry", "--registry", raw("--registry", "--rule", "commit-sha")},
		{"with explain", "--explain", raw("--explain=commit-sha", "--skip-rule", "commit-sha")},
	} {
		got := run(t, c.env)
		if got.code != ExitUsage || got.stdout != "" || !strings.Contains(got.stderr, c.why) {
			t.Errorf("%s: exit %d, stdout %q, stderr %q; want %d and %q", c.name, got.code, got.stdout, got.stderr, ExitUsage, c.why)
		}
	}
}

// TestRuleWithNoInputOfItsTargets: a rule that finds nothing in the
// repository runs, and it is no error.
func TestRuleWithNoInputOfItsTargets(t *testing.T) {
	dir := repo(t)
	if got := run(t, args("--root", dir, "--rule", "untrusted-checkout-toctou")); got.code >= ExitUsage {
		t.Errorf("exit %d: %s", got.code, got.stderr)
	}
}

// TestTextRules: the text says which rules ran when not every rule did,
// naming the fewer of those that ran and those skipped.
func TestTextRules(t *testing.T) {
	dir := example(t)
	facts := dir + "/facts.json"
	for _, c := range []struct {
		golden string
		env    Env
	}{
		{"skip.golden", raw("--root", dir, "--facts", facts, "--color", "never", "--detail", "summary", "--skip-rule", "impostor-commit")},
		{"only.golden", raw("--root", dir, "--facts", facts, "--color", "never", "--detail", "summary", "--rule", "commit-sha,impostor-commit")},
	} {
		golden(t, c.golden, run(t, c.env).stdout)
	}
	skip := run(t, raw("--root", dir, "--facts", facts, "--color", "never", "--skip-rule", "impostor-commit"))
	if !strings.Contains(skip.stdout, "rules  46 of 47 ran; skipped: impostor-commit\n") {
		t.Errorf("no rules line in the normal text:\n%s", skip.stdout)
	}
	only := run(t, raw("--root", dir, "--facts", facts, "--color", "never", "--rule", "commit-sha,impostor-commit"))
	if !strings.Contains(only.stdout, "rules  2 of 47 ran: commit-sha, impostor-commit\n") {
		t.Errorf("no rules line:\n%s", only.stdout)
	}
	if all := run(t, raw("--root", dir, "--facts", facts, "--color", "never")); strings.Contains(all.stdout, "\nrules  ") {
		t.Errorf("a rules line though every rule ran:\n%s", all.stdout)
	}
	// A quality rule of DefaultRunNamed that did not run counts for nothing
	// in the line: it was not left out (the owner decision of 2026-10-16).
	if skipped := run(t, raw("--root", dir, "--facts", facts, "--color", "never", "--skip-rule", "missing-timeout-minutes")); strings.Contains(skipped.stdout, "\nrules  ") {
		t.Errorf("a rules line for a rule of DefaultRunNamed:\n%s", skipped.stdout)
	}
	named := run(t, raw("--root", dir, "--facts", facts, "--color", "never", "--rule", "missing-timeout-minutes"))
	if !strings.Contains(named.stdout, "rules  1 of 48 ran: missing-timeout-minutes\n") || !strings.Contains(named.stdout, "missing-timeout-minutes.job") {
		t.Errorf("a rule of DefaultRunNamed named:\n%s", named.stdout)
	}
}

// guard is a copy of the case of the matrix whose pin of commit-sha may
// raise untrusted-checkout.executed (testdata/interplay of actions/rules).
func guard(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("..", "rules", "testdata", "interplay", "guard-executed"))); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestNotChecked: a fix that changes a field a rule skipped reads says
// so, in the report, the text, the lines and on stderr for --dry-run; with
// every rule, the fix is refused (a limit untrusted-checkout declares)
// and nothing is unchecked. known-vulnerable-actions,
// deprecated-node-runtime, action-list and allowed-actions do not run by
// default (the file of facts does not answer package.advisories,
// action.runs-using, repo.action-list or repo.allowed-actions), so the pin
// is not checked against them either.
func TestNotChecked(t *testing.T) {
	// the fields of the checkout's summary the pin changes, which
	// untrusted-checkout reads; not those of toctou, which runs
	const line = "not checked: untrusted-checkout (skipped; commit-sha.pin-sha changes checkout-site.guard, checkout-site.sha at .github/workflows/w.yml jobs.build.steps[0])"
	dir := guard(t)
	facts := dir + "/facts.json"
	if s := selection(t, run(t, args("--root", dir, "--facts", facts, "--skip-rule", "untrusted-checkout", "--fix")).stdout); s.Fix == nil || strings.Join(s.Fix.Unchecked, ",") != "action-list,allowed-actions,deprecated-node-runtime,known-vulnerable-actions,untrusted-checkout" {
		t.Errorf("unchecked_rules: %+v", s.Fix)
	}
	dir = guard(t)
	if text := run(t, raw("--root", dir, "--facts", facts, "--color", "never", "--skip-rule", "untrusted-checkout", "--fix")); !strings.Contains(text.stdout, "  "+line+"\n") {
		t.Errorf("text:\n%s", text.stdout)
	}
	dir = guard(t)
	if lines := run(t, raw("--root", dir, "--facts", facts, "--format", "line", "--skip-rule", "untrusted-checkout", "--fix")); !strings.Contains(lines.stdout, "sisakulint: fix: "+line+"\n") {
		t.Errorf("line:\n%s", lines.stdout)
	}
	dir = guard(t)
	dry := run(t, raw("--root", dir, "--facts", facts, "--skip-rule", "untrusted-checkout", "--fix", "--dry-run"))
	both := run(t, raw("--root", dir, "--facts", facts, "--skip-rule", "untrusted-checkout,untrusted-checkout-toctou", "--fix", "--dry-run"))
	if !strings.Contains(dry.stderr, "sisakulint: "+line+"\n") || dry.stdout == "" || dry.stdout != both.stdout {
		t.Errorf("--dry-run: stderr %q, stdout %q; want the line on stderr, and the diff as with toctou skipped too", dry.stderr, dry.stdout)
	}
	dir = guard(t)
	refused := run(t, args("--root", dir, "--facts", facts, "--fix"))
	if s := selection(t, refused.stdout); refused.code != ExitFix || s.Fix == nil || len(s.Fix.Unchecked) != 0 {
		t.Errorf("every rule: exit %d, fix %+v", refused.code, s.Fix)
	}
}

// TestNotCheckedWhenTheFixFails: what the fixes were not checked against
// is said though writing them failed.
func TestNotCheckedWhenTheFixFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a directory without the permission to")
	}
	dir := guard(t)
	// the fix fails before it writes: a directory that cannot be written
	// (as TestFixWritesNothingOnAFailure of fix_test.go)
	workflows := filepath.Join(dir, ".github", "workflows")
	if err := os.Chmod(workflows, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(workflows, 0o755) })
	got := run(t, raw("--root", dir, "--facts", dir+"/facts.json", "--color", "never", "--skip-rule", "untrusted-checkout", "--fix"))
	if got.code != ExitFix || !strings.Contains(got.stdout, "error: ") || !strings.Contains(got.stdout, "not checked: untrusted-checkout") {
		t.Errorf("exit %d:\n%s", got.code, got.stdout)
	}
}

func TestSkipRuleStdin(t *testing.T) {
	src := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\npermissions: {}\n"
	got := run(t, Env{Args: []string{"--format=json", "--stdin-name", ".github/workflows/w.yml", "--skip-rule", "commit-sha"}, Stdin: strings.NewReader(src)})
	if s := selection(t, got.stdout); len(s.Findings) != 0 || strings.Join(s.Skipped, ",") != "action-list,allowed-actions,archived-uses,commit-sha,deprecated-node-runtime,impostor-commit,known-vulnerable-actions,missing-timeout-minutes,unset-configuration-variable" || got.code != 0 {
		t.Errorf("stdin, commit-sha skipped: exit %d, %+v", got.code, s)
	}
}

// TestUncheckedTextEscapes: a path with a control byte (a
// job's name) is written escaped.
func TestUncheckedTextEscapes(t *testing.T) {
	u := lint.Unchecked{Rule: lint.MustRuleID("untrusted-checkout"), Changed: []lint.Changed{{Input: facts.MustCleanInputPath(".github/workflows/w.yml"), Path: "jobs.a\x1b[31m.steps[0]", Fields: []ir.SummaryField{ir.FieldCheckoutSiteGuard}}}}
	got := uncheckedText(u)
	if strings.Contains(got, "\x1b") {
		t.Errorf("an escape byte in %q", got)
	}
	if want := "not checked: untrusted-checkout (skipped; the fixes of .github/workflows/w.yml change checkout-site.guard at jobs.a"; !strings.HasPrefix(got, want) {
		t.Errorf("got %q, want it to start with %q", got, want)
	}
}

// TestNotCheckedOfTheExample: on the example of every rule, the pin of
// commit-sha alone says only what changes the summaries of checkouts (the
// pins of the other actions say nothing).
func TestNotCheckedOfTheExample(t *testing.T) {
	ex := filepath.Join("..", "rules", "testdata", "all-rules")
	got := run(t, raw("--root", ex, "--facts", filepath.Join(ex, "facts.json"), "--rule", "commit-sha", "--fix", "--dry-run"))
	golden := filepath.Join("testdata", "text", "notchecked-all-rules.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got.stderr), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got.stderr != string(want) {
		t.Errorf("stderr:\n%s\nwant:\n%s", got.stderr, want)
	}
}

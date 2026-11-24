package cli

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

var update = flag.Bool("update", false, "write the golden files of testdata/text")

func textOf(t *testing.T, rep lint.Report, in lint.Inputs, o textOptions) string {
	t.Helper()
	var b bytes.Buffer
	if err := writeText(&b, rep, in, registry(t), o); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata/text", name)
	if *update {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("%s differs (go test ./actions/cli/ -run %s -update):\n%s", name, t.Name(), got)
	}
}

func TestTextGolden(t *testing.T) {
	rep, in := runText(t, textRepo)
	for _, c := range []struct {
		name string
		o    textOptions
	}{
		{"default.golden", textOptions{threshold: lint.SeverityInfo}},
		{"summary.golden", textOptions{detail: detailSummary, threshold: lint.SeverityInfo}},
		{"verbose.golden", textOptions{detail: detailFull, threshold: lint.SeverityInfo}},
		{"color.golden", textOptions{color: true, threshold: lint.SeverityInfo}},
		{"color-summary.golden", textOptions{detail: detailSummary, color: true, threshold: lint.SeverityInfo}},
		{"fail-on-critical.golden", textOptions{threshold: lint.SeverityCritical}},
	} {
		t.Run(c.name, func(t *testing.T) { golden(t, c.name, textOf(t, rep, in, c.o)) })
	}
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

// Without the escapes of color, the text with color is the text without.
func TestTextColorOnly(t *testing.T) {
	rep, in := runText(t, textRepo)
	for _, d := range []detail{detailNormal, detailSummary, detailFull} {
		plain := textOf(t, rep, in, textOptions{detail: d, threshold: lint.SeverityInfo})
		colored := textOf(t, rep, in, textOptions{detail: d, color: true, threshold: lint.SeverityInfo})
		if colored == plain || ansi.ReplaceAllString(colored, "") != plain {
			t.Errorf("detail %d: the text with color is not the plain text with escapes:\n%s", d, colored)
		}
	}
	plain, colored := linesOf(t, rep, in, false), linesOf(t, rep, in, true)
	if colored == plain || ansi.ReplaceAllString(colored, "") != plain {
		t.Errorf("the lines with color are not the plain lines with escapes:\n%s", colored)
	}
}

// The gutter of a source is gray, and the count of a row bold.
func TestTextColorParts(t *testing.T) {
	rep, in := runText(t, textRepo)
	got := textOf(t, rep, in, textOptions{color: true, threshold: lint.SeverityInfo})
	for _, want := range []string{gray + "    7 | " + reset + "      - uses: actions/setup-go@v5", "  " + bold + "×4" + reset + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%q", want, got)
		}
	}
}

func TestTextSections(t *testing.T) {
	rep, in := runText(t, textRepo)
	got := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	for _, want := range []string{
		"critical  code-injection.controlled  ×5\n",
		"critical  code-injection.wiki  .github/workflows/wiki.yml:8:24\n",
		"high  commit-sha.unpinned  ×7\n",
		"  actions/checkout@v4 is not pinned to a full commit SHA  ×4\n    .github/workflows/alias.yml:6:36 via alias at 10:15  (+3 more, -v)\n    6 |       - uses: &co actions/checkout@v4\n",
		"  actions/setup-node@v4 is not pinned to a full commit SHA  ×2\n    .github/workflows/pins.yml:6:34  (+1 more, -v)\n",
		"  actions/setup-go@v5 is not pinned to a full commit SHA\n    .github/workflows/pins.yml:7:32\n    7 |       - uses: actions/setup-go@v5\n",
		"  fact: repo.wiki-open = true\n",
		"  fix (review): move the expressions into the env of the step, and read the variables where they were, quoted as the shell needs (bash and sh)  [--fix=review]\n",
		"conditional  2 findings hold only if what is not known here is so",
		"  impostor-commit.fork-commit (high)  2 findings, 1 unknown",
		"git.commit-ref repo=actions/cache sha=668228422ae6a00e4ad889ee87cd7109ec5666a7  → 2 places",
		"  why: offline: pass --facts or --online",
		"inconclusive  10 findings: the rules could not decide whether the place of each finding has the problem that the rule of the finding looks for; a person decides",
		"critical  known-vulnerable-actions.advisories-unknown  .github/workflows/alias.yml:6:36 via alias at 10:15  inconclusive\n",
		"    … 7 more (-v)\n",
		"  code-injection  step-output-run 1",
		"  known-vulnerable-actions  advisories-unknown 9", // offline: the advisories of each uses are not known
		"inputs  5 read, 1 invalid  (every workflow and action.yml under --root)",
		"  invalid ×1: diagnostics",
		"bits 27 = 1 (confirmed findings) + 2 (conditional findings) + 8 (inconclusive findings) + 16 (inputs not valid)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	if n := strings.Count(got, "  no fix: "); n != 1 {
		t.Errorf("%d lines of no fix, want 1 for the fold:\n%s", n, got)
	}
	if strings.Contains(got, "(1 edits)") || strings.Contains(got, "(2 edits)") {
		t.Errorf("the title of a finding's fix, not of its kind:\n%s", got)
	}
	if strings.Index(got, "critical  ") > strings.Index(got, "high  ") {
		t.Errorf("a high finding before the critical ones:\n%s", got)
	}
}

// A fold of critical findings shows the source of each place it shows, at
// most 3 for a row; a fold of others, the source of the first place of
// each row.
func TestTextGroupSource(t *testing.T) {
	rep, in := runText(t, textRepo)
	got := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	for _, want := range []string{
		"and an attacker controls it on issues  ×4\n    .github/workflows/env.yml:8:24\n    8 |       - run: echo \"${{ env.TITLE }}\"\n",
		"    .github/workflows/env.yml:9:30\n    9 |       - run: echo \"again ${{ env.TITLE }}\"\n",
		"    … 1 more (-v)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	if n := strings.Count(got, "- uses: actions/setup-node@v4"); n != 1 {
		t.Errorf("%d sources of the row of setup-node, want 1 (its first place):\n%s", n, got)
	}
	full := textOf(t, rep, in, textOptions{detail: detailFull, threshold: lint.SeverityInfo})
	for _, want := range []string{"- uses: actions/setup-go@v5", "fourth ${{ env.TITLE }}", "(1 edits)"} {
		if !strings.Contains(full, want) {
			t.Errorf("no %q in full:\n%s", want, full)
		}
	}
}

func TestTextErrorsAndFix(t *testing.T) {
	rep, in := runText(t, textRepo)
	rep.Errors = []lint.RunError{{Rule: lint.MustRuleID("commit-sha"), Input: facts.MustCleanInputPath("a.yml"), Message: "broke\x1b[2J"}}
	rep.Fix = &lint.FixResult{Safety: lint.SafetySafe, Written: []facts.InputPath{facts.MustCleanInputPath("a.yml")}, Error: "b.yml: permission denied"}
	got := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	for _, want := range []string{
		"errors  1 (a rule or a fix broke its contract; the report is not whole)",
		`  commit-sha a.yml: broke\x1b[2J`,
		"fix (safe)  wrote 1 file",
		"  a.yml",
		"  error: b.yml: permission denied",
		"+ 4 (internal errors)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

// TestTextNoInput: the text of a run with no input.
func TestTextNoInput(t *testing.T) {
	rep, in := runText(t, t.TempDir())
	got := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	for _, want := range []string{"inputs  no input", "0 findings", "bits 2 = 2 (no input)"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

// TestSnippetLineEnds: the last line with no newline, and CRLF.
func TestSnippetLineEnds(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github/workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on: push\r\npermissions: {}\r\njobs:\r\n  a:\r\n    runs-on: ubuntu-latest\r\n    steps:\r\n      - uses: actions/setup-go@v5"
	if err := os.WriteFile(filepath.Join(wf, "crlf.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, in := runText(t, dir)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
		t.Fatalf("%d findings, want 1", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)))
	}
	got := snippet(in, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Location)
	want := []string{
		"    7 |       - uses: actions/setup-go@v5", // permissions: {} is line 2
		"      |                                ^^",
	}
	if len(got) != 2 || got[0].String() != want[0] || got[1].String() != want[1] {
		t.Errorf("snippet =\n%q\nwant\n%q", got, want)
	}
}

// Whatever a workflow has, the text has no control character but the
// newline and the tab, and no mark that reorders text.
func FuzzWriteText(f *testing.F) {
	for _, n := range []string{"issues.yml", "env.yml", "wiki.yml", "alias.yml", "bad.yml", "pins.yml"} {
		b, err := os.ReadFile(filepath.Join(textRepo, ".github/workflows", n))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte("on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\" \x1b[2J\u202e\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		in, err := lint.Single(lint.InputBytes{Name: facts.MustCleanInputPath(".github/workflows/\x1b\u202ex.yml"), Bytes: b})
		if err != nil {
			t.Skip()
		}
		rep := lint.Run(t.Context(), in, registry(t), offline{})
		for _, d := range []detail{detailSummary, detailNormal, detailFull} {
			out := textOf(t, rep, in, textOptions{detail: d, threshold: lint.SeverityInfo})
			if !utf8.ValidString(out) {
				t.Fatalf("not UTF-8:\n%q", out)
			}
			for _, r := range out {
				if r != '\n' && hazard(r) {
					t.Fatalf("%U in\n%q", r, out)
				}
			}
		}
		out := linesOf(t, rep, in, false)
		if strings.Count(out, "\n") != lineCount(rep) {
			t.Fatalf("%d lines, want %d:\n%q", strings.Count(out, "\n"), lineCount(rep), out)
		}
		for _, r := range out {
			if r != '\n' && hazard(r) {
				t.Fatalf("%U in the lines\n%q", r, out)
			}
		}
	})
}

// worst is at the end, before the count, and has the critical rows only,
// each with its message.
func TestTextWorst(t *testing.T) {
	rep, in := runText(t, textRepo)
	for _, o := range []textOptions{{threshold: lint.SeverityInfo}, {detail: detailFull, threshold: lint.SeverityInfo}, {threshold: lint.SeverityCritical}} {
		got := textOf(t, rep, in, o)
		want := "worst\n" +
			"  critical  code-injection.controlled  ×4  .github/workflows/env.yml:8:24\n" +
			"    env.TITLE is written into the run script by ${{ }}, and an attacker controls it on issues\n" +
			"  critical  code-injection.controlled  .github/workflows/issues.yml:11:21\n" +
			"    github.event.issue.title is written into the run script by ${{ }}, and an attacker controls it on issues\n" +
			"  critical  code-injection.wiki  .github/workflows/wiki.yml:8:24\n" +
			"    github.event.pages[0].title is written into the run script by ${{ }}, and an attacker controls it on gollum\n" +
			// then the inconclusive findings of the same severity, marked
			"  critical  known-vulnerable-actions.advisories-unknown  .github/workflows/alias.yml:6:36  inconclusive\n"
		i := strings.Index(got, want)
		if i < 0 || i < strings.Index(got, "inputs  ") || i > strings.Index(got, "25 findings") {
			t.Errorf("%+v: no %q between the inputs and the count in\n%s", o, want, got)
		}
	}
}

func TestTextSummary(t *testing.T) {
	rep, in := runText(t, textRepo)
	got := textOf(t, rep, in, textOptions{detail: detailSummary, threshold: lint.SeverityInfo})
	want := "critical  code-injection.controlled  ×5 (2 messages)  .github/workflows/env.yml:8:24\n" +
		"critical  code-injection.wiki        ×1  .github/workflows/wiki.yml:8:24\n" +
		"high      commit-sha.unpinned        ×7 (3 messages)  .github/workflows/alias.yml:6:36 via alias at 10:15\n" +
		"\n" +
		"conditional   impostor-commit.fork-commit  ×2, 1 unknown  (offline: pass --facts or --online)\n" +
		"inconclusive  10 findings (code-injection, known-vulnerable-actions)\n" +
		"inputs        5 read, 1 invalid  (every workflow and action.yml under --root)\n" +
		"\n" +
		"25 findings: 13 confirmed (critical 6, high 7), 2 conditional, 10 inconclusive\n" +
		"30 quality findings: the bits do not count quality findings\n" +
		"bits 27 = 1 (confirmed findings) + 2 (conditional findings) + 8 (inconclusive findings) + 16 (inputs not valid)\n"
	if got != want {
		t.Errorf("summary =\n%s\nwant\n%s", got, want)
	}
}

// TestTextSummaryEmpty: the summary of a run with no input.
func TestTextSummaryEmpty(t *testing.T) {
	rep, in := runText(t, t.TempDir())
	got := textOf(t, rep, in, textOptions{detail: detailSummary, threshold: lint.SeverityInfo})
	if want := "inputs        no input\n\n0 findings\nbits 2 = 2 (no input)\n"; got != want {
		t.Errorf("summary of no input =\n%q\nwant\n%q", got, want)
	}
}

// Only normal says how many more places a row of a fold of others has
// (its first place is shown), on the line of that place; the head of the
// fold says nothing of it.
func TestTextEveryPlaceHint(t *testing.T) {
	rep, in := runText(t, textRepo)
	for _, c := range []struct {
		d    detail
		want int
	}{{detailNormal, 2}, {detailSummary, 0}, {detailFull, 0}} {
		got := textOf(t, rep, in, textOptions{detail: c.d, threshold: lint.SeverityInfo})
		if n := strings.Count(got, " more, -v)\n"); n != c.want || strings.Contains(got, "(-v for every place)") {
			t.Errorf("detail %d: %d hints of more places, want %d, and none on the head:\n%s", c.d, n, c.want, got)
		}
	}
}

// A fold says its impact once, under its head, and its remedy once,
// before its fixes; its rows are facts.
func TestTextImpactOnce(t *testing.T) {
	rep, in := runText(t, textRepo)
	got := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	for _, want := range []string{
		"high  commit-sha.unpinned  ×7\n  impact: whoever can move the ref decides what runs here\n  actions/checkout@v4 is not pinned to a full commit SHA  ×4\n",
		"  remedy: pin the uses to a full commit SHA\n  no fix: ",
		"critical  code-injection.wiki  .github/workflows/wiki.yml:8:24\n  github.event.pages[0].title is written into the run script by ${{ }}, and an attacker controls it on gollum\n  impact: the value becomes code\n    8 |",
		"  remedy: pass it through env and read the variable\n  fact: repo.wiki-open = true",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	// and each inconclusive finding shown says both, as in full: the first
	// shown of them
	if i, r := strings.Count(got, "  impact: "), strings.Count(got, "  remedy: "); i != 3+shown || r != 3+shown {
		t.Errorf("%d impacts and %d remedies, want %d each, one for each fold and each inconclusive finding shown:\n%s", i, r, 3+shown, got)
	}
	full := textOf(t, rep, in, textOptions{detail: detailFull, threshold: lint.SeverityInfo})
	if i, r := strings.Count(full, "  impact: "), strings.Count(full, "  remedy: "); i != len(rep.Findings) || r != len(rep.Findings) {
		t.Errorf("full: %d impacts and %d remedies, want one for each of the %d findings:\n%s", i, r, len(rep.Findings), full)
	}
}

// An impact and a remedy are cleaned as all a report says.
func TestTextImpactClean(t *testing.T) {
	rep, in := runText(t, textRepo)
	for i := range rep.Findings {
		rep.Findings[i].Consequence, rep.Findings[i].Remedy = "bad\x1b[2J", "fix\u202e"
	}
	got := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	if strings.Contains(got, "\x1b[2J") || strings.Contains(got, "\u202e") || !strings.Contains(got, `impact: bad\x1b[2J`) || !strings.Contains(got, `remedy: fix\u202e`) {
		t.Errorf("an impact or a remedy not cleaned:\n%q", got)
	}
}

// A conditional finding in full is what it detects, its impact, its source, what
// decides it, and its remedy.
func TestTextConditionalVerbose(t *testing.T) {
	rep, in := runText(t, textRepo)
	got := textOf(t, rep, in, textOptions{detail: detailFull, threshold: lint.SeverityInfo})
	for _, want := range []string{
		"  impact: the step runs the code of a commit that exists only in a fork repository, and any GitHub user can create a fork repository and push commits to the fork repository; when no repository has the commit, the job fails in the step Set up job, and no step of the job runs\n",
		"  decided by: git.commit-ref repo=actions/cache sha=668228422ae6a00e4ad889ee87cd7109ec5666a7\n  remedy: pin a commit of a branch or a tag of the repository\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
}

// The hint to give the whole repository is there when an input decides a
// finding, even when that decider is past those shown.
func TestTextWholeRepositoryHintPastCut(t *testing.T) {
	var by []decider
	for i := range shown + 2 {
		by = append(by, decider{facts: []facts.Query{facts.TestFlag{Name: string(rune('a' + i))}}})
	}
	by[len(by)-1] = decider{inputs: []facts.InputPath{facts.MustCleanInputPath(".github/workflows/other.yml")}}
	for _, verbose := range []bool{false, true} {
		p := &printer{}
		p.conditional([]ruleConditionals{{severity: lint.SeverityHigh, results: []lint.Finding{{}}, by: by}}, verbose)
		if !strings.Contains(p.b.String(), "or give the whole repository (no PATH)") {
			t.Errorf("verbose=%v: no hint to give the whole repository:\n%s", verbose, p.b.String())
		}
	}
}

func TestTextExcluded(t *testing.T) {
	in, err := lint.EnumerateExcept(os.DirFS("testdata/repo"), []lint.Exclude{mustExclude(t, ".github/actions")})
	if err != nil {
		t.Fatal(err)
	}
	rep := lint.Run(context.Background(), in, registry(t), offline{})
	text := textOf(t, rep, in, textOptions{threshold: lint.SeverityInfo})
	for _, s := range []string{" 1 excluded", "  excluded ×1: --exclude .github/actions"} {
		if !strings.Contains(text, s) {
			t.Errorf("no %q in\n%s", s, text)
		}
	}
	var b bytes.Buffer
	if err := writeLines(&b, rep, in, registry(t), false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "excluded") {
		t.Errorf("a line for an excluded input:\n%s", b.String())
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "a"), 0o755)
	if err := os.WriteFile(filepath.Join(dir, "a/action.yml"), []byte("runs:\n  using: composite\n  steps: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	only, _ := lint.EnumerateExcept(os.DirFS(dir), []lint.Exclude{mustExclude(t, "a")})
	r2 := lint.Run(context.Background(), only, registry(t), offline{})
	if got := textOf(t, r2, only, textOptions{threshold: lint.SeverityInfo}); !strings.Contains(got, "2 (no input)") {
		t.Errorf("every input excluded: no %q in\n%s", "2 (no input)", got)
	}
}

func mustExclude(t *testing.T, s string) lint.Exclude {
	t.Helper()
	e, err := lint.ParseExclude(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

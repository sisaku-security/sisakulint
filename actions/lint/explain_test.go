package lint

import (
	"context"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// TestMarkdownText: a string is written as it is but where CommonMark,
// GFM or GitHub would read it as markup; the brackets as character
// references (a renderer with math reads \( and \[ as the start of a
// formula), and the spaces and tabs a line starts with, which would make an
// indented code block.
func TestMarkdownText(t *testing.T) {
	for in, out := range map[string]string{
		"plain words 09":                        "plain words 09",
		"日本語と é":                                "日本語と é",
		"a workflow's run: step.":               "a workflow's run: step.",
		"github.head_ref":                       "github.head_ref",
		"_x_":                                   `\_x\_`,
		"a*b":                                   `a\*b`,
		"a`b":                                   "a\\`b",
		`\d`:                                    `\\d`,
		"~x~":                                   `\~x\~`,
		"[x](y)":                                "&#91;x](y)",
		"f(x)":                                  "f(x)",
		"<owner>/<repo>":                        "&lt;owner>/&lt;repo>",
		"a < b":                                 "a < b",
		"&amp; and &#36;":                       "&amp;amp; and &amp;#36;",
		"R&D":                                   "R&D",
		"${{ a }} and ${{ b }}":                 `\${{ a }} and \${{ b }}`,
		"- x":                                   `\- x`,
		"+ x":                                   `\+ x`,
		"# x":                                   `\# x`,
		"> x":                                   `\> x`,
		"1. x":                                  `1\. x`,
		"2) x":                                  `2\) x`,
		"12 x. y":                               "12 x. y",
		"8.2 (high)":                            "8.2 (high)",
		"1.":                                    `1\.`,
		"-x and --rule":                         "-x and --rule",
		"---":                                   `\---`,
		"-":                                     `\-`,
		"#x":                                    "#x",
		"## x":                                  `\## x`,
		"+x":                                    "+x",
		"    four spaces":                       "&#32;&#32;&#32;&#32;four spaces",
		"\tx y":                                 "&#9;x y",
		":smile:":                               ":smile:",
		"on: push:":                             "on: push:",
		"(https://api.example.com/<the value>)": `(https\://api.example.com/&lt;the value>)`,
		"see https://example.com/a/b.":          "see https://example.com/a/b.",
		"https://example.com/a/_x_":             `https\://example.com/a/\_x\_`,
		"www.example.com/a~b":                   `www\.example.com/a\~b`,
		"www.example.com/a":                     "www.example.com/a",
		"awww.x/~":                              `awww.x/\~`,
		"<1foo@bar.com>":                        "&lt;1foo@bar.com>",
		"a <-x@y.io>":                           "a &lt;-x@y.io>",
		"-- -":                                  `\-- -`,
		"- - x":                                 `\- - x`,
		"x #":                                   `x \#`,
		"x ##":                                  `x \#\#`,
		"x#":                                    "x#",
		"C#":                                    "C#",
		`\(x\) and \[y\]`:                       `\\&#40;x\\&#41; and \\&#91;y\\&#93;`,
		"a\\ (b)":                               `a\\ (b)`,
		"":                                      "",
	} {
		if got := MarkdownText(in); got != out {
			t.Errorf("MarkdownText(%q) = %q, want %q", in, got, out)
		}
	}
}

// TestMarkdownCodeBlock: a fenced code block at the start of a line, its
// fence longer than any run of backquotes in it, a blank line left blank,
// and a line break after the last line.
func TestMarkdownCodeBlock(t *testing.T) {
	for _, c := range []struct{ lang, in, out string }{
		{"yaml", "a\n\nb", "```yaml\na\n\nb\n```\n"},
		{"yaml", "a\n", "```yaml\na\n```\n"},
		{"text", "x ``` y\n", "````text\nx ``` y\n````\n"},
	} {
		if got := MarkdownCodeBlock(c.lang, c.in); got != c.out {
			t.Errorf("MarkdownCodeBlock(%q, %q) = %q, want %q", c.lang, c.in, got, c.out)
		}
	}
}

// explainOf is the Markdown of the rules ms, by a registry of them.
func explainOf(t *testing.T, ids []RuleID, ms ...Meta) string {
	t.Helper()
	var rules []Rule
	for _, m := range ms {
		rules = append(rules, testRule{meta: m})
	}
	reg, err := NewRegistry(rules)
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.Explain(ids, "abc (modified)")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ruleOf is meta(id) with its own kinds.
func ruleOf(id string) Meta {
	m := meta(id)
	m.FindingKinds = ownKinds(id)
	return m
}

// TestExplain: the whole Markdown of the least rule; empty fields and
// groups are left out.
func TestExplain(t *testing.T) {
	var cvss strings.Builder
	for _, nv := range []string{"AV:N", "AC:L", "AT:P", "PR:N", "UI:N", "VC:H", "VI:N", "VA:N", "SC:N", "SI:N", "SA:N", "E:U"} {
		n, v, _ := strings.Cut(nv, ":")
		cvss.WriteString("- " + n + ": " + v + "\n  - reason: for the test\n  - cites: none\n")
	}
	want := "# sisakulint rules\n\n" +
		"- commit: abc (modified)\n- terms: sisakulint --explain=terms\n\n" +
		"## a-rule\n\n" +
		"- problem: a rule a-rule detects\n" +
		"- expected: a rule a-rule holds\n" +
		"- severity: high\n" +
		"- targets: workflow\n" +
		"- facets:\n  - weakness: script-injection\n  - attack-means: string\n- default run: always: in a run without --rule, the rule runs unless --skip-rule names the rule\n\n" +
		"### finding kinds\n\n" +
		"- a-rule.said\n" +
		"  - detected: {text}\n" +
		"  - consequence: it was said\n" +
		"  - remedy: say it not\n" +
		"  - severity: high (found from the CVSS metrics below by the table)\n" +
		"  - attackers: commenter\n" +
		"  - preconditions: p\n" +
		"  - true positives:\n    - a-rule.said.yml (workflow, true-positive)\n      ```yaml\n      on: push\n      ```\n" +
		"  - true negatives:\n    - a-rule.said.yml (workflow, true-negative)\n      ```yaml\n      on: push\n      ```\n\n" +
		"### threat\n\n" +
		"- precondition p: a\n" +
		"  - cites:\n" +
		"    - <https://example.com/p>\n" +
		"- actor: commenter\n" +
		"  - via: comments\n" +
		"  - gains: run-code\n\n" +
		"### CVSS\n\n" +
		"#### a-rule.said\n\n" +
		"- vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U\n" +
		"- CVSS-B: 8.2 (high)\n" +
		"- CVSS-BT: 4.6 (medium)\n" +
		"- impact: H (from VC)\n" +
		"- likelihood: medium (from AV:N, AT:P, PR:N)\n" +
		"- severity: high (impact H, likelihood medium; the table: sisakulint --explain=terms)\n" +
		cvss.String() + "\n" +
		"### citations\n\n" +
		"- <https://example.com/x>\n" +
		"- <https://example.com/p>\n"
	if got := explainOf(t, nil, ruleOf("a-rule")); got != want {
		t.Errorf("Explain =\n%s\nwant\n%s", got, want)
	}
}

// TestExplainFields: the fields the least rule leaves empty, each where
// its group is; the sources are the rule's and what its text cites, each
// once.
func TestExplainFields(t *testing.T) {
	m := fixing(ruleOf("a-rule"), FixKind{ID: MustFixKindID("pin"), Title: "pin it", FactKinds: []facts.Kind{facts.KindTestText}, Safety: SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord}})
	m = asking(m, facts.KindTestFlag)
	k := &m.FindingKinds[0]
	// each sentence has punctuation, so that one written without md is seen
	m.Threat.Actors[0].Via = "comments (on a PR)"
	k.Remedy = "say it not!"
	k.CVSS.VI.Reason = "for the test: VI"
	m.Threat.Actors[0].Events = []workflow.EventName{workflow.EventNameIssueComment}
	m.Threat.Actors[0].RunStarters = map[workflow.EventName]RunStarter{workflow.EventNameIssueComment: RunStarterAttacker}
	m.Threat.Preconditions[0].Observed = []Observation{{Date: MustDate("2026-09-24"), Runner: MustVersion("2.337.0"), What: "it ran."}, {Date: MustDate("2026-09-25"), What: "the API said so"}}
	k.CVSS.AV.Cites = []Citation{MustCitation("https://example.com/av")}
	k.CVSS.VC.Cites = []Citation{MustCitation("https://example.com/p")} // the precondition cites it too
	k.ExploitMaturity = Metric[ExploitMaturity]{Value: ExploitMaturityAttacked, Reason: "for the test"}
	m.Threat.Incidents = []Incident{{ID: incidentI, Date: MustDate("2025-03-14"), CVE: MustCVE("CVE-2025-30066"), Advisory: MustCitation("https://example.com/ghsa"),
		Compromised: repos(t, "o/c"), Downstream: repos(t, "o/d", "o/e"), Summary: "it happened; again"}}
	k.Incidents = []IncidentID{incidentI}
	m.UndetectedForms = []UndetectedForm{
		{ID: MustUndetectedFormID("o"), Text: "not an attack*", Disposition: NoAddedGain(), Examples: []Example{withCause(exampleOf("o.yml"))}},
		{ID: MustUndetectedFormID("r"), Text: "b reports it", Disposition: OtherRule(MustRuleID("b-rule")), Examples: []Example{withCause(exampleOf("r.yml"))}},
		{ID: MustUndetectedFormID("l"), Text: "the run decides", Disposition: Limitation(DeciderRunTime), Examples: []Example{withCause(exampleOf("l.yml"))}},
	}
	m.InconclusiveKinds = []InconclusiveKind{{ID: MustInconclusiveKindID("g"), Text: "a place", Disposition: Todo(NeedFact, NeedSameFile), Examples: []Example{exampleOf("g.yml")}}}
	m.FalsePositiveForms = []FalsePositiveForm{
		{ID: MustFalsePositiveFormID("f"), Text: "an if keeps it out", FindingKinds: []FindingKindID{k.ID}, Disposition: Todo(NeedSameFile), Examples: []Example{withCause(exampleOf("f.yml"))}},
		{ID: MustFalsePositiveFormID("p"), Text: "a private repository", FindingKinds: []FindingKindID{k.ID}, FactKinds: []facts.Kind{facts.KindRepoPublic}, Examples: []Example{withCause(exampleOf("p.yml"))}},
	}
	got := explainOf(t, []RuleID{m.ID}, m, ruleOf("b-rule")) // b-rule has the kind the fix raises
	for _, want := range []string{
		"- actor: commenter\n  - via: comments (on a PR)\n  - events: issue_comment\n  - run starters: issue_comment: attacker\n",
		"  - remedy: say it not!\n  - severity: high (found from the CVSS metrics below by the table)\n  - fix kinds: pin\n  - fact kinds: test.flag (provider: test, assumed value: none)\n  - attackers: commenter\n  - preconditions: p\n  - incidents: i\n",
		"- VI: N\n  - reason: for the test: VI\n",
		"- precondition p: a\n  - observed: 2026-09-24, runner 2.337.0: it ran.\n  - observed: 2026-09-25: the API said so\n  - cites:\n",
		"- AV: N\n  - reason: for the test\n  - cites:\n    - <https://example.com/av>\n",
		"- E: A\n",
		"- incident i: 2025-03-14, CVE-2025-30066: it happened; again\n  - advisory: <https://example.com/ghsa>\n  - compromised: o/c\n  - downstream: o/d, o/e\n",
		"- targets: workflow\n- facets:\n  - weakness: script-injection\n  - attack-means: string\n- default run: always: in a run without --rule, the rule runs unless --skip-rule names the rule\n\n### finding kinds\n",
		"### fix kinds\n\n- pin: pin it\n  - safety: review\n  - fact kinds: test.text\n  - possible side effects:\n    - unquoted-one-word: An unquoted place becomes one word: a value with blanks is no longer read as several words, and outside &#91;&#91; ]] is no longer globbed.\n",
		"### undetected forms\n\n- o: not an attack\\*\n  - finding kinds: a-rule.said\n  - disposition: no-added-gain\n  - example: o.yml (workflow, undetected)\n    ```yaml\n    on: push\n    ```\n- r: b reports it\n  - finding kinds: a-rule.said\n  - disposition: other-rule (rule: b-rule)\n  - example: r.yml (workflow, undetected)\n    ```yaml\n    on: push\n    ```\n- l: the run decides\n  - finding kinds: a-rule.said\n  - disposition: limitation (decided by: run-time)\n  - example: l.yml (workflow, undetected)\n    ```yaml\n    on: push\n    ```\n",
		"### inconclusive\n\n- g: a place\n  - disposition: todo (needs: same-file, fact)\n  - example: g.yml (workflow, inconclusive)\n    ```yaml\n    on: push\n    ```\n",
		"### false positive forms\n\n- f: an if keeps it out\n  - finding kinds: a-rule.said\n  - disposition: todo (needs: same-file)\n  - example: f.yml (workflow, false-positive)\n    ```yaml\n    on: push\n    ```\n- p: a private repository\n  - finding kinds: a-rule.said\n  - fact kinds:\n    - repo.public (provider: repo-setting, assumed value: true)\n  - example: p.yml (workflow, false-positive)\n    ```yaml\n    on: push\n    ```\n\n### threat",
		"### citations\n\n- <https://example.com/x>\n- <https://example.com/p>\n- <https://example.com/ghsa>\n- <https://example.com/av>\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no\n%s\nin\n%s", want, got)
		}
	}
	if strings.Count(got, "cites: none") != 10 {
		t.Errorf("cites: none %d times, want 10 (the metrics but AV and VC)", strings.Count(got, "cites: none"))
	}
}

// TestExplainIDs: the rules of ids in the order of the registry, each
// once; all of them for none; an ID not registered is an error.
func TestExplainIDs(t *testing.T) {
	a, b, c := ruleOf("a-rule"), ruleOf("b-rule"), ruleOf("c-rule")
	heads := func(s string) string {
		var h []string
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "## ") {
				h = append(h, l[3:])
			}
		}
		return strings.Join(h, " ")
	}
	for _, x := range []struct {
		ids  []RuleID
		want string
	}{
		{nil, `a-rule b-rule c-rule`},
		{[]RuleID{c.ID, a.ID, c.ID}, `a-rule c-rule`},
		{[]RuleID{b.ID}, `b-rule`},
	} {
		if got := heads(explainOf(t, x.ids, c, a, b)); got != x.want {
			t.Errorf("Explain(%v): %s, want %s", x.ids, got, x.want)
		}
	}
	reg, err := NewRegistry([]Rule{testRule{meta: a}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Explain([]RuleID{MustRuleID("z-rule")}, "abc"); err == nil || !strings.Contains(err.Error(), "z-rule") {
		t.Errorf("Explain(z-rule) = %v, want an error naming it", err)
	}
}

func repos(t *testing.T, names ...string) []facts.Repo {
	t.Helper()
	var out []facts.Repo
	for _, n := range names {
		r, err := facts.ParseRepo(n)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// TestExplainCodeFence: an example is a fenced code block in its item,
// indented to the item's text; its fence is longer than the longest run of
// backquotes in it; its blank lines stay blank and its lines keep their
// indentation.
func TestExplainCodeFence(t *testing.T) {
	m := ruleOf("a-rule")
	m.FindingKinds[0].TruePositives = []Example{{InputKind: InputKindWorkflow, Name: facts.MustCleanInputPath("t.yml"), Text: "on: push\n\njobs:\n  a:\n    run: echo ```\n", Notes: ExampleNotes{Situation: "s", Reason: "r", Attack: "a", AttackRunBehavior: "b"}}}
	reg, err := NewRegistry([]Rule{testRule{meta: m}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.Explain(nil, "c")
	if err != nil {
		t.Fatal(err)
	}
	want := "  - true positives:\n" +
		"    - t.yml (workflow, true-positive)\n" +
		"      ````yaml\n" +
		"      on: push\n" +
		"\n" +
		"      jobs:\n" +
		"        a:\n" +
		"          run: echo ```\n" +
		"      ````\n"
	if !strings.Contains(string(b), want) {
		t.Errorf("the Markdown has no\n%s\nin\n%s", want, b)
	}
}

// withArguments is m whose first kind has the arguments a, named in its
// text of detected, and b, not named.
func withArguments(m Meta) Meta {
	k := &m.FindingKinds[0]
	k.Detected = "{a} is said"
	k.Arguments = []KindArgument{
		{Name: MustKindArgumentName("a"), Text: "The thing said.", InDetected: true},
		{Name: MustKindArgumentName("b"), Text: "Where the thing is said.", InDetected: false},
	}
	return m
}

// TestExplainArguments: the arguments of a kind under its detected, one
// that the text does not name marked; a kind without arguments has no
// such item.
func TestExplainArguments(t *testing.T) {
	got := explainOf(t, nil, withArguments(ruleOf("a-rule")), ruleOf("b-rule"))
	want := "  - detected: {a} is said\n" +
		"  - arguments:\n" +
		"    - {a}: The thing said.\n" +
		"    - {b}: Where the thing is said. (not in the text of detected)\n" +
		"  - consequence:"
	if !strings.Contains(got, want) {
		t.Errorf("no\n%s\nin\n%s", want, got)
	}
	if strings.Count(got, "arguments:") != 1 {
		t.Errorf("arguments: %d times, want 1 (b-rule's kind has none)\n%s", strings.Count(got, "arguments:"), got)
	}
}

// TestExplainQualityArguments: a quality rule's kind has its arguments too.
func TestExplainQualityArguments(t *testing.T) {
	m := goodQualityMeta()
	m.FindingKinds[0].Detected = "{a} is slow"
	m.FindingKinds[0].Arguments = []KindArgument{{Name: MustKindArgumentName("a"), Text: "The job.", InDetected: true}}
	reg, err := newRegistry(nil, false, testQuality{m: m})
	if err != nil {
		t.Fatal(err)
	}
	out, err := reg.Explain(nil, "c")
	if err != nil {
		t.Fatal(err)
	}
	if want := "  - detected: {a} is slow\n  - arguments:\n    - {a}: The job.\n"; !strings.Contains(string(out), want) {
		t.Errorf("no\n%s\nin\n%s", want, out)
	}
}

// TestExplainSeverityOneKind: a rule of one kind does not say its severity
// is the worst of its kinds; a rule of two does; a kind's severity says it
// is found from the CVSS metrics by the table.
func TestExplainSeverityOneKind(t *testing.T) {
	one := explainOf(t, nil, ruleOf("a-rule"))
	if !strings.Contains(one, "- severity: high\n") || strings.Contains(one, "the worst of its kinds") {
		t.Errorf("a rule of one kind:\n%s", one)
	}
	m := ruleOf("a-rule")
	k := m.FindingKinds[0]
	k.ID = MustFindingKindID("a-rule.other")
	m.FindingKinds = append(m.FindingKinds, k)
	two := explainOf(t, nil, m)
	if !strings.Contains(two, "- severity: high (the worst of its kinds)\n") {
		t.Errorf("a rule of two kinds:\n%s", two)
	}
	if strings.Contains(one, "CVSS below") || !strings.Contains(one, "  - severity: high (found from the CVSS metrics below by the table)\n") {
		t.Errorf("the severity of a kind:\n%s", one)
	}
}

// TestExplainExampleClass: an example says which declaration it shows
// after its input kind.
func TestExplainExampleClass(t *testing.T) {
	got := explainOf(t, nil, ruleOf("a-rule"))
	for _, want := range []string{
		"  - true positives:\n    - a-rule.said.yml (workflow, true-positive)\n",
		"  - true negatives:\n    - a-rule.said.yml (workflow, true-negative)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no\n%s\nin\n%s", want, got)
		}
	}
}

// TestExplainFactKindAssumed: the fact kinds of a kind and of a false
// positive form say each kind's provider and assumed value (a false
// positive form takes only kinds with one).
func TestExplainFactKindAssumed(t *testing.T) {
	m := asking(ruleOf("a-rule"), facts.KindRepoAllowForking)
	m.FalsePositiveForms = []FalsePositiveForm{{ID: MustFalsePositiveFormID("p"), Text: "a private repository", FindingKinds: []FindingKindID{m.FindingKinds[0].ID}, FactKinds: []facts.Kind{facts.KindRepoPublic}, Examples: []Example{withCause(exampleOf("p.yml"))}}}
	got := explainOf(t, nil, m)
	for _, want := range []string{
		"  - fact kinds: repo.allow-forking (provider: repo-setting, assumed value: none)\n",
		"    - repo.public (provider: repo-setting, assumed value: true)\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("no\n%s\nin\n%s", want, got)
		}
	}
}

// TestExplainFindingFileFlipped: an example of several files whose finding
// holds only with the kind's facts the other way says the file of the
// finding, as CheckExamples runs a true positive.
func TestExplainFindingFileFlipped(t *testing.T) {
	q := facts.TestFlag{Name: "x"}
	m := asking(meta("test"), facts.KindTestFlag) // its kind test.said is that of the args said
	e := exampleOf(".github/workflows/called.yml")
	e.Others = []ExampleFile{{InputKind: InputKindWorkflow, Name: facts.MustCleanInputPath(".github/workflows/ci.yml"), Text: "on: push\n"}}
	e.Facts = []facts.Entry{{Query: q, RawAnswer: facts.RawAnswer{State: facts.StateFound, Value: []byte("false")}}}
	m.FindingKinds[0].TruePositives = []Example{e}
	rule := testRule{meta: m, check: func(_ context.Context, c *RuleContext) error {
		if c.input.Name.String() != ".github/workflows/ci.yml" || c.workflow == nil {
			return nil
		}
		cond, _ := FactEq(q, true)
		c.Report(FindingDraft{Args: said("x"), Location: At(c.input, c.workflow.Base), Condition: &cond})
		return nil
	}}
	reg, err := NewRegistry([]Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.Explain(nil, "c")
	if err != nil {
		t.Fatal(err)
	}
	if want := "    - called.yml (workflow, true-positive)"; strings.Contains(string(b), want) {
		t.Fatalf("the example is named by its file alone:\n%s", b)
	}
	if want := "  - finding on: .github/workflows/ci.yml\n"; !strings.Contains(string(b), want) {
		t.Errorf("no\n%s\nin\n%s", want, b)
	}
}

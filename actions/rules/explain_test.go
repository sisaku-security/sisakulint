package rules

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// goldenCommit is the commit the golden Markdown is written with.
const goldenCommit = "0123456789abcdef0123456789abcdef01234567"

// TestExplainGolden keeps the Markdown of All in testdata/explain.golden.md,
// to be read by people when it changes.
func TestExplainGolden(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reg.Explain(nil, goldenCommit)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile("testdata/explain.golden.md", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/explain.golden.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the Markdown is not testdata/explain.golden.md (go test -update writes it):\n%s", got)
	}
}

// TestExplainCoversRegistry: every string of the registry's JSON is in the
// Markdown, so that a field Explain does not write is seen. The escape is
// written again here, apart from lint's (lint.MarkdownText): what CommonMark
// 0.31.2, GFM or GitHub would read as markup, a URL GFM would link with any
// of that in it, and the spaces and tabs a string starts with.
func TestExplainCoversRegistry(t *testing.T) {
	if os.Getenv("ACTIONS_LONG") != "1" {
		t.Skip("a long test; runs with ACTIONS_LONG=1")
	}
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.Explain(nil, goldenCommit)
	if err != nil {
		t.Fatal(err)
	}
	md := string(b)
	j, err := reg.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(j, &v); err != nil {
		t.Fatal(err)
	}
	delete(v, "schema") // the name of the JSON's form, not of a rule
	var (
		reference = regexp.MustCompile(`^&#?[A-Za-z0-9]+;`)
		bullet    = regexp.MustCompile(`^(?:>|[-+](?:[ \t]|$)|#{1,6}(?:[ \t]|$)|[- \t]*-[- \t]*-[- \t]*-[- \t]*$)`)
		ordered   = regexp.MustCompile(`^[0-9]+[.)](?:[ \t]|$)`)
		closing   = regexp.MustCompile(`[ \t]#+$`)
		word      = func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }
	)
	escape := func(s string) string {
		if strings.HasPrefix(s, "https://") {
			return "<" + s + ">"
		}
		rs := []rune(s)
		out := make([]string, len(rs)) // each rune as written
		for i, r := range rs {
			rest := string(rs[i:])
			switch {
			case strings.ContainsRune("\\*`~$", r):
				out[i] = `\` + string(r)
			case r == '_' && !(i > 0 && i+1 < len(rs) && word(rs[i-1]) && word(rs[i+1])):
				out[i] = `\_`
			case r == '[':
				out[i] = "&#91;"
			case strings.ContainsRune("()]", r) && i > 0 && rs[i-1] == '\\':
				out[i] = map[rune]string{'(': "&#40;", ')': "&#41;", ']': "&#93;"}[r]
			case r == '<' && i+1 < len(rs) && rs[i+1] != ' ' && rs[i+1] != '\t':
				out[i] = "&lt;"
			case reference.MatchString(rest):
				out[i] = "&amp;"
			default:
				out[i] = string(r)
			}
		}
		if bullet.MatchString(s) {
			out[0] = `\` + string(rs[0])
		}
		if m := ordered.FindString(s); m != "" {
			n := len([]rune(strings.TrimRight(m, " \t"))) - 1
			out[n] = `\` + string(rs[n])
		}
		if loc := closing.FindStringIndex(s); loc != nil {
			for i := len([]rune(s[:loc[0]])) + 1; i < len(rs); i++ {
				out[i] = `\#`
			}
		}
		lower := []rune(strings.ToLower(s))
		for i := range rs {
			if i > 0 && word(rs[i-1]) || len(lower) != len(rs) {
				continue
			}
			mark := -1
			switch rest := string(lower[i:]); {
			case strings.HasPrefix(rest, "http://"), strings.HasPrefix(rest, "https://"), strings.HasPrefix(rest, "ftp://"):
				mark = i + strings.IndexRune(rest, ':')
			case strings.HasPrefix(rest, "www."):
				mark = i + 3
			}
			if mark < 0 {
				continue
			}
			for j := i; j < len(rs) && rs[j] != ' ' && rs[j] != '\t'; j++ {
				if j != mark && out[j] != string(rs[j]) {
					out[mark] = `\` + string(rs[mark])
					break
				}
			}
		}
		for i := 0; i < len(rs) && (rs[i] == ' ' || rs[i] == '\t'); i++ {
			out[i] = map[rune]string{' ': "&#32;", '\t': "&#9;"}[rs[i]]
		}
		return strings.Join(out, "")
	}
	seen := map[string]bool{}
	want := map[string]int{} // each string escaped, and how many times the JSON has it
	var texts []string       // the texts of the examples
	var walk func(path string, x any)
	walk = func(path string, x any) {
		switch x := x.(type) {
		case map[string]any:
			for k, y := range x {
				walk(path+"."+k, y)
			}
		case []any:
			for _, y := range x {
				walk(path+"[]", y)
			}
		case string:
			seen[path] = true
			if strings.HasSuffix(path, "examples[].text") || strings.HasSuffix(path, "true_positives[].text") || strings.HasSuffix(path, "true_negatives[].text") || strings.HasSuffix(path, "others[].text") {
				texts = append(texts, x) // a code block, not escaped: below
				return
			}
			want[escape(x)]++
		}
	}
	walk("", v)
	for esc, n := range want {
		if got := strings.Count(md, esc); got < n {
			t.Errorf("%s is %d times in the registry's JSON, but %d times in the Markdown", esc, n, got)
		}
	}
	// an example is a code block, indented to its item: each of its lines
	// is in the Markdown, after the indentation
	unindented := map[string]bool{}
	for _, l := range strings.Split(md, "\n") {
		unindented[strings.TrimLeft(l, " ")] = true
	}
	for _, x := range texts {
		for _, l := range strings.Split(strings.TrimSuffix(x, "\n"), "\n") {
			if !unindented[strings.TrimLeft(l, " ")] {
				t.Errorf("the line %q of an example is not in the Markdown", l)
			}
		}
	}
	// the count does not see a field whose value is often in the others (a
	// version, a target) left out; a new field is seen here
	for p := range seen {
		if !slices.Contains(explainedPaths, p) {
			t.Errorf("%s is in the registry's JSON but not in explainedPaths: write it in Explain, then here", p)
		}
	}
	for _, p := range explainedPaths {
		if !seen[p] {
			t.Errorf("%s of explainedPaths has no string in the registry's JSON", p)
		}
	}
}

// explainedPaths are the paths of the strings of the registry's JSON that
// Explain writes; TestExplainCoversRegistry fails on one that is not here.
var explainedPaths = []string{
	".quality_rules[].citations[]",
	".quality_rules[].default_run",
	".quality_rules[].default_run_fact_kinds[]",
	".quality_rules[].expected",
	".quality_rules[].false_positive_forms[].decided_by",
	".quality_rules[].false_positive_forms[].disposition",
	".quality_rules[].false_positive_forms[].examples[].input_kind",
	".quality_rules[].false_positive_forms[].examples[].name",
	".quality_rules[].false_positive_forms[].examples[].text",
	".quality_rules[].false_positive_forms[].finding_kinds[]",
	".quality_rules[].false_positive_forms[].id",
	".quality_rules[].false_positive_forms[].needs[]",
	".quality_rules[].false_positive_forms[].text",
	".quality_rules[].finding_kinds[].consequence",
	".quality_rules[].finding_kinds[].detected",
	".quality_rules[].finding_kinds[].fact_kinds[]",
	".quality_rules[].finding_kinds[].id",
	".quality_rules[].finding_kinds[].remedy",
	".quality_rules[].finding_kinds[].true_negatives[].input_kind",
	".quality_rules[].finding_kinds[].true_negatives[].name",
	".quality_rules[].finding_kinds[].true_negatives[].others[].input_kind",
	".quality_rules[].finding_kinds[].true_negatives[].others[].name",
	".quality_rules[].finding_kinds[].true_negatives[].others[].text",
	".quality_rules[].finding_kinds[].true_negatives[].text",
	".quality_rules[].finding_kinds[].true_positives[].input_kind",
	".quality_rules[].finding_kinds[].true_positives[].name",
	".quality_rules[].finding_kinds[].true_positives[].others[].input_kind",
	".quality_rules[].finding_kinds[].true_positives[].others[].name",
	".quality_rules[].finding_kinds[].true_positives[].others[].text",
	".quality_rules[].finding_kinds[].true_positives[].text",
	".quality_rules[].id",
	".quality_rules[].problem",
	".quality_rules[].targets[]",
	".quality_rules[].undetected_forms[].decided_by",
	".quality_rules[].undetected_forms[].disposition",
	".quality_rules[].undetected_forms[].examples[].input_kind",
	".quality_rules[].undetected_forms[].examples[].name",
	".quality_rules[].undetected_forms[].examples[].text",
	".quality_rules[].undetected_forms[].finding_kinds[]",
	".quality_rules[].undetected_forms[].id",
	".quality_rules[].undetected_forms[].needs[]",
	".quality_rules[].undetected_forms[].text",
	".rules[].citations[]",
	".rules[].default_run",
	".rules[].default_run_fact_kinds[]",
	".rules[].expected",
	".rules[].facets.attack_means[]",
	".rules[].facets.weakness[]",
	".rules[].false_positive_forms[].added_attackers[]",
	".rules[].false_positive_forms[].decided_by",
	".rules[].false_positive_forms[].disposition",
	".rules[].false_positive_forms[].examples[].input_kind",
	".rules[].false_positive_forms[].examples[].name",
	".rules[].false_positive_forms[].examples[].others[].input_kind",
	".rules[].false_positive_forms[].examples[].others[].name",
	".rules[].false_positive_forms[].examples[].others[].text",
	".rules[].false_positive_forms[].examples[].text",
	".rules[].false_positive_forms[].fact_kinds[].kind",
	".rules[].false_positive_forms[].fact_kinds[].provider",
	".rules[].false_positive_forms[].finding_kinds[]",
	".rules[].false_positive_forms[].id",
	".rules[].false_positive_forms[].needs[]",
	".rules[].false_positive_forms[].text",
	".rules[].finding_kinds[].attackers[]",
	".rules[].finding_kinds[].consequence",
	".rules[].finding_kinds[].cvss.b.rating",
	".rules[].finding_kinds[].cvss.b.score",
	".rules[].finding_kinds[].cvss.bt.rating",
	".rules[].finding_kinds[].cvss.bt.score",
	".rules[].finding_kinds[].cvss.metrics[].cites[]",
	".rules[].finding_kinds[].cvss.metrics[].metric",
	".rules[].finding_kinds[].cvss.metrics[].reason",
	".rules[].finding_kinds[].cvss.metrics[].value",
	".rules[].finding_kinds[].cvss.vector",
	".rules[].finding_kinds[].detected",
	".rules[].finding_kinds[].fact_kinds[]",
	".rules[].finding_kinds[].fixes[]",
	".rules[].finding_kinds[].id",
	".rules[].finding_kinds[].incidents[]",
	".rules[].finding_kinds[].preconditions[]",
	".rules[].finding_kinds[].remedy",
	".rules[].finding_kinds[].severity",
	".rules[].finding_kinds[].severity_basis.impact.from[]",
	".rules[].finding_kinds[].severity_basis.impact.level",
	".rules[].finding_kinds[].severity_basis.likelihood.from[]",
	".rules[].finding_kinds[].severity_basis.likelihood.level",
	".rules[].finding_kinds[].severity_basis.likelihood.lowered_by[]",
	".rules[].finding_kinds[].true_negatives[].input_kind",
	".rules[].finding_kinds[].true_negatives[].name",
	".rules[].finding_kinds[].true_negatives[].others[].input_kind",
	".rules[].finding_kinds[].true_negatives[].others[].name",
	".rules[].finding_kinds[].true_negatives[].others[].text",
	".rules[].finding_kinds[].true_negatives[].text",
	".rules[].finding_kinds[].true_positives[].added_attackers[]",
	".rules[].finding_kinds[].true_positives[].input_kind",
	".rules[].finding_kinds[].true_positives[].name",
	".rules[].finding_kinds[].true_positives[].others[].input_kind",
	".rules[].finding_kinds[].true_positives[].others[].name",
	".rules[].finding_kinds[].true_positives[].others[].text",
	".rules[].finding_kinds[].true_positives[].text",
	".rules[].fix_kinds[].fact_kinds[]",
	".rules[].fix_kinds[].id",
	".rules[].fix_kinds[].possible_side_effects[].id",
	".rules[].fix_kinds[].possible_side_effects[].text",
	".rules[].fix_kinds[].safety",
	".rules[].fix_kinds[].title",
	".rules[].id",
	".rules[].inconclusive_kinds[].decided_by",
	".rules[].inconclusive_kinds[].disposition",
	".rules[].inconclusive_kinds[].examples[].input_kind",
	".rules[].inconclusive_kinds[].examples[].name",
	".rules[].inconclusive_kinds[].examples[].others[].input_kind",
	".rules[].inconclusive_kinds[].examples[].others[].name",
	".rules[].inconclusive_kinds[].examples[].others[].text",
	".rules[].inconclusive_kinds[].examples[].text",
	".rules[].inconclusive_kinds[].id",
	".rules[].inconclusive_kinds[].needs[]",
	".rules[].inconclusive_kinds[].text",
	".rules[].problem",
	".rules[].severity",
	".rules[].targets[]",
	".rules[].threat.actors[].attacker",
	".rules[].threat.actors[].events[]",
	".rules[].threat.actors[].gains[]",
	".rules[].threat.actors[].run_starters[].event",
	".rules[].threat.actors[].run_starters[].run_starter",
	".rules[].threat.actors[].via",
	".rules[].threat.incidents[].advisory",
	".rules[].threat.incidents[].compromised[]",
	".rules[].threat.incidents[].cve",
	".rules[].threat.incidents[].date",
	".rules[].threat.incidents[].downstream[]",
	".rules[].threat.incidents[].id",
	".rules[].threat.incidents[].summary",
	".rules[].threat.preconditions[].cites[]",
	".rules[].threat.preconditions[].id",
	".rules[].threat.preconditions[].observed[].date",
	".rules[].threat.preconditions[].observed[].runner",
	".rules[].threat.preconditions[].observed[].what",
	".rules[].threat.preconditions[].text",
	".rules[].undetected_forms[].added_attackers[]",
	".rules[].undetected_forms[].decided_by",
	".rules[].undetected_forms[].disposition",
	".rules[].undetected_forms[].examples[].input_kind",
	".rules[].undetected_forms[].examples[].name",
	".rules[].undetected_forms[].examples[].others[].input_kind",
	".rules[].undetected_forms[].examples[].others[].name",
	".rules[].undetected_forms[].examples[].others[].text",
	".rules[].undetected_forms[].examples[].text",
	".rules[].undetected_forms[].finding_kinds[]",
	".rules[].undetected_forms[].id",
	".rules[].undetected_forms[].needs[]",
	".rules[].undetected_forms[].rule",
	".rules[].undetected_forms[].text",
}

// TestExplainFindingFile: an example of several files on which the rule
// reports a finding says the file of the finding; an example on which the
// rule reports none, and an example of one file, say nothing of it.
func TestExplainFindingFile(t *testing.T) {
	reg, err := lint.NewRegistry(All(), Quality()...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.Explain([]lint.RuleID{lint.MustRuleID("secrets-inherit")}, goldenCommit)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	// the true positive local.nameless and the false positive
	// no-attacker-value-caller: called.yml and ci.yml, the finding on ci.yml;
	// the true negative local.named-reads has no finding. The line of a
	// true positive is indented by 6 spaces and the line of a false
	// positive by 4, so the count of the 4 spaces holds both
	if strings.Count(got, "      - finding on: .github/workflows/ci.yml\n") != 1 || strings.Count(got, "    - finding on: .github/workflows/ci.yml\n") != 2 || strings.Count(got, "finding on:") != 2 {
		t.Errorf("secrets-inherit does not say the file of the finding of local.nameless and no-attacker-value-caller alone:\n%s", got)
	}
}

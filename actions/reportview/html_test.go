package reportview

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/rules"
)

const dataOpen = `<script type="application/json" id="report-data">`

// dataOf is the JSON in the page.
func dataOf(t *testing.T, page []byte) []byte {
	t.Helper()
	_, rest, ok := bytes.Cut(page, []byte(dataOpen))
	if !ok {
		t.Fatal("no data in the page")
	}
	data, _, ok := bytes.Cut(rest, []byte("</script>"))
	if !ok {
		t.Fatal("the data is not closed")
	}
	return data
}

const hostile = `name: "</script><img src=x onerror=window.pwned=1>"
on: issues
permissions: {}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: "</script><script>window.pwned=2</script>"
        run: echo "${{ github.event.issue.title }}" # </script><script>window.pwned=3</script>
`

func TestHTMLEscapes(t *testing.T) {
	rep, in := runOn(t, map[string]string{".github/workflows/w.yml": hostile})
	p, err := Build(rep, in, testRegistry(t))
	if err != nil {
		t.Fatal(err)
	}
	page, err := p.HTML()
	if err != nil {
		t.Fatal(err)
	}
	data := dataOf(t, page)
	if bytes.ContainsAny(data, "<>") {
		t.Errorf("the data has < or >: %s", data)
	}
	if !json.Valid(data) {
		t.Error("the data is not JSON")
	}
	if !bytes.Contains(data, []byte(`\u003c/script\u003e\u003cscript\u003ewindow.pwned=2`)) {
		t.Error("the name of the step is not in the data")
	}
	if n := bytes.Count(page, []byte("<script")); n != 2 {
		t.Errorf("%d scripts in the page, want the data and the script", n)
	}
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", ".style.", "setAttribute(\"style\""} {
		if strings.Contains(script, bad) {
			t.Errorf("the script uses %s: text goes in by textContent, and style by class (the policy)", bad)
		}
	}
	if !strings.Contains(script, "data.files") {
		t.Error("the script does not draw the files")
	}
	if strings.Contains(script, "</script") || strings.Contains(style, "</style") {
		t.Error("the script or the style closes its element")
	}
	again, err := p.HTML()
	if err != nil || !bytes.Equal(page, again) {
		t.Error("the page is not the same bytes twice")
	}
	if !bytes.Contains(page, []byte(policy)) || !strings.Contains(policy, "default-src 'none'") {
		t.Errorf("the policy %q", policy)
	}
}

// TestEvaluateMatchesEval: the script's evaluate gives what lint.Eval
// gives, for the shapes of conditions and every truth of their leaves.
func TestEvaluateMatchesEval(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the script's evaluate is not compared with lint.Eval")
	}
	names := []facts.InputPath{inputPath(t, "a.yml"), inputPath(t, "b.yml"), inputPath(t, "c.yml")}
	leaf := func(i int) lint.Condition { return lint.InputPresent(names[i]) }
	shapes := []lint.Condition{
		leaf(0), lint.All(), lint.Any(),
		lint.All(leaf(0), leaf(1)), lint.Any(leaf(0), leaf(1)),
		lint.All(leaf(0), leaf(1), leaf(2)), lint.Any(leaf(0), leaf(1), leaf(2)),
		lint.All(lint.Any(leaf(0), leaf(1)), leaf(2)), lint.Any(lint.All(leaf(0), leaf(1)), leaf(2)),
		lint.All(lint.Any(leaf(0)), lint.All(leaf(1), lint.Any(leaf(2)))),
	}
	states := []lint.LookupState{lint.LookupFound, lint.LookupAbsent, lint.LookupUnknown}
	type check struct {
		Condition Condition     `json:"condition"`
		Truths    map[int]truth `json:"truths"`
		Want      truth         `json:"want"`
	}
	var checks []check
	for _, c := range shapes {
		for k := range 27 {
			st := [3]lint.LookupState{states[k%3], states[k/3%3], states[k/9]}
			look := func(n facts.InputPath) lint.LookupState { return st[slices.Index(names, n)] }
			id := 0
			x, err := conditionOf(c, answers(nil), look, &id)
			if err != nil {
				t.Fatal(err)
			}
			truths := map[int]truth{}
			var walk func(Condition)
			walk = func(c Condition) {
				if c.Op == op(lint.ConditionOpLeaf) {
					truths[c.ID] = c.Truth
				}
				for _, p := range c.Parts {
					walk(p)
				}
			}
			walk(x)
			checks = append(checks, check{x, truths, truth(lint.Eval(c, answers(nil), look))})
		}
	}
	b, err := json.Marshal(checks)
	if err != nil {
		t.Fatal(err)
	}
	js, err := filepath.Abs("assets/view.js")
	if err != nil {
		t.Fatal(err)
	}
	const harness = `const {evaluate} = require(process.argv[1]);
const checks = JSON.parse(require("fs").readFileSync(0, "utf8"));
let bad = 0;
for (const c of checks) {
  const got = evaluate(c.condition, c.truths);
  if (got !== c.want) { bad++; console.log(JSON.stringify(c), "got", got); }
}
console.log(bad ? "failed " + bad : "ok " + checks.length);`
	cmd := exec.Command(node, "-e", harness, js)
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "ok "+strconv.Itoa(len(checks)) {
		t.Fatal(got)
	}
}

// TestGroupRules: the script's groupRules makes a group of each value in
// the order of the facet, with the rules that have it and the other values
// each has; a value no rule has makes none; with no facet, one group of
// every rule in their order. With the registry's rules, every rule is in a
// group of each axis.
func TestGroupRules(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the script's groupRules is not run")
	}
	js, err := filepath.Abs("assets/view.js")
	if err != nil {
		t.Fatal(err)
	}
	run := func(input any) string {
		b, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		const harness = `const {groupRules} = require(process.argv[1]);
const {rules, facet} = JSON.parse(require("fs").readFileSync(0, "utf8"));
console.log(groupRules(rules, facet).map((g) => (g.value || "-") + ": " + g.rules.map((x) => x.rule.rule + (x.also.length ? "+" + x.also.join("+") : "")).join(" ")).join("\n"));`
		cmd := exec.Command(node, "-e", harness, js)
		cmd.Stdin = bytes.NewReader(b)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	rule := func(id string, ws ...string) map[string]any {
		return map[string]any{"rule": id, "meta": map[string]any{"facets": map[string]any{"weakness": ws}}}
	}
	rs := []any{rule("a", "x", "y"), rule("b", "y")}
	facet := map[string]any{"facet": "weakness", "key": "weakness", "values": []any{
		map[string]any{"value": "x", "description": "X"}, map[string]any{"value": "z", "description": "Z"}, map[string]any{"value": "y", "description": "Y"},
	}}
	if got, want := run(map[string]any{"rules": rs, "facet": facet}), "x: a+y\ny: a+x b"; got != want {
		t.Errorf("grouped by weakness:\n%s\nwant\n%s", got, want)
	}
	if got, want := run(map[string]any{"rules": rs, "facet": nil}), "-: a b"; got != want {
		t.Errorf("not grouped:\n%s\nwant\n%s", got, want)
	}
	// a quality rule is in a group of its own, after the rules, whatever
	// the facet
	q := map[string]any{"rule": "q", "quality": true, "meta": map[string]any{}}
	withQ := append(slices.Clone(rs), q)
	if got, want := run(map[string]any{"rules": withQ, "facet": facet}), "x: a+y\ny: a+x b\nquality rules: q"; got != want {
		t.Errorf("grouped by weakness, with a quality rule:\n%s\nwant\n%s", got, want)
	}
	if got, want := run(map[string]any{"rules": withQ, "facet": nil}), "-: a b\nquality rules: q"; got != want {
		t.Errorf("not grouped, with a quality rule:\n%s\nwant\n%s", got, want)
	}
	if got, want := run(map[string]any{"rules": []any{q}, "facet": nil}), "quality rules: q"; got != want {
		t.Errorf("a quality rule alone:\n%s\nwant\n%s", got, want)
	}

	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	c, err := BuildCatalog(context.Background(), reg, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	metas, err := reg.MetaJSON()
	if err != nil {
		t.Fatal(err)
	}
	var all []any
	for _, r := range reg.Rules() {
		all = append(all, map[string]any{"rule": r.Meta().ID.String(), "meta": metas[r.Meta().ID]})
	}
	for _, f := range c.Facets {
		got := run(map[string]any{"rules": all, "facet": f})
		in := grouped(got)
		for _, r := range reg.Rules() {
			if !in[r.Meta().ID.String()] {
				t.Errorf("grouped by %s, %s is in no group:\n%s", f.Facet, r.Meta().ID, got)
			}
		}
		// a rule left out is in no group, though another's ID starts with
		// its own
		var some []any
		for _, x := range all {
			if x.(map[string]any)["rule"] != "untrusted-checkout" {
				some = append(some, x)
			}
		}
		if g := grouped(run(map[string]any{"rules": some, "facet": f})); g["untrusted-checkout"] || !g["untrusted-checkout-toctou"] {
			t.Errorf("grouped by %s without untrusted-checkout: %v", f.Facet, g)
		}
		if f.Facet == lint.FacetWeakness && !strings.Contains(got, "ai-action-unrestricted-trigger+gate-bypass") {
			t.Errorf("grouped by weakness, ai-action-unrestricted-trigger is not in agent-hijack with gate-bypass also:\n%s", got)
		}
	}
}

// grouped are the IDs of the rules in the groups of the harness's output of
// TestGroupRules: each line is a value, a colon and the rules, each with
// the other values it has after a plus.
func grouped(out string) map[string]bool {
	in := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		_, rules, _ := strings.Cut(line, ": ")
		for _, r := range strings.Fields(rules) {
			id, _, _ := strings.Cut(r, "+")
			in[id] = true
		}
	}
	return in
}

// termCase is a key of the meta of a rule, by its registry path, and a
// value under it (empty for the key alone), with the metric when the value
// is of a CVSS metric.
type termCase struct {
	Path   string `json:"path"`
	Value  string `json:"value"`
	Metric string `json:"metric"`
}

// termCases are the keys and the string values of the meta m, under the
// registry path p.
func termCases(m any, p string, metric string, out *[]termCase) {
	switch x := m.(type) {
	case map[string]any:
		mt, _ := x["metric"].(string)
		for k, v := range x {
			c := k
			if p != "" {
				c = p + "." + k
			}
			*out = append(*out, termCase{Path: c})
			termCases(v, c, mt, out)
		}
	case []any:
		for _, v := range x {
			termCases(v, p, metric, out)
		}
	case string:
		if !strings.HasSuffix(p, "cvss.metrics.value") {
			metric = ""
		}
		*out = append(*out, termCase{Path: p, Value: x, Metric: metric})
	}
}

// TestTermLookup: for every key and string value of the meta of every
// rule, the script's itemNameAt and valueAt give the definition the Go
// tables give (lint.TermPathsOf, lint.Definitions): the item name of the
// key or the axis it is, and the value of the value group of the path, or
// of the metric for a value of a CVSS metric; and refRoot gives the path a
// reference is drawn under.
func TestTermLookup(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the script's itemNameAt and valueAt are not run")
	}
	js, err := filepath.Abs("assets/view.js")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := lint.NewRegistry(rules.All())
	if err != nil {
		t.Fatal(err)
	}
	metas, err := reg.MetaJSON()
	if err != nil {
		t.Fatal(err)
	}
	var cases []termCase
	for _, raw := range metas {
		var m any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		termCases(m, "", "", &cases)
	}
	cases = append(cases, termCase{Path: "threat.actors.events", Value: "issues"}, termCase{Path: "finding_kinds.cvss.metrics.value", Value: "H", Metric: "VC"})
	defs, paths := lint.Definitions(), lint.TermPathsOf()
	group := func(id lint.ValueGroupID) *lint.ValueGroup {
		for i, g := range defs.ValueGroups {
			if g.ID == id {
				return &defs.ValueGroups[i]
			}
		}
		return nil
	}
	metricOf := map[string]lint.ValueGroupID{}
	for m, g := range paths.Metrics {
		metricOf[m.String()] = g
	}
	pathOf := map[string]lint.RegistryPath{}
	for p := range paths.ItemNames {
		pathOf[p.String()] = p
	}
	for p := range paths.Values {
		pathOf[p.String()] = p
	}
	for p := range paths.Axes {
		pathOf[p.String()] = p
	}
	want := func(c termCase) string {
		p, known := pathOf[c.Path]
		if c.Value == "" {
			if !known {
				return "null"
			}
			if n, ok := paths.ItemNames[p]; ok {
				for _, d := range defs.ItemNames {
					if d.Name == n.String() {
						return d.Name + ": " + d.Text
					}
				}
			}
			if a, ok := paths.Axes[p]; ok {
				g := group(a)
				return g.Heading + ": " + g.Description
			}
			return "null"
		}
		id, ok := metricOf[c.Metric]
		if c.Metric == "" {
			id, ok = paths.Values[p]
			if !ok {
				id, ok = paths.Axes[p]
			}
		}
		if !ok || !known && c.Metric == "" {
			return "null"
		}
		for _, v := range group(id).Values {
			if v.Name == c.Value {
				return v.Name + ": " + v.Text
			}
		}
		return "null"
	}
	b, err := json.Marshal(map[string]any{"terms": CatalogTerms{defs, paths}, "cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	const harness = `const {itemNameAt, valueAt, refRoot} = require(process.argv[1]);
const {terms, cases} = JSON.parse(require("fs").readFileSync(0, "utf8"));
const text = (d) => (d ? d.name + ": " + d.text : "null");
for (const c of cases) console.log(JSON.stringify(c.value === "" ? text(itemNameAt(terms, c.path)) : text(valueAt(terms, c.path, c.value, c.metric || undefined))));
console.log(JSON.stringify(["preconditions", "incidents", "fixes", "id"].map(refRoot)));`
	cmd := exec.Command(node, "-e", harness, js)
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(cases)+1 {
		t.Fatalf("the script wrote %d lines for %d cases", len(lines), len(cases))
	}
	found := 0
	for i, c := range cases {
		var got string
		if err := json.Unmarshal([]byte(lines[i]), &got); err != nil {
			t.Fatal(err)
		}
		if w := want(c); got != w {
			t.Errorf("%+v: the script gives %q, want %q", c, got, w)
		} else if got != "null" {
			found++
		}
	}
	if found == 0 {
		t.Error("no case has a definition")
	}
	if got, want := lines[len(lines)-1], `["threat.preconditions","threat.incidents","fix_kinds",null]`; got != want {
		t.Errorf("refRoot gives %s, want %s", got, want)
	}
	for _, c := range []termCase{{Path: "threat.actors.events", Value: "issues"}} {
		if w := want(c); w != "null" {
			t.Errorf("%+v has a definition %q", c, w)
		}
	}
	if w := want(termCase{Path: "finding_kinds.cvss.metrics.value", Value: "H", Metric: "VC"}); !strings.HasPrefix(w, "H: ") {
		t.Errorf("the value H of the metric VC is %q", w)
	}
}

// TestWithArguments: withArguments puts the arguments of each kind into a
// copy of the Meta, and leaves the Meta as it was.
func TestWithArguments(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the script's withArguments is not run")
	}
	js, err := filepath.Abs("assets/view.js")
	if err != nil {
		t.Fatal(err)
	}
	const harness = `const {withArguments} = require(process.argv[1]);
const m = {finding_kinds: [{id: "r.k"}, {id: "r.j"}]};
const got = withArguments(m, {"r.k": [{name: "a", text: "t", in_detected: true}]});
console.log(JSON.stringify([got.finding_kinds, m.finding_kinds]));`
	out, err := exec.Command(node, "-e", harness, js).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := `[[{"id":"r.k","arguments":[{"name":"a","text":"t","in_detected":true}]},{"id":"r.j"}],[{"id":"r.k"},{"id":"r.j"}]]`
	if got := strings.TrimSpace(string(out)); got != want {
		t.Errorf("withArguments:\n%s\nwant\n%s", got, want)
	}
}

// TestHTMLEscapesQuality: the text of a quality finding goes into the data
// escaped, as that of a finding does.
func TestHTMLEscapesQuality(t *testing.T) {
	run, f, reg := qualityRun(t, "cache-bloat", lint.ExampleTruePositive, "partial-restore.split")
	f.Related = slices.Clone(f.Related)
	f.Related[0].Note = "</script><script>window.pwned=3</script>"
	p, err := Build(lint.Report{QualityFindings: []lint.QualityFinding{f}}, run.Inputs, reg)
	if err != nil {
		t.Fatal(err)
	}
	page, err := p.HTML()
	if err != nil {
		t.Fatal(err)
	}
	data := dataOf(t, page)
	if bytes.ContainsAny(data, "<>") || !bytes.Contains(data, []byte(`\u003c/script\u003e\u003cscript\u003ewindow.pwned=3`)) {
		t.Errorf("the data: %s", data)
	}
}

// TestCountText: the script's countText names the findings and the quality
// findings it is given, each in the singular for one, and both as absent for
// none; summaryText is the summary of a page, which says how many of the
// findings are inconclusive and how many of those --accept accepted, and,
// when there are quality findings, that the findings do not include them and
// that they do not change the exit code.
func TestCountText(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the script's countText is not run")
	}
	js, err := filepath.Abs("assets/view.js")
	if err != nil {
		t.Fatal(err)
	}
	const harness = `const {countText, summaryText} = require(process.argv[1]);
console.log([[2, 0], [1, 0], [0, 1], [1, 2], [0, 0]].map(([f, q]) => countText(f, q)).join("\n"));
console.log([[122, 23, 0, 56], [5, 3, 2, 0], [0, 0, 0, 1], [1, 1, 0, 2]].map((a) => summaryText(...a)).join("\n"));`
	out, err := exec.Command(node, "-e", harness, js).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := "2 findings\n1 finding\n1 quality finding\n1 finding, 2 quality findings\nno findings and no quality findings\n" +
		"122 findings (23 of the findings inconclusive), 56 quality findings. The 122 findings do not include the 56 quality findings. Quality findings do not change the exit code, so a CI step that runs the linter does not fail because of quality findings.\n" +
		"5 findings (3 of the findings inconclusive, and 2 of the inconclusive findings accepted by --accept)\n" +
		"0 findings, 1 quality finding. The 0 findings do not include the 1 quality finding. Quality findings do not change the exit code, so a CI step that runs the linter does not fail because of quality findings.\n" +
		"1 finding (1 of the findings inconclusive), 2 quality findings. The 1 finding does not include the 2 quality findings. Quality findings do not change the exit code, so a CI step that runs the linter does not fail because of quality findings."
	if got := strings.TrimSpace(string(out)); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

// TestRowClass: the script's rowClass colors a row by the places on it: a
// place of a security finding first, then a place of a quality finding,
// then an inconclusive place, and a row of evidence or related places alone
// is the evidence color, whether the evidence is of a security finding or
// of a quality finding.
func TestRowClass(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the script's rowClass is not run")
	}
	js, err := filepath.Abs("assets/view.js")
	if err != nil {
		t.Fatal(err)
	}
	const harness = `const {rowClass} = require(process.argv[1]);
console.log([{finding: 1, quality: 1, inconclusive: 1}, {finding: 0, quality: 1, inconclusive: 1}, {finding: 0, quality: 0, inconclusive: 1}, {finding: 0, quality: 0, inconclusive: 0}].map(rowClass).join("\n"));`
	out, err := exec.Command(node, "-e", harness, js).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got, want := strings.TrimSpace(string(out)), "row-finding\nrow-quality\nrow-inconclusive\nrow-evidence"; got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
}

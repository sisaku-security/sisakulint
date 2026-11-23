package lint

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// TestTermsGolden keeps the terms in testdata/terms.golden.md, to be read
// by people when they change.
func TestTermsGolden(t *testing.T) {
	got := Terms("0123456789abcdef0123456789abcdef01234567")
	if *update {
		if err := os.WriteFile("testdata/terms.golden.md", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/terms.golden.md")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("the terms are not testdata/terms.golden.md (go test -update writes it):\n%s", got)
	}
}

// TestTermsShape: the heading, the commit, and the item names, with what
// they are, before the values.
func TestTermsShape(t *testing.T) {
	got := string(Terms("abc (modified)"))
	if !strings.HasPrefix(got, "# sisakulint terms\n\n- commit: abc (modified)\n\n## item names\n\n"+md(itemNamesDoc)+"\n\n- commit: ") {
		t.Errorf("the terms start\n%s", got)
	}
	for _, want := range []string{"\n### severity\n\nHow bad a kind's threat is", "\n### likelihood\n\nHow readily", "\n## values\n\n### attacker\n\n", "\n### disposition\n\n- no-added-gain: ", "\n### facts\n\n", "\n### CVSS\n\n#### AV: Attack Vector (AV) of CVSS v4.0.\n\n- N: Network.\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("no\n%s\nin\n%s", want, got)
		}
	}
	if strings.Index(got, "## item names") > strings.Index(got, "## values") {
		t.Error("the values are before the item names")
	}
	if !strings.Contains(got, "\n## words in the texts\n\n- privileged event: ") {
		t.Errorf("the terms have no words in the texts, first the privileged event:\n%s", got)
	}
	if w := strings.Index(got, "## words in the texts"); w < strings.Index(got, "## item names") || w > strings.Index(got, "## values") {
		t.Error("the words in the texts are not between the item names and the values")
	}
}

// TestTermsCoverSchemas: each value of the enumerations the terms write,
// and each kind of fact but those for tests, is in the terms with what the
// schema says of it, and each class by its name. The schemas are read
// here, apart from the generated code.
func TestTermsCoverSchemas(t *testing.T) {
	got := string(Terms("abc"))
	defs := func(path string) map[string]json.RawMessage {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var s struct {
			Defs map[string]json.RawMessage `json:"$defs"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		return s.Defs
	}
	reg, fs := defs("schema/registry-v0.json"), defs("../facts/schema/facts-v0.json")
	// section is the part of the terms under the heading head, to the next
	// heading: a value is looked for in its own section, since the texts of
	// the values of the CVSS metrics are much the same (L: Low. of AC and PR)
	section := func(head string) string {
		i := strings.Index(got, "\n"+head)
		if i < 0 {
			t.Errorf("the terms have no heading %q", head)
			return ""
		}
		rest := got[i+1:]
		if j := strings.Index(rest[1:], "\n#"); j >= 0 {
			return rest[:j+2]
		}
		return rest
	}
	heads := map[string]string{
		"attacker": "### attacker\n", "gain": "### gain\n", "need": "### need\n", "decider": "### decider\n", "safety": "### safety\n",
		"severity": "### severity\n", "likelihood": "### likelihood\n", "input-kind": "### input-kind\n",
		"attack-vector": "#### AV: ", "attack-complexity": "#### AC: ", "attack-requirements": "#### AT: ", "privileges-required": "#### PR: ",
		"user-interaction": "#### UI: ", "impact": "#### VC, VI, VA, SC, SI, SA: ", "exploit-maturity": "#### E: ",
		"score-rating": "#### CVSS-B, CVSS-BT: ",
	}
	for name, head := range heads {
		in := section(head)
		var d struct {
			OneOf []struct {
				Const       string `json:"const"`
				Description string `json:"description"`
			} `json:"oneOf"`
		}
		if err := json.Unmarshal(reg[name], &d); err != nil || len(d.OneOf) == 0 {
			t.Errorf("$defs/%s of registry-v0.json has no values (%v)", name, err)
		}
		for _, v := range d.OneOf {
			if want := "\n- " + md(v.Const) + ": " + md(v.Description) + "\n"; !strings.Contains(in, want) {
				t.Errorf("the terms have no %s of $defs/%s: %s", v.Const, name, strings.TrimSpace(want))
			}
		}
	}
	for _, name := range []string{"severity", "likelihood"} {
		var d struct {
			Description string `json:"description"`
		}
		if err := json.Unmarshal(reg[name], &d); err != nil {
			t.Fatal(err)
		}
		if want := "\n### " + name + "\n\n" + md(d.Description) + "\n\n"; !strings.Contains(got, want) {
			t.Errorf("the terms have no paragraph of $defs/%s under its heading: %s", name, want)
		}
	}
	for name, raw := range fs {
		if !strings.Contains(name, ".") {
			continue
		}
		var d struct {
			From        string `json:"x-provider"`
			Description string `json:"description"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		in := strings.Contains(section("### facts\n"), "\n- "+md(name)+": "+md(d.Description)+"\n")
		if in != (d.From != "test") {
			t.Errorf("the kind of fact %s (from %s) is in the terms: %v", name, d.From, in)
		}
	}
	var disposition struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(reg["disposition"], &disposition); err != nil || len(disposition.Enum) == 0 {
		t.Fatalf("$defs/disposition: %v", err)
	}
	for _, c := range disposition.Enum {
		if !strings.Contains(section("### disposition\n"), "\n- "+md(c)+": ") {
			t.Errorf("the terms have no disposition %q", c)
		}
	}
}

// TestItemNamesUsed: each item name is written by --explain, as the golden
// Markdown of the rules shows (actions/rules; the three rules together
// write every item name), so that the table keeps none no one writes; and
// no two have one name.
func TestItemNamesUsed(t *testing.T) {
	b, err := os.ReadFile("../rules/testdata/explain.golden.md")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, n := range itemNames {
		if seen[n.name] {
			t.Errorf("the item name %s is in the table twice", n.name)
		}
		seen[n.name] = true
		// an item "- name: ...", a heading "### name", or within an item:
		// "(name: ...", "(name ...", "; name ...", ", name ..." (a ; or a ,
		// of a text is escaped, \; or \,, and is not one of these)
		used := regexp.MustCompile(`(?m)(^\s*- |^### |\(|[^\\]; |[^\\], )` + regexp.QuoteMeta(n.name) + `[: \n]`)
		if !used.Match(b) {
			t.Errorf("the item name %s is not in actions/rules/testdata/explain.golden.md", n.name)
		}
	}
}

// TestTextTermPrivilegedEvents: the privileged event of the terms names the
// events of job.Privileged, each once and no other, before the events it
// says are not privileged events; and no event of notPrivileged is one of
// job.Privileged.
func TestTextTermPrivilegedEvents(t *testing.T) {
	doc := privilegedEventDoc()
	head, _, ok := strings.Cut(doc, ". Among the events that are not privileged events: ")
	if !ok {
		t.Fatalf("the privileged event says no events that are not privileged events:\n%s", doc)
	}
	_, list, _ := strings.Cut(head, "a GITHUB_TOKEN that writes: ")
	var want []string
	for _, e := range job.Privileged() {
		want = append(want, e.String())
	}
	got := strings.Split(strings.Replace(list, " and ", ", ", 1), ", ")
	if !slices.Equal(got, want) {
		t.Errorf("the privileged event names %q, not job.Privileged %q", got, want)
	}
	in := map[string]bool{}
	for _, e := range want {
		in[e] = true
	}
	for _, e := range privilegedEventPreconditionEvents {
		if !in[e.String()] {
			t.Errorf("%s of the precondition privileged-event is not one of job.Privileged", e)
		}
	}
	for _, n := range notPrivileged {
		for _, e := range n.events {
			if in[e.String()] {
				t.Errorf("%s is one of job.Privileged, which notPrivileged says it is not", e)
			}
		}
	}
}

// TestTextTermsCiteFixedCommits: a word in the texts cites only https URLs
// of a fixed commit, and no path of this repository.
func TestTextTermsCiteFixedCommits(t *testing.T) {
	notPublic := regexp.MustCompile(`sisaku-security/`)
	url := regexp.MustCompile(`https?://[^ ,;()]+`)
	fixed := regexp.MustCompile(`^https://(github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/|raw\.githubusercontent\.com/[^/]+/[^/]+/[0-9a-f]{40}/)`)
	for _, w := range textTerms {
		for _, u := range url.FindAllString(w.doc, -1) {
			if !fixed.MatchString(u) {
				t.Errorf("the word %s cites %s, not an https URL of a fixed commit", w.name, u)
			}
		}
		if m := repoPath.FindString(w.doc); m != "" {
			t.Errorf("the word %s refers to %q, a path of this repository", w.name, m)
		}
		if m := notPublic.FindString(w.doc); m != "" {
			t.Errorf("the word %s refers to %q, the name of a private repository", w.name, m)
		}
	}
}

// TestTermsCredentialPremise: the word credential premise has, under its
// text, the symbols and the formulas one to an item of a nested list; no
// line of the terms has a round or a square bracket after a backslash
// (a renderer with math reads one as a delimiter), and the symbols of the
// formulas are written as they are.
func TestTermsCredentialPremise(t *testing.T) {
	var premise *Definition
	for i, d := range Definitions().TextTerms {
		if d.Name == "credential premise" {
			premise = &Definitions().TextTerms[i]
		}
	}
	if premise == nil {
		t.Fatal("the terms have no credential premise")
	}
	if len(premise.Items) != 16 {
		t.Errorf("credential premise has %d items, want 16", len(premise.Items))
	}
	md := string(Terms("x"))
	head := strings.Index(md, "\n- credential premise: ")
	if head < 0 {
		t.Fatal("the Markdown has no item credential premise")
	}
	lines := strings.Split(md[head+1:], "\n")
	nested := 0
	for _, l := range lines[1:] {
		if !strings.HasPrefix(l, "  - ") {
			break
		}
		nested++
	}
	if nested != 16 {
		t.Errorf("%d nested items under credential premise, want 16", nested)
	}
	for _, bad := range []string{`\(`, `\)`, `\[`, `\]`} {
		if strings.Contains(md, bad) {
			t.Errorf("the terms have %s", bad)
		}
	}
	for _, sym := range []string{"∖", "∪", "∨", "∀", "∈", "¬", "⇔", "≠", "∅"} {
		if !strings.Contains(md, sym) {
			t.Errorf("the terms do not have %s as it is", sym)
		}
	}
}

// TestTermsEmptyItems: the terms say that an item whose value is empty is
// left out, with the example of fix kinds.
func TestTermsEmptyItems(t *testing.T) {
	for _, want := range []string{"the value of an item name is empty", "fix kinds"} {
		if !strings.Contains(itemNamesDoc, want) {
			t.Errorf("itemNamesDoc does not say %q", want)
		}
	}
}

// TestTermsExampleNames: the terms of examples say that the name of the
// file of an example is the ID of the declaration, not what the file has.
func TestTermsExampleNames(t *testing.T) {
	for _, n := range []itemName{nExample, nTruePositives, nTrueNegatives} {
		if !strings.Contains(n.doc, "the name of the file of an example is the ID of the declaration") {
			t.Errorf("%s does not say what the name of the file of an example is", n.name)
		}
	}
}

// TestTermsExampleNoteKeys: the text term example notes names each key of
// the notes of an example, and says that its reason is not the reason of a
// CVSS metric.
func TestTermsExampleNoteKeys(t *testing.T) {
	var doc string
	for _, x := range textTerms {
		if x.name == "example notes" {
			doc = x.doc
		}
	}
	if doc == "" {
		t.Fatal("no text term example notes")
	}
	for _, k := range noteKeys {
		if !strings.Contains(doc, k+":") {
			t.Errorf("example notes does not name %s", k)
		}
	}
	if !strings.Contains(doc, "not the reason of a CVSS metric") {
		t.Error("example notes does not set its reason apart from the reason of a CVSS metric")
	}
}

// Each key of the notes has what it says in the terms.
func TestNoteKeyDocs(t *testing.T) {
	for _, k := range noteKeys {
		if noteKeyDocs[k] == "" {
			t.Errorf("the note key %s has nothing in noteKeyDocs", k)
		}
	}
	if len(noteKeyDocs) != len(noteKeys) {
		t.Errorf("noteKeyDocs has %d keys, noteKeys %d", len(noteKeyDocs), len(noteKeys))
	}
}

// The definition of targets says how a rule reads an action: alone, on the
// events of the callers when the inputs hold every caller, and on every
// event otherwise.
func TestTargetsSaysHowActionsAreRead(t *testing.T) {
	for _, s := range []string{"action-metadata", "by itself", "whole repository", "every caller", "events of the callers", "every event"} {
		if !strings.Contains(nTargets.doc, s) {
			t.Errorf("the definition of targets has no %q: %s", s, nTargets.doc)
		}
	}
}

// TestTextTermPrivilegedEventAppChecks: the privileged event of the terms
// says that status, check_suite and check_run are privileged events, and
// that a finding of a workflow on them alone holds only when
// repo.fork-pr-app-checks or repo.merge-commit-app-checks is true.
func TestTextTermPrivilegedEventAppChecks(t *testing.T) {
	doc := privilegedEventDoc()
	for _, e := range []workflow.EventName{workflow.EventNameStatus, workflow.EventNameCheckSuite, workflow.EventNameCheckRun} {
		if !slices.Contains(job.Privileged(), e) {
			t.Errorf("%s is not one of job.Privileged", e)
		}
	}
	for _, k := range []facts.Kind{facts.KindRepoForkPRAppChecks, facts.KindRepoMergeCommitAppChecks} {
		if !strings.Contains(doc, k.String()) {
			t.Errorf("the privileged event does not say %s:\n%s", k, doc)
		}
	}
}

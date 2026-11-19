package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// sarifRead is what the tests read of a SARIF log of sarifLog.
type sarifRead struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID               string `json:"id"`
					ShortDescription struct{ Text string }
					FullDescription  struct{ Text string }
					Help             struct{ Text, Markdown string }
					Default          struct{ Level string } `json:"defaultConfiguration"`
					Properties       struct {
						Tags             []string
						SecuritySeverity string `json:"security-severity"`
					}
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
			Notifications       []struct {
				Level     string
				Message   struct{ Text string }
				Locations []sarifReadLocation
			} `json:"toolExecutionNotifications"`
		} `json:"invocations"`
		NewlineSequences []string          `json:"newlineSequences"`
		Results          []sarifReadResult `json:"results"`
	} `json:"runs"`
}

type sarifReadResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex int    `json:"ruleIndex"`
	Kind      string
	Level     string
	Message   struct{ Text string }
	Locations []sarifReadLocation
	CodeFlows []struct {
		ThreadFlows []struct {
			Locations []struct{ Location sarifReadLocation }
		}
	}
	RelatedLocations    []sarifReadLocation
	PartialFingerprints map[string]string
	Fixes               []struct {
		ArtifactChanges []struct {
			ArtifactLocation struct{ URI string }
			Replacements     []struct {
				DeletedRegion   sarifRegion
				InsertedContent *struct{ Text string }
			}
		}
	}
	Properties *struct{ Certainty string }
}

type sarifReadLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct{ URI string }
		Region           sarifRegion
	}
}

// reportRead is what the tests read of the report of the same run.
type reportRead struct {
	Rules []struct {
		ID string `json:"id"`
	} `json:"rules"`
	QualityRules []string `json:"quality_rules"`
	Findings     []struct {
		Rule      string `json:"rule"`
		Severity  string `json:"severity"`
		Certainty string `json:"certainty"`
		Args      struct {
			Kind string `json:"kind_id"`
		} `json:"args"`
		Detected string `json:"detected"`
		Location struct {
			File   struct{ Input string } `json:"file"`
			Start  int                    `json:"start"`
			End    int                    `json:"end"`
			Line   int                    `json:"line"`
			Column int                    `json:"column"`
		} `json:"location"`
		Related  []json.RawMessage `json:"related"`
		Evidence []struct {
			Location struct {
				File struct{ Input string } `json:"file"`
				Line int                    `json:"line"`
			} `json:"location"`
		} `json:"evidence"`
		Fix *struct {
			Edits []spliceEdit `json:"edits"`
		} `json:"fix"`
		Acceptance  json.RawMessage `json:"acceptance"`
		Fingerprint string          `json:"fingerprint"`
	} `json:"findings"`
	QualityFindings []struct {
		Args struct {
			Kind string `json:"kind_id"`
		} `json:"args"`
		Fingerprint string `json:"fingerprint"`
	} `json:"quality_findings"`
}

// decided are the findings of r whose certainty is confirmed or
// conditional, and inconclusive those whose certainty is inconclusive, as
// their indexes in r.Findings.
func (r reportRead) split() (decided, inconclusive []int) {
	for i, f := range r.Findings {
		if f.Certainty == "inconclusive" {
			inconclusive = append(inconclusive, i)
		} else {
			decided = append(decided, i)
		}
	}
	return decided, inconclusive
}

var allRules = filepath.Join("..", "rules", "testdata", "all-rules")

// sarifRuns are runs whose SARIF the tests check: of every rule with the
// facts of its examples, of every rule with nothing known, and of places
// one of which a person accepted.
func sarifRuns(t *testing.T) map[string][]string {
	t.Helper()
	dir := twoPlaces(t, "${{ inputs.runner }}")
	return map[string][]string{
		"all rules, with facts":        {"--root", allRules, "--facts", filepath.Join(allRules, "facts.json")},
		"all rules, nothing known":     {"--root", allRules, "--no-assumptions"},
		"places, one of them accepted": {"--root", dir, "--accept", acceptFile(t, dir, "jobs.a.runs-on")},
	}
}

// sarifOf runs a with --format sarif and with --format json.
func sarifOf(t *testing.T, a []string) ([]byte, sarifRead, reportRead) {
	t.Helper()
	got := run(t, raw(append([]string{"--format", "sarif"}, a...)...))
	if got.code >= ExitUsage {
		t.Fatalf("%v: exit %d: %s", a, got.code, got.stderr)
	}
	var s sarifRead
	if err := json.Unmarshal([]byte(got.stdout), &s); err != nil {
		t.Fatalf("%v: %v", a, err)
	}
	js := run(t, raw(append([]string{"--format", "json"}, a...)...))
	var r reportRead
	if err := json.Unmarshal([]byte(js.stdout), &r); err != nil {
		t.Fatalf("%v: %v", a, err)
	}
	if js.code != got.code {
		t.Errorf("%v: exit %d with sarif, %d with json", a, got.code, js.code)
	}
	return []byte(got.stdout), s, r
}

// The SARIF is of the schema, and has what code scanning requires
// (https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support):
// the texts of each rule, at most 1024 characters in the descriptions,
// and the message, the location and partialFingerprints of each result.
func TestSARIFSchema(t *testing.T) {
	d := sarifSchemaCheck(t)
	seen := map[string]bool{}
	for name, a := range sarifRuns(t) {
		b, s, _ := sarifOf(t, a)
		if errs := d.check(decodeSARIF(t, b)); len(errs) != 0 {
			t.Errorf("%s: not of the schema: %v", name, errs[:min(len(errs), 10)])
		}
		run := s.Runs[0]
		for _, r := range run.Tool.Driver.Rules {
			for what, x := range map[string]string{"shortDescription": r.ShortDescription.Text, "fullDescription": r.FullDescription.Text, "help": r.Help.Text} {
				if x == "" {
					t.Errorf("%s: %s: no %s", name, r.ID, what)
				}
			}
			if utf8.RuneCountInString(r.ShortDescription.Text) > 1024 || utf8.RuneCountInString(r.FullDescription.Text) > 1024 {
				t.Errorf("%s: %s: a description over 1024 characters", name, r.ID)
			}
		}
		for _, r := range run.Results {
			if r.Message.Text == "" || len(r.Locations) != 1 || r.PartialFingerprints[sarifLineHash] == "" {
				t.Errorf("%s: %s: message %q, %d locations, partialFingerprints %v", name, r.RuleID, r.Message.Text, len(r.Locations), r.PartialFingerprints)
			}
			if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
				t.Errorf("%s: %s: ruleIndex %d is of %s", name, r.RuleID, r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID)
			}
		}
		if !run.Invocations[0].ExecutionSuccessful {
			t.Errorf("%s: the execution is not successful", name)
		}
		for _, w := range baseIDsOf(t, name, decodeSARIF(t, b)) {
			seen[w] = true
		}
	}
	if !seen["results"] || !seen["codeFlows"] || !seen["fixes"] {
		t.Errorf("artifactLocations in %v", seen)
	}
}

// baseIDsOf checks that each artifactLocation of the SARIF v is a relative
// reference with the uriBaseId %SRCROOT%, and that originalUriBaseIds
// describes %SRCROOT% without a URI, the absolute path of the machine of
// the run (SARIF 3.4.4, 3.14.14). It is where the artifactLocations are:
// results and invocations of the run, and codeFlows and fixes of a result.
func baseIDsOf(t *testing.T, name string, v any) []string {
	t.Helper()
	run := v.(map[string]any)["runs"].([]any)[0].(map[string]any)
	base, _ := run["originalUriBaseIds"].(map[string]any)
	root, _ := base[sarifSrcRoot].(map[string]any)
	if len(base) != 1 || len(root) != 1 || root["description"] == nil {
		t.Errorf("%s: originalUriBaseIds %v", name, base)
	}
	var where []string
	var walk func(top string, x any)
	walk = func(top string, x any) {
		switch x := x.(type) {
		case map[string]any:
			for k, y := range x {
				if k != "artifactLocation" {
					walk(top, y)
					continue
				}
				a := y.(map[string]any)
				u, _ := a["uri"].(string)
				if a["uriBaseId"] != sarifSrcRoot || len(a) != 2 || strings.Contains(u, ":") || strings.HasPrefix(u, "/") {
					t.Errorf("%s: %s: artifactLocation %v", name, top, a)
				}
				where = append(where, top)
			}
		case []any:
			for _, y := range x {
				walk(top, y)
			}
		}
	}
	for _, top := range []string{"results", "invocations"} {
		walk(top, run[top])
	}
	for _, r := range run["results"].([]any) {
		for _, top := range []string{"codeFlows", "fixes"} {
			if r.(map[string]any)[top] != nil {
				where = append(where, top)
			}
		}
	}
	return where
}

// A rule (reportingDescriptor) for each finding kind and inconclusive
// kind of each rule that ran, and for each finding kind of each quality
// rule that ran, whether or not it has a result; the Markdown help on
// each but the inconclusive kinds.
func TestSARIFDescriptors(t *testing.T) {
	reg := registry(t)
	for name, a := range sarifRuns(t) {
		_, s, rep := sarifOf(t, a)
		var want []string
		inconclusive := map[string]bool{}
		for _, x := range rep.Rules {
			m, _ := reg.Meta(lint.MustRuleID(x.ID))
			for _, k := range m.FindingKinds {
				want = append(want, k.ID.String())
			}
			for _, k := range m.InconclusiveKinds {
				id := x.ID + "." + k.ID.String()
				want, inconclusive[id] = append(want, id), true
			}
		}
		for _, id := range rep.QualityRules {
			m, _ := reg.QualityMeta(lint.MustRuleID(id))
			for _, k := range m.FindingKinds {
				want = append(want, k.ID.String())
			}
		}
		var got []string
		for _, d := range s.Runs[0].Tool.Driver.Rules {
			got = append(got, d.ID)
			if inc := inconclusive[d.ID]; (d.Help.Markdown == "") != inc {
				t.Errorf("%s: %s: help.markdown %d bytes", name, d.ID, len(d.Help.Markdown))
			}
		}
		if len(want) == 0 || !slices.Equal(got, want) {
			t.Errorf("%s: rules %v, want %v", name, got, want)
		}
	}
}

// executionSuccessful is false when --fix failed, and the driver has the
// version of the binary.
func TestSARIFFailedFix(t *testing.T) {
	b, err := sarifLog(lint.Report{Fix: &lint.FixResult{Safety: lint.SafetySafe, Error: "x.yml: a symlink"}}, lint.Inputs{}, registry(t), "v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	var s sarifRead
	var v struct {
		Runs []struct {
			Tool struct{ Driver struct{ Version string } }
		}
	}
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	inv := s.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || len(inv.Notifications) != 1 || inv.Notifications[0].Message.Text != "--fix: x.yml: a symlink" || v.Runs[0].Tool.Driver.Version != "v1.2.3" {
		t.Errorf("invocation %+v, version %q", inv, v.Runs[0].Tool.Driver.Version)
	}
}

// Each finding, quality finding and inconclusive place no acceptance
// matched is a result, in that order.
func TestSARIFResults(t *testing.T) {
	for name, a := range sarifRuns(t) {
		_, s, rep := sarifOf(t, a)
		run := s.Runs[0]
		rules := run.Tool.Driver.Rules
		decided, inconclusive := rep.split()
		var open int
		for _, i := range inconclusive {
			if rep.Findings[i].Acceptance == nil {
				open++
			}
		}
		if n := len(decided) + len(rep.QualityFindings) + open; len(run.Results) != n {
			t.Fatalf("%s: %d results, want %d", name, len(run.Results), n)
		}
		level := map[string]string{"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
		score := map[string]string{"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "2.0", "info": "1.0"}
		for i, fi := range decided {
			f := rep.Findings[fi]
			r := run.Results[i]
			d := rules[r.RuleIndex]
			if r.RuleID != f.Args.Kind || r.Kind != "" || r.Level != level[f.Severity] || d.Default.Level != r.Level || d.Properties.SecuritySeverity != score[f.Severity] || d.Properties.Tags[0] != "security" {
				t.Errorf("%s: finding %d (%s %s): result %s kind %q level %s, rule level %s security-severity %s tags %v", name, i, f.Args.Kind, f.Severity, r.RuleID, r.Kind, r.Level, d.Default.Level, d.Properties.SecuritySeverity, d.Properties.Tags)
			}
			if r.PartialFingerprints[sarifLineHash] != f.Fingerprint || r.PartialFingerprints[sarifFingerprint] != f.Fingerprint {
				t.Errorf("%s: finding %d: partialFingerprints %v, fingerprint %s", name, i, r.PartialFingerprints, f.Fingerprint)
			}
			conditional := f.Certainty == "conditional"
			if !strings.HasPrefix(r.Message.Text, f.Detected) || strings.Contains(r.Message.Text, "(conditional: ") != conditional || r.Properties.Certainty != f.Certainty {
				t.Errorf("%s: finding %d (%s): message %q", name, i, f.Certainty, r.Message.Text)
			}
			flow := 0
			if len(r.CodeFlows) != 0 {
				flow = len(r.CodeFlows[0].ThreadFlows[0].Locations)
			}
			// a related location is linked from the message (SARIF 2.1.0
			// 3.11.6), where code scanning shows a link to it
			if flow != len(f.Evidence) || len(r.RelatedLocations) != len(f.Related) || len(f.Related) > 0 && !strings.Contains(r.Message.Text, "](0)") || (len(r.Fixes) != 0) != (f.Fix != nil) {
				t.Errorf("%s: finding %d: %d steps, %d related, %d fixes; want %d, %d, %t", name, i, flow, len(r.RelatedLocations), len(r.Fixes), len(f.Evidence), len(f.Related), f.Fix != nil)
				continue
			}
			for k, e := range f.Evidence {
				l := r.CodeFlows[0].ThreadFlows[0].Locations[k].Location.PhysicalLocation
				if l.ArtifactLocation.URI != e.Location.File.Input || l.Region.StartLine != e.Location.Line {
					t.Errorf("%s: finding %d: step %d at %s:%d, the evidence at %s:%d", name, i, k, l.ArtifactLocation.URI, l.Region.StartLine, e.Location.File.Input, e.Location.Line)
				}
			}
		}
		for i, f := range rep.QualityFindings {
			r := run.Results[len(decided)+i]
			d := rules[r.RuleIndex]
			if r.RuleID != f.Args.Kind || r.Level != "note" || d.Default.Level != "note" || d.Properties.SecuritySeverity != "" || d.Properties.Tags[0] != "quality" || r.PartialFingerprints[sarifLineHash] != f.Fingerprint {
				t.Errorf("%s: quality finding %d: %+v, rule %+v", name, i, r, d)
			}
		}
		j := len(decided) + len(rep.QualityFindings)
		for _, gi := range inconclusive {
			g := rep.Findings[gi]
			if g.Acceptance != nil {
				continue
			}
			r := run.Results[j]
			j++
			d := rules[r.RuleIndex]
			// the level and the security severity of its rule, as a finding
			// of the rule has; the kind is fail (absent), as code scanning
			// reads the level and SARIF 2.1.0 takes no other kind with it
			if r.RuleID != g.Args.Kind || r.Kind != "" || r.Level != level[g.Severity] || d.Default.Level != r.Level || d.Properties.SecuritySeverity != score[g.Severity] ||
				len(d.Properties.Tags) < 2 || d.Properties.Tags[0] != "security" || d.Properties.Tags[1] != "inconclusive" ||
				r.PartialFingerprints[sarifLineHash] != g.Fingerprint || r.PartialFingerprints[sarifFingerprint] != g.Fingerprint || !strings.HasPrefix(r.Message.Text, inconclusiveMessage+g.Detected) ||
				len(r.RelatedLocations) != len(g.Related) || len(g.Related) > 0 && !strings.Contains(r.Message.Text, "](0)") || r.Properties.Certainty != "inconclusive" {
				t.Errorf("%s: inconclusive %s: %+v, rule %+v", name, g.Args.Kind, r, d)
			}
		}
	}
}

// Of the two places, the one a person accepted is not in the SARIF:
// code scanning keeps a result with suppressions open.
func TestSARIFAccepted(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	_, all, _ := sarifOf(t, []string{"--root", dir})
	_, s, _ := sarifOf(t, []string{"--root", dir, "--accept", acceptFile(t, dir, "jobs.a.runs-on")})
	if len(all.Runs[0].Results) != 2 || len(s.Runs[0].Results) != 1 || s.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine != 14 {
		t.Errorf("results %+v of %+v", s.Runs[0].Results, all.Runs[0].Results)
	}
}

// The replacements of a fix, applied at their regions, give what the
// edits of the fix give.
func TestSARIFFixes(t *testing.T) {
	_, s, rep := sarifOf(t, sarifRuns(t)["all rules, with facts"])
	n := 0
	decided, _ := rep.split()
	for i, fi := range decided {
		f := rep.Findings[fi]
		if f.Fix == nil {
			continue
		}
		n++
		src, err := os.ReadFile(filepath.Join(allRules, f.Location.File.Input))
		if err != nil {
			t.Fatal(err)
		}
		want := splice(src, f.Fix.Edits)
		changes := s.Runs[0].Results[i].Fixes[0].ArtifactChanges
		if len(changes) != 1 || changes[0].ArtifactLocation.URI != f.Location.File.Input {
			t.Fatalf("finding %d: changes %+v", i, changes)
		}
		// in the order of the array, each region in the file before the
		// replacements (SARIF 3.57.1)
		var got []byte
		prev := 0
		for k, r := range changes[0].Replacements {
			start, end := offsetOf(src, r.DeletedRegion.StartLine, r.DeletedRegion.StartColumn), offsetOf(src, r.DeletedRegion.EndLine, r.DeletedRegion.EndColumn)
			if start < prev {
				t.Fatalf("finding %d: replacement %d starts at %d, before the end %d of the one before", i, k, start, prev)
			}
			got = append(got, src[prev:start]...)
			if r.InsertedContent != nil {
				got = append(got, r.InsertedContent.Text...)
			}
			prev = end
		}
		if got = append(got, src[prev:]...); string(got) != string(want) {
			t.Errorf("finding %d (%s): the replacements give\n%s\nthe edits\n%s", i, f.Args.Kind, got, want)
		}
	}
	if n == 0 {
		t.Fatal("no finding with a fix")
	}
}

// spliceEdit is an edit of the bytes of a file: the bytes from Start to
// End become New (the edits of a fix in the report).
type spliceEdit struct {
	Start, End int
	New        string
}

// splice is src with each edit made; the edits do not overlap.
func splice(src []byte, edits []spliceEdit) []byte {
	es := slices.Clone(edits)
	slices.SortStableFunc(es, func(a, b spliceEdit) int { return b.Start - a.Start })
	out := slices.Clone(src)
	for _, e := range es {
		out = slices.Concat(out[:e.Start], []byte(e.New), out[e.End:])
	}
	return out
}

// offsetOf is the byte offset of the line and the column of src, the
// column in UTF-16 code units from 1.
func offsetOf(src []byte, line, column int) int {
	off := 0
	for range line - 1 {
		off += strings.IndexByte(string(src[off:]), '\n') + 1
	}
	for n := 1; n < column; {
		r, w := utf8.DecodeRune(src[off:])
		n += len(utf16.Encode([]rune{r}))
		off += w
	}
	return off
}

// The columns are counted in UTF-16 code units: é is one, U+1F600 two.
func TestSARIFColumns(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows", "w.yml")
	if err := os.MkdirAll(filepath.Dir(wf), 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - {name: \"\xc3\xa9\xf0\x9f\x98\x80\", uses: actions/checkout@v4}\n"
	if err := os.WriteFile(wf, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	_, s, rep := sarifOf(t, []string{"--root", dir})
	if len(rep.Findings) == 0 {
		t.Fatal("no finding")
	}
	for i, f := range rep.Findings {
		reg := s.Runs[0].Results[i].Locations[0].PhysicalLocation.Region
		line := src[strings.LastIndexByte(src[:f.Location.Start], '\n')+1:]
		want := len(utf16.Encode([]rune(line[:f.Location.Column-1]))) + 1
		if reg.StartLine != f.Location.Line || reg.StartColumn != want || f.Location.Line == 8 && reg.StartColumn != f.Location.Column-3 {
			t.Errorf("finding %d (%s) at %d:%d (bytes): region %+v, want the column %d", i, f.Args.Kind, f.Location.Line, f.Location.Column, reg, want)
		}
		if got := offsetOf([]byte(src), reg.EndLine, reg.EndColumn); got != f.Location.End {
			t.Errorf("finding %d: the end of the region is at %d, the end of the span at %d", i, got, f.Location.End)
		}
	}
}

// --format sarif writes on stdout what --sarif writes to the file, with
// the exit code of --format json.
func TestSARIFOut(t *testing.T) {
	dir := repo(t)
	stdout := run(t, raw("--root", dir, "--format", "sarif"))
	file := filepath.Join(t.TempDir(), "r.sarif")
	got := run(t, raw("--root", dir, "--sarif", file))
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	js := run(t, args("--root", dir))
	if string(b) != stdout.stdout || got.code != js.code || stdout.code != js.code || !strings.Contains(got.stdout, "commit-sha") {
		t.Errorf("--sarif: exit %d, %d with --format sarif, %d with json; the file is the stdout of --format sarif: %t", got.code, stdout.code, js.code, string(b) == stdout.stdout)
	}
}

func TestSARIFFails(t *testing.T) {
	dir := repo(t)
	got := run(t, raw("--root", dir, "--sarif", filepath.Join(t.TempDir(), "no/such/dir/r.sarif")))
	if got.code != ExitIO || !strings.Contains(got.stderr, "--sarif") || got.stdout == "" {
		t.Errorf("exit %d, stderr %q; want %d, why, and the text on stdout", got.code, got.stderr, ExitIO)
	}
	for _, a := range [][]string{{"--fix", "--dry-run", "--format", "sarif"}, {"--sarif", ""}, {"--format", "sarif2"}} {
		got := run(t, raw(append([]string{"--root", dir}, a...)...))
		if got.code != ExitUsage {
			t.Errorf("%v: exit %d, stderr %q; want %d", a, got.code, got.stderr, ExitUsage)
		}
	}
}

// With --read-all, the SARIF has only the places of the PATHs.
func TestSARIFReadAll(t *testing.T) {
	dir := readAllRepo(t)
	_, all, _ := sarifOf(t, []string{"--root", dir})
	_, s, _ := sarifOf(t, []string{"--root", dir, "--read-all", ".github/workflows/other.yml"})
	uris := func(s sarifRead) []string {
		var out []string
		for _, r := range s.Runs[0].Results {
			if u := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; !slices.Contains(out, u) {
				out = append(out, u)
			}
		}
		slices.Sort(out)
		return out
	}
	if got := uris(s); !slices.Equal(got, []string{".github/workflows/other.yml"}) || len(uris(all)) < 2 {
		t.Errorf("--read-all: the results are in %v; without it, in %v", got, uris(all))
	}
}

// The fixes of the files --fix wrote are left out, and a notification
// says that the locations are of the files before the fixes.
func TestSARIFAfterFix(t *testing.T) {
	dir := example(t)
	file := filepath.Join(t.TempDir(), "r.sarif")
	got := run(t, raw("--root", dir, "--facts", filepath.Join(dir, "facts.json"), "--fix=review", "--sarif", file))
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("exit %d: %s: %v", got.code, got.stderr, err)
	}
	var s sarifRead
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Runs[0].Results {
		if len(r.Fixes) != 0 {
			t.Errorf("%s at %+v has fixes after --fix wrote them", r.RuleID, r.Locations[0].PhysicalLocation)
		}
	}
	ns := s.Runs[0].Invocations[0].Notifications
	if !slices.ContainsFunc(ns, func(n struct {
		Level     string
		Message   struct{ Text string }
		Locations []sarifReadLocation
	}) bool {
		return n.Level == "note" && strings.HasPrefix(n.Message.Text, "--fix wrote the fixes to ")
	}) {
		t.Errorf("no notification of the fixes written: %+v", ns)
	}

	// --fix writes the safe fixes only: a file whose fixes are all for
	// review is not written, and its results keep their fixes
	dir = example(t)
	report := filepath.Join(t.TempDir(), "r.json")
	run(t, raw("--root", dir, "--facts", filepath.Join(dir, "facts.json"), "--fix", "--sarif", file, "--report", report))
	var rep struct {
		Fix struct{ Written []string } `json:"fix"`
	}
	for p, v := range map[string]any{file: &s, report: &rep} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	kept := 0
	for _, r := range s.Runs[0].Results {
		if len(r.Fixes) == 0 {
			continue
		}
		kept++
		if u := r.Fixes[0].ArtifactChanges[0].ArtifactLocation.URI; slices.Contains(rep.Fix.Written, u) {
			t.Errorf("%s has a fix of %s, which --fix wrote", r.RuleID, u)
		}
	}
	if kept == 0 || len(rep.Fix.Written) == 0 {
		t.Errorf("--fix: %d results keep fixes; written %v", kept, rep.Fix.Written)
	}
}

// The identity of an inconclusive place has no line in it: a line added
// above keeps it. Two places have two.
func TestSARIFInconclusiveID(t *testing.T) {
	dir := twoPlaces(t, "${{ inputs.runner }}")
	ids := func() []string {
		_, s, _ := sarifOf(t, []string{"--root", dir})
		var out []string
		for _, r := range s.Runs[0].Results {
			out = append(out, r.PartialFingerprints[sarifFingerprint])
		}
		return out
	}
	before := ids()
	wf := filepath.Join(dir, ".github", "workflows", "w.yml")
	b, err := os.ReadFile(wf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wf, append([]byte("# a line above\n"), b...), 0o644); err != nil {
		t.Fatal(err)
	}
	after := ids()
	if len(before) != 2 || before[0] == before[1] || before[0] == "" || !slices.Equal(before, after) {
		t.Errorf("the identities %v, then %v with a line above", before, after)
	}

	// the same ${{ }} twice on one line: two places that an entry of
	// --accept names alike, and two identities
	if err := os.WriteFile(wf, []byte("on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - id: s\n        run: echo hi\n      - run: echo ${{ steps.s.outputs.x }} ${{ steps.s.outputs.x }}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ids(); len(got) != 2 || got[0] == got[1] {
		t.Errorf("the identities of the same ${{ }} twice: %v", got)
	}
}

// An input not valid and one not read are notifications, the diagnostic
// with its region on a line of the file; the log is of the schema.
func TestSARIFNotifications(t *testing.T) {
	dir := t.TempDir()
	wf := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{
		"bad.yml":   "on: push\njobs: [\n",
		"latin.yml": "on: push\n# \xe9\n",
		"ok.yml":    "on: push\npermissions: {}\njobs: {}\n",
	} {
		if err := os.WriteFile(filepath.Join(wf, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, s, _ := sarifOf(t, []string{"--root", dir})
	if errs := sarifSchemaCheck(t).check(decodeSARIF(t, b)); len(errs) != 0 {
		t.Errorf("not of the schema: %v", errs)
	}
	if !slices.Contains(baseIDsOf(t, "notifications", decodeSARIF(t, b)), "invocations") {
		t.Error("no artifactLocation in the notifications")
	}
	inv := s.Runs[0].Invocations[0]
	files := map[string]bool{}
	for _, n := range inv.Notifications {
		u := n.Locations[0].PhysicalLocation.ArtifactLocation.URI
		files[u] = true
		if r := n.Locations[0].PhysicalLocation.Region; u == ".github/workflows/bad.yml" && (r.StartLine < 1 || r.EndLine > 2) {
			t.Errorf("%s: region %+v is not on the 2 lines of the file", n.Message.Text, r)
		}
		if n.Level != "error" || strings.HasSuffix(n.Message.Text, ": ") {
			t.Errorf("notification %+v", n)
		}
	}
	if !files[".github/workflows/bad.yml"] || !files[".github/workflows/latin.yml"] || len(files) != 2 || !inv.ExecutionSuccessful {
		t.Errorf("notifications %+v, successful %t", inv.Notifications, inv.ExecutionSuccessful)
	}
}

// A byte order mark is not counted in the columns of line 1, and lines
// broken by CR are lines (newlineSequences).
func TestSARIFLineBreaks(t *testing.T) {
	src := "on: push\npermissions: {}\njobs: {a: {runs-on: ubuntu-latest, timeout-minutes: 5, steps: [{uses: actions/checkout@v4}]}}\n"
	one := "{on: push, permissions: {}, jobs: {a: {runs-on: ubuntu-latest, timeout-minutes: 5, steps: [{uses: actions/checkout@v4}]}}}\n"
	regions := func(src string) []sarifRegion {
		dir := t.TempDir()
		wf := filepath.Join(dir, ".github", "workflows", "w.yml")
		if err := os.MkdirAll(filepath.Dir(wf), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(wf, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		_, s, _ := sarifOf(t, []string{"--root", dir, "--rule", "commit-sha"})
		if !slices.Equal(s.Runs[0].NewlineSequences, []string{"\r\n", "\r", "\n"}) {
			t.Errorf("newlineSequences %q", s.Runs[0].NewlineSequences)
		}
		var out []sarifRegion
		for _, r := range s.Runs[0].Results {
			out = append(out, r.Locations[0].PhysicalLocation.Region)
		}
		return out
	}
	for name, c := range map[string][2]string{
		"a byte order mark on line 1": {one, "\xef\xbb\xbf" + one},
		"CR":                          {src, strings.ReplaceAll(src, "\n", "\r")},
		"CR LF":                       {src, strings.ReplaceAll(src, "\n", "\r\n")},
	} {
		want, got := regions(c[0]), regions(c[1])
		if len(want) == 0 || !slices.Equal(want, got) {
			t.Errorf("%s: regions %+v, want %+v", name, got, want)
		}
	}
}

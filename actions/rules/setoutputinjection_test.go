package rules

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// setOutputResults are the findings and the inconclusive places of
// set-output-injection on files, as "input line kind".
func setOutputResults(t *testing.T, files map[string]string) []string {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{SetOutputInjection}, files, nil)
	var out []string
	line := func(name string, start int) string {
		return name + " " + strconv.Itoa(strings.Count(files[name][:start], "\n")+1)
	}
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		out = append(out, line(f.Location.File.Input.String(), f.Location.Span.Start)+" "+f.Args.KindID().String())
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, line(g.Location.File.Input.String(), g.Location.Span.Start)+" inconclusive "+g.InconclusiveKind.String())
	}
	slices.Sort(out)
	return out
}

// TestSetOutputInjectionExperiment: the tree of an experiment, copied under
// testdata/observed, whose steps s1, s2, s3, s6, s7, bg and the step x of the action set
// outputs from the log, s5 printed between stop-commands (the false
// positive stopped-commands), and s4, s8 and n1 set none.
func TestSetOutputInjectionExperiment(t *testing.T) {
	dir := "testdata/observed/log-set-output/2/"
	files := map[string]string{}
	for _, n := range []string{".github/workflows/q1-log-output.yml", ".github/workflows/q2-no-id.yml", ".github/actions/p/action.yml.txt"} {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		files[strings.TrimSuffix(n, ".txt")] = string(b)
	}
	q1, q2, a := ".github/workflows/q1-log-output.yml", ".github/workflows/q2-no-id.yml", ".github/actions/p/action.yml"
	c := " set-output-injection.controlled"
	want := []string{a + " 16" + c, q1 + " 14" + c, q1 + " 19" + c, q1 + " 26" + c, q1 + " 39" + c, q1 + " 47" + c, q1 + " 52" + c, q2 + " 16" + c}
	slices.Sort(want)
	if got := setOutputResults(t, files); !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// TestSetOutputInjection: two references of one step are two findings with
// their own anchors; a literal set-output of the author has no attacker;
// a step with an id whose flag is true and that is the last of the job is
// reported, where unsecure-commands reports nothing.
func TestSetOutputInjection(t *testing.T) {
	head := "on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
	two := head + "    steps:\n      - id: p\n        env:\n          TITLE: ${{ github.event.issue.title }}\n        run: |\n          echo \"$TITLE\"\n          echo \"${{ github.event.issue.body }}\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{SetOutputInjection}, wfFile(two), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 2 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Fingerprint == rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[1].Fingerprint {
		t.Errorf("two references: got %d findings %v", len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)), rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	literal := head + "    steps:\n      - id: p\n        run: echo \"::set-output name=a::b\"\n"
	if got := setOutputResults(t, wfFile(literal)); len(got) != 0 {
		t.Errorf("literal: got %q", got)
	}
	flag := head + "    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - id: p\n        env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n"
	if got, want := setOutputResults(t, wfFile(flag)), []string{".github/workflows/w.yml 12 set-output-injection.controlled"}; !slices.Equal(got, want) {
		t.Errorf("flag, last step: got %q, want %q", got, want)
	}
}

// TestWikiValues: the title of a wiki page holds no -, so no rule that
// needs a - reports it; the summary of a wiki page is a value nobody
// writes, so no rule reports it.
func TestWikiValues(t *testing.T) {
	src := func(ref string) string {
		return "on: gollum\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - id: p\n        env:\n          V: ${{ " + ref + " }}\n        run: |\n          echo \"$V\"\n          tar -xf a.tar \"$V\"\n      - run: echo next\n"
	}
	results := func(ref string) []string {
		rep, _, _ := checkRules(t, []lint.Rule{SetOutputInjection, UnsecureCommands, ArgumentInjection}, wfFile(src(ref)), nil)
		var out []string
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			out = append(out, f.Args.KindID().String())
		}
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			out = append(out, g.Rule.String()+" "+g.InconclusiveKind.String())
		}
		slices.Sort(out)
		return out
	}
	if got := results("github.event.pages[0].title"); len(got) != 0 {
		t.Errorf("title: got %q, want none", got)
	}
	if got := results("github.event.pages[0].summary"); len(got) != 0 {
		t.Errorf("summary: got %q, want none", got)
	}
}

// TestSetOutputInjectionGollum: the rule's Threat does not have the editor
// of a wiki. The name of a wiki page gives an inconclusive place (a page
// pushed by git keeps its blanks); a key of a page that the schema does not
// describe gives the same; on gollum and issues, the value of all of the
// event is a finding on issues alone.
func TestSetOutputInjectionGollum(t *testing.T) {
	src := func(on, ref string) string {
		return "on: " + on + "\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - id: p\n        env:\n          V: ${{ " + ref + " }}\n        run: echo \"$V\"\n"
	}
	for _, c := range []struct {
		on, ref      string
		findingOn    []workflow.EventName
		inconclusive bool
	}{
		{"gollum", "github.event.pages[0].page_name", nil, true},
		{"gollum", "github.event.pages[0][github.event.pages[0].action]", nil, true},
		{"[gollum, issues]", "toJSON(github.event)", []workflow.EventName{workflow.EventNameIssues}, false},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{SetOutputInjection}, wfFile(src(c.on, c.ref)), nil)
		var on []workflow.EventName
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			on = append(on, f.Args.(SetOutputInjectionControlled).ControlledOn...)
		}
		if !slices.Equal(on, c.findingOn) || (len(rep.FindingsWith(lint.CertaintyInconclusive)) == 1) != c.inconclusive || c.inconclusive && rep.FindingsWith(lint.CertaintyInconclusive)[0].InconclusiveKind != structuredValueKind {
			t.Errorf("%s %s: findings %+v, inconclusive %+v", c.on, c.ref, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
		}
	}
}

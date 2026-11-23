package rules

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// unsecureFindings are the findings and the inconclusive places of
// unsecure-commands in src, as "kind line" and "inconclusive kind line".
func unsecureFindings(t *testing.T, src string) []string {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{UnsecureCommands}, wfFile(src), exposureFacts{public: ptr(true)})
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		out = append(out, f.Args.KindID().String()+" "+strconv.Itoa(strings.Count(src[:f.Location.Span.Start], "\n")+1))
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, "inconclusive "+g.InconclusiveKind.String()+" "+strconv.Itoa(strings.Count(src[:g.Location.Span.Start], "\n")+1))
	}
	return out
}

// TestUnsecureCommandsObservedLines: the observed lines with the
// attacker's value: each line the observed runs showed to
// set the env, but the line between ::stop-commands:: and its token
// (stopped-commands, a known false positive), and none of the steps whose
// flag was off (unflagged, one).
func TestUnsecureCommandsObservedLines(t *testing.T) {
	src, err := os.ReadFile("testdata/unsecure-commands/e2.yml")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"unsecure-commands.controlled 17", "unsecure-commands.controlled 18", "unsecure-commands.controlled 19", "unsecure-commands.controlled 20",
		"unsecure-commands.controlled 21", "unsecure-commands.controlled 22", "unsecure-commands.controlled 24",
		"unsecure-commands.controlled 34",
		"unsecure-commands.controlled 45", "unsecure-commands.controlled 53", "unsecure-commands.controlled 57",
	}
	if got := unsecureFindings(t, string(src)); !slices.Equal(got, want) {
		t.Errorf("got %q\nwant %q", got, want)
	}
}

// TestUnsecureCommandsCommitEmail: the email of a commit's author is
// reported, and the email of the pusher, the account that pushed, is not:
// the account that pushed holds a credential that can push.
func TestUnsecureCommandsCommitEmail(t *testing.T) {
	src := "on: push\npermissions: {}\njobs:\n  email:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - env:\n          EMAIL: ${{ github.event.head_commit.author.email }}\n        run: |\n          echo \"author email is $EMAIL\"\n          echo \"pusher email is ${{ github.event.pusher.email }}\"\n      - run: echo next\n"
	want := []string{"unsecure-commands.controlled 12"}
	if got := unsecureFindings(t, src); !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestNewExamplesRead: the examples of the rules are inputs GitHub takes,
// so that what they declare is not met by an input the rules do not read
// (a plain scalar holding ": " is not YAML, and two examples were so).
func TestNewExamplesRead(t *testing.T) {
	for _, r := range All() {
		id := r.Meta().ID.String()
		dirs, _ := filepath.Glob("examples/*/" + id)
		for _, d := range dirs {
			entries, err := os.ReadDir(d)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				files := map[string]string{}
				p := filepath.Join(d, e.Name())
				switch {
				case e.IsDir():
					_ = filepath.WalkDir(p, func(q string, x fs.DirEntry, _ error) error {
						if !x.IsDir() && (strings.HasSuffix(q, ".yml") || strings.HasSuffix(q, ".yaml")) {
							b, _ := os.ReadFile(q)
							rel, _ := filepath.Rel(p, q)
							files[filepath.ToSlash(rel)] = string(b)
						}
						return nil
					})
				case strings.HasSuffix(e.Name(), ".action.yml"):
					b, _ := os.ReadFile(p)
					files[strings.TrimSuffix(e.Name(), ".action.yml")+"/action.yml"] = string(b)
				case strings.HasSuffix(e.Name(), ".yml"):
					b, _ := os.ReadFile(p)
					files[".github/workflows/"+e.Name()] = string(b)
				default:
					continue
				}
				rep, _, _ := checkRules(t, []lint.Rule{r}, files, exposureFacts{})
				for _, in := range rep.Inputs {
					if in.State == lint.InputStateInvalid {
						t.Errorf("%s: %s is invalid", p, in.Name)
					}
				}
			}
		}
	}
}

// TestUnsecureCommandsLastStepWithID: a step with an id whose flag is true
// gets LogWrites (for set-output-injection), but with no step after it
// set-env and add-path reach nothing, and unsecure-commands reports none.
func TestUnsecureCommandsLastStepWithID(t *testing.T) {
	src := "on: issues\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - id: last\n        env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n"
	if got := unsecureFindings(t, src); len(got) != 0 {
		t.Errorf("got %q, want none", got)
	}
	// the flag an expression: flag-expression is not reported either
	src = strings.Replace(src, "ACTIONS_ALLOW_UNSECURE_COMMANDS: true", "ACTIONS_ALLOW_UNSECURE_COMMANDS: ${{ vars.FLAG }}", 1)
	if got := unsecureFindings(t, src); len(got) != 0 {
		t.Errorf("flag expression: got %q, want none", got)
	}
}

// TestUnsecureCommandsWikiPageName: GitHub turns each blank of the title of
// a wiki page into a - in the name of the page (page_name), so the title
// ::add path::DIR makes the name ::add-path::DIR, which the runner reads as
// add-path where the flag is true; on gollum alone the finding is
// unsecure-commands.wiki. A key of a page that the schema does not describe
// is the same. On gollum and issues, the value of all of the event is
// unsecure-commands.controlled.
func TestUnsecureCommandsWikiPageName(t *testing.T) {
	src := func(on, ref string) string {
		return "on: " + on + "\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - env:\n          V: ${{ " + ref + " }}\n        run: echo \"$V\"\n      - run: echo next\n"
	}
	for _, c := range []struct {
		on, ref string
		want    lint.FindingKindID
		cond    bool
	}{
		{"gollum", "github.event.pages[0].page_name", (UnsecureCommandsWiki{}).KindID(), true},
		{"gollum", "github.event.pages[0][github.event.pages[0].action]", (UnsecureCommandsWiki{}).KindID(), true},
		{"[gollum, issues]", "toJSON(github.event)", (UnsecureCommandsControlled{}).KindID(), false},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{UnsecureCommands}, wfFile(src(c.on, c.ref)), nil)
		if len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 || len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 {
			t.Fatalf("%s %s: findings %+v, inconclusive %+v", c.on, c.ref, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
		}
		if f := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0]; f.Args.KindID() != c.want || (f.Condition != nil) != c.cond {
			t.Errorf("%s %s: %+v", c.on, c.ref, f)
		}
	}
	rep, _, _ := checkRules(t, []lint.Rule{UnsecureCommands}, wfFile(src("gollum", "github.event.pages[0].title")), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 0 || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
		t.Errorf("title: findings %+v, inconclusive %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// TestUnsecureCommandsWikiThreat: the editor of
// a wiki writes add-path but no set-env in the name of a wiki page, so
// unsecure-commands.wiki needs an executable of the attacker, as
// envpath-injection.wiki does, and the actor of the editor does not gain
// set-env.
func TestUnsecureCommandsWikiThreat(t *testing.T) {
	for _, k := range unsecureCommandsMeta.FindingKinds {
		if k.FindingText.ID == kindUnsecureCommandsWiki && k.CVSS.AT.Value != lint.AttackRequirementsPresent {
			t.Errorf("unsecure-commands.wiki: AT %v, want present", k.CVSS.AT.Value)
		}
	}
	for _, a := range unsecureCommandsMeta.Threat.Actors {
		if a.Attacker == lint.AttackerWikiEditor && slices.Contains(a.Gains, lint.GainSetEnv) {
			t.Errorf("the editor of a wiki gains set-env: %v", a.Gains)
		}
	}
}

// TestUnsecureCommandsGollumMixed: a value whose
// add-path is of gollum alone and whose commands are not known on another
// event gives the finding of gollum and an inconclusive place for the
// other event, which holds when the wiki is closed. Another value of gollum
// alone (github.event.sender.email, which the table reads as text an
// attacker writes) is unsecure-commands.wiki too.
func TestUnsecureCommandsGollumMixed(t *testing.T) {
	src := func(on, v string) string {
		return "on: " + on + "\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      ACTIONS_ALLOW_UNSECURE_COMMANDS: true\n    steps:\n      - env:\n          B: " + v + "\n        run: echo \"$B\"\n      - run: echo next\n"
	}
	rep, _, _ := checkRules(t, []lint.Rule{UnsecureCommands}, wfFile(src("[gollum, fork]", "${{ github.event.pages[0].page_name }}${{ github.event.forkee.description }}")), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID() != (UnsecureCommandsWiki{}).KindID() || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 || rep.FindingsWith(lint.CertaintyInconclusive)[0].InconclusiveKind != structuredValueKind {
		t.Errorf("mixed: findings %+v, inconclusive %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
	rep, _, _ = checkRules(t, []lint.Rule{UnsecureCommands}, wfFile(src("gollum", "${{ github.event.sender.email }}")), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID() != (UnsecureCommandsWiki{}).KindID() {
		t.Errorf("sender.email: findings %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
}

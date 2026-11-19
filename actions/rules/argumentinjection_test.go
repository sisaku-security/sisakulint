package rules

import (
	"context"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// argumentResults are the findings of argument-injection on files, as
// "option <command> <options>", and its inconclusive kinds.
func argumentResults(t *testing.T, files map[string]string) []string {
	t.Helper()
	rep, _, _ := checkRules(t, []lint.Rule{ArgumentInjection}, files, exposureFacts{})
	if len(rep.Errors) != 0 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	var out []string
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		a := f.Args.(ArgumentInjectionOption)
		out = append(out, "option "+a.Command+" "+strings.Join(a.Options, ",")+" "+a.ExprRef)
	}
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		out = append(out, g.InconclusiveKind.String())
	}
	return out
}

// TestArgumentInjection: the forms of argument-injection, by the attack
// spellings tried on GitHub-hosted runners.
func TestArgumentInjection(t *testing.T) {
	wf := func(on, run string) map[string]string {
		return wfFile("on: " + on + "\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ github.event.pull_request.title }}\n      H: ${{ github.head_ref }}\n      L: ${{ github.event.pull_request.head.label }}\n      N: ${{ github.event.pull_request.head.repo.name }}\n      F: ${{ github.event.pull_request.head.repo.full_name }}\n      D: ${{ github.event.pull_request.head.repo.default_branch }}\n      W: ${{ github.event.pages[0].title }}\n      S: ${{ steps.x.outputs.y }}\n    steps:\n      - id: x\n        run: echo\n      - run: " + run + "\n")
	}
	const prt = "pull_request_target"
	title, head := "github.event.pull_request.title", "github.head_ref"
	for _, c := range []struct {
		name, on, run string
		want          []string
	}{
		// a ${{ }} the runner writes in before the shell reads the script: the
		// attacker writes quotes and ${IFS} too, so every spelling
		{"a branch's name in ${{ }}, tar", prt, `tar -xf a.tar f "${{ github.head_ref }}"`, []string{"option tar --to-command=,--use-compress-program=,-I " + head}},
		{"a branch's name through env, tar", prt, `tar -xf a.tar f "$H"`, []string{"option tar --to-command= " + head}},
		{"a title through env, tar", prt, `tar -xf a.tar f "$T"`, []string{"option tar --to-command=,--use-compress-program=,-I " + title}},
		{"outside quotes, tar", prt, `tar -xf a.tar f $T`, []string{"option tar --to-command= " + title}},
		{"make, a branch's name through env", prt, `make all "$H"`, []string{"unverified-option"}},
		{"make, a title in ${{ }} outside quotes", prt, `make all ${{ github.event.pull_request.title }}`, []string{"option make --eval= " + title}},
		{"make, a title", prt, `make all "$T"`, []string{"option make --eval= " + title}},
		{"sed -i", prt, `sed -i "$T" s.txt`, []string{"option sed --expression=,-e " + title}},
		// the repository git names
		{"git fetch, a local path", prt, `git fetch /tmp/r "$H"`, []string{"option git fetch --upload-pack= " + head}},
		{"git fetch, HTTPS", prt, `git fetch https://github.com/a/b "$H"`, nil},
		{"git fetch, SSH", prt, `git fetch git@github.com:a/b "$H"`, []string{"remote-program"}},
		{"git fetch, the remote of the settings", prt, `git fetch "$H"`, []string{"remote-program"}},
		{"git ls-remote, the value before a local path", prt, `git ls-remote "$H" /tmp/r`, []string{"option git ls-remote --upload-pack= " + head}},
		{"git fetch, a title outside quotes", prt, `git fetch $T`, []string{"option git fetch --upload-pack= " + title}},
		{"git fetch, HTTPS and a title outside quotes", prt, `git fetch https://github.com/a/b $T`, nil},
		{"sed, a repository's name inside a word", prt, `sed -n p notes.txt x${{ github.event.pull_request.head.repo.name }}`, nil},
		// a repository's name spells only a short option joined to its
		// value
		{"sed, a repository's name", prt, `sed -n p s.txt "$N"`, []string{"option sed -e github.event.pull_request.head.repo.name"}},
		{"tar, a repository's name", prt, `tar -xf a.tar f "$N"`, []string{"unverified-option"}},
		{"make, a repository's name", prt, `make all "$N"`, nil},
		// a value known not to begin with -, after an undeclared option
		{"a wiki page's title after an undeclared option", "gollum", `tar -xf a.tar --wildcards "$W"`, nil},
		{"git ls-remote after its operand", prt, `git ls-remote /tmp/r "$H"`, nil},
		{"git checkout", prt, `git checkout "$H"`, nil},
		{"echo", prt, `echo "$T"`, nil},
		{"after --", prt, `tar -xf a.tar -- "$T"`, nil},
		{"after -- and an undeclared option", prt, `tar -xf a.tar --frobnicate -- "$T"`, []string{"undeclared-option"}},
		{"an undeclared option", prt, `tar --frobnicate "$T"`, []string{"undeclared-option"}},
		{"bash, quoted", prt, `bash "$T" x.sh`, nil},
		{"bash, outside quotes", prt, `bash $T`, []string{"option bash -c " + title}},
		{"bash, a branch's name", prt, `bash "$H" x.sh`, nil},
		{"bash, after the code of -c", prt, `bash -c 'echo' $T`, nil},
		{"zsh, outside quotes", prt, `zsh $T`, []string{"unverified-option"}},
		{"python, quoted", prt, `python3 "$T" x.py`, []string{"option python3 -c " + title}},
		{"python, after its script", prt, `python3 x.py "$T"`, nil},
		{"node, quoted", prt, `node "$T" x.js`, []string{"option node --eval= " + title}},
		{"a value not known to begin with -", prt, `tar -xf a.tar f "$D"`, []string{"value-head"}},
		// a label and a full name begin with a login, which does not begin
		// with - (dash-login); a label the runner writes into the script is
		// written-label
		{"a label", prt, `tar -xf a.tar f "$L"`, nil},
		{"a full name", prt, `tar -xf a.tar f "$F"`, nil},
		{"a full name outside quotes", prt, `tar -xf a.tar f $F`, nil},
		{"a label in ${{ }}", prt, `tar -xf a.tar f ${{ github.event.pull_request.head.label }}`, nil},
		{"a label in ${{ }} inside quotes", prt, `tar -xf a.tar f "${{ github.event.pull_request.head.label }}"`, nil},
		{"a label before a branch's name", prt, `tar -xf a.tar f "$L$H"`, nil},
		{"a label and a branch's name in ${{ }}", prt, `tar -xf a.tar f "${{ github.event.pull_request.head.label }}${{ github.head_ref }}"`, []string{"option tar --to-command=,--use-compress-program=,-I " + head}},
		{"a label outside quotes after IFS=: (changed-ifs)", prt, "|\n          IFS=:\n          tar -xf a.tar f $L", nil},
		{"an output of a step", prt, `tar -xf a.tar f "${{ steps.x.outputs.y }}"`, []string{"step-output-run"}},
		{"twice in a script", prt, "|\n          tar -xf a.tar f \"$T\"\n          tar -xf a.tar f \"$T\"", []string{"option tar --to-command=,--use-compress-program=,-I " + title, "option tar --to-command=,--use-compress-program=,-I " + title}},
		{"an option's value, outside quotes", prt, `tar -xf $T`, []string{"option tar --to-command= " + title}},
		{"an option's value, quoted", prt, `tar -xf "$T"`, nil},
		{"test", prt, `test -n "$T"`, nil},
		{"python -u then a script", prt, `python3 -u scripts/check.py "$T"`, []string{"undeclared-option"}},
		{"bash -c outside quotes", prt, `bash -c $T`, nil},
		{"bash and a value not analyzed, in ${{ }}", prt, `bash "${{ steps.x.outputs.y }}" x.sh`, []string{"step-output-run"}},
		{"bash and a value not analyzed, through env", prt, `bash "$S" x.sh`, nil},
		{"a value not analyzed through env", prt, "tar -xf a.tar f \"$S\"", []string{"step-output-run"}},
		{"pull_request", "pull_request", `tar -xf a.tar f "$T"`, nil},
	} {
		got := argumentResults(t, wf(c.on, c.run))
		slices.Sort(got)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", c.name, got, want)
		}
	}
}

// TestArgumentInjectionAfterCodeInjectionFix:
// code-injection's fix moves the ${{ }} into the step's env, and the word
// tar gets still starts with the value, so the finding of argument-injection
// stays with the same fingerprint, which ApplyFixes takes (it fails on a new
// finding).
func TestArgumentInjectionAfterCodeInjectionFix(t *testing.T) {
	files := wfFile("on: pull_request_target\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: tar -xf archive.tar notes.txt \"${{ github.head_ref }}\"\n")
	rules := []lint.Rule{CodeInjection, ArgumentInjection}
	rep, in, reg := checkRules(t, rules, files, exposureFacts{})
	var before []lint.Fingerprint
	for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule == ArgumentInjectionID {
			before = append(before, f.Fingerprint)
		}
	}
	if len(before) != 1 {
		t.Fatalf("before the fix: %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional))
	}
	applied, err := lint.ApplyFixes(context.Background(), in, reg, exposureFacts{}, rep, lint.SafetyReview)
	if err != nil {
		t.Fatalf("the fix of code-injection: %v", err)
	}
	out := map[string]string{}
	for p, b := range applied.Files {
		out[p.String()] = string(b)
	}
	if !strings.Contains(out[".github/workflows/w.yml"], `"${GITHUB_HEAD_REF}"`) && !strings.Contains(out[".github/workflows/w.yml"], "env:") {
		t.Fatalf("code-injection did not move the value: %s", out[".github/workflows/w.yml"])
	}
	after, _, _ := checkRules(t, rules, out, exposureFacts{})
	var got []lint.Fingerprint
	for _, f := range after.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
		if f.Rule == ArgumentInjectionID {
			got = append(got, f.Fingerprint)
		}
	}
	if !slices.Equal(got, before) {
		t.Errorf("after the fix: %v, before: %v\n%s", got, before, out[".github/workflows/w.yml"])
	}
}

// TestArgumentInjectionExperiments: the workflows of the experiments on
// GitHub-hosted runners, their literal values made the pull request's title
// and their events pull_request_target, give by step what the experiments
// saw. A step whose command is a variable of a matrix ("$S") gives
// nothing: the command is not known.
func TestArgumentInjectionExperiments(t *testing.T) {
	exp := "testdata/observed/"
	value := regexp.MustCompile(`(?m)^(\s+)([A-Z]): [^$\n].*$`)
	for _, c := range []struct {
		file string
		want map[string][]string // step name: the kinds of its results
	}{
		{"argument-injection/2/.github/workflows/argument-injection.yml", map[string][]string{
			// the value in one word is an option, and /tmp/r the repository
			// (the program was seen to run)
			"git reads the quoted value as an option": {"argument-injection.option"},
		}},
		{"argument-injection/1/.github/workflows/argument-options.yml", map[string][]string{
			"tar --use-compress-program in one quoted word":         {"argument-injection.option"},
			"tar --to-command in one quoted word":                   {"argument-injection.option"},
			"sed --expression in one quoted word, after the script": {"argument-injection.option"},
			"make --eval in one quoted word":                        {"argument-injection.option"},
		}},
		{"argument-injection/3/.github/workflows/argument-operands.yml", map[string][]string{
			"tar reads an option after its operand":                {"argument-injection.option"},
			"tar with old options takes the word as the archive":   {"argument-injection.option"}, // FalsePositiveForm tar-old-options
			"make reads an option after its operand":               {"argument-injection.option"},
			"sed -i takes no separate value":                       {"argument-injection.option"},
			"sed under POSIXLY_CORRECT":                            {"argument-injection.option"}, // FalsePositiveForm posixly-correct
			"tar and make under POSIXLY_CORRECT":                   {"argument-injection.option", "argument-injection.option"},
			"git subcommands, the option after a local repository": {"argument-injection.option", "argument-injection.option", "argument-injection.option", "argument-injection.option"},
		}},
		{"argument-injection/6/.github/workflows/shell-options.yml", map[string][]string{
			"python -c":           {"argument-injection.option", "argument-injection.option"},
			"node -e and --eval=": {"argument-injection.option", "argument-injection.option", "argument-injection.option"},
			"perl -e":             {"argument-injection.option", "argument-injection.option"},
			"ruby -e":             {"argument-injection.option"},
		}},
		{"argument-injection/5/.github/workflows/shell-options-2.yml", map[string][]string{
			"git upload-pack without blanks, after the operand": {"argument-injection.option", "argument-injection.option", "argument-injection.option"},
		}},
	} {
		b, err := os.ReadFile(exp + c.file)
		if err != nil {
			t.Fatal(err)
		}
		src := value.ReplaceAllString(string(b), "${1}${2}: ${{ github.event.pull_request.title }}")
		src = strings.Replace(src, "on:\n  push:\n  pull_request:\n", "on:\n  pull_request_target:\n", 1)
		src = strings.Replace(src, "on:\n  push:\n", "on:\n  pull_request_target:\n", 1)
		src = strings.ReplaceAll(src, "github.event_name == 'pull_request'", "github.event_name == 'pull_request_target'")
		rep, _, _ := checkRules(t, []lint.Rule{ArgumentInjection}, wfFile(src), exposureFacts{})
		got := map[string][]string{}
		step := func(at int) string {
			i := strings.LastIndex(src[:at], "- name: ")
			if i < 0 {
				return ""
			}
			return strings.TrimSpace(strings.SplitN(src[i+len("- name: "):], "\n", 2)[0])
		}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			got[step(f.Location.Span.Start)] = append(got[step(f.Location.Span.Start)], f.Args.KindID().String())
		}
		for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
			got[step(g.Location.Span.Start)] = append(got[step(g.Location.Span.Start)], g.InconclusiveKind.String())
		}
		for name, kinds := range got {
			if !slices.Equal(kinds, c.want[name]) {
				t.Errorf("%s: %s: got %v, want %v", c.file, name, kinds, c.want[name])
			}
		}
		for name, kinds := range c.want {
			if _, ok := got[name]; !ok {
				t.Errorf("%s: %s: got nothing, want %v", c.file, name, kinds)
			}
		}
	}
}

// TestArgumentInjectionWikiPageName: GitHub turns a + at the head of the
// title of a wiki page into a - at the head of the name of the page
// (page_name), so the editor of the wiki makes the name begin with -; on
// gollum alone the finding is argument-injection.wiki, which holds if
// anyone may edit the wiki. A word that the name begins is the same, and
// the title still holds no -.
func TestArgumentInjectionWikiPageName(t *testing.T) {
	src := func(word string) string {
		return "on: gollum\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: tar -xf a.tar \"" + word + "\"\n"
	}
	for _, c := range []struct {
		word string
		want int
	}{
		{"${{ github.event.pages[0].page_name }}", 1},
		{"${{ github.event.pages[0].page_name }}-${{ github.event.pages[0].title }}", 1},
		{"${{ github.event.pages[0].title }}", 0},
		{"${{ github.event.pages[0][github.event.pages[0].action] }}", 1},
	} {
		rep, _, _ := checkRules(t, []lint.Rule{ArgumentInjection}, wfFile(src(c.word)), nil)
		if len(rep.FindingsWith(lint.CertaintyInconclusive)) != 0 {
			t.Errorf("%s: inconclusive %+v", c.word, rep.FindingsWith(lint.CertaintyInconclusive))
		}
		if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != c.want {
			t.Fatalf("%s: findings %+v, want %d", c.word, rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), c.want)
		}
		for _, f := range rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional) {
			if f.Args.KindID() != (ArgumentInjectionWiki{}).KindID() || f.Condition == nil {
				t.Errorf("%s: %+v, want argument-injection.wiki with a condition", c.word, f)
			}
		}
	}
}

// TestArgumentInjectionGollumMixed: a word whose
// - at the head is of gollum alone and whose head is not known on another
// event gives argument-injection.wiki and an inconclusive place
// (value-head) for the other event.
func TestArgumentInjectionGollumMixed(t *testing.T) {
	src := "on: [gollum, pull_request_target]\npermissions: {}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          B: ${{ github.event.pages[0].page_name }}${{ github.event.pull_request.head.repo.html_url }}\n        run: tar -xf a.tar \"$B\"\n"
	rep, _, _ := checkRules(t, []lint.Rule{ArgumentInjection}, wfFile(src), nil)
	if len(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)) != 1 || rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)[0].Args.KindID() != (ArgumentInjectionWiki{}).KindID() || len(rep.FindingsWith(lint.CertaintyInconclusive)) != 1 || rep.FindingsWith(lint.CertaintyInconclusive)[0].InconclusiveKind != valueHeadKind {
		t.Errorf("findings %+v, inconclusive %+v", rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), rep.FindingsWith(lint.CertaintyInconclusive))
	}
}

// bash expands the name of a coproc in the shell that starts the coproc,
// and runs the commands of its substitutions.
func TestArgumentInjectionCoprocName(t *testing.T) {
	got := argumentResults(t, wfFile("on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          T: ${{ github.event.pull_request.title }}\n        run: coproc \"$(tar -xf archive.tar notes.txt \"$T\")\" { :; }\n"))
	if len(got) != 1 || !strings.HasPrefix(got[0], "option tar") {
		t.Fatalf("results %q, want the option of tar", got)
	}
}

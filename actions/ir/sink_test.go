package ir

import (
	"slices"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/taint"
)

const sinkWorkflow = `on: issues
jobs:
  build:
    steps:
      - run: |
          echo "${{ github.event.issue.title }}"
          echo "t=${{ github.event.issue.body }}" >> "$GITHUB_ENV"
      - uses: actions/github-script@v7
        with:
          script: console.log("${{ github.event.issue.title }}")
`

// TestSinksAreTheProjection: each summary has what taint.Analyze gives of
// its sink.
func TestSinksAreTheProjection(t *testing.T) {
	tree, w := parse(t, sinkWorkflow)
	want := taint.Analyze(w, nil).Sinks
	got := New(".github/workflows/w.yml", tree, w, nil).allSinks()
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("got %d, want %d", len(got), len(want))
	}
	for i, s := range want {
		g := got[i]
		if g.kind != s.Kind || len(g.refs) != len(s.Refs) || len(g.environmentFileWrites) != len(s.EnvironmentFileWrites) || len(g.inconclusiveWrites) != len(s.InconclusiveWrites) {
			t.Fatalf("%d: %+v", i, g)
		}
		for j, r := range s.Refs {
			if g.refs[j].Verdict != r.Verdict || g.refs[j].InconclusiveKind != r.InconclusiveKind || g.refs[j].Text != s.Value.Text()[r.Span.Start:r.Span.End] || len(g.refs[j].ControlledOn) != len(r.ControlledOn) {
				t.Errorf("%d: ref %d: %+v", i, j, g.refs[j])
			}
		}
	}
}

// TestOneAnalysis: the Sinks, the StepFixes and the CheckoutSites of an
// input come of one taint.Analyze and one reading of each script.
func TestOneAnalysis(t *testing.T) {
	tree, w := parse(t, sinkWorkflow)
	x := New(".github/workflows/w.yml", tree, w, nil)
	x.allSinks()
	x.allStepFixes()
	x.allCheckoutSites()
	x.allSinks()
	if x.analyzed != 1 {
		t.Errorf("taint.Analyze ran %d times", x.analyzed)
	}
}

// TestSinkOfCompositeAction: a composite action.yml has summaries too.
func TestSinkOfCompositeAction(t *testing.T) {
	tree, a := parseAction(t, "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo \"${{ github.event.issue.title }}\"\n")
	if got := New("action.yml", tree, nil, a).allSinks(); len(got) != 1 || len(got[0].refs) != 1 {
		t.Fatalf("got %d", len(got))
	}
}

// TestSinkArguments: the words of a run's commands with an attacker's value
// in them, a ${{ }} and a variable of env, with the options of the command
// that run a program.
func TestSinkArguments(t *testing.T) {
	tree, w := parse(t, `on: pull_request_target
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          H: ${{ github.head_ref }}
        run: |
          tar -xf a.tar f "${{ github.head_ref }}"
          tar -xf a.tar f "$H"
`)
	sinks := New(".github/workflows/w.yml", tree, w, nil).allSinks()
	if len(sinks) != 1 || len(sinks[0].arguments) != 2 {
		t.Fatalf("%+v", sinks)
	}
	text := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0].Run.Value.Text()
	// a ${{ }} the runner writes in before the shell reads the script takes
	// every spelling; the variable, a branch's name, the one word without blanks
	spelled := [][]string{{"--to-command=", "--use-compress-program=", "-I"}, {"--to-command="}}
	for i, want := range []string{"${{ github.head_ref }}", "$H"} {
		a := sinks[0].arguments[i]
		if a.Command != "tar" || !a.Known || a.Word != 4 || a.Path != "github.head_ref" || !a.Head || !a.Quoted || len(a.LeadingDash) == 0 || a.Ref.Text != want {
			t.Errorf("%d: %+v", i, a)
		}
		if !a.OptionPlace || !a.Runs || !slices.Equal(a.Spelled, spelled[i]) || a.Remote || !a.Unverified {
			t.Errorf("%d: options %+v", i, a)
		}
		if s := a.At.span; text[s.Start:s.End] != want {
			t.Errorf("%d: at %q", i, text[s.Start:s.End])
		}
	}
}

// TestSinkArgumentSpellings: a repository's name spells only a short
// option with its value joined (sed -e, tar -I), whatever follows it in
// env; a branch's name keeps every spelling without blanks; git's
// --upload-pack runs on the runner for a repository on a local path, runs
// nowhere for HTTPS, and is decided elsewhere for SSH and the rest.
func TestSinkArgumentSpellings(t *testing.T) {
	for _, c := range []struct {
		name, env, run       string
		spelled              []string
		remote, ssh, unverif bool
	}{
		{"sed, a repository's name", "${{ github.event.pull_request.head.repo.name }}", `sed -n p s.txt "$X"`, []string{"-e"}, false, false, false},
		{"sed, a repository's name and text after it", "${{ github.event.pull_request.head.repo.name }}=x", `sed -n p s.txt "$X"`, []string{"-e"}, false, false, false},
		{"sed, a repository's name in ${{ }}", "", `sed -n p s.txt "${{ github.event.pull_request.head.repo.name }}"`, []string{"-e"}, false, false, false},
		{"tar, a repository's name", "${{ github.event.pull_request.head.repo.name }}", `tar -xf a.tar f "$X"`, nil, false, false, true},
		{"make, a repository's name", "${{ github.event.pull_request.head.repo.name }}", `make all "$X"`, nil, false, false, false},
		// seen to run only with ( and ', not with a name
		{"python, a repository's name", "${{ github.event.pull_request.head.repo.name }}", `python3 "$X" x.py`, nil, false, false, true},
		// -u of git clone was seen to run with blanks only
		{"git clone, a repository's name", "${{ github.event.pull_request.head.repo.name }}", `git clone /tmp/r d "$X"`, nil, false, false, true},
		// a label after the name may hold = and blanks
		{"tar, a repository's name and a label", "${{ github.event.pull_request.head.repo.name }}=${{ github.event.pull_request.head.label }}", `tar -xf a.tar f "$X"`, []string{"--to-command="}, false, false, true},
		{"sed, a branch's name", "${{ github.head_ref }}", `sed -n p s.txt "$X"`, []string{"--expression=", "-e"}, false, false, false},
		{"git, a local path", "${{ github.head_ref }}", `git fetch /tmp/r "$X"`, []string{"--upload-pack="}, false, false, false},
		{"git, HTTPS", "${{ github.head_ref }}", `git fetch https://github.com/a/b "$X"`, nil, false, false, false},
		{"git, SSH", "${{ github.head_ref }}", `git fetch git@github.com:a/b "$X"`, nil, true, true, false},
		{"git, no repository", "${{ github.head_ref }}", `git fetch "$X"`, nil, true, false, false},
		{"git, HTTPS, a title outside quotes", "${{ github.event.pull_request.title }}", `git fetch https://github.com/a/b $X`, nil, false, false, false},
		{"git, the value before a local path", "${{ github.head_ref }}", `git ls-remote "$X" /tmp/r`, []string{"--upload-pack="}, false, false, false},
	} {
		env := ""
		if c.env != "" {
			env = "      - env:\n          X: " + c.env + "\n        run: " + c.run + "\n"
		} else {
			env = "      - run: " + c.run + "\n"
		}
		tree, w := parse(t, "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n"+env)
		sinks := New(".github/workflows/w.yml", tree, w, nil).allSinks()
		if len(sinks) != 1 || len(sinks[0].arguments) != 1 {
			t.Fatalf("%s: %+v", c.name, sinks)
		}
		a := sinks[0].arguments[0]
		if !slices.Equal(a.Spelled, c.spelled) || a.Remote != c.remote || a.RemoteSSH != c.ssh || a.Unverified != c.unverif {
			t.Errorf("%s: spelled %v remote %v ssh %v unverified %v", c.name, a.Spelled, a.Remote, a.RemoteSSH, a.Unverified)
		}
	}
}

// TestSinkVariableCodes: a variable of env that a run of bash reads as
// code, where it is, and where env gives its value.
func TestSinkVariableCodes(t *testing.T) {
	src := `on: issues
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - env:
          ISSUE_TITLE: ${{ github.event.issue.title }}
        run: eval "echo $ISSUE_TITLE"
`
	tree, w := parse(t, src)
	sinks := New(".github/workflows/w.yml", tree, w, nil).allSinks()
	if len(sinks) != 1 || len(sinks[0].variableCodes) != 1 {
		t.Fatalf("%+v", sinks)
	}
	v := sinks[0].variableCodes[0]
	text := w.Jobs.Value.Entries[0].Value.Value.Steps.Value.Items[0].Run.Value.Text()
	if v.Text != "$ISSUE_TITLE" || v.Path != "github.event.issue.title" || v.Reading != analysis.CodeReadingCodeArgument || v.Ref.Verdict != analysis.Controlled {
		t.Errorf("%+v", v)
	}
	if s := v.At.span; text[s.Start:s.End] != "$ISSUE_TITLE" {
		t.Errorf("at %q", text[s.Start:s.End])
	}
	if len(v.Ref.Env) != 1 || src[v.Ref.Env[0].src.Start:v.Ref.Env[0].src.End] != "${{ github.event.issue.title }}" {
		t.Errorf("env %+v", v.Ref.Env)
	}
}

// TestSinkArgumentSameWord: a repository's name followed in the same word
// by a branch's name ("$X$Y") is not a repository's name alone.
func TestSinkArgumentSameWord(t *testing.T) {
	tree, w := parse(t, "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          X: ${{ github.event.pull_request.head.repo.name }}\n          Y: ${{ github.head_ref }}\n        run: tar -xf a.tar f \"$X$Y\"\n")
	sinks := New(".github/workflows/w.yml", tree, w, nil).allSinks()
	if len(sinks) != 1 || len(sinks[0].arguments) != 2 {
		t.Fatalf("%+v", sinks)
	}
	if a := sinks[0].arguments[0]; a.RepoName || !slices.Equal(a.Spelled, []string{"--to-command="}) {
		t.Errorf("$X: repo name %v, spelled %v", a.RepoName, a.Spelled)
	}
}

// TestSinkArgumentRepoNameInWord: a repository's name in a ${{ }} that is
// not at the head of the word does not split the word, so the command does
// not read the value as an option.
func TestSinkArgumentRepoNameInWord(t *testing.T) {
	tree, w := parse(t, "on: pull_request_target\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: sed -n p notes.txt x${{ github.event.pull_request.head.repo.name }}\n")
	sinks := New(".github/workflows/w.yml", tree, w, nil).allSinks()
	if len(sinks) != 1 || len(sinks[0].arguments) != 1 {
		t.Fatalf("%+v", sinks)
	}
	if a := sinks[0].arguments[0]; a.OptionPlace || !a.RepoName {
		t.Errorf("option place %v, repo name %v", a.OptionPlace, a.RepoName)
	}
}

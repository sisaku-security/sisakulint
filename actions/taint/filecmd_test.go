package taint

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// writtenOf analyzes a workflow of one step on issues with env and run, and
// writes each EnvironmentFileWrite of its run as "<file> <side> <text>[ H]" (H when it
// has a DelimWrite) and each InconclusiveWrite as "gap <file> <kind> <text>".
func writtenOf(t *testing.T, env, run string) string {
	t.Helper()
	return writtenOn(t, "issues", env, run)
}

// writtenOn is writtenOf on the event on.
func writtenOn(t *testing.T, on, env, run string) string {
	t.Helper()
	src := "on: " + on + "\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n" + env + "        run: " + run + "\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	if w == nil {
		t.Fatalf("no workflow: %s", src)
	}
	var out []string
	for _, s := range Analyze(w, nil).Sinks {
		text := s.Value.Text()
		for _, x := range s.EnvironmentFileWrites {
			h := ""
			if x.Heredoc != nil {
				h = " H"
			}
			out = append(out, fmt.Sprintf("%s %s %s%s", x.File, x.Side, text[x.Span.Start:x.Span.End], h))
		}
		for _, g := range s.InconclusiveWrites {
			out = append(out, fmt.Sprintf("gap %s %s %s", g.File, g.Kind, text[g.Span.Start:g.Span.End]))
		}
	}
	return strings.Join(out, "; ")
}

const titleEnv = "          T: ${{ github.event.issue.title }}\n          H: ${{ github.head_ref }}\n          N: ${{ github.event.issue.number }}\n"

func TestWritten(t *testing.T) {
	for _, c := range []struct{ run, want string }{
		{`echo "t=$T" >> "$GITHUB_OUTPUT"`, `GITHUB_OUTPUT SideValue $T`},
		{`echo "t=${T}" >> $GITHUB_ENV`, `GITHUB_ENV SideValue ${T}`},
		{`echo "t=${{ github.event.issue.title }}" >> "$GITHUB_OUTPUT"`, `GITHUB_OUTPUT SideValue github.event.issue.title`},
		{`echo "$T=1" >> "$GITHUB_ENV"`, `GITHUB_ENV SideKey $T`},
		{`echo "$T" >> "$GITHUB_ENV"`, `GITHUB_ENV SideKey $T`},
		// a context that cannot hold a line break, and one no attacker writes
		{`echo "h=$H n=$N" >> "$GITHUB_OUTPUT"`, ``},
		{`echo "t=$(echo "$T" | tr -d '\n')" >> "$GITHUB_OUTPUT"`, ``},
		{`echo "t=$(echo "$T" | head -1)" >> "$GITHUB_OUTPUT"`, `gap GITHUB_OUTPUT subst-value $(echo "$T" | head -1)`},
		{`jq -r . <<< "$T" >> "$GITHUB_OUTPUT"`, `gap GITHUB_OUTPUT writer-unknown jq -r . <<< "$T" >> "$GITHUB_OUTPUT"`},
		{`echo "t=$T" >> "$GITHUB_STEP_SUMMARY"`, ``},
		{`echo "t=$SCRIPT_VAR" >> "$GITHUB_OUTPUT"`, ``},
		// a subshell's own assignment, and a function defined outside that a
		// subshell calls after its assignment
		{`( out="$GITHUB_ENV"; echo "t=$T" >> "$out" )`, `GITHUB_ENV SideValue $T`},
		{`f() { echo "t=$T" >> "$out"; }; ( out="$GITHUB_ENV"; f )`, `GITHUB_ENV SideValue $T`},
		// bash expands the name of a coproc in the shell that starts it
		{`coproc "$(echo "t=$T" >> "$GITHUB_ENV")" { :; }`, `GITHUB_ENV SideValue $T`},
		{`"exec >> \"$GITHUB_OUTPUT\"; echo \"t=$T\""`, `gap GITHUB_OUTPUT exec-redirect exec >> "$GITHUB_OUTPUT"`},
		// the tree stops at the word with the case (shell's TestParseStop): what follows is not read
		{`"echo \"$(case x in a) b;; esac)\"; echo \"t=$T\" >> $GITHUB_ENV"`, `gap GITHUB_ENV after-stop "$(case x in a) b;; esac)"; echo "t=$T" >> $GITHUB_ENV`},
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.run, got, c.want)
		}
	}
}

// $GITHUB_PATH: the runner reads each line whole as a directory
// (FileCommandManager.cs of actions/runner v2.337.0, 134 to 157), so a
// value an attacker controls anywhere on it counts, line breaks or not.
func TestWrittenPath(t *testing.T) {
	for _, c := range []struct{ run, want string }{
		{`echo "$T" >> "$GITHUB_PATH"`, `GITHUB_PATH SideLine $T`},
		{`echo "$HOME/tools/$T" >> $GITHUB_PATH`, `GITHUB_PATH SideLine $T`},
		// neither = nor << splits the line
		{`echo "a=$T" >> "$GITHUB_PATH"`, `GITHUB_PATH SideLine $T`},
		{`echo "a<<$T" >> "$GITHUB_PATH"`, `GITHUB_PATH SideLine $T`},
		// a number is no one's to choose (a branch name: TestWrittenPathBranch)
		{`echo "$N" >> "$GITHUB_PATH"`, ``},
		{`echo "${{ github.event.issue.title }}" | tee -a "$GITHUB_PATH"`, `GITHUB_PATH SideLine github.event.issue.title`},
		{`'{ echo "$T"; echo "a/$T"; } >> "$GITHUB_PATH"'`, `GITHUB_PATH SideLine $T; GITHUB_PATH SideLine $T`},
		// an alias of the file, and a descriptor of it
		{`'p=$GITHUB_PATH; echo "$T" >> "$p"'`, `GITHUB_PATH SideLine $T`},
		{`'exec {fd}>> "$GITHUB_PATH"; echo "$T" >&$fd'`, `GITHUB_PATH SideLine $T`},
		// taking the line breaks out leaves the directory the attacker's
		{`echo "$(echo "$T" | tr -d '\n')" >> "$GITHUB_PATH"`, `gap GITHUB_PATH subst-value $(echo "$T" | tr -d '\n')`},
		{`echo "${T@Q}" >> "$GITHUB_PATH"`, `GITHUB_PATH SideLine ${T@Q}`},
		{`jq -r . <<< "$T" >> "$GITHUB_PATH"`, `gap GITHUB_PATH writer-unknown jq -r . <<< "$T" >> "$GITHUB_PATH"`},
		{`"exec >> \"$GITHUB_PATH\"; echo \"$T\""`, `gap GITHUB_PATH exec-redirect exec >> "$GITHUB_PATH"`},
		{`echo "$SCRIPT_VAR" >> "$GITHUB_PATH"`, ``},
		// one value to two files
		{`echo "$T" | tee -a "$GITHUB_ENV" "$GITHUB_PATH"`, `GITHUB_ENV SideKey $T; GITHUB_PATH SideLine $T`},
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.run, got, c.want)
		}
	}
}

// A branch name, which cannot hold a line break, is enough on
// $GITHUB_PATH: at the head of a line it is a path relative to where the
// command runs. After the =
// of $GITHUB_ENV it is still not reported, nor what a $( ) makes of it.
func TestWrittenPathBranch(t *testing.T) {
	const env = "          H: ${{ github.head_ref }}\n"
	for _, c := range []struct{ run, want string }{
		{`echo "$H" >> "$GITHUB_PATH"`, `GITHUB_PATH SideLine $H`},
		{`echo "$(echo "$H" | tr -d '\n')" >> "$GITHUB_PATH"`, `gap GITHUB_PATH subst-value $(echo "$H" | tr -d '\n')`},
		{`jq -r . <<< "$H" >> "$GITHUB_PATH"`, `gap GITHUB_PATH writer-unknown jq -r . <<< "$H" >> "$GITHUB_PATH"`},
		{`"exec >> \"$GITHUB_PATH\"; echo \"$H\""`, `gap GITHUB_PATH exec-redirect exec >> "$GITHUB_PATH"`},
		{`echo "h=$H" >> "$GITHUB_ENV"`, ``},
		{`echo "h=$(echo "$H" | head -1)" >> "$GITHUB_ENV"`, ``},
		// what jq writes starts the line, before any =: a branch name there names a
		// variable (git allows = in it)
		{`jq -r . <<< "$H" >> "$GITHUB_ENV"`, `gap GITHUB_ENV writer-unknown jq -r . <<< "$H" >> "$GITHUB_ENV"`},
		{`echo "$H=1" >> "$GITHUB_ENV"`, `GITHUB_ENV SideKey $H`},
	} {
		if got := writtenOn(t, "pull_request_target", env, c.run); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.run, got, c.want)
		}
	}
}

func TestWrittenHeredoc(t *testing.T) {
	for _, c := range []struct{ run, want string }{
		// a literal delimiter an attacker can write: the body is theirs; a
		// form the fix rewrites with a random delimiter
		{`'{ echo "t<<EOF"; echo "$T"; echo "EOF"; } >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T H`},
		{"|\n          echo \"t<<EOF\" >> \"$GITHUB_OUTPUT\"\n          echo \"$T\" >> \"$GITHUB_OUTPUT\"\n          echo EOF >> \"$GITHUB_OUTPUT\"", `GITHUB_OUTPUT SideBody $T H`},
		// not of that form: printf, a delimiter in two parts, not an item of the list
		{`'{ printf "t<<EOF\n"; echo "$T"; echo EOF; } >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T`},
		{`'{ echo "t<<"EOF; echo "$T"; echo EOF; } >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T`},
		{`'true && { echo "t<<EOF"; echo "$T"; echo EOF; } >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T`},
		// the delimiter the fix writes
		{`'GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"; { echo "t<<${GHA_DELIM}"; echo "$T"; echo "${GHA_DELIM}"; } >> "$GITHUB_OUTPUT"'`, ``},
		// another random delimiter is not read as one
		{`'D=$(uuidgen); { echo "t<<$D"; echo "$T"; echo "$D"; } >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T`},
		// the fix's delimiter set again in between
		{`'GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"; GHA_DELIM=x; { echo "t<<${GHA_DELIM}"; echo "$T"; echo "${GHA_DELIM}"; } >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T`},
		// after the heredoc closes, a line is a pair again
		{`'{ echo "a<<EOF"; echo b; echo EOF; echo "t=$T"; } >> "$GITHUB_ENV"'`, `GITHUB_ENV SideValue $T`},
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.run, got, c.want)
		}
	}
}

// TestWrittenEnvCase: a variable of another case is another variable.
func TestWrittenEnvCase(t *testing.T) {
	if got := writtenOf(t, "          title: ${{ github.event.issue.title }}\n", `echo "t=$TITLE" >> "$GITHUB_OUTPUT"`); got != "" {
		t.Errorf("got %s", got)
	}
	if got := writtenOf(t, "          title: ${{ github.event.issue.title }}\n", `echo "t=$title" >> "$GITHUB_OUTPUT"`); got != "GITHUB_OUTPUT SideValue $title" {
		t.Errorf("got %s", got)
	}
}

func TestWrittenLines(t *testing.T) {
	src := "on: [issues, pull_request_target]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"${{ github.event.issue.title }} ${{ github.head_ref }}\"\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	refs := Analyze(w, nil).Sinks[0].Refs
	if len(refs[0].Lines) == 0 || len(refs[0].ControlledOn) == 0 {
		t.Errorf("a title: %+v", refs[0])
	}
	if len(refs[1].Lines) != 0 || len(refs[1].ControlledOn) == 0 {
		t.Errorf("a branch name: %+v", refs[1])
	}
}

func TestShell(t *testing.T) {
	for _, c := range []struct {
		step string
		want Shell
	}{
		{"      - run: x\n", ShellBash},
		{"      - run: x\n        shell: sh\n", ShellSh},
		{"      - run: x\n        shell: pwsh\n", ShellPwsh},
		{"      - run: x\n        shell: python\n", ShellUnknown},
	} {
		src := "on: issues\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + c.step
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		if got := Analyze(w, nil).Sinks[0].Shell; got != c.want {
			t.Errorf("%q: %v", c.step, got)
		}
	}
}

// TestHomepageLines: the homepage of the repository a discussion moves to holds a
// line break, though the schema says uri.
func TestHomepageLines(t *testing.T) {
	path := []expr.PathElem{{Name: "github"}, {Name: "event"}, {Name: "changes"}, {Name: "new_repository"}, {Name: "homepage"}}
	if got := Lookup(workflow.EventNameDiscussion, workflow.ActivityTypeTransferred, path); got != ControlArbitrary {
		t.Errorf("changes.new_repository.homepage is %v", got)
	}
}

// TestWrittenConstructs: forms of writes to $GITHUB_ENV and $GITHUB_OUTPUT
// that Analyze once read wrongly, each with what Analyze reads now.
func TestWrittenConstructs(t *testing.T) {
	for _, c := range []struct{ name, run, want string }{
		// a value without line breaks still names a variable before the =
		{"line-free key", `echo "$(echo "$T" | tr -d '\n')=1" >> "$GITHUB_ENV"`, `gap GITHUB_ENV subst-value $(echo "$T" | tr -d '\n')`},
		{"line-free body", `'{ echo "k<<EOF"; echo "$(echo "$T" | tr -d ''\n'')"; echo EOF; } >> "$GITHUB_OUTPUT"'`, `gap GITHUB_OUTPUT subst-value $(echo "$T" | tr -d '\n')`},
		// what a command not known writes ends its line
		{"unknown ends a line", `'{ echo "n<<EOF"; cat notes.md; echo "EOF"; } >> "$GITHUB_OUTPUT"; echo "t=$T" >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideValue $T`},
		// the first line of a heredoc is written whatever the conditions
		{"opening under if", `'{ if true; then echo "t<<EOF"; fi; echo "$T"; echo "EOF"; } >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T`},
		// writes in the order they run, as far as it is known
		{"nested write", `'GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"; { echo "t=$T"; echo "k<<${GHA_DELIM}" >> "$GITHUB_OUTPUT"; } >> "$GITHUB_OUTPUT"; echo "${GHA_DELIM}" >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideValue $T`},
		{"function", `'echo "k<<EOF" >> "$GITHUB_OUTPUT"; f() { echo "x=$T" >> "$GITHUB_OUTPUT"; }; echo EOF >> "$GITHUB_OUTPUT"; f'`, `GITHUB_OUTPUT SideValue $T`},
		// exec inside a construct
		{"exec in braces", `'{ exec >> "$GITHUB_OUTPUT"; echo "t=$T"; }'`, `gap GITHUB_OUTPUT exec-redirect exec >> "$GITHUB_OUTPUT"`},
		// a print before the exec in a loop runs after it in the next round
		{"exec in a loop", `'for i in 1 2; do echo "t=$T"; exec >> "$GITHUB_OUTPUT"; done'`, `gap GITHUB_OUTPUT exec-redirect exec >> "$GITHUB_OUTPUT"`},
		// case is not read
		{"case", `'case x in a) echo "t=$T" ;; esac >> "$GITHUB_OUTPUT"'`, `gap GITHUB_OUTPUT writer-unknown case x in a) echo "t=$T" ;; esac >> "$GITHUB_OUTPUT"`},
		{"write in case", `'case x in a) echo "t=$T" >> "$GITHUB_OUTPUT" ;; esac'`, `gap GITHUB_OUTPUT writer-unknown case x in a) echo "t=$T" >> "$GITHUB_OUTPUT" ;; esac`},
		// an array's list in case
		{"array in case", `'case x in a) arr=( $T ); echo "k=${arr[0]}" >> "$GITHUB_OUTPUT" ;; esac'`, `gap GITHUB_OUTPUT writer-unknown case x in a) arr=( $T ); echo "k=${arr[0]}" >> "$GITHUB_OUTPUT" ;; esac`},
		// a ' in a comment of case begins no quote
		{"comment in case", `"case x in a) # it's\n echo \"t=$T\" ;; esac >> \"$GITHUB_OUTPUT\""`, "gap GITHUB_OUTPUT writer-unknown case x in a) # it's\n echo \"t=$T\" ;; esac >> \"$GITHUB_OUTPUT\""},
		// a length is a number
		{"length", `echo "n=${#T}" >> "$GITHUB_OUTPUT"`, ``},
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s: %s:\n got %s\nwant %s", c.name, c.run, got, c.want)
		}
	}
}

// TestWrittenOnceUnread: forms once left unread, each reported or not
// examined now.
func TestWrittenOnceUnread(t *testing.T) {
	const fix = `GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"`
	const doc = `{ echo "t<<${GHA_DELIM}"; echo "$T"; echo "${GHA_DELIM}"; } >> "$GITHUB_OUTPUT"`
	for _, c := range []struct{ name, run, want string }{
		// what an operator holds
		{"inside an operator", `echo "t=${FOO:-$T}" >> "$GITHUB_OUTPUT"`, `GITHUB_OUTPUT SideValue $T`},
		{"quoted by @Q", `echo "t=${T@Q}" >> "$GITHUB_OUTPUT"`, ``},
		{"indirect", `echo "t=${!T}" >> "$GITHUB_OUTPUT"`, `gap GITHUB_OUTPUT subst-value ${!T}`},
		// other spellings of the file
		{"with an operator", `echo "t=$T" >> "${GITHUB_OUTPUT:?}"`, `GITHUB_OUTPUT SideValue $T`},
		{"in another variable", `'out=$GITHUB_OUTPUT; echo "t=$T" >> "$out"'`, `GITHUB_OUTPUT SideValue $T`},
		// << across pieces of a line
		{"<< in two pieces", `'printf ''k<%s\n'' ''<EOF'' >> "$GITHUB_OUTPUT"; echo "$T" >> "$GITHUB_OUTPUT"; echo EOF >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideBody $T`},
		// the fix's delimiter set otherwise
		{"export", `'` + fix + `; export GHA_DELIM=EOF; ` + doc + `'`, `GITHUB_OUTPUT SideBody $T`},
		{"read", `'` + fix + `; read -r GHA_DELIM < f; ` + doc + `'`, `GITHUB_OUTPUT SideBody $T`},
		{"in a function", `'f() { GHA_DELIM=EOF; }; ` + fix + `; f; ` + doc + `'`, `GITHUB_OUTPUT SideBody $T`},
		{"in the background", `'` + fix + ` & ` + doc + `'`, `GITHUB_OUTPUT SideBody $T`},
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s: %s:\n got %s\nwant %s", c.name, c.run, got, c.want)
		}
	}
}

// Forms once left unread are read or not examined now: nothing is passed
// over in silence.
func TestWrittenNoSilence(t *testing.T) {
	const fix = `GHA_DELIM="ghadelimiter_$(od -An -N16 -tx1 /dev/urandom | tr -d '' \n'')"`
	const doc = `{ echo "t<<${GHA_DELIM}"; echo "$T"; echo "${GHA_DELIM}"; } >> "$GITHUB_OUTPUT"`
	for _, c := range []struct{ name, run, want string }{
		{"for", `'` + fix + `; for GHA_DELIM in EOF; do :; done; ` + doc + `'`, `GITHUB_OUTPUT SideBody $T`},
		{"export of the file", `'export out=$GITHUB_OUTPUT; echo "t=$T" >> "$out"'`, `GITHUB_OUTPUT SideValue $T`},
		// what reaches the write (shell.NameVisibility)
		{"set in a subshell", `'( out=$GITHUB_OUTPUT ); echo "t=$T" >> "$out"'`, ``},
		{"set in a pipeline", `'out=$GITHUB_OUTPUT | true; echo "t=$T" >> "$out"'`, ``},
		{"set in the background", `'out=$GITHUB_OUTPUT & wait; echo "t=$T" >> "$out"'`, ``},
		{"set again", `'out=$GITHUB_OUTPUT; out=/tmp/x; echo "t=$T" >> "$out"'`, ``},
		{"unset", `'out=$GITHUB_OUTPUT; unset out; echo "t=$T" >> "$out"'`, ``},
		{"set after", `'echo "t=$T" >> "$out"; out=$GITHUB_OUTPUT'`, ``},
		{"set by a function", `'f(){ out=$GITHUB_OUTPUT; }; f; echo "t=$T" >> "$out"'`, `GITHUB_OUTPUT SideValue $T`},
		{"set in a branch", `'if c; then out="$GITHUB_OUTPUT"; else out=/tmp/x; fi; echo "t=$T" >> "$out"'`, `GITHUB_OUTPUT SideValue $T`},
		{"set on one path", `'out=/tmp/x; c && out=$GITHUB_OUTPUT; echo "t=$T" >> "$out"'`, `GITHUB_OUTPUT SideValue $T`}, // a path writes to the file
		{"the fix's delimiter on one path", `'if c; then ` + fix + `; fi; ` + doc + `'`, `GITHUB_OUTPUT SideBody $T`},
		{"a target not read", `'echo "t=$T" >> "$(echo $GITHUB_OUTPUT)"'`, `gap GITHUB_OUTPUT writer-unknown echo "t=$T" >> "$(echo $GITHUB_OUTPUT)"`},
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s: %s:\n got %s\nwant %s", c.name, c.run, got, c.want)
		}
	}
}

// TestWrittenFunctionsAndDescriptors: functions given arguments, names
// defined twice, descriptors an exec opens, and the redirects of braces.
func TestWrittenFunctionsAndDescriptors(t *testing.T) {
	for _, c := range []struct{ name, run, want string }{
		// a function given arguments or input writes what may be them
		{"argument", `'f() { echo "t=$1"; }; f "$T" >> "$GITHUB_OUTPUT"'`, `gap GITHUB_OUTPUT writer-unknown f "$T" >> "$GITHUB_OUTPUT"`},
		{"piped", `'f() { echo "t=$(cat)"; }; echo "$T" | f >> "$GITHUB_OUTPUT"'`, `gap GITHUB_OUTPUT writer-unknown echo "$T" | f >> "$GITHUB_OUTPUT"`},
		// a name defined twice is not known
		{"defined twice", `'f() { echo "t=$T"; }; f >> "$GITHUB_OUTPUT"; f() { echo safe; }'`, `GITHUB_OUTPUT SideValue $T`}, // the call sees the first definition (shell.NameVisibility)
		// exec that points a descriptor elsewhere again
		// a descriptor an exec of the file may have opened is not followed through
		// every exec: not a finding, a place not examined
		{"exec again", `'exec 3>> "$GITHUB_OUTPUT"; exec 3>&1; echo "t=$T" >&3'`, `gap GITHUB_OUTPUT writer-unknown echo "t=$T" >&3`},
		// an exec in a subshell that does not hold the write opens nothing for
		// it
		{"exec in a pipeline", `'exec 3>> "$GITHUB_OUTPUT" | echo "t=$T" >&3'`, ``},
		{"exec in the background", `'exec 3>> "$GITHUB_OUTPUT" & wait; echo "t=$T" >&3'`, ``},
		{"function before exec", `'f() { echo "t=$T" >&3; }; exec 3>> "$GITHUB_OUTPUT"; f'`, `GITHUB_OUTPUT SideValue $T`}, // the body runs where it is called
		// the redirects of the braces around
		{"braces around", `'{ echo "t=$T" >&2; } 2>> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideValue $T`},
		{"1<&3", `'exec 3>> "$GITHUB_OUTPUT"; echo "t=$T" 1<&3'`, `GITHUB_OUTPUT SideValue $T`},
		{"1<>", `echo "t=$T" 1<> "$GITHUB_OUTPUT"`, `GITHUB_OUTPUT SideValue $T`},
		{"{fd}", `'exec {fd}>> "$GITHUB_OUTPUT"; echo "t=$T" >&$fd'`, `GITHUB_OUTPUT SideValue $T`},
		{"exec 2>>", `'exec 2>> "$GITHUB_OUTPUT"; echo "t=$T"'`, `gap GITHUB_OUTPUT exec-redirect exec 2>> "$GITHUB_OUTPUT"`},
		// >&$v whose value is a number on every path
		{">&$v of 3", `'exec 3>> "$GITHUB_OUTPUT"; v=3; echo "t=$T" >&$v'`, `GITHUB_OUTPUT SideValue $T`},
		{">&$v of a file command", `'v=$GITHUB_OUTPUT; echo "t=$T" >&$v'`, `GITHUB_OUTPUT SideValue $T`},
		// a call after an element of an array
		{"call after an element", `'f() { echo "t=$T" >> "$GITHUB_OUTPUT"; }; a[0]=x f'`, `GITHUB_OUTPUT SideValue $T`},
		// an operator that gives another value is not the file
		{"another value", `echo "t=$T" >> "${GITHUB_OUTPUT:+/dev/null}"`, `gap GITHUB_OUTPUT writer-unknown echo "t=$T" >> "${GITHUB_OUTPUT:+/dev/null}"`},
		// one place written twice is one
		{"called twice", `'f() { echo "t=$T"; }; f >> "$GITHUB_OUTPUT"; f >> "$GITHUB_OUTPUT"'`, `GITHUB_OUTPUT SideValue $T`},
		// a call before a command not known that reads the pipe: what the body
		// writes may be what the command writes
		{"call before cat", `'f() { echo "t=$T"; }; f | cat >> "$GITHUB_OUTPUT"'`, `gap GITHUB_OUTPUT writer-unknown f | cat >> "$GITHUB_OUTPUT"`},
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s: %s:\n got %s\nwant %s", c.name, c.run, got, c.want)
		}
	}
}

// TestWrittenPathSubstitutionsAndTee: forms of writes that Analyze once neither reported
// nor marked as not examined, on every file command.
func TestWrittenPathSubstitutionsAndTee(t *testing.T) {
	for _, c := range []struct{ name, run, want string }{
		// a variable inside ` `, which the tree does not read
		{"backquote path", "echo \"`echo $T`\" >> \"$GITHUB_PATH\"", "gap GITHUB_PATH subst-value `echo $T`"},
		{"backquote env", "echo \"t=`echo $T`\" >> \"$GITHUB_ENV\"", "gap GITHUB_ENV subst-value `echo $T`"},
		// tee not in a pipeline, its input a here-string or a heredoc
		{"tee here-string path", `tee -a "$GITHUB_PATH" <<< "$T"`, `gap GITHUB_PATH writer-unknown tee -a "$GITHUB_PATH" <<< "$T"`},
		{"tee here-string env", `tee -a "$GITHUB_ENV" <<< "t=$T"`, `gap GITHUB_ENV writer-unknown tee -a "$GITHUB_ENV" <<< "t=$T"`},
		{"tee heredoc", "|\n          tee -a \"$GITHUB_PATH\" <<EOF\n          $T\n          EOF", "gap GITHUB_PATH writer-unknown tee -a \"$GITHUB_PATH\" <<EOF"}, // the command, as the other writers not known
	} {
		if got := writtenOf(t, titleEnv, c.run); got != c.want {
			t.Errorf("%s: %s:\n got %s\nwant %s", c.name, c.run, got, c.want)
		}
	}
}

// TestWrittenAliasesAndKeys: a variable set to two files, a key made by a
// substitution, and a name in $(( )) without $.
func TestWrittenAliasesAndKeys(t *testing.T) {
	const branch = "          H: ${{ github.head_ref }}\n"
	for _, c := range []struct{ name, on, env, run, want string }{
		// a variable set to two files is neither; each write through it is not examined
		{"alias of two files", "issues", titleEnv, "|\n          f=$GITHUB_ENV\n          echo \"a=$T\" >> $f\n          f=$GITHUB_PATH\n          echo \"/opt/bin\" >> $f",
			"GITHUB_ENV SideValue $T"}, // the write reads the assignment that reaches it (shell.NameVisibility): $GITHUB_ENV
		// before the =, any value an attacker controls names a variable, a branch name too
		{"key through $( )", "pull_request_target", branch, `echo "$(echo $H)=1" >> "$GITHUB_ENV"`, `gap GITHUB_ENV subst-value $(echo $H)`},
		{"key through ` `", "pull_request_target", branch, "echo \"`echo $H`=1\" >> \"$GITHUB_ENV\"", "gap GITHUB_ENV subst-value `echo $H`"},
		{"tee of a here-string", "pull_request_target", branch, `tee -a "$GITHUB_ENV" <<< "$H=1"`, `gap GITHUB_ENV writer-unknown tee -a "$GITHUB_ENV" <<< "$H=1"`},
		// the value side of a branch name stays as it was
		{"value through $( )", "pull_request_target", branch, `echo "h=$(echo $H)" >> "$GITHUB_ENV"`, ``},
		// a name in $(( )) without $
		{"arithmetic", "issues", titleEnv, `echo "$((T))" >> "$GITHUB_PATH"`, `gap GITHUB_PATH subst-value $((T))`},
		// a number has no line break: after the = of $GITHUB_OUTPUT it is not a gap
		{"arithmetic of a value", "issues", titleEnv, `echo "t=$((T-30))" >> "$GITHUB_OUTPUT"`, ``},
	} {
		if got := writtenOn(t, c.on, c.env, c.run); got != c.want {
			t.Errorf("%s: %s:\n got %s\nwant %s", c.name, c.run, got, c.want)
		}
	}
}

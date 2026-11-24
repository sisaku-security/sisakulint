package shell

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The values of the variable V that the cases run with: each makes the
// file PWNED when bash or a program runs it as code at one of the readings
// (the blanks for the command word, a subscript for arithmetic).
var shellValues = []string{"$(touch PWNED)", "$(touch${IFS}PWNED)", "a[$(touch${IFS}PWNED)]", "sh -c touch${IFS}PWNED", "touch PWNED"}

var (
	pythonValues = []string{`__import__("os").system("touch PWNED")`}
	nodeValues   = []string{`require("fs").writeFileSync("PWNED", "")`}
	perlValues   = []string{`system("touch PWNED")`}
)

type varCodeCase struct {
	src     string
	reading CodeReading // unset: VariableCodes gives no V
	bare    bool        // the V it gives is a name without $
	program string      // the program the case needs, other than bash
	values  []string    // nil: shellValues
}

// varCodeCases are where the value of V runs and VariableCodes reads it, and
// where the value does not run.
var varCodeCases = []varCodeCase{
	{src: `eval "echo $V"`, reading: CodeReadingCodeArgument},
	{src: `eval $V`, reading: CodeReadingCodeArgument},
	{src: `eval "${V/a/b}"`, reading: CodeReadingCodeArgument},
	{src: `eval "${V:-x}"`, reading: CodeReadingCodeArgument},
	{src: `builtin eval "$V"`, reading: CodeReadingCodeArgument},
	{src: `coproc eval "$V"; sleep 1`, reading: CodeReadingCodeArgument},
	{src: `coproc "$(eval "$V")" { :; }; sleep 1`, reading: CodeReadingCodeArgument},
	{src: `bash -c "$V"`, reading: CodeReadingCodeArgument},
	{src: `sh -c "echo $V"`, reading: CodeReadingCodeArgument},
	// the subscript before a length or an indirect reference
	{src: `a=(1); echo "${#a[$V]}"`, reading: CodeReadingArithmetic},
	{src: `a=(x); echo "${!a[$V]}"`, reading: CodeReadingArithmetic},
	{src: `declare -A m; m=([k]=v); echo "${#m[$V]}"`}, // an associative array: the key is not evaluated
	// the code of -c is the first word after the options and their values
	{src: `bash -cx "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c -x "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c -- "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c - "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c +x "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c -o pipefail "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -co pipefail "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c +o pipefail "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c -O extglob "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c -oo pipefail errexit "$V"`, reading: CodeReadingCodeArgument}, // each letter takes a value
	{src: `bash -c +oo pipefail errexit "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c +xo pipefail "$V"`, reading: CodeReadingCodeArgument},
	{src: `bash -c +xO extglob "$V"`, reading: CodeReadingCodeArgument},
	{src: `python3 -c "$V"`, reading: CodeReadingCodeArgument, program: "python3", values: pythonValues},
	{src: `node -e "$V"`, reading: CodeReadingCodeArgument, program: "node", values: nodeValues},
	{src: `node --eval="$V"`, reading: CodeReadingCodeArgument, program: "node", values: nodeValues},
	{src: `perl -e "$V"`, reading: CodeReadingCodeArgument, program: "perl", values: perlValues},
	{src: `ruby -e "$V"`, reading: CodeReadingCodeArgument, program: "ruby", values: perlValues},
	{src: `git -c core.fsmonitor="$V" status`, reading: CodeReadingCodeArgument, program: "git"},
	{src: `git -c core.sshCommand="$V" ls-remote ssh://h/r`, reading: CodeReadingCodeArgument, program: "git"},
	{src: `git -c alias.x="!$V" x`, reading: CodeReadingCodeArgument, program: "git"},
	{src: `git -c "$V" x`, reading: CodeReadingCodeArgument, program: "git", values: []string{"alias.x=!touch PWNED"}},
	{src: `git -c user.name=$V x`, reading: CodeReadingCodeArgument, program: "git", values: []string{"y -c alias.x=!touch${IFS}PWNED"}}, // its words add another -c
	{src: `git -c user.name="$V" commit -m m`, program: "git"},                                                                           // data: git runs no value of user.name
	{src: `git -c user.email="$V" -c core.quotePath=false status`, program: "git"},
	{src: `let "$V"`, reading: CodeReadingArithmetic},
	{src: `printf -v "$V" x`, reading: CodeReadingArithmetic},
	{src: `test -v "$V"`, reading: CodeReadingArithmetic},
	{src: `a=(); [ -v "$V" ]`, reading: CodeReadingArithmetic},
	{src: `read $V <<< y`, reading: CodeReadingArithmetic},
	{src: `read "$V" <<< y`, reading: CodeReadingArithmetic},
	{src: `[[ $V -eq 1 ]]`, reading: CodeReadingArithmetic},
	{src: `(( $V + 1 ))`, reading: CodeReadingArithmetic},
	{src: `$V`, reading: CodeReadingCommandWord},
	{src: `$V arg`, reading: CodeReadingCommandWord},
	{src: `echo x; $V`, reading: CodeReadingCommandWord},
	{src: `timeout 5 $V`, reading: CodeReadingCommandWord},
	{src: `env $V`, reading: CodeReadingCommandWord},
	{src: `echo "$V" | bash`, reading: CodeReadingCodeInput},
	{src: `echo "$V" | cat | bash`, reading: CodeReadingCodeInput},
	{src: `echo "$V" | { bash; }`, reading: CodeReadingCodeInput},
	{src: `echo "$V" | y=$(bash)`, reading: CodeReadingCodeInput},
	{src: "bash <<EOF\n$V\nEOF", reading: CodeReadingCodeInput},
	{src: `bash <<< "$V"`, reading: CodeReadingCodeInput},
	{src: `echo "$V" | source /dev/stdin`, reading: CodeReadingCodeInput},
	{src: `echo "$V" | python3`, reading: CodeReadingCodeInput, program: "python3", values: pythonValues},
	{src: "python3 - <<EOF\n$V\nEOF", reading: CodeReadingCodeInput, program: "python3", values: pythonValues},
	{src: "bash - <<EOF\n$V\nEOF", reading: CodeReadingCodeInput},
	{src: `python3 <<< "$V"`, reading: CodeReadingCodeInput, program: "python3", values: pythonValues},
	{src: "python3 <<EOF\n$V\nEOF", reading: CodeReadingCodeInput, program: "python3", values: pythonValues},
	{src: `echo "$V" | sh`, reading: CodeReadingCodeInput},
	{src: `sh <<< "$V"`, reading: CodeReadingCodeInput},
	{src: `. /dev/stdin <<< "$V"`, reading: CodeReadingCodeInput},
	{src: `source /dev/stdin <<< "$V"`, reading: CodeReadingCodeInput},
	{src: "source /dev/stdin <<EOF\n$V\nEOF", reading: CodeReadingCodeInput},
	{src: `a[$V]=1`, reading: CodeReadingArithmetic},
	{src: `a[V]=1`, reading: CodeReadingArithmetic, bare: true},
	{src: `let x=V`, reading: CodeReadingArithmetic, bare: true},
	{src: `let "x=V+1"`, reading: CodeReadingArithmetic, bare: true},
	{src: `echo "${!V}"`, reading: CodeReadingArithmetic},
	{src: `eval "echo ${!V}"`, reading: CodeReadingArithmetic},
	{src: `read -r "$V" <<< y`, reading: CodeReadingArithmetic},
	{src: `${U:-$V}`, reading: CodeReadingCommandWord},
	{src: `x=$(${U:-$V})`, reading: CodeReadingCommandWord},

	// the inside of substitutions, arithmetic and ${ }
	{src: `x=$(eval "$V")`, reading: CodeReadingCodeArgument},
	{src: `echo "$(eval $V)"`, reading: CodeReadingCodeArgument},
	{src: `x=$(bash -c "$V")`, reading: CodeReadingCodeArgument},
	{src: `echo "$(echo "$V" | bash)"`, reading: CodeReadingCodeInput},
	{src: `x=$($V)`, reading: CodeReadingCommandWord},
	{src: `cat <(eval "$V")`, reading: CodeReadingCodeArgument},
	{src: `echo x > >(eval "$V"); sleep 1`, reading: CodeReadingCodeArgument},
	{src: "x=`eval \"$V\"`", reading: CodeReadingCodeArgument},
	{src: "x=`$V`", reading: CodeReadingCommandWord},
	{src: "x=`(( V + 1 ))`", reading: CodeReadingArithmetic, bare: true},
	{src: `echo $(( $V + 1 ))`, reading: CodeReadingArithmetic},
	{src: `echo $(( V + 1 ))`, reading: CodeReadingArithmetic, bare: true},
	{src: `echo "$(( V ))"`, reading: CodeReadingArithmetic, bare: true},
	{src: `(( V + 1 ))`, reading: CodeReadingArithmetic, bare: true},
	{src: `[[ V -eq 1 ]]`, reading: CodeReadingArithmetic, bare: true},
	{src: `a=(1); echo ${a[$V]}`, reading: CodeReadingArithmetic},
	{src: `a=(1); echo "${a[V]}"`, reading: CodeReadingArithmetic, bare: true},
	{src: `echo "${V:0:V}"`, reading: CodeReadingArithmetic, bare: true},
	{src: `echo ${V:0:$V}`, reading: CodeReadingArithmetic},
	{src: `eval "${U:-$V}"`, reading: CodeReadingCodeArgument},
	{src: `echo "${U:-$(eval "$V")}"`, reading: CodeReadingCodeArgument},
	{src: `U=abc; echo "${U#$(eval "$V")}"`, reading: CodeReadingCodeArgument}, // a pattern is expanded
	// ${V@P} expands the value as a prompt string, which runs its command
	// substitutions wherever it is; ${V@E} decodes the escapes of the value
	{src: `echo "${V@P}"`, reading: CodeReadingPromptExpansion},
	{src: `${V@P}`, reading: CodeReadingPromptExpansion},
	{src: `${V@E}`, reading: CodeReadingCommandWord},
	// the script of ` `, its backslashes taken off
	{src: "x=`eval \\\"$V\\\"`", reading: CodeReadingCodeArgument},
	// the expressions of for (( ; ; ))
	{src: `for (( i=V; i<0; i++ )); do :; done`, reading: CodeReadingArithmetic, bare: true},
	{src: `eval "${V@E}"`, reading: CodeReadingCodeArgument},
	{src: `U=abc; echo "${U/a/$(eval "$V")}"`, reading: CodeReadingCodeArgument},
	{src: `x=$(( $(eval "$V") ))`, reading: CodeReadingCodeArgument},

	// where the value does not run
	{src: `"$V"`},
	{src: `"$V" arg`},
	{src: `timeout 5 "$V"`},
	{src: `source $V`},
	{src: `. "$V"`},
	{src: `A+=$V`},
	{src: `x=$(echo $V)`},
	{src: `read -a "$V" <<< y`},
	{src: `mapfile "$V" <<< y`},
	{src: `declare "$V"`},
	{src: `unset "$V"`},
	{src: `f(){ local "$V"; }; f`},
	{src: `export "$V"`},
	{src: `echo $V`},
	{src: `echo "$V"`},
	{src: `A=$V`},
	{src: "cat <<EOF\n$V\nEOF"},
	{src: "bash <<'EOF'\necho \"$V\"\nEOF"},
	{src: `eval "${#V}"`},
	{src: `echo "$(echo "$V")"`},
	{src: "x=`echo $V`"},
	{src: `echo "${U:-$V}"`},
	{src: `declare -A m; echo "${m[$V]}"`},
	{src: `f(){ local -A m; echo "${m[$V]}"; }; f`},
	{src: `bash script.sh <<< "$V"`},
	{src: `echo "$V" | bash script.sh`},
	{src: `bash -c cat <<< "$V"`},
	{src: `bash -c -o "$V" true`}, // the value of -o names an option
	{src: `python3 script.py <<< "$V"`},
	{src: `source script.sh <<< "$V"`},
	{src: `declare -A m; m[$V]=1`},
	{src: `[[ -v V ]]`},
	{src: `(( V = 1 ))`},
	{src: `a=(); (( a[0] = 1 )); echo "${a[0]}"`},
	{src: `eval "echo ${V@Q}"`},
	{src: `echo "${V@E}"`},
	{src: `x$V`},
	{src: `echo "$V" | wc -l | bash`},
	{src: `echo "$V" > /dev/null | bash`},
	{src: `echo "$V" | bash < /dev/null`},
	{src: `echo "$V" | sha256sum | bash`},
	{src: `echo "$V" | grep -c x | bash`}, // what reaches bash is changed or not known (PipePassage)
	{src: `${U:-"$V"}`},
	{src: `read -p "$V" x <<< y`},
}

// unreadCases run the value of V, and VariableCodes does not read them
// (the undetected forms env-variable-nested, env-variable-runs-argument and
// script-var of code-injection).
var unreadCases = []string{
	"xargs $V </dev/null",
	`find . -maxdepth 0 -exec $V \;`,
	`declare -i n; n=$V`,
	`eval "$(echo $V)"`,
	"bash <<'EOF'\n$V\nEOF",
	"eval \"${U:-`echo $V`}\"",
	`echo $[ V + 1 ]`,
}

// vOf is what VariableCodes gives of the variable V in src.
func vOf(src string) []VariableCode {
	var out []VariableCode
	for _, c := range VariableCodes(src, Parse(src)) {
		if c.Name.String() == "V" {
			out = append(out, c)
		}
	}
	return out
}

// runsValue is whether bash, running src with V set to a value of values,
// makes the file PWNED, and with which value.
func runsValue(t *testing.T, bash, src string, values []string) (string, bool) {
	t.Helper()
	for _, val := range values {
		dir := t.TempDir()
		setup := exec.Command("git", "init", "-q")
		setup.Dir = dir
		if setup.Run() == nil {
			_ = os.WriteFile(filepath.Join(dir, "f"), nil, 0o644)
			add := exec.Command("git", "add", "f")
			add.Dir = dir
			_ = add.Run()
		}
		cmd := exec.Command(bash, "-c", src)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "V="+val, "HOME="+dir, "GIT_CONFIG_NOSYSTEM=1")
		_ = cmd.Run()
		if _, err := os.Stat(filepath.Join(dir, "PWNED")); err == nil {
			return val, true
		}
	}
	return "", false
}

// TestVariableCodesWithBash runs each case with bash: where VariableCodes
// reads V, some value of V runs; where it does not, none does.
func TestVariableCodesWithBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	for _, c := range varCodeCases {
		t.Run(c.src, func(t *testing.T) {
			if c.program != "" {
				if _, err := exec.LookPath(c.program); err != nil {
					t.Skipf("no %s", c.program)
				}
			}
			values := c.values
			if values == nil {
				values = shellValues
			}
			got := vOf(c.src)
			val, runs := runsValue(t, bash, c.src, values)
			if c.reading == CodeReadingUnset {
				if len(got) != 0 {
					t.Errorf("VariableCodes = %v, want none", got)
				}
				if runs {
					t.Errorf("the value %q ran: the case is not one where the value does not run", val)
				}
				return
			}
			if len(got) != 1 || got[0].Reading != c.reading || got[0].Bare != c.bare {
				t.Errorf("VariableCodes = %v, want one V read as %v (bare %v)", got, c.reading, c.bare)
			}
			if !runs {
				t.Errorf("no value of %v ran", values)
			}
		})
	}
}

// TestVariableCodesUnread: the forms that run the value of V and that
// VariableCodes does not read.
func TestVariableCodesUnread(t *testing.T) {
	for _, src := range unreadCases {
		if got := vOf(src); len(got) != 0 {
			t.Errorf("%q: VariableCodes = %v, want none", src, got)
		}
	}
}

// misreadCases do not run the value of V, and VariableCodes reads them as
// code (the false positive form associative-key-not-literal of
// code-injection): the names a declare declares associative in a word that
// is not literal are not read.
var misreadCases = []string{
	`declare -A m=([k]=v); echo "${#m[$V]}"`,
}

// TestVariableCodesMisread: the forms of misreadCases give a V, and bash
// does not run the value of V.
func TestVariableCodesMisread(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	for _, src := range misreadCases {
		if got := vOf(src); len(got) == 0 {
			t.Errorf("%q: VariableCodes gives no V: the form is read, and the declaration of the false positive is to be removed", src)
		}
		if val, runs := runsValue(t, bash, src, shellValues); runs {
			t.Errorf("%q: the value %q ran", src, val)
		}
	}
}

// TestVariableCodesInPlaces: where VariableCodes reads a variable as code,
// Places gives no fix (CommandString or QuotingUnknown), so that the fix of
// code-injection never writes a variable there. ${!NAME} and ${NAME@P},
// which are code by their operator, are not what the fix writes (${NAME}).
func TestVariableCodesInPlaces(t *testing.T) {
	for _, c := range varCodeCases {
		for _, v := range VariableCodes(c.src, Parse(c.src)) {
			if strings.HasPrefix(c.src[v.Span.Start:], "${!") || v.Reading == CodeReadingPromptExpansion {
				continue
			}
			q := Places(c.src, []int{v.Span.Start})[0].Quoting
			if q != CommandString && q != QuotingUnknown {
				t.Errorf("%q: %s at %d is %v", c.src, v.Name, v.Span.Start, q)
			}
		}
	}
}

func TestVariableCodesSpans(t *testing.T) {
	for _, c := range varCodeCases {
		for _, v := range VariableCodes(c.src, Parse(c.src)) {
			text := c.src[v.Span.Start:v.Span.End]
			want := []string{"$" + v.Name.String(), "${" + v.Name.String(), "${!" + v.Name.String()}
			if v.Bare {
				want = []string{v.Name.String()}
			}
			if !slices.ContainsFunc(want, func(w string) bool { return len(text) >= len(w) && text[:len(w)] == w }) {
				t.Errorf("%q: %v spans %q", c.src, v, text)
			}
		}
	}
}

func TestVariableCodesIncomplete(t *testing.T) {
	// bash refuses the line whose quote is not closed, and runs the lines
	// before it
	if got := vOf(`eval "$V"; echo "`); len(got) != 0 {
		t.Errorf("one line: VariableCodes = %v, want none", got)
	}
	if got := vOf("eval \"$V\"\necho \"open"); len(got) != 1 {
		t.Errorf("two lines: VariableCodes = %v, want the V of the first line", got)
	}
}

// BenchmarkVariableCodes reads a script of 4000 lines, each with $(( )),
// ${ } with an operator and ` `: each inside is parsed on its own, so the
// time grows with the length of the script, not with its square.
func BenchmarkVariableCodes(b *testing.B) {
	src := strings.Repeat("echo $((x+1)) \"${U:-$V}\" `echo $V`\n", 4000)
	sc := Parse(src)
	b.ResetTimer()
	for range b.N {
		VariableCodes(src, sc)
	}
}

// TestVariableCodesAssignedElement: arithmetic reads the subscript of the
// element that = assigns, and not the value of the array.
func TestVariableCodesAssignedElement(t *testing.T) {
	src := `(( a[V] = 1 ))`
	got := VariableCodes(src, Parse(src))
	if len(got) != 1 || got[0].Name.String() != "V" || got[0].Reading != CodeReadingArithmetic || !got[0].Bare {
		t.Errorf("VariableCodes = %v, want V alone", got)
	}
}

// TestGitKeyRuns: the git configuration keys whose value git runs.
func TestGitKeyRuns(t *testing.T) {
	for key, want := range map[string]bool{
		"core.sshCommand": true, "core.pager": true, "alias.st": true, "credential.helper": true,
		"credential.https://x.helper": true, "diff.x.textconv": true, "filter.lfs.smudge": true,
		"remote.origin.uploadpack": true, "": true, "core": true,
		"user.name": false, "user.email": false, "core.quotePath": false, "http.extraHeader": false,
		"safe.directory": false, "init.defaultBranch": false,
	} {
		if got := gitKeyRuns(key); got != want {
			t.Errorf("gitKeyRuns(%q) = %v, want %v", key, got, want)
		}
	}
}

package shell

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// marked is src without its markers @@, and where they were.
func marked(src string) (string, []int) {
	var b strings.Builder
	var at []int
	for {
		i := strings.Index(src, "@@")
		if i < 0 {
			b.WriteString(src)
			return b.String(), at
		}
		b.WriteString(src[:i])
		at = append(at, b.Len())
		src = src[i+2:]
	}
}

// contextCases are the places of TestContexts.
var contextCases = []struct {
	src  string
	want []Quoting
}{
	{"echo @@", []Quoting{Unquoted}},
	// the command word: the string names what runs
	{"@@x arg", []Quoting{CommandString}},
	{"X=@@x make", []Quoting{Unquoted}},
	// an element of an array before the command word: its subscript is
	// arithmetic, its value data; the word after the assignments is the
	// command word
	{`a["@@x"]=1`, []Quoting{CommandString}},
	{`a[0]="@@x"`, []Quoting{DoubleQuoted}},
	{`a[0]=x @@x`, []Quoting{CommandString}},
	{`a[0]=x b=@@x cmd`, []Quoting{Unquoted}},
	{`a[@@x]=1 cmd`, []Quoting{CommandString}},
	{`@@x=1 cmd`, []Quoting{CommandString}}, // the name decides whether the word is an assignment
	// a variable with the integer attribute: its assignments are arithmetic
	// (the owner's decision of 2026-11-15: declare, typeset and local
	// commands of the tree)
	{"declare -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"declare -x -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"declare \"$o\" n\nn=@@x", []Quoting{QuotingUnknown}},
	{"f(){ local -i n; }\nn=@@x", []Quoting{QuotingUnknown}},
	{"builtin declare -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"command typeset -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"command -p declare -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"builtin -- declare -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"command -- typeset -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"command -v declare -i n\nn=@@x", []Quoting{Unquoted}},
	{"# declare -i n\nn=@@x", []Quoting{Unquoted}},
	{"echo 'declare -i n'\nn=@@x", []Quoting{Unquoted}},
	// the integer attribute given by eval or by a command named only when it
	// runs
	{"eval 'declare -i n'\n: \"${n:=@@x}\"", []Quoting{CommandString}},
	{"eval declare -i n\nn=@@x", []Quoting{QuotingUnknown}},
	{"d=declare; $d -i n\n: \"${n:=@@x}\"", []Quoting{CommandString}},
	{"eval 'echo -n a'\nn=@@x", []Quoting{Unquoted}},
	{"\"$CMD\" -v\nn=@@x", []Quoting{Unquoted}},
	{"$DOCKER build --file x .\nn=@@x", []Quoting{Unquoted}}, // a long option is not of declare
	{"$d -xi n\nn=@@x", []Quoting{QuotingUnknown}},
	{"sudo -E @@x", []Quoting{CommandString}},
	{"echo 'a' @@ \"b\"", []Quoting{Unquoted}},
	{`echo "a @@ b"`, []Quoting{DoubleQuoted}},
	{`echo "a\" @@"`, []Quoting{DoubleQuoted}},
	{`echo 'a @@'`, []Quoting{SingleQuoted}},
	{`echo $'a\' @@'`, []Quoting{SingleQuoted}},
	{`echo \' @@`, []Quoting{Unquoted}},
	{`echo "it's @@"`, []Quoting{DoubleQuoted}},
	{"echo a \\\n  @@", []Quoting{Unquoted}},
	// a comment starts a word; # inside a word is not one
	{"# it's @@\necho @@", []Quoting{Comment, Unquoted}},
	{"echo a\n#@@", []Quoting{Comment}},
	{"echo a#b @@", []Quoting{Unquoted}},
	{"echo @@ # a comment at the end", []Quoting{Unquoted}},
	// heredocs: a quoted delimiter stops expansion in the body
	{"cat <<EOF\n@@\nEOF\necho @@", []Quoting{Heredoc, Unquoted}},
	{"cat <<-EOF\n\t@@\n\tEOF\necho @@", []Quoting{Heredoc, Unquoted}},
	{"cat <<'EOF'\n@@\nEOF", []Quoting{QuotedHeredoc}},
	{"cat <<\"EOF\"\n@@\nEOF", []Quoting{QuotedHeredoc}},
	{"cat <<\\EOF\n@@\nEOF", []Quoting{QuotedHeredoc}},
	{"cat <<E\"O\"F\n@@\nEOF", []Quoting{QuotedHeredoc}},
	{"cat <<A <<'B'\n@@\nA\n@@\nB\necho @@", []Quoting{Heredoc, QuotedHeredoc, Unquoted}},
	{"cat <<< @@", []Quoting{Unquoted}},
	// what another program reads as code: the shell's expansion lands in it
	{`eval "echo @@"`, []Quoting{CommandString}},
	{`echo a; eval @@`, []Quoting{CommandString}},
	{`echo a; echo @@`, []Quoting{Unquoted}},
	{`bash -c 'echo @@'`, []Quoting{CommandString}},
	{`sh -c "echo @@"`, []Quoting{CommandString}},
	{`sudo /bin/bash -c "@@"`, []Quoting{CommandString}},
	{`python3 -c "print('@@')"`, []Quoting{CommandString}},
	{`node -e "console.log('@@')"`, []Quoting{CommandString}},
	{"python3 <<EOF\nprint('@@')\nEOF", []Quoting{CommandString}},
	{"FOO=1 bash -c \"@@\" && echo @@", []Quoting{CommandString, Unquoted}},
	// a prefix's options may take arguments, so what comes after a prefix is
	// not followed
	{`sudo -u root bash -c "@@"`, []Quoting{CommandString}},
	{`env -u X bash -c "@@"`, []Quoting{CommandString}},
	{`nice -n 5 sh -c "@@"`, []Quoting{CommandString}},
	{`exec -a n bash -c "@@"`, []Quoting{CommandString}},
	{"sudo -u root bash <<EOF\n@@\nEOF", []Quoting{CommandString}},
	{`sudo -u root @@`, []Quoting{CommandString}},
	// a here-string to a reader of code, and a pipe into one
	{`bash <<< "@@"`, []Quoting{CommandString}},
	{`python3 <<< "@@"`, []Quoting{CommandString}},
	{`cat <<< "@@"`, []Quoting{DoubleQuoted}},
	{`echo "@@" | bash`, []Quoting{CommandString}},
	{`echo "@@" | tr a b | sh -e`, []Quoting{CommandString}},
	{`echo "@@" | xargs rm`, []Quoting{CommandString}},
	{"cat <<EOF | bash\n@@\nEOF", []Quoting{CommandString}},
	{"cat <<EOF | bash\n@@\na\\\nEOF", []Quoting{QuotingUnknown}}, // a body not followed to its end
	{`echo "@@" || bash`, []Quoting{DoubleQuoted}},
	{"echo \"@@\"; bash", []Quoting{DoubleQuoted}},
	// what the pipe carries reaches the reader through the pipes only
	// (PipeSources, PipeReaders)
	{`echo "@@" > f | bash`, []Quoting{DoubleQuoted}},
	{`echo "@@" | sha256sum | bash`, []Quoting{DoubleQuoted}},
	{`echo "@@" | bash < /dev/null`, []Quoting{DoubleQuoted}},
	{`echo "@@" | { echo hi; }`, []Quoting{CommandString}}, // echo receives the pipe: a compound that receives it is taken as a reader
	{`echo "@@" | cat | bash`, []Quoting{CommandString}},
	{`echo "@@" | { bash; }`, []Quoting{CommandString}},
	{`echo "@@" | y=$(bash)`, []Quoting{CommandString}},
	{`echo "@@" | echo $(bash) < /dev/null`, []Quoting{CommandString}},
	{`echo "@@" | cat f | bash`, []Quoting{DoubleQuoted}},
	// a compound command passes what it reads on through its own pipes and
	// variables: one with a command that reads the pipe is a reader
	{`echo "@@" | { cat | bash; }`, []Quoting{CommandString}},
	{`echo "@@" | ( tr a b | sh )`, []Quoting{CommandString}},
	{`echo "@@" | while read -r l; do echo "$l" | bash; done`, []Quoting{CommandString}},
	{`echo "@@" | { x=$(cat); echo "$x" | bash; }`, []Quoting{CommandString}},
	{`echo "@@" > /proc/self/fd/1 | bash`, []Quoting{CommandString}},
	// the whole command word
	{"@@", []Quoting{CommandString}},
	{"@@ arg", []Quoting{CommandString}},
	{"echo a && @@x", []Quoting{CommandString}}, // with nothing after &&, the list is not a script
	{"if @@; then :; fi", []Quoting{CommandString}},
	{"x=1 @@ --flag", []Quoting{CommandString}},
	{"(@@)", []Quoting{CommandString}},
	{"(( @@ > 1 ))", []Quoting{CommandString}},
	// what bash itself reads as code or arithmetic
	{`trap "echo @@" EXIT`, []Quoting{CommandString}},
	{`let "x=@@"`, []Quoting{CommandString}},
	{"[[ 1 -eq @@x ]]", []Quoting{CommandString}},
	// inside [[ ]] (a string put there is a word: the rule puts one of the
	// same length), only the operands of arithmetic and of -v are code, quoted
	// or not; the others are strings, read as their quotes say (cond-operand)
	{`[[ "@@" -ge 0 || ( 0 -ne '@@' ) ]]`, []Quoting{CommandString, CommandString}},
	{`[[ -v "@@" ]]`, []Quoting{CommandString}},
	{`[[ "@@" == /deploy ]]`, []Quoting{DoubleQuoted}},
	{`[[ '@@' =~ ^v ]]`, []Quoting{SingleQuoted}},
	{`[[ @@x == x && x != @@x ]]`, []Quoting{Unquoted, Unquoted}},
	{`[[ -n x && "@@" == y ]] && echo "@@"`, []Quoting{DoubleQuoted, DoubleQuoted}},
	{`[[ x < "@@" ]]`, []Quoting{DoubleQuoted}},
	{`[[ ( "@@" == y ) ]]`, []Quoting{DoubleQuoted}},
	{`[[ ! "@@" ]]`, []Quoting{DoubleQuoted}},
	{`[[ -n "@@" && -f @@x ]]`, []Quoting{DoubleQuoted, Unquoted}},
	{`[[ x =~ ^(a|@@b c)$ ]]`, []Quoting{Unquoted}},
	{"[[ -n x &&\n  \"@@\" == y ]]", []Quoting{DoubleQuoted}},
	{`[[ x ]] > "@@"`, []Quoting{DoubleQuoted}},
	{`[[ @@x ]]`, []Quoting{Unquoted}},
	// where [[ ]] is not read: the place of an operator, or what bash refuses
	{`[[ x @@ y ]]`, []Quoting{QuotingUnknown}},
	{"[[ 1 -eq @@ ]]", []Quoting{QuotingUnknown}}, // nothing there: an operand left out
	{`[[ -n == "@@" ]]`, []Quoting{QuotingUnknown}},
	{`[[ a 2> "@@" ]]`, []Quoting{QuotingUnknown}},
	{`[[ a >& "@@" ]]`, []Quoting{QuotingUnknown}},
	{`[[ a >| "@@" ]]`, []Quoting{QuotingUnknown}},
	{`[[ $(fi) == "@@" ]]`, []Quoting{QuotingUnknown}},
	// no ]] before what ends a command: as any simple command
	{`[[ x == "@@" & ]]`, []Quoting{CommandString}},
	{"[[ x == \"@@\" <<E\nE\n]]", []Quoting{CommandString}},
	// the arithmetic of -v: the subscript; ! before it
	{`[[ -v a[@@x] ]]`, []Quoting{CommandString}},
	{`[[ ! -v "@@" ]]`, []Quoting{CommandString}},
	// a pattern, extglob too, and a regular expression are one word, with
	// blanks inside ( )
	{`[[ "@@" == @(a|b) ]]`, []Quoting{DoubleQuoted}},
	{`[[ "@@" == +([0-9]) && x != !(a b) ]]`, []Quoting{DoubleQuoted}},
	{`[[ ( x =~ a|@@b) ]]`, []Quoting{Unquoted}},
	// after ]]: a here-string is data, a heredoc's body is not code
	{`[[ x ]] <<< "@@"`, []Quoting{DoubleQuoted}},
	{"[[ x ]] <<E\n@@\nE", []Quoting{Heredoc}},
	{`[[ x == "@@" -eq 1 ]]`, []Quoting{QuotingUnknown}},
	{`[[ x <<< "@@" ]]`, []Quoting{QuotingUnknown}},
	{`[[ x == "@@"; ]]`, []Quoting{CommandString}}, // no ]] before the ;
	{"declare -i x=@@", []Quoting{CommandString}},
	// after a $ or a backslash the string would join what is before it
	{`echo "$@@"`, []Quoting{QuotingUnknown}},
	{`echo \@@`, []Quoting{QuotingUnknown}},
	{"cat <<EOF\n$@@\nEOF", []Quoting{QuotingUnknown}},
	// a line continued in an unquoted heredoc, a delimiter with a space
	{"bash <<EOF\necho a\\\nEOF\necho \"@@\"\nEOF", []Quoting{QuotingUnknown}},
	{"cat <<\"E O F\"\n@@\nE O F\necho @@", []Quoting{QuotedHeredoc, Unquoted}},
	// where one quoted word is not what the words were
	{"for x in @@; do :; done", []Quoting{CommandString}}, // no word there: what a word put there would be is not known
	{"case $x in @@) :;; esac", []Quoting{QuotingUnknown}},
	{"select x in @@; do :; done", []Quoting{CommandString}},
	{"select x do @@ &done", []Quoting{CommandString}},
	// the words of for and select are data, read as their quotes say; the
	// name and the arithmetic of for (( ; ; )) are code
	{`for i in a "@@x"; do :; done`, []Quoting{DoubleQuoted}},
	{`for i in a @@x; do :; done`, []Quoting{QuotingUnknown}}, // the words it is split into are what the loop goes over
	{`for i in $(echo @@x); do :; done`, []Quoting{Unquoted}}, // an argument of echo inside: the loop splits what echo writes, before the fix and after it
	{`for i in "$(echo @@x)"; do :; done`, []Quoting{Unquoted}},
	{`for @@x in a; do :; done`, []Quoting{CommandString}},
	{`for (( i=@@x; ; )); do :; done`, []Quoting{CommandString}},
	{"/bin/for @@x", []Quoting{Unquoted}}, // the program /bin/for, not the reserved word
	// a pipe at the end of a line
	{"echo \"@@\" |\nbash", []Quoting{CommandString}},
	{"echo \"@@\" &&\necho @@", []Quoting{DoubleQuoted, Unquoted}},
	{"echo \"@@\" &&\n@@x", []Quoting{DoubleQuoted, CommandString}},
	{`echo "@@" |& bash`, []Quoting{CommandString}},
	{`bash < <(echo "@@")`, []Quoting{CommandString}}, // a <( ) bash reads as code
	{`echo "@@" > >(bash)`, []Quoting{QuotingUnknown}},
	{`python3 -c"@@"`, []Quoting{CommandString}},
	{`perl -e"@@"`, []Quoting{CommandString}},
	{`bash -c"@@"`, []Quoting{DoubleQuoted}}, // bash reads the letters after -c as other options
	{"(( n = @@ ))", []Quoting{CommandString}},
	{`echo $[ @@ ]`, []Quoting{QuotingUnknown}},
	{"declare -i n\nn=@@", []Quoting{QuotingUnknown}},
	{`read -r "@@"`, []Quoting{CommandString}},
	{`printf -v "@@" x`, []Quoting{CommandString}},
	{`docker run img sh -c "@@"`, []Quoting{CommandString}},
	{`kubectl exec p -- python3 -c "@@"`, []Quoting{CommandString}},
	{`docker run img echo "@@"`, []Quoting{DoubleQuoted}},
	// inside a substitution or an expansion the lexer does not follow
	{`echo $(echo @@)`, []Quoting{QuotingUnknown}},
	{"echo `echo @@`", []Quoting{QuotingUnknown}},
	{`echo ${X:-@@}`, []Quoting{QuotingUnknown}},
	{`echo "$(printf '%s' @@)"`, []Quoting{QuotingUnknown}},
	{`echo $(date) @@ "$(date) @@"`, []Quoting{Unquoted, DoubleQuoted}},
	{`echo $((1 + 2)) @@`, []Quoting{Unquoted}},
	{"case $x in a) echo @@;; esac", []Quoting{QuotingUnknown}},
	// a script the lexer cannot follow to its end tells nothing
	{`echo "abc @@`, []Quoting{QuotingUnknown}},
	{"echo @@ 'abc", []Quoting{QuotingUnknown}},
	{"cat <<EOF\n@@", []Quoting{QuotingUnknown}},
	{"echo $(case $x in a) @@;; esac)", []Quoting{QuotingUnknown}},
	{"echo @@>(case x in a) b;; esac)", []Quoting{QuotingUnknown}},
	{"echo @@a >(case x in a) b;; esac)", []Quoting{QuotingUnknown}},
	// 2>&1 does not end the pipeline: a fix that read this as data would
	// leave the injection
	{`echo "@@" 2>&1 | bash`, []Quoting{CommandString}},
	// the body of a heredoc starts on the next line, even when the line
	// goes on with a pipe: the bash there is a line of the body
	{"cat <<EOF |\nbash\n@@\nEOF\ntr a-z A-Z", []Quoting{Heredoc}},
	// a command word or an option with an expansion in it names what is
	// not known until it runs
	{`$(echo)eval "@@"`, []Quoting{CommandString}},
	{`sh $(x)-c "@@"`, []Quoting{CommandString}},
	// assignments, with a substitution or an array in them, with +=, after a
	// line continued: their values are data (bash 5.3.15: A=(a b)x assigns
	// the string "(a b)x")
	{"X=$(id -u)@@\necho a", []Quoting{Unquoted}},
	{"A=(a b)@@\necho a", []Quoting{Unquoted}},
	{"x A=(a)@@", []Quoting{Unquoted}},       // bash refuses the ( of an argument; the fix does not change that
	{"x A=(a) B$(y)@@", []Quoting{Unquoted}}, // so too
	{"X+=@@a", []Quoting{Unquoted}},
	{"X=\"${Y:-$(cmd)}\"@@\necho a", []Quoting{Unquoted}},
	{"A=a \\\nX=@@b cmd", []Quoting{Unquoted}},
	{"X=@@a cmd", []Quoting{Unquoted}},
	{"@@X=a cmd", []Quoting{CommandString}}, // the name decides whether the word is an assignment
	{"A=a \\\nB=b \\\nC=\"@@\" cmd", []Quoting{DoubleQuoted}},
	{"#\\\nA= \\\nB=@@x", []Quoting{Unquoted}}, // the backslash in the comment continues nothing: A= B=x are two assignments
	// an expansion in an argument leaves its letters: they name the option;
	// a command word that is not literal names a command known only when it
	// runs, which may read its arguments as code
	{`python3 x.py --repo "$R" --pr "@@"`, []Quoting{DoubleQuoted}},
	{`python ${P}/x.py --id "@@"`, []Quoting{DoubleQuoted}},
	{`${P}/x.sh "@@"`, []Quoting{CommandString}},
	{`"$BASH" -c "@@x"`, []Quoting{CommandString}},
	{`"$CMD" "@@x"`, []Quoting{CommandString}},
	{`$(x) "@@"`, []Quoting{CommandString}},
	// a function whose body reads the input, after a pipe or with a
	// heredoc, is read as a compound command is
	{`f() { bash; }; echo "@@x" | f`, []Quoting{CommandString}},
	{`f() { read l; eval "$l"; }; echo "@@x" | f`, []Quoting{CommandString}},
	{`f() { echo a; }; echo "@@x" | f`, []Quoting{CommandString}}, // echo receives the input: taken as a reader
	{`f() { :; } < /dev/null; echo "@@x" | f`, []Quoting{DoubleQuoted}},
	{"f() { bash; }; f <<EOF\n@@x\nEOF", []Quoting{CommandString}},
	{`f() { bash; }; f <<< "@@x"`, []Quoting{CommandString}},
	{`echo "@@x" | f; f() { bash; }`, []Quoting{DoubleQuoted}}, // no definition reaches the call: bash runs the program f
	// what the body of a function writes, when the call writes into a
	// reader of code, is code (the whole body, whichever call runs it)
	{`f() { echo "@@x"; }; f | bash`, []Quoting{CommandString}},
	{`f() { echo "@@x"; }; f | cat`, []Quoting{DoubleQuoted}},
	{`g() { echo "@@x"; }; f() { g; }; f | bash`, []Quoting{CommandString}},
	{`f() { echo "@@x" > /dev/null; }; f | bash`, []Quoting{CommandString}}, // the whole body
	{`f() { echo "@@x"; }; f > o | bash`, []Quoting{DoubleQuoted}},          // the call's output does not reach the pipe
	// the output of a substitution read as code
	{`f() { echo "@@x"; }; eval "$(f)"`, []Quoting{CommandString}},
	{`f() { echo "@@x"; }; bash <<< "$(f)"`, []Quoting{CommandString}},
	{`f() { echo "@@x"; }; bash -c "$(f)"`, []Quoting{CommandString}},
	{"f() { echo \"@@x\"; }; bash <<EOF\n$(f)\nEOF", []Quoting{CommandString}},
	{`f() { echo "@@x"; }; echo "$(f)"`, []Quoting{DoubleQuoted}},
	{`f() { echo "@@x"; }; echo "$(f)" | bash`, []Quoting{CommandString}}, // the output of $(f) is a word of what echo writes
	// an argument of a call that the body of the function reads as code
	{`f() { eval "$1"; }; f "@@x"`, []Quoting{CommandString}},
	// the definitions that reach the call (NameVisibility): bash runs the
	// later definition, and a call before the definition runs no function
	{`f() { eval "$1"; }; f() { echo "$1"; }; f "@@x"`, []Quoting{DoubleQuoted}},
	{`f "@@x"; f() { eval "$1"; }`, []Quoting{DoubleQuoted}},
	{`while c; do f "@@x"; f() { eval "$1"; }; done`, []Quoting{CommandString}}, // a later round calls it
	{`f() { bash -c "$@"; }; f a "@@x"`, []Quoting{CommandString}},
	{`f() { eval "$1"; }; f a "@@x"`, []Quoting{CommandString}}, // every argument of a function that reads code
	{`f() { echo "$1"; }; f "@@x"`, []Quoting{DoubleQuoted}},
	{`f() { eval "${2}"; }; f a "@@x"`, []Quoting{CommandString}},
	// shift, a substring of $@, and $@ passed on to a function: every argument
	{`f() { shift; eval "$1"; }; f a "@@x"`, []Quoting{CommandString}},
	{`f() { eval "${@:2}"; }; f a "@@x"`, []Quoting{CommandString}},
	{`f() { eval "${*:1}"; }; f "@@x"`, []Quoting{CommandString}},
	{`g() { eval "$1"; }; f() { g "$@"; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { set -- "$2"; eval "$1"; }; f a "@@x"`, []Quoting{CommandString}},
	{`f() { for a; do eval "$a"; done; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { "$@"; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { bash <(echo "$1"); }; f "@@x"`, []Quoting{CommandString}},
	{`f() { echo $(( $2 )); }; f "@@x" 1`, []Quoting{CommandString}},
	{`f() { echo "$1" > out; }; f "@@x"`, []Quoting{DoubleQuoted}},
	// what VariableCodes reads as code, for any parameter, and a write to a
	// coproc
	{`f() { echo "${a[$1]}"; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { a[$1]=1; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { echo "${x:$1}"; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { echo "${1@P}"; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { echo "${!1}"; }; f "@@x"`, []Quoting{CommandString}},
	// a body that reads only other names as code
	{`f() { echo "${a[$i]}"; echo "$1"; }; f "@@x"`, []Quoting{DoubleQuoted}},
	{`f() { echo "${x:$n}"; echo "$1"; }; f "@@x"`, []Quoting{DoubleQuoted}},
	{`f() { n=0; echo "$1"; }; declare -i k; f "@@x"`, []Quoting{DoubleQuoted}},
	// a name that receives an argument
	{`a=(1); f() { i=$1; echo "${a[$i]}"; }; f "@@x"`, []Quoting{CommandString}},
	{`a=(1); f() { for i; do echo "${a[$i]}"; done; }; f "@@x"`, []Quoting{CommandString}},
	{`a=(1); f() { for i in "$@"; do echo "${a[$i]}"; done; }; f "@@x"`, []Quoting{CommandString}},
	{`b=(1); f() { x=("$@"); echo "${b[${x[0]}]}"; }; f "@@x"`, []Quoting{CommandString}},
	{`a=(1); f() { i=$1; j=$i; echo "${a[$j]}"; }; f "@@x"`, []Quoting{CommandString}},
	// assigns and argNames read the same assignments
	{`declare -i n; f() { export "$1"; }; f "@@x"`, []Quoting{CommandString}},
	{`declare -i k; f() { for k in "$1"; do :; done; }; f "@@x"`, []Quoting{CommandString}},
	{`declare -i n; f() { i=$1; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { for k in "$1"; do eval "$k"; done; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { declare -a x=("$1"); eval "${x[0]}"; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { export "$1"; }; f "@@x"`, []Quoting{DoubleQuoted}},
	{`declare -i k; f() { for k; do :; done; }; f "@@x"`, []Quoting{CommandString}},
	{`declare -i n; f() { n=$1; }; f "@@x"`, []Quoting{CommandString}},
	{`f() { echo "$1" >&${N[1]}; }; coproc N { bash; }; f "@@x"`, []Quoting{CommandString}},
	{`g() { echo "$1"; }; f() { g "$@"; }; f "@@x"`, []Quoting{DoubleQuoted}},
	{`c() { eval "$1"; }; b() { a go "$@"; }; a() { if [ "$1" != go ]; then b "$@"; else c "$2"; fi; }; b "@@x"`, []Quoting{CommandString}}, // a cycle of calls
	{`f() { echo $(( $1 )); }; f "@@x"`, []Quoting{CommandString}},
	// what a command writes to the input of a coproc whose command
	// reads its input, as for a pipe
	{`coproc bash; echo "@@x" >&${COPROC[1]}`, []Quoting{CommandString}},
	{`coproc N { bash; }; echo "@@x" >&"${N[1]}"`, []Quoting{CommandString}},
	{`coproc cat; echo "@@x" >&${COPROC[1]}`, []Quoting{CommandString}}, // cat passes it on: taken as a reader, as in a pipe into a compound
	{`coproc bash; echo "@@x"`, []Quoting{DoubleQuoted}},
	{`coproc bash; echo "@@x" >&${COPROC[0]}`, []Quoting{CommandString}}, // any element of the array is taken
	// a heredoc's body, a compound command, a function and a moved descriptor
	{"coproc bash; cat <<EOF >&${COPROC[1]}\n@@x\nEOF", []Quoting{CommandString}},
	{`coproc N { bash; }; { echo "@@x"; } >&${N[1]}`, []Quoting{CommandString}},
	{`coproc N { bash; }; f() { echo "@@x"; }; f >&${N[1]}`, []Quoting{CommandString}},
	{`coproc bash; echo "@@x" >&${COPROC[1]}-`, []Quoting{CommandString}},
	// any element of the array, written to directly
	{`coproc bash; echo "@@x" > /dev/fd/${COPROC[1]}`, []Quoting{CommandString}},
	{`coproc N { bash; }; echo "@@x" >&${N[1]-}`, []Quoting{CommandString}},
	{`coproc N { bash; }; echo "@@x" 1<&${N[1]}`, []Quoting{CommandString}}, // n<&m copies for output too
	{`coproc N { bash; }; cat 0<&${N[1]}; echo "@@x"`, []Quoting{DoubleQuoted}},
	{`coproc N { bash; }; f() { echo "$1" >&${N[1]}; }; f "@@x"`, []Quoting{CommandString}},
	// a descriptor copied from the array, or a variable that holds one, is not
	// followed: the fix, which a person reviews, may leave the injection
	{`coproc N { bash; }; exec 3>&${N[1]}; echo "@@x" >&3`, []Quoting{DoubleQuoted}},
	{`coproc N { bash; }; fd=${N[1]}; echo "@@x" >&$fd`, []Quoting{DoubleQuoted}},
	{`coproc N { bash; }; exec >&${N[1]}; echo "@@x"`, []Quoting{DoubleQuoted}},
	{`coproc N { :; } < /dev/null; echo "@@x" >&${N[1]}`, []Quoting{DoubleQuoted}}, // the coproc does not read its input
	{`coproc N { bash; }; echo "@@x" >&${M[1]}`, []Quoting{DoubleQuoted}},
	{`coproc { :; } < /dev/null; echo "@@x" >&${COPROC[1]}`, []Quoting{DoubleQuoted}},
	// a brace expansion or a pattern outside quotes in an argument may make
	// the option whose value is code
	{`bash {-c,} "@@x"`, []Quoting{CommandString}},
	{`bash -{c,} "@@x"`, []Quoting{CommandString}},
	{`sh {-c,"@@x"}`, []Quoting{CommandString}},
	{`bash -[c] "@@x"`, []Quoting{CommandString}},
	{`echo {-c,} "@@x"`, []Quoting{DoubleQuoted}}, // echo has no option whose value is code
	{`bash "{-c,}" "@@x"`, []Quoting{DoubleQuoted}},
	{`git {-c,} "core.fsmonitor=@@x" status`, []Quoting{CommandString}}, // an option that names a program
	{`python3 {a,b}.py "@@x"`, []Quoting{CommandString}},
	{`bash ./x{1,2}.sh "@@x"`, []Quoting{CommandString}},
	// -c of bash, sh and dash takes its code from the next word: the letters
	// joined to it are other options
	{`bash -c"@@x"`, []Quoting{DoubleQuoted}},
	{`sh -c"@@x"`, []Quoting{DoubleQuoted}},
	{`bash -cx "@@x"`, []Quoting{CommandString}},
	{`bash -ec "@@x"`, []Quoting{CommandString}},
	{`zsh -c"@@x"`, []Quoting{DoubleQuoted}},
	{`busybox sh -cx "@@x"`, []Quoting{CommandString}},
	// one -p and then one -- after time are part of the reserved word
	{`time -p eval "@@x"`, []Quoting{CommandString}},
	{`time -- eval "@@x"`, []Quoting{CommandString}},
	{`time -p -- eval "@@x"`, []Quoting{CommandString}},
	{`time -p [[ "@@x" -eq 1 ]]`, []Quoting{CommandString}},
	{`time -p {bash,-c} "@@x"`, []Quoting{CommandString}},
	{`time -p echo "@@x"`, []Quoting{DoubleQuoted}},
	{`time -p -p "@@x"`, []Quoting{DoubleQuoted}},      // the command -p, which the rule does not know
	{"time -p\necho \"@@x\"", []Quoting{DoubleQuoted}}, // time -p alone
	{`time -p; echo "@@x"`, []Quoting{DoubleQuoted}},
	{`time || echo "@@x"`, []Quoting{QuotingUnknown}}, // bash refuses the script
	{`time & echo "@@x"`, []Quoting{DoubleQuoted}},
	{`time -p ( echo "@@x" )`, []Quoting{DoubleQuoted}},
	{`time -p ((n=1)); echo "@@x"`, []Quoting{DoubleQuoted}},
	{`time -- ( echo "@@x" )`, []Quoting{DoubleQuoted}},
	{`bash '-'{c,} "@@x"`, []Quoting{CommandString}},
	{`bash \-{c,} "@@x"`, []Quoting{CommandString}},
	{`bash {{-c,},} "@@x"`, []Quoting{CommandString}},
	// a brace expansion or a pattern outside quotes in the command word: bash
	// makes the command when it runs
	{`{bash,-c} "@@x"`, []Quoting{CommandString}},
	{`{eval,} "@@x"`, []Quoting{CommandString}},
	{`ev{a..a}l "@@x"`, []Quoting{CommandString}},
	{`/bin/ba?h -c "@@x"`, []Quoting{CommandString}},
	{`/bin/ba[s]h -c "@@x"`, []Quoting{CommandString}},
	{`/bin/*sh -c "@@x"`, []Quoting{CommandString}},
	{`[ "@@x" = a ]`, []Quoting{DoubleQuoted}}, // the command test
	{`"{bash,-c}" "@@x"`, []Quoting{DoubleQuoted}},
	{`\{bash,-c} "@@x"`, []Quoting{DoubleQuoted}},
	{`ba\*sh "@@x"`, []Quoting{DoubleQuoted}},
	{`{a} "@@x"`, []Quoting{DoubleQuoted}},
	{`echo{ "@@x"`, []Quoting{DoubleQuoted}},
	{`./x{y..}.sh "@@x"`, []Quoting{DoubleQuoted}}, // not a sequence: bash leaves {y..}
	{`./[] "@@x"`, []Quoting{DoubleQuoted}},        // [] is not a bracket expression
	{`./a[1].sh "@@x"`, []Quoting{CommandString}},
	// the target of a redirect is a file, not an option: sh reads "@@" as the
	// name of its script
	{`sh <-c "@@"`, []Quoting{DoubleQuoted}},
	{`sh 0$(x)-c "@@"`, []Quoting{DoubleQuoted}}, // the word starts with 0: no option
	// $$ and then {, [ or ': bash reads $$ (5.3.15: echo $${a} prints the
	// number and {a}); a # inside $(( )), or after the ) of a substitution,
	// is no comment
	{"0 $${ @@", []Quoting{Unquoted}},
	{"0 $$[ @@", []Quoting{Unquoted}},
	{"echo $(( 1 # x )) @@", []Quoting{Unquoted}},
	{"echo $(a$(b)#c) @@", []Quoting{Unquoted}},
	{`echo $(( 16#ff)) "@@"`, []Quoting{DoubleQuoted}},
	{`echo $((1 +16#ff)) "@@"`, []Quoting{DoubleQuoted}},
	{"echo $((1 <<\n2)) \"@@\"", []Quoting{DoubleQuoted}},
	{"echo \"${X:-$(#)}\" @@", []Quoting{QuotingUnknown}},
	// a quoted reserved word is a command name; a command word that is not
	// literal reads its input as code; the target of a redirect is a file
	{`"!" "@@"`, []Quoting{DoubleQuoted}},
	{"\"!\" <<EOF\n@@\nEOF", []Quoting{Heredoc}},
	{"\"'\" <<EOF\n@@\nEOF", []Quoting{Heredoc}},
	{"\"$(x)y\" <<EOF\n@@\nEOF", []Quoting{CommandString}},
	{`<. x "@@"`, []Quoting{DoubleQuoted}},     // the redirect fails, and x does not run
	{`> >let x "@@"`, []Quoting{DoubleQuoted}}, // bash refuses it; the fix does not change that
	{`<. A=@@x`, []Quoting{Unquoted}},
	{`<<<"" x "@@"`, []Quoting{CommandString}},
	{`<(x) @@y`, []Quoting{CommandString}},
	{`echo "@@" >|sh`, []Quoting{DoubleQuoted}}, // >| writes to the file sh
	{`""A= @@x`, []Quoting{Unquoted}},           // ""A= is a command name, not an assignment
	{"\\A= \\\nA0=@@0", []Quoting{Unquoted}},
	{`echo | A=@@x <bash`, []Quoting{Unquoted}}, // no command: nothing reads the pipe
	{`echo "@@" |<<<bash`, []Quoting{DoubleQuoted}},
	{`echo "@@" |<bash >&2`, []Quoting{DoubleQuoted}},
	{`echo | bash x.sh "@@"`, []Quoting{DoubleQuoted}},
	// the target of a redirect is the name of a file (redirect-target)
	{`{ echo a; } >> @@""`, []Quoting{Unquoted}},
	{`> @@"" echo a`, []Quoting{Unquoted}},
	{`yarn lint &>@@ /tmp/f`, []Quoting{Unquoted}},
	{`yarn lint &> @@`, []Quoting{Unquoted}},
	// a # after the ) of a substitution is in the word, not a comment
	{`echo 0$(true)#@@ "b"`, []Quoting{Unquoted}},
	{`echo 0$(true)#a "@@"`, []Quoting{DoubleQuoted}},
	// a # right after a line continued starts a comment
	{"echo a \\\n#@@ b", []Quoting{Comment}},
	{`python3.12 -c "@@"`, []Quoting{CommandString}},
	{`/usr/bin/bash -c "@@"`, []Quoting{CommandString}},
	{`bash -ec "@@"`, []Quoting{CommandString}},
	{`node --eval "@@"`, []Quoting{CommandString}},
	{`node --eval="@@"`, []Quoting{CommandString}},
	{`xargs python -c "@@"`, []Quoting{CommandString}},
	{`xargs printf -v "@@" x`, []Quoting{DoubleQuoted}},
	{`echo "@@" | source /dev/stdin`, []Quoting{CommandString}},
	{". /dev/stdin <<EOF\n@@\nEOF", []Quoting{CommandString}},
	{`builtin eval "@@"`, []Quoting{CommandString}},
	{`[ -v "@@" ]`, []Quoting{CommandString}},
	{`test -v "@@"`, []Quoting{CommandString}},
	{`test "@@" = x`, []Quoting{DoubleQuoted}},
	{`echo x | perl -ne "@@"`, []Quoting{CommandString}},
	{`echo x | ruby -ne "@@"`, []Quoting{CommandString}},
	{`php -nr "@@"`, []Quoting{CommandString}},
	{`bun --eval="@@"`, []Quoting{CommandString}},
	{`git -c core.fsmonitor="@@" status`, []Quoting{CommandString}},
	{`git -c "@@" status`, []Quoting{CommandString}},
	{`git -c user.name=x commit -m "@@"`, []Quoting{DoubleQuoted}},
	{`git --exec-path="@@" status`, []Quoting{CommandString}},
	{`setsid foo "@@"`, []Quoting{CommandString}},
	// git's options before the subcommand are not read after it
	{`git grep -c "@@"`, []Quoting{DoubleQuoted}},
	{`git log -c "@@"`, []Quoting{DoubleQuoted}},
	{`git -C dir -c "@@" status`, []Quoting{CommandString}},
	{`git --no-pager -c "@@" status`, []Quoting{CommandString}},
	{`git --frob x -c "@@" status`, []Quoting{CommandString}},
	// the standard input of a wrapper goes to the command it runs
	{`echo "@@" | setsid bash`, []Quoting{CommandString}},
	{"builtin source /dev/stdin <<EOF\n@@\nEOF", []Quoting{CommandString}},
	// coproc runs the command after it (and after its name)
	{`coproc @@x`, []Quoting{CommandString}},
	{`coproc N { @@x; }`, []Quoting{CommandString}},
	{`coproc @@x { a; }`, []Quoting{CommandString}},
	{`coproc a "@@"`, []Quoting{DoubleQuoted}},
	{`coproc a @@`, []Quoting{Unquoted}},
	{`coproc N { a; }; echo @@`, []Quoting{Unquoted}},
	{`"coproc" @@x`, []Quoting{Unquoted}},
	{`a=1 coproc @@x`, []Quoting{Unquoted}},
	{`coproc time @@x`, []Quoting{CommandString}},  // time is a program there, which runs its operand
	{`coproc echo @@ | bash`, []Quoting{Unquoted}}, // a coproc writes nothing to the pipe of the pipeline
	{`coproc echo @@ | cat | bash`, []Quoting{Unquoted}},
	{`coproc x | echo @@ | bash`, []Quoting{CommandString}}, // what comes after the coproc does
	{`echo @@ | coproc cat`, []Quoting{Unquoted}},           // a coproc does not read the pipe of the pipeline
	// places that must give no fix: a reader of code takes what is written
	// there as code, whatever the quotes inside say
	{"{ cat; } <<EOF\n@@\nEOF", []Quoting{CommandString}}, // a compound in which a command reads the input is taken as a reader
	// the heredoc of if, while and for, read as that of { }
	{"while true; do bash; break; done <<EOF\n@@x\nEOF", []Quoting{CommandString}},
	{"while read l; do eval \"$l\"; done <<EOF\n@@x\nEOF", []Quoting{CommandString}},
	{"if true; then bash; fi <<EOF\n@@x\nEOF", []Quoting{CommandString}},
	{"if true; then bash; fi <<< \"@@x\"", []Quoting{CommandString}},
	{"if true; then echo a; fi <<EOF\n@@x\nEOF", []Quoting{CommandString}}, // echo receives the input, as | { echo hi; } does: taken as a reader
	{"{ echo a; } <<< \"@@x\"", []Quoting{CommandString}},
	{"if true; then :; fi > f <<EOF\n@@x\nEOF", []Quoting{CommandString}},
	{"{ read -r l; eval \"$l\"; } <<EOF\n@@\nEOF", []Quoting{CommandString}},
	// a heredoc or a here-string to a descriptor other than 0: a command can
	// make the descriptor its input (bash 0<&3), which is not followed; the
	// text is code
	{"{ bash 0<&3; } 3<<< \"@@x\"", []Quoting{CommandString}},
	{"{ bash <&3; } 3<<EOF\n@@x\nEOF", []Quoting{CommandString}},
	{"bash 0<&3 3<<< \"@@x\"", []Quoting{CommandString}},
	{"cat 3<<EOF\n@@x\nEOF", []Quoting{CommandString}},
	{"{ cat; } {fd}<<< \"@@x\"", []Quoting{CommandString}},
	{"cat 0<<< \"@@x\"", []Quoting{DoubleQuoted}},
	{"1000<<<\"@@x\" . /dev/fd/1000", []Quoting{CommandString}}, // any number bash takes as a descriptor
	{"0003<<<\"@@x\" . /dev/fd/3", []Quoting{CommandString}},
	// a redirect's target is not the command word: A=x <bash reads the file
	// bash and runs no command
	{"echo \"@@x\" | A=x <bash", []Quoting{DoubleQuoted}},
	// the words after the operator of a ${ } in a heredoc's body
	{"cat <<EOF\n${x:-@@x}\nEOF", []Quoting{QuotingUnknown}},
	{`$(echo eval) "@@"`, []Quoting{CommandString}}, // a command word that is not literal may name eval
	{`echo $(( @@ ))`, []Quoting{CommandString}},
	{`eval "$(echo "@@")"`, []Quoting{CommandString}},
	{`bash -c "$(echo "@@")"`, []Quoting{CommandString}},
	{`bash <<< "$(echo "@@")"`, []Quoting{CommandString}},
	{`$(echo "@@")`, []Quoting{CommandString}},
	{"`echo \"@@\"`", []Quoting{CommandString}},
	{"cat <<EOF\n$(eval \"@@\")\nEOF", []Quoting{CommandString}},
	// a line of a heredoc's body with an expansion: outside it, the body;
	// inside it, as inside a substitution; inside the body of a reader of
	// code, code
	{"cat <<EOF\n$(date) @@x\nEOF", []Quoting{Heredoc}},
	{"cat <<EOF\n$(echo @@x)\nEOF", []Quoting{Unquoted}},
	{"cat <<EOF\n`echo \"@@x\"`\nEOF", []Quoting{DoubleQuoted}},
	{"cat <<EOF\n$(eval \"@@x\")\nEOF", []Quoting{CommandString}},
	{"bash <<EOF\n$(echo @@x) a\nEOF", []Quoting{CommandString}},
	{"bash <<EOF\n$(date) @@x\nEOF", []Quoting{CommandString}},
	{"cat <<EOF\n${x:-@@x}\nEOF", []Quoting{QuotingUnknown}}, // no word there: not read
	{`declare -i n; n=$(echo "@@")`, []Quoting{CommandString}},
	{`bash <(echo "@@")`, []Quoting{CommandString}},
	{`source <(echo "@@")`, []Quoting{CommandString}}, // source reads its operand as code
	// a <( ) whose file a reader of code reads, as its operand or its
	// standard input, is code; the file of another is not followed (exec,
	// read and mapfile may pass it on to code)
	{`bash <(echo "@@x")`, []Quoting{CommandString}},
	{`bash < <(echo "@@x")`, []Quoting{CommandString}},
	{`bash -s < <(echo "@@x")`, []Quoting{CommandString}},
	{`source /dev/stdin < <(echo "@@x")`, []Quoting{CommandString}},
	{`python3 <(echo "@@x")`, []Quoting{CommandString}},
	{`diff <(echo "@@x") f`, []Quoting{QuotingUnknown}},
	{`cat < <(echo "@@x")`, []Quoting{QuotingUnknown}},
	{`exec < <(echo "@@x"); bash`, []Quoting{CommandString}}, // exec gives its input to the shell
	{`mapfile -t a < <(echo "@@x"); eval "${a[0]}"`, []Quoting{QuotingUnknown}},
	{`{ read -r l; eval "$l"; } < <(echo "@@x")`, []Quoting{QuotingUnknown}},
	{`awk -f <(echo "@@x")`, []Quoting{QuotingUnknown}},
	{`bash --rcfile <(echo "@@x")`, []Quoting{CommandString}},
	{`echo $(( $(echo "@@x") ))`, []Quoting{CommandString}},
	{`echo ${X:$(echo "@@x")}`, []Quoting{CommandString}},
	{`echo ${a[$(echo "@@x")]}`, []Quoting{CommandString}},
	{`for ((i=$(echo "@@x"); ;)); do :; done`, []Quoting{CommandString}},
	// inside a substitution, a place is read by the quotes and the word
	// around it inside, unless a word around it outside is code (nested)
	{`echo $(echo @@x)`, []Quoting{Unquoted}},
	{`echo "$(echo "@@x")"`, []Quoting{DoubleQuoted}},
	{`echo "$(echo @@x)"`, []Quoting{Unquoted}},
	{`echo "$(echo '@@x')"`, []Quoting{SingleQuoted}},
	{"echo `echo @@x`", []Quoting{Unquoted}},
	{"echo \"`echo \\\"@@x\\\"`\"", []Quoting{DoubleQuoted}},
	{`cat <<< "$(echo "@@x")"`, []Quoting{DoubleQuoted}},
	{`echo $(@@x a)`, []Quoting{CommandString}},
	{`echo "$(eval "@@x")"`, []Quoting{CommandString}},
	{`echo $(echo "@@x" | bash)`, []Quoting{CommandString}},
	{`eval "$(echo "@@x")"`, []Quoting{CommandString}},
	{`eval "$(echo "$(echo "@@x")")"`, []Quoting{CommandString}},
	{"eval \"`echo @@x`\"", []Quoting{CommandString}},
	{`echo "$(echo "@@x")" | bash`, []Quoting{CommandString}},
	// the words of :-, :=, :? and :+ are values, read as their quotes say;
	// arithmetic, a subscript, an offset and a length are code; a pattern
	// and a replacement are not read here
	{`echo $(echo ${X:-@@x})`, []Quoting{Unquoted}},
	{`echo "${x:-@@x}"`, []Quoting{DoubleQuoted}},
	{`echo ${x:=@@x}`, []Quoting{Unquoted}},
	{`echo "${x/@@x/b}"`, []Quoting{QuotingUnknown}},
	{`echo "${x/a/@@x}"`, []Quoting{QuotingUnknown}},
	{`echo $(( @@x ))`, []Quoting{CommandString}},
	{`echo "$(( $(echo @@x) ))"`, []Quoting{CommandString}},
	{`echo ${x:@@x:1}`, []Quoting{CommandString}},
	{`echo "${a[@@x]}"`, []Quoting{CommandString}},
	{`echo "${x:-${a[@@x]}}"`, []Quoting{CommandString}},
	{`eval "${x:-@@x}"`, []Quoting{CommandString}},
	{`$(echo "@@x")`, []Quoting{CommandString}},
	{`declare -i n; n=$(echo "@@x")`, []Quoting{CommandString}},
	// the other ways to assign to a variable that may be an integer: the value
	// is arithmetic
	{"declare -i n; : \"${n:=@@x}\"", []Quoting{CommandString}},
	{"declare -i n; : \"${n=@@x}\"", []Quoting{CommandString}},
	{"declare -i n; : \"${n:-@@x}\"", []Quoting{DoubleQuoted}},
	{"declare -i n; for n in \"@@x\"; do :; done", []Quoting{QuotingUnknown}},
	{"declare -i n; for m in a; do echo \"$(for n in \"@@x\"; do :; done)\"; done", []Quoting{CommandString}},
	{"declare -i n; export n=\"@@x\"", []Quoting{CommandString}},
	{"declare -i n; export n=$(echo \"@@x\")", []Quoting{CommandString}},
	{"declare -i n; builtin readonly n=\"@@x\"", []Quoting{CommandString}},
	{"declare -i n; export \"@@x\"", []Quoting{CommandString}}, // the value n=a[$(cmd)] assigns
	{"declare -i n; export \"n=@@x\"", []Quoting{CommandString}},
	{"declare -i n; readonly N=a \"n=@@x\"", []Quoting{CommandString}},
	{"export n=\"@@x\"", []Quoting{DoubleQuoted}},
	{": \"${n:=@@x}\"", []Quoting{DoubleQuoted}},
	{"for n in \"@@x\"; do :; done", []Quoting{DoubleQuoted}},
}

func TestContexts(t *testing.T) {
	for _, c := range contextCases {
		src, at := marked(c.src)
		got := Quotings(src, at)
		if len(got) != len(c.want) {
			t.Errorf("%q: %v, want %v", c.src, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: %v, want %v", c.src, got, c.want)
				break
			}
		}
	}
}

func TestContextsBeyondTheScript(t *testing.T) {
	if got := Quotings("echo a", []int{5, 6, 9}); got[0] != Unquoted || got[1] != Unquoted || got[2] != QuotingUnknown {
		t.Errorf("got %v", got)
	}
}

// TestContextsLarge: the quotings of large scripts: a script of 1 MB, many
// unclosed [[, many places inside substitutions, and a quote never closed.
// The time of the places inside substitutions is compared with
// ACTIONS_SCALE=1 only, as it depends on the machine (run it alone, go test
// -p 1, without -race); the quotings are checked in every run.
func TestContextsLarge(t *testing.T) {
	src := strings.Repeat("echo \"a $(date) b\" 'c' <<<x # d\n", 1<<15)
	at := []int{0, len(src) / 2, len(src) - 1}
	if got := Quotings(src, at); len(got) != 3 || got[0] != CommandString { // the first echo
		t.Errorf("got %v", got)
	}
	// a [[ with no ]], many times over
	if got := Quotings(strings.Repeat("[[ a\n", 1<<16), []int{0}); got[0] != CommandString {
		t.Errorf("got %v", got)
	}
	// many places inside substitutions: time linear in them (16,000 took 46 s
	// when each place scanned every part)
	line := `echo "$(echo "@@x")"` + "\n"
	many, at := marked(strings.Repeat(line, 1<<14))
	start := time.Now()
	if got := Quotings(many, at); got[len(got)-1] != DoubleQuoted {
		t.Errorf("got %v", got[len(got)-1])
	}
	if d := time.Since(start); os.Getenv("ACTIONS_SCALE") == "1" && d > 5*time.Second {
		t.Errorf("%d places inside substitutions took %v", len(at), d)
	}
	open := "echo \"" + strings.Repeat("a", 1<<20)
	if got := Quotings(open, []int{len(open) - 1}); got[0] != QuotingUnknown {
		t.Errorf("got %v", got)
	}
}

// TestContextsFunctionsTime: Quotings reads many calls of functions in time
// linear in them: a body of 4,000 commands called after a pipe, before a
// reader of code and with a here-string 4,000 times each, and a chain of
// 1,000 functions (46 to 70 s when each call read the body again). The test
// checks only the time, so it runs with ACTIONS_SCALE=1 only, as the time
// depends on the machine (run it alone, go test -p 1, without -race).
func TestContextsFunctionsTime(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of Quotings on many calls of functions")
	}
	body := "f() {\n" + strings.Repeat("  echo a\n", 4000) + "}\n"
	chain := ""
	for i := range 1000 {
		chain += fmt.Sprintf("g%d() { g%d; }\n", i, i+1)
	}
	// a body that assigns a chain of 6,000 names from the last to the first
	// and 2,000 arrays (each pass over the body marked one name)
	assignChain := "h() {\n"
	for i := 6000; i > 0; i-- {
		assignChain += fmt.Sprintf("  x%d=$x%d\n", i, i-1)
	}
	assignChain += "  x0=$1\n" + strings.Repeat("  a=(\"$x6000\" b)\n", 2000) + "  eval \"$a\"\n}\n"
	for _, c := range []struct{ name, src string }{
		{"echo x | f", body + strings.Repeat("echo \"@@x\" | f\n", 4000)},
		{"f | bash", body + strings.Repeat("f | bash\necho \"@@x\"\n", 4000)},
		{"f <<< x", body + strings.Repeat("f <<< \"@@x\"\n", 4000)},
		{"a chain", chain + strings.Repeat("g0 | bash\necho \"@@x\"\n", 1000)},
		{"many definitions of one name", strings.Repeat("f() { eval \"$1\"; }\n", 2000) + strings.Repeat("f \"@@x\""+strings.Repeat(" a", 50)+"\n", 2000)},
		{"writes to a coproc's input", "coproc N { bash; }\n" + strings.Repeat("w=1\necho \"@@x\" >&${N[1]}\n", 4000)},
		{"a chain of assignments", assignChain + strings.Repeat("h \"@@x\"\n", 100)},
		{"recursive definitions", strings.Repeat("f() { f \"$@\"; g; }\n", 2000) + strings.Repeat("f | bash\nf \"@@x\"\n", 2000)},
	} {
		src, at := marked(c.src)
		start := time.Now()
		Quotings(src, at)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: %v", c.name, d)
		}
	}
}

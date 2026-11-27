package shell

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// isOut names the files of these tests: $OUT and ${OUT}, quoted or not.
func isOut(w Word) bool {
	return len(w.Parts) == 1 && w.Parts[0].Kind == PartParam && w.Parts[0].Name.String() == "OUT"
}

// holes are the ranges of the xxx of src: each run of x's stands for a ${{ }}.
func holes(src string) []Span {
	var out []Span
	for i := 0; i < len(src); {
		if !strings.HasPrefix(src[i:], "xxx") {
			i++
			continue
		}
		j := i
		for j < len(src) && src[j] == 'x' {
			j++
		}
		out = append(out, Span{i, j})
		i = j
	}
	return out
}

// dumpWrites writes the writes of src to $OUT on a line each: its pieces,
// a literal as "text" (\n for a line break), a hole as H, a parameter as
// $NAME, a substitution as $(), a value not read as ?, a command not known
// as !cmd; Exec as EXEC; Top as T when the command is an item of the list.
func dumpWrites(src string, o WriteOptions) string {
	sc := Parse(src)
	if o.Target == nil {
		o.Target = isOut
	}
	o.Holes = holes(src)
	var lines []string
	for _, w := range Writes(src, sc, o) {
		if w.Log {
			continue // dumpLog reads these
		}
		var b strings.Builder
		if w.At == w.Top {
			b.WriteString("T ")
		}
		if w.Exec {
			b.WriteString("EXEC")
		}
		for _, x := range w.Out {
			switch x.Kind {
			case OutLit:
				fmt.Fprintf(&b, "%q", x.Text)
			case OutHole:
				b.WriteString("H")
			case OutParam:
				b.WriteString("$" + x.Part.Name.String())
			case OutSubst:
				b.WriteString("$()")
			case OutOpaque:
				b.WriteString("?")
			case OutUnknown:
				b.WriteString("!" + strings.Fields(src[x.Span.Start:x.Span.End])[0])
			}
			b.WriteString(" ")
		}
		lines = append(lines, strings.TrimSpace(b.String()))
	}
	return strings.Join(lines, " | ")
}

func TestWrites(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`echo "t=$T" >> "$OUT"`, `T "t=" $T "\n"`},
		// {name} before a redirect: the descriptor name holds, which stays
		// after the command; >&$name, ">&${name}" write to it
		{"exec {fd}>>\"$OUT\"\necho \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"echo hi {fd}>>\"$OUT\"; echo \"t=$T\" >&\"$fd\"", `T "t=" $T "\n"`}, // hi goes to the standard output
		{"exec {fd}>>\"$OUT\"; echo \"t=$T\" >&${fd}", `T "t=" $T "\n"`},
		{"exec {fd}>>\"$OUT\"; exec {fd}>&-; echo \"t=$T\" >&$fd", ``},
		{"exec {fd}>>\"$OUT\"; fd=2; echo \"t=$T\" >&$fd", ``},
		{"( exec {fd}>>\"$OUT\" ); echo \"t=$T\" >&$fd", ``},
		// {name} on a compound command stays after it, but on ( ... ) (bash
		// 5.3)
		{"{ :; } {fd}>>\"$OUT\"; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"if true; then :; fi {fd}>>\"$OUT\"; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"while false; do :; done {fd}>>\"$OUT\"; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"( : ) {fd}>>\"$OUT\"; echo \"t=$T\" >&$fd", ``},
		// a descriptor opened on one path still names the file
		{"if c; then exec {fd}>>\"$OUT\"; fi; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		// a read of many v+=x in a loop does not keep later reads from their
		// values
		{"v=; while c; do v+=1; v+=2; v+=3; v+=4; v+=5; v+=6; v+=7; v+=8; echo a >&$v; done\nexec {fd}>>\"$OUT\"; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		// /dev/stderr as the value of v names where 2 points
		{"exec 2>>\"$OUT\"; v=/dev/stderr; echo \"t=$T\" >&$v", `T EXEC | T "t=" $T "\n"`},
		// the values of v+=x in a loop
		{"exec 34>>\"$OUT\"; v=; while c; do v+=3; v+=4; done; echo \"t=$T\" >&$v", `T "t=" $T "\n"`},
		{`echo "t=xxxxxx" >> $OUT`, `T "t=" H "\n"`},
		{`echo a b > "${OUT}"`, `T "a" " " "b" "\n"`},
		{`echo -n "t=$T" >> "$OUT"`, `T "t=" $T`},
		{`echo -e "t=$T" >> "$OUT"`, `T !echo`},
		{`printf 'k=%s\n' "$T" >> "$OUT"`, `T "k=" $T "\n"`},
		{`printf '%s=%s\n' a "$T" b "$U" >> "$OUT"`, `T "a" "=" $T "\n" "b" "=" $U "\n"`},
		{`printf '%d\n' "$T" >> "$OUT"`, `T !printf`},
		{`printf '%s %s\n' "$T" >> "$OUT"`, `T $T " " "\n"`},
		{"cat <<EOF >> \"$OUT\"\nk=$T\nEOF", `T "k=" $T "\n"`},
		{"cat <<'EOF' >> \"$OUT\"\nk=$T\nEOF", `T "k=$T\n"`},
		{`cat <<< "k=$T" >> "$OUT"`, `T "k=" $T "\n"`},
		{`cat f >> "$OUT"`, `T !cat`},
		{`jq -r .x <<< "$T" >> "$OUT"`, `T !jq`},
		{"{\n  echo \"a=$A\"\n  echo \"b<<EOF\"\n  echo \"$B\"\n  echo EOF\n} >> \"$OUT\"",
			`T "a=" $A "\n" "b<<EOF" "\n" $B "\n" "EOF" "\n"`},
		{`{ date; echo "a=$A"; } >> "$OUT"`, `T !date "a=" $A "\n"`},
		{`{ echo x >&2; echo "a=$A"; } >> "$OUT"`, `T "a=" $A "\n"`},
		{`echo "a=$A" | tee -a "$OUT"`, `"a=" $A "\n"`},
		{`echo "a=$A" | tee -a "$OUT" "${OUT}"`, `"a=" $A "\n" | "a=" $A "\n"`},
		{`echo "a=$A" | tee "$OUT" >/dev/null`, `"a=" $A "\n"`},
		{`if true; then echo "a=$A"; fi >> "$OUT"`, `T !true "a=" $A "\n"`},
		{`case $x in a) echo "a=$A";; esac >> "$OUT"`, `T !case`},
		{`echo "a=$(echo "$A" | tr -d '\n')" >> "$OUT"`, `T "a=" $() "\n"`},
		{"echo \"a=`id`\" >> \"$OUT\"", `T "a=" $() "\n"`}, // ` ` is a substitution as $( ) is
		{`exec >> "$OUT"`, `T EXEC`},
		{`true && echo "a=$A" >> "$OUT"`, `"a=" $A "\n"`},
		{`x=$(echo "a=$A" >> "$OUT")`, `"a=" $A "\n"`},
		{`echo "a=\"$A\"\\" >> "$OUT"`, `T "a=\"" $A "\"\\" "\n"`},
		{`echo $'a\nb' >> "$OUT"`, `T !echo`},
		{`echo "a=$A" >> other`, ``},
		{`[[ a > "$OUT" ]]`, ``}, // > compares inside [[ ]]
		// what a pipe gives a command not known is its input
		{`echo "t=$T" | sed 's/a/b/' >> "$OUT"`, `!echo`},
		{`echo "t=$T" | tr a b | tee -a "$OUT"`, `!echo`},
		{`echo "t=$T" | { read x; echo "t=$x"; } >> "$OUT"`, `!echo`},
		// bash splits an unquoted value into more arguments
		{`printf '%s=%s\n' k $T >> "$OUT"`, `T !printf`},
		// >& with a file is &>
		{`echo a >& "$OUT"`, `T "a" "\n"`},
		{`echo a >& 2`, ``},
		// where the descriptors of a command point, in order
		{`echo a 2>> "$OUT" >&2`, `T "a" "\n"`},
		{`echo a >&2 2>> "$OUT"`, ``},
		{"exec 3>> \"$OUT\"\necho a >&3", `T "a" "\n"`},
		{"exec > >(tee -a \"$OUT\")\necho a", `T EXEC`},
		{`f() { echo "a=$A"; }; f >> "$OUT"`, `T "a=" $A "\n"`},
		// exec opens a descriptor in the shell that runs it, which a
		// subshell, a command of a pipeline and a function not called are
		// not
		{"{ exec 3>> \"$OUT\"; }\necho a >&3", `T "a" "\n"`},
		{"if true; then exec 3>> \"$OUT\"; fi\necho a >&3", `T "a" "\n"`},
		{"for i in 1; do exec 3>> \"$OUT\"; done\necho a >&3", `T "a" "\n"`},
		{"case x in x) exec 3>> \"$OUT\";; esac\necho a >&3", ``}, // the parser does not read inside a case (the undetected form case-arm)
		{"f() { exec 3>> \"$OUT\"; }\nf\necho a >&3", `T "a" "\n"`},
		{"f() { exec 3>> \"$OUT\"; }\necho a >&3", ``},    // not called
		{"( exec 3>> \"$OUT\" )\necho a >&3", ``},         // a subshell
		{"coproc { exec 3>> \"$OUT\"; }\necho a >&3", ``}, // a coproc runs in a subshell
		{"coproc { echo a >> \"$OUT\"; }", `"a" "\n"`},
		{"coproc echo a >> \"$OUT\"", `"a" "\n"`},
		{"echo \"t=$T\" | coproc cat >> \"$OUT\"", `!cat`}, // a coproc does not read the pipe of the pipeline
		{"coproc echo \"t=$T\" | cat >> \"$OUT\"", `!cat`}, // nor writes to it
		{"coproc echo \"t=$T\" | cat | cat >> \"$OUT\"", `!cat`},
		{"( g() { echo \"t=$T\"; }; g ) >> \"$OUT\"", `T "t=" $T "\n"`},   // a function a subshell defines and calls
		{"echo \"V=$T\" | coproc { :; } | cat | tee -a \"$OUT\"", `!cat`}, // what echo writes does not reach tee
		{"echo \"V=$T\" > f | tee -a \"$OUT\"", ``},                       // echo writes to f, not to the pipe (PipeSources)
		{"echo \"V=$T\" > f | cat | tee -a \"$OUT\"", `!cat`},
		{"coproc \"$(echo a >> \"$OUT\")\" { :; }", `"a" "\n"`}, // bash expands the name in the shell
		{"exec 3>> \"$OUT\" | true\necho a >&3", ``},            // exec in a pipeline
		// bash 5.3: exec -- and command exec keep their redirects, builtin
		// exec does not, and >&3- moves 3 for the command alone
		{"exec -- 3>> \"$OUT\"\necho a >&3", `T "a" "\n"`},
		{"command exec 3>> \"$OUT\"\necho a >&3", `T "a" "\n"`},
		{"builtin exec 3>> \"$OUT\"\necho a >&3", ``},
		{"exec 3>> \"$OUT\"\necho a >&3-", `T "a" "\n"`},
		{"exec 3>> \"$OUT\"\nexec 4>&3-\necho a >&3", ``},                                  // the move closes 3
		{"exec 3>> \"$OUT\" & wait\necho a >&3", ``},                                       // & runs it in a subshell
		{"exec 3>> \"$OUT\" | echo \"X=$T\" >&3", ``},                                      // each command of a pipeline runs in a subshell of its own
		{"shopt -s lastpipe\ntrue | exec 3>> \"$OUT\"\necho a >&3", `T "a" "\n"`},          // the last command runs in the shell
		{"if false; then shopt -s lastpipe; fi\ntrue | exec 3>> \"$OUT\"\necho a >&3", ``}, // a shopt that may not run is not followed
		{"{ exec 3>> \"$OUT\"; } 4>/dev/null\necho a >&3", `T "a" "\n"`},                   // the brace's own redirect stays inside
		{"{ exec 3>&4; } 4>> \"$OUT\"\necho a >&3", `T "a" "\n"`},                          // brace dup of its redirect
		{"exec 3>> \"$OUT\"\n{ exec 3>&-; }\necho a >&3", ``},                              // closed inside a brace
		{"g() { f; }\nf() { exec 3>> \"$OUT\"; }\ng\necho a >&3", `T "a" "\n"`},            // nested call
		{"f() { exec 3>> \"$OUT\"; f; }\nf\necho a >&3", `T "a" "\n"`},                     // recursive call
		{"f() { exec 3>> \"$OUT\"; echo a >&3; }", `"a" "\n"`},                             // inside the body
		// the body runs where it is called, with the descriptors there
		{"exec 3>> \"$OUT\"\nf() { echo a >&3; }\n( exec 3>&-; f )", ``},
		{"f() { echo a >&3; }\nexec 3>> \"$OUT\"\nf", `"a" "\n"`}, // in the body: not the top command
		{"f\nf() { echo a >> \"$OUT\"; }", ``},                    // called before it is defined
		// what a compound's or a call's own redirects point is restored after
		// it, whatever an exec inside did to it
		{"{ exec 3>> \"$OUT\"; } 3>/dev/null\necho a >&3", ``},
		{"f() { exec 3>> \"$OUT\"; }\nf 3>/dev/null\necho a >&3", ``},
		{"exec 3>> \"$OUT\"\n{ exec 3>/dev/null; } 3>/dev/null\necho a >&3", `T "a" "\n"`},
		{"while true; do exec 3>> \"$OUT\"; break; done 3>/dev/null\necho a >&3", ``},
		{"f() { exec 3>&1; }\nf >> \"$OUT\"\necho a >&3", `T | T "a" "\n"`}, // the call writes nothing itself
		{"f() { exec 3>&4; } 4>> \"$OUT\"\nf\necho a >&3", `T "a" "\n"`},
		{"{ exec 2>> \"$OUT\"; } 2>/dev/null\necho a >&2", `EXEC`},
		// a substitution runs in a subshell
		{"x=$(exec 3>> \"$OUT\")\necho a >&3", ``},
		{"cat <(exec 3>> \"$OUT\")\necho a >&3", ``},
		{"echo x > >(exec 3>> \"$OUT\")\necho a >&3", ``},
	} {
		if got := dumpWrites(c.src, WriteOptions{}); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

// TestWritesTargets: the last redirect of the standard output decides.
func TestWritesTargets(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`echo a >> $OUT`, `T "a" "\n"`},
		{`echo a >>"${OUT}"`, `T "a" "\n"`},
		{`echo a >> "$OUT" >/dev/null`, ``},
		{`echo a >/dev/null >> "$OUT"`, `T "a" "\n"`},
		{`echo a >> "$OUT" 2>&1`, `T "a" "\n"`},
		{`echo a 2>> "$OUT"`, ``},
		{`echo a &>> "$OUT"`, `T "a" "\n"`},
		{`echo a >> "$OUT" >&2`, ``},
		{`echo a >> "$OUT_X"`, ``},
		{`echo a >> "$OUT/x"`, ``},
	} {
		if got := dumpWrites(c.src, WriteOptions{}); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

// TestWritesEchoSh: dash's echo reads backslash escapes, so what it writes
// of a value, or of a literal with a backslash, is not known.
func TestWritesEchoSh(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`echo "a=$A" >> "$OUT"`, `T !echo`},
		{`echo "a=xxxxx" >> "$OUT"`, `T !echo`},
		{`echo 'a\nb' >> "$OUT"`, `T !echo`},
		{`echo "a=b" >> "$OUT"`, `T "a=b" "\n"`},
		{`printf 'a=%s\n' "$A" >> "$OUT"`, `T "a=" $A "\n"`},
	} {
		if got := dumpWrites(c.src, WriteOptions{EchoEscapes: true}); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

func TestWritesExact(t *testing.T) {
	src := `echo "k<<EOF" >> "$OUT"`
	w := Writes(src, Parse(src), WriteOptions{Target: isOut})
	o := w[0].Out[0]
	if !o.Exact || src[o.Span.Start:o.Span.End] != "k<<EOF" || o.Quote != QuoteDouble || o.Word != 1 || o.By == nil {
		t.Errorf("%+v", o)
	}
	src = `echo "k=\"x" >> "$OUT"`
	if o := Writes(src, Parse(src), WriteOptions{Target: isOut})[0].Out[0]; o.Exact || o.Text != `k="x` {
		t.Errorf("an escape: %+v", o)
	}
}

func TestLineFree(t *testing.T) {
	for _, c := range []struct {
		src  string
		want bool
	}{
		{`$(echo "$A" | tr -d '\n')`, true},
		{`$(echo -n "$A" | tr -d '\n\r')`, true},
		{`$(printf '%s' "$A" | tr -d '\n')`, true},
		{`$(printf '%s\n' "$A" | tr -d '\012')`, true},
		{`$(echo "$A" | tr '\n' ' ')`, true},
		{`$(echo "$A" | tr -d '[:space:]')`, true},
		{`$(echo "$A" | sed s/x/y/ | tr -d '\n')`, true},
		{`$(echo "$A" | tr -d '\n' | sed 's/x/\n/')`, false},
		{`$(echo "$A" | tr -d 'n')`, false},
		{`$(echo "$A" | tr -d \n)`, false},
		// tr reads its own escapes
		{`$(echo "$A" | tr -d '\\n')`, false},
		{"$(echo \"$A\" | tr '\\n' '\n')", false},
		{`$(echo "$A" | tr '\n' '\n')`, false},
		{`$(echo "$A" | tr -cd '\n')`, false},
		{`$(echo "$A" "$B" | tr -d '\n')`, false},
		{`$(cat f | tr -d '\n')`, false},
		{`$(echo "$A")`, false},
		{`$(tr -d '\n' <<< "$A")`, false},
		// a ${ } that removes the longest end from, or the longest start to,
		// a character of a set that holds the line break
		{`${A%%[[:space:]]*}`, true},
		{`${A%%$'\n'*}`, true},
		{`${A%[[:space:]]*}`, false},
		{`${A%%x*}`, false},
		{`${A%%[[:cntrl:]]*}`, true},
		{`${A%%[[:space:]_]*}`, true},
		{`${A%%[[:space:][:punct:]]*}`, true},
		{"${A%%[$' \\n']*}", true},
		{`${A##*[[:space:]]}`, true},
		{`${A##*[[:space:]_]}`, true},
		{`${A##*$'\n'}`, true},
		{`${A%%[[:blank:]]*}`, false},
		{`${A%%[ ]*}`, false},
		{`${A%%[![:space:]]*}`, false},
		{`${A#*[[:space:]]}`, false},
		{`${A##[[:space:]]*}`, false},
		{`${A%%*[[:space:]]}`, false},
		{`${A%%'[[:space:]]'*}`, false},
		{`${A%%[[:space:]]}`, false},
	} {
		src := "echo " + c.src
		p := &Parse(src).List[0].(*Simple).Words[1].Parts[0]
		if got := LineFree(src, p); got != c.want {
			t.Errorf("%s: %v", c.src, got)
		}
	}
}

func TestParams(t *testing.T) {
	src := "jq -r \"$A\" <<EOF\n$B $(echo ${C:-x})\nEOF"
	var names []string
	for _, p := range Params(Parse(src).List) {
		names = append(names, p.Name.String())
	}
	if got := strings.Join(names, " "); got != "A B C" {
		t.Errorf("params %s", got)
	}
}

// TextParams reads the bytes as tokens of commands: quotes, comments,
// expansions and heredocs as bash reads them.
func TestTextParams(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"case $A in x) echo \"$B\" '$C' $(echo $D) ;; esac", "A B D"},
		// a ' in a comment begins no quote
		{"case $A in\n  x) # it's\n    echo \"$B\" ;;\nesac", "A B"},
		{"case $A in x) cat <<EOF\n$B\nEOF\n;; esac", "A B"},
		{"case $A in x) echo \"$B", "A B"}, // not ended
		// the list of an array's assignment
		{"a=( $B \"$C\" )", "B C"},
		{"case $A in x) a+=( $B ) ;; esac", "A B"},
		{"declare -a a=( $B )", "B"},
	} {
		var names []string
		for _, p := range TextParams(c.src, Span{0, len(c.src)}) {
			names = append(names, p.Name.String())
		}
		if got := strings.Join(names, " "); got != c.want {
			t.Errorf("%q: params %s, want %s", c.src, got, c.want)
		}
	}
}

// TestWritesInFunc: a function writes where it is called.
func TestWritesInFunc(t *testing.T) {
	src := `f() { echo "a=$A" >> "$OUT"; }; echo b >> "$OUT"`
	ws := Writes(src, Parse(src), WriteOptions{Target: isOut})
	if len(ws) != 2 || !ws[0].InFunc || ws[1].InFunc {
		t.Errorf("%+v", ws)
	}
}

// TestWritesFuncProcRecursion: a function that calls itself in its own
// >( ) ends, whether it is called or not.
func TestWritesFuncProcRecursion(t *testing.T) {
	for _, src := range []string{`f() { echo a > >(f >> "$OUT"); }`, `f() { echo a > >(f | tee -a "$OUT"); }; f`} {
		Writes(src, Parse(src), WriteOptions{Target: isOut})
	}
}

// TestWritesFdValuesEnd: the values of a variable that v+=x appends to
// on many paths are read once at each place.
func TestWritesFdValuesEnd(t *testing.T) {
	var b strings.Builder
	b.WriteString("v=x\n")
	for stage := 0; stage < 8; stage++ {
		b.WriteString("if c0; then v+=0")
		for i := 1; i < 10; i++ {
			fmt.Fprintf(&b, "; elif c%d; then v+=%d", i, i)
		}
		b.WriteString("; fi\n")
	}
	b.WriteString("echo \"$X\" >&$v\n")
	src := b.String()
	Writes(src, Parse(src), WriteOptions{Log: true, Target: func(Word) bool { return false }})
}

// TestWritesCallsEnd: following the calls of functions that call others
// twice ends, however deep they nest.
func TestWritesCallsEnd(t *testing.T) {
	var b strings.Builder
	b.WriteString("f0() { exec 3>> \"$OUT\"; }\n")
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&b, "f%d() { f%d; f%d; }\n", i, i-1, i-1)
	}
	b.WriteString("f40 >> \"$OUT\"\nf40\necho a >&3\n")
	src := b.String()
	Writes(src, Parse(src), WriteOptions{Target: isOut})
}

// dumpLog is dumpWrites of what goes to the log alone: no file is a
// target, and each write is L and its pieces.
func dumpLog(src string) string {
	var lines []string
	sc := Parse(src)
	for _, w := range Writes(src, sc, WriteOptions{Log: true, Target: func(Word) bool { return false }, Holes: holes(src)}) {
		if !w.Log {
			continue
		}
		var b strings.Builder
		b.WriteString("L")
		if w.InFunc {
			b.WriteString(" F")
		}
		for _, x := range w.Out {
			switch x.Kind {
			case OutLit:
				fmt.Fprintf(&b, " %q", x.Text)
			case OutHole:
				b.WriteString(" H")
			case OutParam:
				b.WriteString(" $" + x.Part.Name.String())
			case OutSubst:
				b.WriteString(" $()")
			case OutOpaque:
				b.WriteString(" ?")
			case OutUnknown:
				b.WriteString(" !" + strings.Fields(src[x.Span.Start:x.Span.End])[0])
			}
		}
		lines = append(lines, b.String())
	}
	return strings.Join(lines, " | ")
}

func TestWritesLog(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`echo "$X"`, `L $X "\n"`},
		{`echo "$X" >&2`, `L $X "\n"`},
		{`echo "$X" 1>&2`, `L $X "\n"`},
		{`echo "$X" 2>&1 >/dev/null`, ``},
		{`echo "$X" >/dev/null 2>&1`, ``},
		{`printf '%s\n' "$X" > /dev/stderr`, `L $X "\n"`},
		{`echo "$X" >> /dev/stdout`, `L $X "\n"`},
		{`echo "$X" > /dev/fd/2`, `L $X "\n"`},
		{`echo "$X" > f`, ``},
		{`echo xxxxxx`, `L H "\n"`},
		{`Y=$(echo "$X")`, ``},
		{`Y=$(echo "$X" >&2)`, `L $X "\n"`},
		{`echo "$X" | base64`, `L !echo`},
		{`echo "$X" | base64 > f`, ``},
		{`echo "$X" | tee f`, `L !echo`},
		{`{ echo "$X"; } > f`, ``},
		{`{ echo "$X"; } >&2`, `L $X "\n"`},
		{`( echo "$X" )`, `L $X "\n"`},
		{`coproc echo "$X"`, ``},
		{`coproc { echo "$X"; }`, ``},
		{`coproc { echo "$X" >&2; }`, `L $X "\n"`},
		{"exec >/dev/null\necho \"$X\"", ``},
		{"exec 1>&2\necho \"$X\"", `L $X "\n"`},
		{"f() { echo \"$1\"; }\nf \"$X\"", `L F $1 "\n"`},
		{"f() { echo \"$1\"; } >/dev/null\nf \"$X\"", ``},
		// the body read where it is called writes to the log what goes there
		{"f() { echo \"$X\" >&2; }\nx=$(f)", `L F $X "\n"`},
		{"f() { echo \"$X\" >&2; }\nf > /dev/null", `L F $X "\n"`},
		{`cat <<< "$X"`, `L $X "\n"`},
		{"cat <<EOF\n$X\nEOF", `L $X "\n"`},
		{`curl -H "$X" https://example.com`, `L !curl`},
		// >&$v whose value is a number on every path: >&N
		{"v=2; echo \"$X\" >&$v", `L $X "\n"`},
		{"v=2; echo \"$X\" >&\"$v\"", `L $X "\n"`},
		{"v=\"/tmp/f\"; echo \"$X\" >&$v", ``},
		{"v=/dev/stderr; echo \"$X\" >&$v", `L $X "\n"`},
		{"v=/dev/stdout; echo \"$X\" >&$v >/dev/null", ``},
		{"read -r v; echo \"$X\" >&$v", `L !read | L $X "\n"`}, // a value not known: the log too (a descriptor 1 or 2)
		// v+=x appends to the values that reach it; the tree does not tell
		// whether v=1 also reaches the read without v+=1, so v may be 1 or 11:
		// a value not known
		{"v=1; v+=1; echo \"$X\" >&$v", ``}, // 11
		{"v=; v+=2; echo \"$X\" >&$v", `L $X "\n"`},
		{"v+=2; echo \"$X\" >&$v", `L $X "\n"`},
		{"v=1; v+=1; v=5; echo \"$X\" >&$v", ``},
		{"declare -i v=1; v=1; v+=1; echo \"$X\" >&$v", `L !declare | L $X "\n"`},
		{"v=7; v+=1; echo \"$X\" >&$v", ``}, // 7 or 71: no log
		{"if c; then v=2; else v=5; fi; echo \"$X\" >&$v", `L !c | L $X "\n"`},
		{"if c; then v=7; else v=5; fi; echo \"$X\" >&$v", `L !c`},
		{"env -i v=2 sh -c x; echo \"$X\" >&$v", `L !env | L $X "\n"`},
		// a {name} redirect on one path: on the other, the value from before
		// the script, which is not known
		{"if c; then exec {fd}>/dev/null; fi; echo \"$X\" >&$fd", `L !c | L $X "\n"`},
		{"if c; then exec {fd}>&2; fi; echo \"$X\" >&$fd", `L !c | L $X "\n"`},
		// each {name} redirect opens a descriptor of its own, and >&- of a
		// command that is not exec is restored after it (bash 5.3)
		{"exec {fd}>&2; { :; } {fd}>&-; echo \"$X\" >&$fd", `L !: | L $X "\n"`},
		{"exec {fd}>&2; : {fd}>&-; echo \"$X\" >&$fd", `L !: | L $X "\n"`},
		{"exec {fd}>&2; exec {fd}>&-; echo \"$X\" >&$fd", ``},
		{"exec {fd}>&2; c && { :; } {fd}>/dev/null; echo \"$X\" >&$fd", `L !c | L !: | L $X "\n"`},
		{"exec {fd}>&2; c && : {fd}>/dev/null; echo \"$X\" >&$fd", `L !c | L !: | L $X "\n"`},
		{"exec {fd}>&2; { :; } {fd}>/dev/null; echo \"$X\" >&$fd", `L !:`},
		// the descriptor {name}>&- closes: the value before the compound's
		// body, all the values of the paths, and a {name} of the same command
		// before (bash 5.3)
		{"exec 4>&2; fd=3; { fd=4; echo \"$X\" >&$fd; } {fd}>&-", `L $X "\n"`},
		// with more values, each descriptor may stay open: another name may
		// hold its number; when each path closes the descriptor its own
		// redirect opened, the descriptor is closed
		{"if c; then exec {fd}>&2; else exec {fd}>/dev/null; fi; exec {fd}>&-; echo \"$X\" >&$fd", `L !c`}, // each path closes its own
		{"exec {fd}>&2; b=$fd; if c; then exec {fd}>/dev/null; fi; exec {fd}>&-; echo \"$X\" >&$b", `L !c | L $X "\n"`},
		{"exec {fd}>&2; [[ b=fd -gt 0 ]]; if c; then exec {fd}>/dev/null; fi; exec {fd}>&-; echo \"$X\" >&$b", `L ![[ | L !c | L $X "\n"`},
		{"if c; then exec {fd}>&2; else exec {fd}>/dev/null; fi; exec {fd}>&-; echo \"$X\" >&10", `L !c | L $X "\n"`},
		{"exec {fd}>&2; echo \"$X\" {fd}>/dev/null >&$fd", ``},
		// a number the script writes names a descriptor open on every path
		{"exec 3>&2 4>/dev/null; if c; then fd=3; else fd=4; fi; exec {fd}>&-; echo \"$X\" >&3", `L !c | L $X "\n"`},
		{"fd=2; if c; then exec {fd}>/dev/null; fi; exec {fd}>&-; echo \"$X\" >&2", `L !c | L $X "\n"`},
		// the value of v names the file 5-, and - closes (bash 5.3)
		{"exec 5>&2; v=5-; echo \"$X\" >&$v", ``},
		// a copy of the inherited standard output keeps pointing at the log
		// when the standard output moves
		{"exec {fd}>&1; exec >/dev/null; echo \"$X\" >&$fd", `L $X "\n"`},
		{"exec 3>&1; exec >/dev/null; echo \"$X\" >&3", `L $X "\n"`},
		{"exec 3>&1; exec >/dev/null; echo \"$X\"", ``},
	} {
		if got := dumpLog(c.src); got != c.want {
			t.Errorf("%q: got %q, want %q", c.src, got, c.want)
		}
	}
}

// TestWritesLogFiles is that the log does not change what goes to files.
func TestWritesLogFiles(t *testing.T) {
	for _, src := range []string{
		`echo "t=$T" >> "$OUT"`,
		"{ echo a; echo \"$T\"; } >> $OUT",
		"exec >> $OUT\necho \"$T\"",
		`echo "$T" | tee -a "$OUT"`,
		"f() { echo \"$T\"; }\nf >> $OUT",
	} {
		plain, logged := dumpWrites(src, WriteOptions{}), dumpWrites(src, WriteOptions{Log: true})
		if plain != logged {
			t.Errorf("%q: without the log %q, with it %q", src, plain, logged)
		}
	}
}

// A descriptor may point at a place of its own on each path: where the
// paths meet, it may point at each of them.
func TestWritesPaths(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		// the branches of if, the commands after && and ||
		{"if [ -z \"$Q\" ]; then exec 3>>\"$OUT\"; else exec 3>/dev/null; fi; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"if c; then exec 3>/dev/null; elif d; then exec 3>>\"$OUT\"; else exec 3>/dev/null; fi; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; if c; then exec 3>/dev/null; else exec 3>/dev/null; fi; echo \"t=$T\" >&3", ``},
		{"exec 3>>\"$OUT\"; c && exec 3>/dev/null; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"c || exec 3>>\"$OUT\"; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		// a descriptor whose number v holds on one path, and another on the
		// other: each file
		{"exec 3>>\"$OUT\" 4>>${OUT}; if c; then v=3; else v=4; fi; echo \"t=$T\" >&$v", `T "t=" $T "\n" | T "t=" $T "\n"`},
		// a later round starts where a round ends
		{"while c; do echo \"t=$T\" >&3; exec 3>>\"$OUT\"; done", `"t=" $T "\n"`},
		{"for i in a b; do echo \"t=$T\" >&3; exec 3>>\"$OUT\"; [ c ] && continue; exec 3>/dev/null; done", `"t=" $T "\n"`},
		{"exec 3>/dev/null; for i in a; do :; done; echo \"t=$T\" >&3", ``},
		// break, continue and return leave from where they are
		{"while c; do exec 3>>\"$OUT\"; if d; then break; fi; exec 3>/dev/null; done; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"f() { exec 3>>\"$OUT\"; if c; then return; fi; exec 3>/dev/null; }; f; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"f() { exec 3>>\"$OUT\"; return; exec 3>/dev/null; }; f; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"break; exec 3>>\"$OUT\"; echo \"t=$T\" >&3", `T "t=" $T "\n"`}, // outside a loop: an error, and the script goes on
		// a call of a function defined on each path runs one of the bodies
		{"if c; then f() { exec 3>>\"$OUT\"; }; else f() { exec 3>/dev/null; }; fi; f; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		// exit ends the path
		{"if c; then exec 3>>\"$OUT\"; exit 0; fi; echo \"t=$T\" >&3", ``},
		{"c && { exec 3>>\"$OUT\"; exit 1; }; echo \"t=$T\" >&3", ``},
		{"f() { exit 1; }; if c; then exec 3>>\"$OUT\"; f; fi; echo \"t=$T\" >&3", ``},
		{"exec 3>>\"$OUT\"; c && exit; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"if c; then exec 3>>\"$OUT\"; ( exit 0 ); fi; echo \"t=$T\" >&3", `T "t=" $T "\n"`}, // the subshell ends
		{"x=$(exit 1); exec 3>>\"$OUT\"; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		// return and break out of a command with redirects of its own restore
		// them; a break in a function does not leave a loop around the call
		{"exec 3>>\"$OUT\"; f() { { return; } 3>/dev/null; }; f; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"exec 3>/dev/null; f() { { exec 3>>\"$OUT\"; return; } 3>/dev/null; }; f; echo \"t=$T\" >&3", ``},
		{"exec 3>/dev/null; for i in 1; do { exec 3>>\"$OUT\"; break; } 3>/dev/null; done; echo \"t=$T\" >&3", ``},
		{"f() { break; }; for i in 1; do f; exec 3>>\"$OUT\"; done; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		// a compound command's {name} is assigned after the targets before it
		// are read; in ( ... ), in the subshell
		{"exec {a}>>\"$OUT\"; { echo \"t=$T\" >&$b; } {b}>&$a {a}>/dev/null", `"t=" $T "\n"`},
		{"exec {fd}>/dev/null; ( echo \"t=$T\" >&$fd ) {fd}>>\"$OUT\"", `"t=" $T "\n"`},
		{"exec {fd}>>\"$OUT\"; ( echo \"t=$T\" >&$fd ) {fd}>/dev/null", ``},
		// with no command, bash assigns after the redirects
		{"exec 3>>\"$OUT\"; fd=3 {fd}>/dev/null; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		// a value not known, a copy of a number, or a number of 10 and up may
		// name a descriptor that points at the file
		{"exec {a}>>\"$OUT\"; b=$a; echo \"t=$T\" >&$b", `T "t=" $T "\n"`},
		{"exec {a}>>\"$OUT\"; echo \"t=$T\" >&10", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; fd=$(echo 3); echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"exec {a}>>\"$OUT\"; b=$a; if c; then a=5; fi; exec {a}>&-; echo \"t=$T\" >&$b", `T "t=" $T "\n"`},
		{"exec {fd}>>\"$OUT\"; b=$fd; if c; then exec {fd}>/dev/null; fi; exec {fd}>&-; echo \"t=$T\" >&$b", `T "t=" $T "\n"`},
		// rounds are read ahead until a round adds nothing
		{"while c; do echo \"t=$T\" >&5; exec 5>&4; exec 4>&3; exec 3>>\"$OUT\"; done", `"t=" $T "\n"`},
		// a break leaves the loop, not to the next round; a for of literal
		// words runs a round
		{"exec 3>/dev/null; for i in 1 2; do echo \"t=$T\" >&3; if c; then exec 3>>\"$OUT\"; break; fi; done", ``},
		{"exec 3>/dev/null; for i in 1 2; do echo \"t=$T\" >&3; for j in 1 2; do exec 3>>\"$OUT\"; break 2; done; done", ``},
		{"exec 3>/dev/null; for i in 1 2; do echo \"t=$T\" >&3; if c; then exec 3>>\"$OUT\"; continue; fi; done", `"t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; for i in 1 2; do exec 3>/dev/null; done; echo \"t=$T\" >&3", ``},
		{"exec 3>>\"$OUT\"; for i in $L; do exec 3>/dev/null; done; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		// >&$v- moves the descriptor of the value of v (bash 5.3)
		{"exec 3>>\"$OUT\"; v=3; echo \"t=$T\" >&$v-", `T "t=" $T "\n"`},
		{"exec {fd}>>\"$OUT\"; echo \"t=$T\" >&$fd-", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; v=3; exec 4>&\"$v\"-; echo \"t=$T\" >&4", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; v=3; exec 4>&$v-; echo \"t=$T\" >&3", ``},
		{"exec 3>>\"$OUT\"; v=3; exec 4>&\"$v-\"; echo \"t=$T\" >&4", ``}, // the - quoted makes no number: a file (bash names the file 3-, or refuses with exec)
		// a target of >& with expansions that is not a parameter alone
		{"exec 3>>\"$OUT\"; v=3; echo \"t=$T\" >&$((v))", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; echo \"t=$T\" >&$(echo 3)", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; v=3; echo \"t=$T\" >&${v:-1}", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; echo \"t=$T\" >&\"$D/f\"", ``}, // a literal character that is not a digit names a file
		// break run by command, builtin or eval; 3>&3- leaves 3 open; a
		// {name}>&m that fails leaves name as it was; bash keeps the standard
		// output in 10 and up
		{"exec 3>>\"$OUT\"; for i in 1; do c && command break; exec 3>/dev/null; done; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; for i in 1; do c && eval break; exec 3>/dev/null; done; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; f() { for i in 1; do c && eval return; exec 3>/dev/null; done; }; f; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; exec 3>&3-; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"exec {fd}>>\"$OUT\"; exec {fd}>&4; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"exec 2>>\"$OUT\"; echo \"t=$T\" 2>/dev/null >&10", `T EXEC | T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; { echo \"t=$T\" >&10; } >&3", `T`}, // echo writes to the standard output bash keeps in 10, the log
		// the values of v assigned in a body read ahead inside another loop;
		// {fd}>&3 of a descriptor open on every path does not fail, {fd}>&2
		// after 2 is closed does; a program bash forks keeps nothing in 10;
		// command -p break
		{"exec 4>>\"$OUT\"; v=3; while c; do for v in 3; do v=4; done; done; echo \"t=$T\" >&$v", `T "t=" $T "\n"`},
		{"exec {fd}>>\"$OUT\"; exec 2>&-; exec {fd}>&2; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"exec 2>>\"$OUT\"; cat <<<\"t=$T\" 2>/dev/null >&10", `T EXEC`},
		{"exec 3>>\"$OUT\"; for i in 1; do c && command -p break; exec 3>/dev/null; done; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		// n<>f and n<&m of any descriptor open it for output
		{"exec 3<>\"$OUT\"; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"exec {fd}<>\"$OUT\"; echo \"t=$T\" >&$fd", `T "t=" $T "\n"`},
		{"exec 3>>\"$OUT\"; exec 4<&3; echo \"t=$T\" >&4", `T "t=" $T "\n"`},
		// a duplicate of a descriptor not open leaves exec's descriptor where
		// it pointed; bash keeps a command's descriptors in 10 and up
		{"exec 3>>\"$OUT\"; exec 3>&4; echo \"t=$T\" >&3", `T "t=" $T "\n"`},
		{"echo \"t=$T\" >&4", ``},
		{"exec 2>>\"$OUT\"; { echo \"t=$T\" >&10; } 2>/dev/null", `T EXEC | "t=" $T "\n"`},
	} {
		if got := dumpWrites(c.src, WriteOptions{}); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
	for _, c := range []struct{ src, want string }{
		{"if c; then exec 2>/dev/null; fi; echo \"$X\" >&2", `L !c | L $X "\n"`},
		{"if c; then exec 2>/dev/null; else exec 2>f; fi; echo \"$X\" >&2", `L !c`},
		{"exec {fd}>&2; if c; then exec {fd}>&-; fi; echo \"$X\" >&$fd", `L !c | L $X "\n"`},
		{"exec {fd}>&2; old=$fd; if c; then exec {fd}>/dev/null; fi; exec {fd}>&-; echo \"$X\" >&$old", `L !c | L $X "\n"`},
		{"if c; then exec 2>/dev/null; exit 0; fi; echo \"$X\" >&2", `L !c | L !exit | L $X "\n"`},
		{"exec 2>/dev/null; if c; then exec 2>&1; exit 0; fi; echo \"$X\" >&2", `L !c | L !exit`},
		{"f() { rm -f x; return 0; } 2>/dev/null; f; echo \"x=$X\" >&2", `L F !rm | L F !return | L "x=" $X "\n"`},
		{"echo \"$X\" >&${LOGFD:-2}", `L $X "\n"`},
		{"{ echo \"$X\" >&10; } 2>/dev/null", `L $X "\n"`},
		{"f() { echo \"$X\" >&10; }; f 2>/dev/null", `L F $X "\n"`},
		{"exec {fd}>&2; echo \"$X\" >&$fd-", `L $X "\n"`},
		{"{ echo \"$X\" >&10; } >/dev/null", `L $X "\n"`},
		{"f() { echo \"$X\" >&10; }; f >/dev/null", `L F $X "\n"`},
		{"exec 3>>\"$OUT\"; { echo \"$X\" >&10; } >&3", `L $X "\n"`},
		{"exec 3>>\"$OUT\"; exec {fd}>&3; echo \"$X\" >&$fd", ``},
	} {
		if got := dumpLog(c.src); got != c.want {
			t.Errorf("%q: got %q, want %q", c.src, got, c.want)
		}
	}
}

// Reading the rounds of loops nested in loops ahead ends, however deep
// they nest (maxAhead).
func TestWritesRoundsEnd(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&b, "while c%d; do exec 3>>\"$OUT\"; ", i)
	}
	b.WriteString("echo \"t=$T\" >&3")
	for i := 0; i < 40; i++ {
		b.WriteString("; done")
	}
	src := b.String()
	if got := dumpWrites(src, WriteOptions{}); got != `"t=" $T "\n"` {
		t.Errorf("got %s", got)
	}
}

// Calls read ahead in rounds leave the calls after the loop to be read.
func TestWritesRoundsCalls(t *testing.T) {
	var b strings.Builder
	b.WriteString("g() { :; }; h() { exec 3>>\"$OUT\"; }; while c3; do while c2; do while c1; do while c0; do ")
	for i := 0; i < 300; i++ {
		b.WriteString("g; ")
	}
	b.WriteString(":; done; done; done; done; h; echo \"t=$T\" >&3")
	src := b.String()
	if got := dumpWrites(src, WriteOptions{}); got != `T "t=" $T "\n"` {
		t.Errorf("got %s", got)
	}
}

// The places of a descriptor do not grow with the paths that point it at
// one file.
func TestWritesPathsEnd(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 2400; i++ {
		b.WriteString("if c; then exec 3>>\"$OUT\"; fi\n")
	}
	b.WriteString("echo \"t=$T\" >&3\n")
	src := b.String()
	if got := dumpWrites(src, WriteOptions{}); got != `T "t=" $T "\n"` {
		t.Errorf("got %s", got)
	}
}

// A script of many for loops and {name} redirects is read in time near
// its length.
func TestWritesLoopsEnd(t *testing.T) {
	for _, line := range []string{
		"for i in 1 2; do :; done\n",
		"for i in 1 2; do exec {fd}>/dev/null; echo \"$X\" >&$fd; exec {fd}>&-; done\n",
	} {
		var b strings.Builder
		for i := 0; i < 1000; i++ {
			if strings.Contains(line, "%d") {
				fmt.Fprintf(&b, line, i)
			} else {
				b.WriteString(line)
			}
		}
		src := b.String()
		Writes(src, Parse(src), WriteOptions{Log: true, Target: isOut})
	}
}

// Nested for loops that assign one name and break out of each other are
// read in time near their depth.
func TestWritesNestEnd(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		b.WriteString("for i in 1 2; do c && break 2; exec 3>>\"$OUT\"; ")
	}
	b.WriteString("echo \"$X\" >&3")
	for i := 0; i < 40; i++ {
		b.WriteString("; c && continue 3; done")
	}
	src := b.String()
	Writes(src, Parse(src), WriteOptions{Log: true, Target: isOut})
}

// TestWritesLogStdoutPaths: the standard output, as the other descriptors,
// may point at a place of its own on each path.
func TestWritesLogStdoutPaths(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"exec >/dev/null; if c; then exec >&2; fi; echo \"$X\"", `L $X "\n"`},
		{"exec >/dev/null; c && exec >&2; echo \"$X\"", `L $X "\n"`},
		{"exec >/dev/null; if c; then exec >f; else exec >g; fi; echo \"$X\"", ``},
		{"exec >&4 || true; echo \"$X\"", `L !true | L $X "\n"`},
		{"exec 3>&4; exec >&3; echo \"$X\"", `L $X "\n"`},
		// a redirect that fails undoes the others of the exec (bash 5.3)
		{"exec 2>/dev/null 3>&4; echo \"$X\" >&2", `L $X "\n"`},
		{"exec 4>&2; exec 2>/dev/null 3>&4; echo \"$X\" >&2", ``},
		{"exec 2>/dev/null 3>&$v; echo \"$X\" >&2", `L $X "\n"`},
		// a compound command or a call whose redirect fails does not run
		// its body (bash 5.3)
		{"{ exec 2>/dev/null; } >&4 || true; echo \"$X\" >&2", `L !true | L $X "\n"`},
		{"f() { exec 2>/dev/null; }; f >&4 || true; echo \"$X\" >&2", `L !true | L $X "\n"`},
		{"exec 4>&2; { exec 2>/dev/null; } >&4; echo \"$X\" >&2", ``},
		{"exec 3>&2; echo \"$X\" >/dev/fd/03", ``},                                           // no file /dev/fd/03
		{"if c; then f() { exec 2>/dev/null; }; fi; f; echo \"$X\" >&2", `L !c | L $X "\n"`}, // f may not be defined
		{"f() { echo \"$X\" >&2; }; f |& grep -q x", `L !f`},                                 // |& reaches the body of a call
		// a jump whose redirect may fail may not jump
		{"exec 2>/dev/null; if c; then exec 2>&1; exit 0 >&4 || true; fi; echo \"$X\" >&2", `L !c | L !true | L $X "\n"`},
		// a command whose name is not literal may be break
		{"B=break; for i in 1 2; do c && $B; exec 2>/dev/null; done; echo \"$X\" >&2", `L !c | L !$B | L $X "\n"`},
		{"{ exec >/dev/null; }; echo \"$X\"", ``},
		{"exec >/dev/null; for i in 1 2; do echo \"$X\"; exec >&2; done", `L $X "\n"`},
		{"( exec >/dev/null ); echo \"$X\"", `L $X "\n"`},
		{"echo \"$(echo \"$X\")\"", `L $() "\n"`},  // the shell of the command, back from its substitution's
		{"{ echo \"$X\" >&2; } |& base64", `L !{`}, // |&: 2 to the pipe after the redirects
		{"exec 2>/dev/null; if c; then exec 2>&1; fi; echo \"$X\" >&2", `L !c | L $X "\n"`},
	} {
		if got := dumpLog(c.src); got != c.want {
			t.Errorf("%q: got %q, want %q", c.src, got, c.want)
		}
	}
}

// TestWalkNotRun: the commands whose redirects may fail, which bash may
// not run.
func TestWalkNotRun(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   []string
	}{
		{"{ V=safe; } >&4 || true", []string{"{ V=safe; } >&4"}},
		{"f() { V=safe; }; f >&4 || true", []string{"f >&4"}},
		{"exec 4>&2; { V=safe; } >&4", nil},
		{"declare v=4 >&4", []string{"declare v=4 >&4"}},
		{"if c; then exec 4>&2; fi; { V=safe; } >&4", []string{"{ V=safe; } >&4"}},
	} {
		sc := Parse(tc.script)
		var got []string
		for at := range walkNotRun(tc.script, sc, NewNameVisibility(tc.script, sc)) {
			for _, c := range simpleAndCompounds(sc) {
				if c.Span().Start == at {
					got = append(got, tc.script[c.Span().Start:c.Span().End])
				}
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.script, got, tc.want)
		}
	}
}

// simpleAndCompounds are the simple and compound commands of sc.
func simpleAndCompounds(sc *Script) []Command {
	var out []Command
	Walk("", sc.List, Enclosing{}, Visitor{Command: func(c Command, _ Enclosing) bool {
		switch c.(type) {
		case *Simple, *Compound:
			out = append(out, c)
		}
		return true
	}})
	return out
}

// TestJumpOf: how a simple command leaves its paths.
func TestJumpOf(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want jumpKind
		n    int
	}{
		{"break", jumpBreak, 1}, {"break 2", jumpBreak, 2}, {"continue", jumpContinue, 1},
		{"command -p break", jumpBreak, 1}, {"builtin -- continue 3", jumpContinue, 3},
		{"return", jumpReturn, 1}, {"exit", jumpExit, 1},
		{"$B", jumpMay, 1}, {"\"$CMD\" x", jumpMay, 1}, {"eval x", jumpMay, 1}, {"source f", jumpMay, 1}, {". f", jumpMay, 1},
		{"trap 'break' ERR", jumpMay, 1}, {"trap 'echo' ERR", jumpNone, 1},
		{"trap \"rm -f /tmp/returnfile\" EXIT", jumpNone, 1}, {"trap 'echo breakfast' EXIT", jumpNone, 1}, {"trap 'f; return' RETURN", jumpMay, 1}, {"command -v break", jumpNone, 1}, {"echo break", jumpNone, 1},
	} {
		x := Parse(tc.src).List[0].(*Simple)
		if k, n := jumpOf(tc.src, x.Words); k != tc.want || n != tc.n {
			t.Errorf("%q: got %v %d, want %v %d", tc.src, k, n, tc.want, tc.n)
		}
	}
}

// TestWritesCallTop: the body of a function a top command calls is in that
// command (Write.Top), not a top command of its own.
func TestWritesCallTop(t *testing.T) {
	src := "f() { echo \"$X\"; } >> $OUT\nf"
	sc := Parse(src)
	for _, w := range Writes(src, sc, WriteOptions{Target: isOut}) {
		if w.Top != nil && w.Top != sc.List[1] {
			t.Errorf("%q: the top of the write at %v is %v", src, w.At.Span(), w.Top.Span())
		}
	}
}

// TestWalkAheadLimit: past maxAhead, a round read ahead reads no more
// commands, and the reading still leaves each command it entered.
func TestWalkAheadLimit(t *testing.T) {
	src := "exec >/dev/null; while c; do while d; do :; :; :; exec >&2; done; done; echo x"
	sc := Parse(src)
	r := newFdReading(src)
	r.findChanges(sc.List)
	r.ahead.max = 3
	var got StdoutKind
	Walk(src, sc.List, Enclosing{}, Visitor{Descriptors: &DescriptorReading{reading: r}, Command: func(c Command, at Enclosing) bool {
		if src[c.Span().Start:c.Span().End] == "echo x" {
			got = at.Stdout
		}
		return true
	}})
	if len(r.frames) != 0 || len(r.loops) != 0 || len(r.scopes) != 0 {
		t.Errorf("frames %d, loops %d, scopes %d left", len(r.frames), len(r.loops), len(r.scopes))
	}
	if got != StdoutLog {
		t.Errorf("the standard output of echo x goes to %v, want StdoutLog", got)
	}
}

// TestCopiesName: whether a script may copy the value of a name to
// another name.
func TestCopiesName(t *testing.T) {
	for src, want := range map[string]bool{
		"b=$fd":                true,
		"((b=fd))":             true,
		"let b=fd":             true,
		"[[ b=fd -gt 0 ]]":     true,
		"a[b=fd]=1":            true,
		"declare -i b; b=fd":   true,
		"declare -n b=fd":      true,
		"echo x >&10":          true, // a number of {name}'s may name its descriptor
		"echo x >&$fd":         false,
		"exec {fd}>&-":         false,
		"echo x >&$fd-":        false,
		"echo x >&\"$fd\"":     false,
		"fdx=1; x=$fdy":        false,
		"echo x # b=$fd":       false,
		"exec {fd}>&2; echo x": false,
	} {
		r := newFdReading(src)
		r.list = Parse(src).List
		if got := r.copiesName("fd"); got != want {
			t.Errorf("%q: got %v, want %v", src, got, want)
		}
	}
}

// TestWritesPipeErrAndFailedRedirect: |& of a call joins 2 to 1 for the
// call alone, and a command whose redirect fails on every path writes
// nothing.
func TestWritesPipeErrAndFailedRedirect(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"f() { { echo \"$X\" >&2; } 2>>$OUT; }; f |& cat", `$X "\n"`},
		{"echo \"t=$T\" >> $OUT 2>&4", ""},
		{"{ echo \"t=$T\"; } >> $OUT 2>&4", ""},
		// a call that does not run leaves the function to be read at the next
		// call
		{"f() { echo \"t=$T\"; }\nf 2>&4 || true\nf >> $OUT", `T "t=" $T "\n"`},
	} {
		if got := dumpWrites(c.src, WriteOptions{}); got != c.want {
			t.Errorf("%q: got %q, want %q", c.src, got, c.want)
		}
	}
}

// TestWritesGather: a compound command, a call of a function and a command of
// a pipeline write what the simple commands in them that point their standard
// output there write, read with the descriptors where each runs. bash 5.3.15
// writes nothing to $OUT in the forms whose write is empty (2026-11-16).
func TestWritesGather(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`{ exec >/dev/null; echo "t=$T"; } >> "$OUT"`, `T`},
		{`{ exec >&-; echo "t=$T"; } >> "$OUT"`, `T`},
		{`{ exec 3>/dev/null; echo "t=$T"; } >> "$OUT"`, `T "t=" $T "\n"`},
		{`{ exec 3>&1; exec >/dev/null; echo "t=$T" >&3; } >> "$OUT"`, `"t=" $T "\n" | T`},
		{`{ if c; then exec >/dev/null; fi; echo "t=$T"; } >> "$OUT"`, `T !c "t=" $T "\n"`},
		{`( exec >/dev/null; echo "t=$T" ) >> "$OUT"`, `T`},
		{`f() { exec >/dev/null; echo "t=$T"; }; f >> "$OUT"`, `T`},
		{`f() { echo "t=$T"; }; f >> "$OUT"`, `T "t=" $T "\n"`},
		{`f() { echo "t=$1"; }; f "$T" >> "$OUT"`, `T !f`},
		{`f() { echo "t=$T"; f; }; f >> "$OUT"`, `T "t=" $T "\n" !f`},
		{`{ case "$x" in a) echo "t=$T";; esac; } >> "$OUT"`, `T !case`},
		{`f() { exec {fd}>&1; echo "t=$T" >&$fd; }; f >> "$OUT"; f >/dev/null`, `T | "t=" $T "\n"`},
		{`{ { echo "t=$T"; } >> "$OTHER"; } >> "$OUT"`, `T`},
		{`{ exec >/dev/null; echo "t=$T"; } | tee -a "$OUT"`, ``},
		{`echo "t=$T" | tee -a "$OUT"`, `"t=" $T "\n"`},
		{`{ echo a | tr a b; } | tee -a "$OUT"`, `!echo`},
		{`echo "t=$T" > >(tee -a "$OUT")`, `T "t=" $T "\n"`},
		{`{ echo "t=$T"; } > >(cat >> "$OUT")`, `!cat | T "t=" $T "\n"`},
		{`f() { echo "t=$T"; }; { f; } >> "$OUT"`, `T "t=" $T "\n"`},
		{`f() { echo "t=$1"; }; { f "$T"; } >> "$OUT"`, `T !f`},
		{`printf x | { cat; } >> "$OUT"`, `!printf`},
		{`f() { exec >/dev/null; echo "t=$T"; }; f | tee -a "$OUT"`, ``},
		// a call that is a command of a pipeline: its bodies write to its
		// pipe
		{`f() { echo "t=$T"; }; f | tee -a "$OUT"`, `"t=" $T "\n"`},
		{`f() { echo "t=$T" >&2; }; f |& tee -a "$OUT"`, `"t=" $T "\n"`},
		{`f() { echo "t=$T"; }; g() { f; }; g | tee -a "$OUT"`, `"t=" $T "\n"`},
		{`f() { echo "t=$T"; }; { f | tee -a "$OUT"; }`, `"t=" $T "\n"`},
		{`f() { echo "t=$T"; }; f | tee -a "$OUT" | cat`, `"t=" $T "\n"`},
		{`f() { echo "t=$T"; }; f >> "$OUT" | cat`, `"t=" $T "\n"`},
		{`f() { echo "t=$1"; }; f "$T" | tee -a "$OUT"`, `!f`},
	} {
		if got := dumpWrites(c.src, WriteOptions{}); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

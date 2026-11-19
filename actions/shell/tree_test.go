package shell

import (
	"fmt"
	"strings"
	"testing"
)

// dump writes a tree on one line: commands as (kind ...), words as [parts],
// each part as <quote><kind>:<bytes> (quote: - none, S single, A ANSI, D
// double; kind: lit, $NAME for a parameter, op(NAME), sub{...}, in{...},
// out{...}, opaque), redirects as <op><fd>[target], a heredoc's body as
// doc(delim,quoted){parts}.
func dump(src string, s *Script) string {
	var b strings.Builder
	dumpList(&b, src, s.List)
	if !s.Complete {
		fmt.Fprintf(&b, " STOP@%d", s.Stop)
	}
	return b.String()
}

func dumpList(b *strings.Builder, src string, cs []Command) {
	for i, c := range cs {
		if i > 0 {
			b.WriteString("; ")
		}
		dumpCommand(b, src, c)
	}
}

func dumpCommand(b *strings.Builder, src string, c Command) {
	switch c := c.(type) {
	case *Simple:
		b.WriteString("(simple")
		for _, w := range c.Assigns {
			b.WriteString(" =")
			dumpWord(b, src, w)
		}
		for _, w := range c.Words {
			b.WriteString(" ")
			dumpWord(b, src, w)
		}
		dumpRedirects(b, src, c.Redirects)
		b.WriteString(")")
	case *Compound:
		fmt.Fprintf(b, "(%s ", strings.ToLower(strings.TrimPrefix(c.Kind.String(), "Compound")))
		if c.Name != nil {
			b.WriteString("name")
			dumpWord(b, src, *c.Name)
			b.WriteString(" ")
		}
		if c.Var != nil {
			b.WriteString("var")
			dumpWord(b, src, *c.Var)
			if c.HasIn {
				b.WriteString(" in")
			}
			for _, w := range c.In {
				dumpWord(b, src, w)
			}
			b.WriteString(" ")
		}
		dumpList(b, src, c.Body)
		dumpRedirects(b, src, c.Redirects)
		b.WriteString(")")
	case *FuncDef:
		b.WriteString("(func ")
		dumpWord(b, src, c.Name)
		b.WriteString(" ")
		dumpCommand(b, src, c.Body)
		b.WriteString(")")
	case *Pipeline:
		b.WriteString("(pipe ")
		dumpList(b, src, c.Commands)
		b.WriteString(")")
	case *Asynchronous:
		b.WriteString("(async ")
		dumpCommand(b, src, c.Command)
		b.WriteString(")")
	case *AndOr:
		b.WriteString("(andor ")
		for i, x := range c.Commands {
			if i > 0 {
				fmt.Fprintf(b, " %s ", map[AndOrOp]string{AndOrAnd: "&&", AndOrOr: "||"}[c.Ops[i-1]])
			}
			dumpCommand(b, src, x)
		}
		b.WriteString(")")
	}
}

func dumpRedirects(b *strings.Builder, src string, rs []Redirect) {
	for _, r := range rs {
		fmt.Fprintf(b, " %s", strings.TrimPrefix(r.Op.String(), "Redir"))
		if r.Fd >= 0 {
			fmt.Fprintf(b, "%d", r.Fd)
		}
		if r.Var.String() != "" {
			fmt.Fprintf(b, "{%s}", r.Var)
		}
		dumpWord(b, src, r.Target)
		if d := r.Heredoc; d != nil {
			fmt.Fprintf(b, "doc(%s,%v){", d.Delim, d.Quoted)
			dumpParts(b, src, d.Parts)
			b.WriteString("}")
		}
	}
}

func dumpWord(b *strings.Builder, src string, w Word) {
	b.WriteString("[")
	dumpParts(b, src, w.Parts)
	b.WriteString("]")
}

func dumpParts(b *strings.Builder, src string, ps []Part) {
	for i, p := range ps {
		if i > 0 {
			b.WriteString(" ")
		}
		b.WriteString(map[Quote]string{QuoteNone: "-", QuoteSingle: "S", QuoteANSI: "A", QuoteDouble: "D"}[p.Quote])
		switch p.Kind {
		case PartLiteral:
			fmt.Fprintf(b, "lit:%s", src[p.Span.Start:p.Span.End])
		case PartParam:
			fmt.Fprintf(b, "$%s", p.Name)
		case PartParamOp:
			fmt.Fprintf(b, "op(%s)", p.Name)
		case PartSubst, PartProcIn, PartProcOut:
			name := map[PartKind]string{PartSubst: "sub", PartProcIn: "in", PartProcOut: "out"}[p.Kind]
			if p.Backquote {
				name = "bq"
			}
			if p.Sub == nil {
				b.WriteString(name)
				break
			}
			fmt.Fprintf(b, "%s{", name)
			dumpList(b, src, p.Sub.List)
			b.WriteString("}")
		case PartOpaque:
			b.WriteString("opaque")
		case PartArith:
			b.WriteString("arith")
		}
	}
}

func TestParse(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`echo "t=${TITLE}"x'y'$N >> "$GITHUB_OUTPUT"`,
			`(simple [-lit:echo] [Dlit:t= D$TITLE -lit:x Slit:y -$N] Append[D$GITHUB_OUTPUT])`},
		{"{\n  echo \"title=$TITLE\"\n  cat <<EOF\nbody=$BODY\nEOF\n} >> \"$GITHUB_OUTPUT\"",
			`(brace (simple [-lit:echo] [Dlit:title= D$TITLE]); (simple [-lit:cat] Heredoc[-lit:EOF]doc(EOF,false){-lit:body= -$BODY -lit:` + "\n" + `}) Append[D$GITHUB_OUTPUT])`},
		{`echo "$X" | tee -a "$GITHUB_ENV"`,
			`(pipe (simple [-lit:echo] [D$X]); (simple [-lit:tee] [-lit:-a] [D$GITHUB_ENV]))`},
		{"( echo a ) >> f", `(subshell (simple [-lit:echo] [-lit:a]) Append[-lit:f])`},
		// & ends an and-or list run asynchronously
		{"a &", `(async (simple [-lit:a]))`},
		{"a & b", `(async (simple [-lit:a])); (simple [-lit:b])`},
		{"a && b &", `(async (andor (simple [-lit:a]) && (simple [-lit:b])))`},
		{"{ a; } &", `(async (brace (simple [-lit:a])))`},
		{"a | b &", `(async (pipe (simple [-lit:a]); (simple [-lit:b])))`},
		{"a && b", `(andor (simple [-lit:a]) && (simple [-lit:b]))`},
		{"while read -r l; do echo \"$l\"; done >> f",
			`(while (simple [-lit:read] [-lit:-r] [-lit:l]); (simple [-lit:echo] [D$l]) Append[-lit:f])`},
		{"if [ -n \"$A\" ]; then echo a; else echo b; fi > f",
			`(if (simple [-lit:[] [-lit:-n] [D$A] [-lit:]]); (simple [-lit:echo] [-lit:a]); (simple [-lit:echo] [-lit:b]) Out[-lit:f])`},
		{"a && b || c; d &\ne", `(andor (simple [-lit:a]) && (simple [-lit:b]) || (simple [-lit:c])); (async (simple [-lit:d])); (simple [-lit:e])`},
		{"echo a |\n  bash", `(pipe (simple [-lit:echo] [-lit:a]); (simple [-lit:bash]))`},
		{"echo a \\\n  b", `(simple [-lit:echo] [-lit:a] [-lit:b])`},
		{`X=1 Y="$Z" cmd`, `(simple =[-lit:X=1] =[-lit:Y= D$Z] [-lit:cmd])`},
		// an element of an array before the command word is an assignment
		{"a[0]=x cmd", `(simple =[-lit:a[0]=x] [-lit:cmd])`},
		{"a[0]=x", `(simple =[-lit:a[0]=x])`},
		{"a[i+1]+=x b=1 cmd", `(simple =[-lit:a[i+1]+=x] =[-lit:b=1] [-lit:cmd])`},
		{`a["k"]=1 cmd`, `(simple =[-lit:a[ Dlit:k -lit:]=1] [-lit:cmd])`},
		{"cmd a[0]=x", `(simple [-lit:cmd] [-lit:a[0]=x])`},
		{`echo ${X} ${X:-d} ${#X} $1 $@ "$"`, `(simple [-lit:echo] [-$X] [-op(X)] [-op(X)] [-$1] [-$@] [Dlit:$])`},
		{`echo "" '' $'a'`, `(simple [-lit:echo] [Dlit:] [Slit:] [Alit:a])`},
		{`echo "PR=$(echo "$PR" | tr -d '\n')" >> "$GITHUB_ENV"`,
			`(simple [-lit:echo] [Dlit:PR= Dsub{(pipe (simple [-lit:echo] [D$PR]); (simple [-lit:tr] [-lit:-d] [Slit:\n]))}] Append[D$GITHUB_ENV])`},
		{`echo 0>(cat)`, `(simple [-lit:echo] [-lit:0] [-out{(simple [-lit:cat])}])`},
		{`diff <(sort a) >(cat)`, `(simple [-lit:diff] [-in{(simple [-lit:sort] [-lit:a])}] [-out{(simple [-lit:cat])}])`},
		{"echo `date` $((1+2))", `(simple [-lit:echo] [-bq{(simple [-lit:date])}] [-arith])`},
		{"A=(a b) cmd", `(simple =[-lit:A= -opaque] [-lit:cmd])`},
		{"f() { echo a; }", `(func [-lit:f] (brace (simple [-lit:echo] [-lit:a])))`},
		{"function f { echo a; }", `(func [-lit:f] (brace (simple [-lit:echo] [-lit:a])))`},
		{"for x in a b; do echo \"$x\"; done", `(for var[-lit:x] in[-lit:a][-lit:b] (simple [-lit:echo] [D$x]))`},
		// the name and the words of for and select
		{"for x in a \"$b\" $(c); do :; done", `(for var[-lit:x] in[-lit:a][D$b][-sub{(simple [-lit:c])}] (simple [-lit::]))`},
		{"for x; do :; done", `(for var[-lit:x] (simple [-lit::]))`},
		{"for x in; do :; done", `(for var[-lit:x] in (simple [-lit::]))`},
		{"select x in a\ndo :; done", `(select var[-lit:x] in[-lit:a] (simple [-lit::]))`},
		{"case $x in a) echo a;; esac > f", `(case  Out[-lit:f])`},
		{"(( n = 1 )) && echo a", `(andor (arith ) && (simple [-lit:echo] [-lit:a]))`},
		{"cat <<'E' | bash\n$X\nE", `(pipe (simple [-lit:cat] Heredoc[Slit:E]doc(E,true){}); (simple [-lit:bash]))`},
		{"# c\necho a # d", `(simple [-lit:echo] [-lit:a])`},
		{"! a | b", `(pipe (simple [-lit:a]); (simple [-lit:b]))`},
		{"cat <<EOF >> f\nx=$(echo \"$X\")\nEOF", `(simple [-lit:cat] Heredoc[-lit:EOF]doc(EOF,false){-lit:x= -sub{(simple [-lit:echo] [D$X])} -lit:` + "\n" + `} Append[-lit:f])`},
		// [[ ]] is one command up to its ]]: && and || inside do not end it, and
		// < and > are no redirects
		{"[[ -n $A && -z $B ]]", `(simple [-lit:[[] [-lit:-n] [-$A] [-lit:-z] [-$B] [-lit:]]])`},
		{"[[ ( a < b ) ||\n ! c =~ ^(d|e f)$ ]] > o && x", `(andor (simple [-lit:[[] [-lit:a] [-lit:b] [-lit:!] [-lit:c] [-lit:=~] [-lit:^] [-lit:d] [-lit:e] [-lit:f] [-lit:$] [-lit:]]] Out[-lit:o]) && (simple [-lit:x]))`},
		{"[[ a ]; b", `(simple [-lit:[[] [-lit:a] [-lit:]]); (simple [-lit:b])`}, // no ]]: bash refuses it
		// coproc is a reserved word: a name only before a compound command,
		// and the word right after it is a reserved word (bash's parse.y)
		{"coproc a b", `(coproc (simple [-lit:a] [-lit:b]))`},
		{"coproc { a; }", `(coproc (brace (simple [-lit:a])))`},
		{"coproc N { a; }", `(coproc name[-lit:N] (brace (simple [-lit:a])))`},
		{"coproc N ( a )", `(coproc name[-lit:N] (subshell (simple [-lit:a])))`},
		{"coproc time { a; }", `(coproc name[-lit:time] (brace (simple [-lit:a])))`},
		// bash expands the name in the shell that starts the coproc
		{"coproc \"$(echo N)\" { a; }", `(coproc name[Dsub{(simple [-lit:echo] [-lit:N])}] (brace (simple [-lit:a])))`},
		{"coproc { if true; then a; fi; }", `(coproc (brace (if (simple [-lit:true]); (simple [-lit:a]))))`},
		{"coproc while [[ -f x ]]; do a; done", `(coproc (while (simple [-lit:[[] [-lit:-f] [-lit:x] [-lit:]]]); (simple [-lit:a])))`},
		{"x | coproc a", `(pipe (simple [-lit:x]); (coproc (simple [-lit:a])))`},
		{"! coproc a", `(coproc (simple [-lit:a]))`},
		{"time coproc a", `(coproc (simple [-lit:a]))`},
		// one -p and then one -- after time are part of the reserved word
		// (bash 5.3.15)
		{"time -p eval x", `(simple [-lit:eval] [-lit:x])`},
		{"time -- eval x", `(simple [-lit:eval] [-lit:x])`},
		{"time -p -- eval x", `(simple [-lit:eval] [-lit:x])`},
		{"time -p -p x", `(simple [-lit:-p] [-lit:x])`},
		{"time -- -p x", `(simple [-lit:-p] [-lit:x])`},
		{"time \"-p\" x", `(simple [Dlit:-p] [-lit:x])`},
		{"! time -p eval x", `(simple [-lit:eval] [-lit:x])`},
		// time with no command runs nothing: a command of no words
		{"time\necho a", `(simple); (simple [-lit:echo] [-lit:a])`},
		{"time -p; echo a", `(simple); (simple [-lit:echo] [-lit:a])`},
		{"time -p ( a )", `(subshell (simple [-lit:a]))`},
		{"coproc a > f", `(coproc (simple [-lit:a] Out[-lit:f]))`},
		{"coproc N\n{ a; }", `(coproc (simple [-lit:N])); (brace (simple [-lit:a]))`}, // a name does not go past the line
		{"coproc for ((i=0;i<1;i++)); do a; done", `(coproc (for (simple [-lit:a])))`},
		{"$(coproc a)", `(simple [-sub{(coproc (simple [-lit:a]))}])`},
		// a # inside a word is a letter of it, inside $( ) too (bash 5.3.15:
		// echo $(echo $(echo a)#b) prints a#b); inside $(( )), blanks, lines and
		// << are of the expression; in the ( ) of an array, a # after a blank
		// begins a comment
		{"echo $(echo $(echo a)#b)", `(simple [-lit:echo] [-sub{(simple [-lit:echo] [-sub{(simple [-lit:echo] [-lit:a])} -lit:#b])}])`},
		{"echo $(( 16#ff)) $((1 <<\n2)) b", `(simple [-lit:echo] [-arith] [-arith] [-lit:b])`},
		{"a=(x # c\ny) b", `(simple =[-lit:a= -opaque] [-lit:b])`},
		{"echo $${a} $$'q' $$[1]", `(simple [-lit:echo] [-$$ -lit:{a}] [-$$ Slit:q] [-$$ -lit:[1]])`},
	} {
		if got := dump(c.src, Parse(c.src)); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

// TestParseRedirects: redirects written with a number, or with no space.
func TestParseRedirects(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		// the {name} before a redirect's operator, and words that are not one
		{`exec {fd}>>"$GITHUB_ENV"`, `(simple [-lit:exec] Append{fd}[D$GITHUB_ENV])`},
		{`echo hi {h}>/dev/null`, `(simple [-lit:echo] [-lit:hi] Out{h}[-lit:/dev/null])`},
		{`exec {fd}>&-`, `(simple [-lit:exec] DupOut{fd}[-lit:-])`},
		{`echo {fd} >f`, `(simple [-lit:echo] [-lit:{fd}] Out[-lit:f])`},
		{`echo {a b}>f`, `(simple [-lit:echo] [-lit:{a] [-lit:b}] Out[-lit:f])`},
		{`echo "{fd}">f`, `(simple [-lit:echo] [Dlit:{fd}] Out[-lit:f])`},
		{`echo a 2>>"$GITHUB_OUTPUT"`, `(simple [-lit:echo] [-lit:a] Append2[D$GITHUB_OUTPUT])`},
		{`echo a >>$GITHUB_OUTPUT`, `(simple [-lit:echo] [-lit:a] Append[-$GITHUB_OUTPUT])`},
		{`echo a 1>&2`, `(simple [-lit:echo] [-lit:a] DupOut1[-lit:2])`},
		{`echo a &>>f 2>&1 <in`, `(simple [-lit:echo] [-lit:a] AppendAll[-lit:f] DupOut2[-lit:1] In[-lit:in])`},
		{`echo a2>f`, `(simple [-lit:echo] [-lit:a2] Out[-lit:f])`},
		{`cat <<< "$X"`, `(simple [-lit:cat] HereString[D$X])`},
		// the number or the {name} before << is the descriptor of the heredoc,
		// as before the other operators
		{"cat 3<<EOF\nx\nEOF", `(simple [-lit:cat] Heredoc3[-lit:EOF]doc(EOF,false){-lit:x` + "\n" + `})`},
		{"cat {fd}<<EOF\nx\nEOF", `(simple [-lit:cat] Heredoc{fd}[-lit:EOF]doc(EOF,false){-lit:x` + "\n" + `})`},
		{"cat 3<<< x", `(simple [-lit:cat] HereString3[-lit:x])`},
		{"cat 1000<<< x", `(simple [-lit:cat] HereString1000[-lit:x])`},
		{"cat 0003<<< x", `(simple [-lit:cat] HereString3[-lit:x])`},
		{"cat 2147483648<<< x", `(simple [-lit:cat] [-lit:2147483648] HereString[-lit:x])`},
		{`echo >`, `(simple [-lit:echo] Out[])`},
	} {
		if got := dump(c.src, Parse(c.src)); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

// TestParseStop: where the script cannot be followed, the tree ends.
func TestParseStop(t *testing.T) {
	for _, c := range []struct {
		src  string
		stop int
	}{
		{`echo "abc`, 5},
		{"cat <<EOF\nx", 4},
		{"echo a; echo $[ 1 ]; echo b", 13},
		{"x=$(cat <<EOF\ny\nEOF\n)", 0}, // the word the heredoc is in is not in the tree
		{"echo $(case x in a) b;; esac)", 5},
		{"echo a; fi; echo b", 8},
		{"echo a; cat <<0\n", 12},
		// a construct left open at the end: the tree ends where it begins
		{"if true; then echo a", 0},
		{"{ echo a } >> f", 0},
		{"echo \"x=$T\" >> \"$GITHUB_OUTPUT\"\nif true; then\n  echo b\n", 32},
		// what a substitution does not make a script of stops the whole
		{"echo $(fi) ; echo b >> f", 0},
		// coproc with no command after it
		{"coproc", 0},
		{"echo a; coproc", 8},
		{"{ coproc }", 0},
		{"coproc\n{ a; }", 0},
		// &>( and >>( are a redirect and then (, and $$( is $$ and then (: a
		// syntax error to bash 5.3.15
		{`echo &>(cat)`, 0},
		{`echo >>(cat)`, 0},
		{"echo $$(echo a)", 0},
		{"echo $(if x; then y) ; echo bbbbbbbbbb", 0},
		// bash reads a whole and-or list before it runs it: one that is not a
		// script is not in the tree
		{"echo a; \"\" | |sh", 8},
		{"echo a; echo b ( c )", 8},
		// a heredoc whose body is not followed, or has what is not a script,
		// is not in the tree
		{"cat <<EOF\n$(if)\nEOF\necho b", 0},
		{"cat <<EOF >> \"$GITHUB_OUTPUT\"\nx=a \\\nb\nEOF\necho done", 4},
	} {
		s := Parse(c.src)
		if s.Complete || s.Stop != c.stop {
			t.Errorf("%q: complete %v, stop %d, want %d (%s)", c.src, s.Complete, s.Stop, c.stop, dump(c.src, s))
		}
		for _, cmd := range s.List {
			if cmd.Span().End > s.Stop {
				t.Errorf("%q: %s ends at %d, past the stop %d", c.src, dump(c.src, &Script{List: []Command{cmd}, Complete: true}), cmd.Span().End, s.Stop)
			}
		}
	}
}

// TestParseSpans: the spans of a Sub are positions of the whole script.
func TestParseSpans(t *testing.T) {
	src := `echo "a$(printf '%s' "$X")b" >> f`
	w := Parse(src).List[0].(*Simple).Words[1]
	sub := w.Parts[1].Sub.List[0].(*Simple)
	if got := src[sub.Words[2].Span.Start:sub.Words[2].Span.End]; got != `"$X"` {
		t.Errorf("the third word of the substitution is %q", got)
	}
	if p := sub.Words[2].Parts[0]; src[p.Span.Start:p.Span.End] != "$X" || p.Name.String() != "X" {
		t.Errorf("its part is %q, %v", src[p.Span.Start:p.Span.End], p.Name)
	}
}

// TestParseLarge: deep nesting, and a large script, take linear time.
func TestParseLarge(t *testing.T) {
	deep := strings.Repeat("$(", maxDepth/2) + strings.Repeat(")", maxDepth/2)
	if s := Parse("echo " + deep); !s.Complete {
		t.Errorf("deep: stop %d", s.Stop)
	}
	// deeper than the tree is made: not followed, and no stack runs out
	for _, deeper := range []string{strings.Repeat("$(", 1<<18) + strings.Repeat(")", 1<<18), strings.Repeat("{ ", 1<<18) + strings.Repeat("; }", 1<<18)} {
		if s := Parse("echo " + deeper); s.Complete {
			t.Errorf("deeper %.8q...: complete", deeper)
		}
	}
	// $(( )) nested past maxParamDepth: the inner ones are not read again
	Parse("echo " + strings.Repeat("$((1+", 1<<14) + "1" + strings.Repeat("))", 1<<14))
	src := strings.Repeat("echo \"a $(date) b\" 'c' <<<x # d\n", 1<<15)
	if s := Parse(src); !s.Complete || len(s.List) != 1<<15 {
		t.Errorf("large: complete %v, %d commands", s.Complete, len(s.List))
	}
}

func TestParseCoprocComplete(t *testing.T) {
	for _, src := range []string{"coproc for ((i=0;i<1;i++)); do a; done", "echo $(coproc a)", "coproc N { a; }"} {
		if sc := Parse(src); !sc.Complete {
			t.Errorf("%q: stops at %d", src, sc.Stop)
		}
	}
}

// TestPipelineStderr: a pipeline keeps which of its operators is |&.
func TestPipelineStderr(t *testing.T) {
	for script, want := range map[string][]bool{
		"a |& b":     {true},
		"a | b |& c": {false, true},
		"a | b":      {false},
	} {
		p, ok := Parse(script).List[0].(*Pipeline)
		if !ok || fmt.Sprint(p.Stderr) != fmt.Sprint(want) {
			t.Errorf("%q: %v", script, Parse(script).List[0])
		}
	}
}

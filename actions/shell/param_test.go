package shell

import (
	"fmt"
	"strings"
	"testing"
)

// dumpParam writes a parameter expansion on one line: its prefix, name,
// subscript, operator and words, each word as dumpWord writes it.
func dumpParam(src string, p *ParamExpansion) string {
	if p == nil {
		return "nil"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", strings.TrimPrefix(p.Prefix.String(), "ParamPrefix"), p.Name)
	if p.Subscript != nil {
		b.WriteString(" sub")
		dumpWord(&b, src, *p.Subscript)
	}
	if p.All != ParamAllNone {
		fmt.Fprintf(&b, " %s", strings.TrimPrefix(p.All.String(), "ParamAll"))
	}
	fmt.Fprintf(&b, " %s", strings.TrimPrefix(p.Op.String(), "ParamOp"))
	if p.Colon {
		b.WriteString(":")
	}
	if p.Op == ParamOpTransform {
		fmt.Fprintf(&b, "@%s", p.Transform)
	}
	for _, w := range p.Words {
		b.WriteString(" ")
		dumpWord(&b, src, w)
	}
	if p.Offset != nil {
		b.WriteString(" off")
		dumpWord(&b, src, *p.Offset)
	}
	if p.Length != nil {
		b.WriteString(" len")
		dumpWord(&b, src, *p.Length)
	}
	return b.String()
}

// firstParam is the parameter expansion of the first ${...} part of the
// first word of the first command of src, or of its heredoc's body.
func firstParam(t *testing.T, src string) *ParamExpansion {
	t.Helper()
	sc := Parse(src)
	if len(sc.List) == 0 {
		t.Fatalf("%q: no command", src)
	}
	s, ok := sc.List[0].(*Simple)
	if !ok {
		t.Fatalf("%q: not a simple command", src)
	}
	var ps []Part
	for _, w := range s.Words {
		ps = append(ps, w.Parts...)
	}
	for _, r := range s.Redirects {
		if r.Heredoc != nil {
			ps = append(ps, r.Heredoc.Parts...)
		}
	}
	for _, p := range ps {
		if p.Kind == PartParamOp {
			return p.Param
		}
	}
	t.Fatalf("%q: no ${...} with an operator", src)
	return nil
}

func TestParseParamExpansion(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`echo ${T@a}`, `None T Transform@a`},
		{`echo ${T@A}`, `None T Transform@A`},
		{`echo ${T@Q}`, `None T Transform@Q`},
		{`echo ${T:-d}`, `None T Default: [-lit:d]`},
		{`echo ${T-d}`, `None T Default [-lit:d]`},
		{`echo ${T:=d}`, `None T Assign: [-lit:d]`},
		{`echo ${T=d}`, `None T Assign [-lit:d]`},
		{`echo ${T:?d}`, `None T Error: [-lit:d]`},
		{`echo ${T:+d}`, `None T Alternate: [-lit:d]`},
		{`echo ${T+d}`, `None T Alternate [-lit:d]`},
		{`echo ${T:-}`, `None T Default: []`},
		{`echo ${T:0:3}`, `None T Substring off[-lit:0] len[-lit:3]`},
		{`echo ${T: -1}`, `None T Substring off[-lit: -1]`},
		{`echo ${T#a}`, `None T RemovePrefix [-lit:a]`},
		{`echo ${T##a}`, `None T RemoveLongestPrefix [-lit:a]`},
		{`echo ${T%a}`, `None T RemoveSuffix [-lit:a]`},
		{`echo ${T%%[[:space:]]*}`, `None T RemoveLongestSuffix [-lit:[[:space:]]*]`},
		{`echo ${T/a/b}`, `None T Replace [-lit:a] [-lit:b]`},
		{`echo ${T//a/b}`, `None T ReplaceAll [-lit:a] [-lit:b]`},
		{`echo ${T/#a/b}`, `None T ReplacePrefix [-lit:a] [-lit:b]`},
		{`echo ${T/%a/b}`, `None T ReplaceSuffix [-lit:a] [-lit:b]`},
		{`echo ${T/a}`, `None T Replace [-lit:a]`},
		{`echo ${T/"/"/x}`, `None T Replace [Dlit:/] [-lit:x]`},
		{`echo ${T^^}`, `None T UpperAll`},
		{`echo ${T^}`, `None T UpperFirst`},
		{`echo ${T,,}`, `None T LowerAll`},
		{`echo ${T~~}`, `None T ToggleAll`},
		{`echo ${T^^[ab]}`, `None T UpperAll [-lit:[ab]]`},
		{`echo ${#T}`, `Length T None`},
		{`echo ${!T}`, `Indirect T None`},
		{`echo ${!pre*}`, `Indirect pre Star None`},
		{`echo ${!a[@]}`, `Indirect a At None`},
		{`echo ${a[i+1]}`, `None a sub[-lit:i+1] None`},
		{`echo ${a[@]}`, `None a At None`},
		{`echo ${a[0]:-d}`, `None a sub[-lit:0] Default: [-lit:d]`},
		{`echo ${#a[@]}`, `Length a At None`},
		{`echo ${@:1:2}`, `None @ Substring off[-lit:1] len[-lit:2]`},
		// the word after the operator: its expansions, quotes and blanks
		{`echo ${x:-$(c)}`, `None x Default: [-sub{(simple [-lit:c])}]`},
		{`echo ${x:-a b}`, `None x Default: [-lit:a b]`},
		{`echo ${x:-'a'}`, `None x Default: [Slit:a]`},
		{`echo ${x:-"a b"}`, `None x Default: [Dlit:a b]`},
		{`echo "${x:-$y}"`, `None x Default: [D$y]`},
		{`echo "${x:-"a b"}"`, `None x Default: [Dlit:a b]`},
		{`echo "${x:-'a'}"`, `None x Default: [Dlit:'a']`},
		{`echo ${a:-${b:-$(c)}}`, `None a Default: [-op(b)]`},
		{"cat <<EOF\n${x:-$(c)}\nEOF", `None x Default: [Dsub{(simple [-lit:c])}]`},
		// the words of a substitution in the word have their own quotes; a
		// heredoc's body is as inside "..."
		{`echo "${x:-$(c $y 'a')}"`, `None x Default: [Dsub{(simple [-lit:c] [-$y] [Slit:a])}]`},
		{"cat <<EOF\n${x:-'$(c)'}\nEOF", `None x Default: [Dlit:' Dsub{(simple [-lit:c])} Dlit:']`},
		// the pattern of / ends at the first / outside quotes and
		// expansions, inside [ ] too
		{`echo ${x//[/$T}`, `None x ReplaceAll [-lit:[] [-$T]`},
		{`echo ${x//[(]/_}`, `None x ReplaceAll [-lit:[(]] [-lit:_]`},
		{`echo ${x/"$(echo "/")"/y}`, `None x Replace [Dsub{(simple [-lit:echo] [Dlit:/])}] [-lit:y]`},
		// inside "...", ' quotes in a pattern and the string of /, and
		// $'...' is decoded
		{`echo "${x/a/'b'}"`, `None x Replace [-lit:a] [Slit:b]`},
		{`echo "${x:-$'a'}"`, `None x Default: [Alit:a]`},
		// a ? of the offset pairs with a :
		{`echo ${x:1?2:3}`, `None x Substring off[-lit:1?2:3]`},
	} {
		if got := dumpParam(c.src, firstParam(t, c.src)); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

// TestParseParamExpansionNested: the expansion inside the word after the
// operator has its own words.
func TestParseParamExpansionNested(t *testing.T) {
	src := `echo ${a:-${b:-$(c)}}`
	inner := firstParam(t, src).Words[0].Parts[0].Param
	if got, want := dumpParam(src, inner), `None b Default: [-sub{(simple [-lit:c])}]`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestParseParamExpansionUnknown: what is not read as an expansion with an
// operator keeps no ParamExpansion, and the parser does not panic.
func TestParseParamExpansionUnknown(t *testing.T) {
	for _, src := range []string{`echo ${@Z}`, `echo ${T@QQ}`, `echo ${T@z}`, `echo ${#x:-d}`, `echo ${x:}`} {
		if p := firstParam(t, src); p != nil {
			t.Errorf("%q: got %s, want nil", src, dumpParam(src, p))
		}
	}
	for _, src := range []string{`echo ${x:-$(a}`, `echo ${x:-`, "echo ${x:-$(\n", `echo "${x:-"}"`} {
		Parse(src) // no panic
	}
}

func TestParamValue(t *testing.T) {
	for _, c := range []struct {
		op     string
		value  ParamValue
		change ParamChange
		words  int // how many of the words may become the value
	}{
		{"T@a", ParamValueNone, ParamChangeUnset, 0},
		{"#T", ParamValueNone, ParamChangeUnset, 0},
		{"T:+d", ParamValueNone, ParamChangeUnset, 1},
		{"T+d", ParamValueNone, ParamChangeUnset, 1},
		{"!pre*", ParamValueNone, ParamChangeUnset, 0},
		{"!a[@]", ParamValueNone, ParamChangeUnset, 0},
		{"T@Q", ParamValueQuoted, ParamChangeUnset, 0},
		{"T@A", ParamValueQuoted, ParamChangeUnset, 0},
		{"T@K", ParamValueQuoted, ParamChangeUnset, 0},
		{"T@k", ParamValueQuoted, ParamChangeUnset, 0},
		{"T@E", ParamValueChanged, ParamChangeOther, 0},
		{"T@P", ParamValueChanged, ParamChangeOther, 0},
		{"T@U", ParamValueChanged, ParamChangeCaseChange, 0},
		{"T@u", ParamValueChanged, ParamChangeCaseChange, 0},
		{"T@L", ParamValueChanged, ParamChangeCaseChange, 0},
		{"T^^", ParamValueChanged, ParamChangeCaseChange, 0},
		{"T,", ParamValueChanged, ParamChangeCaseChange, 0},
		{"T~~", ParamValueChanged, ParamChangeCaseChange, 0},
		{"T:0:3", ParamValueChanged, ParamChangeSubstring, 0},
		{"T#a", ParamValueChanged, ParamChangePrefixRemoval, 0},
		{"T##a", ParamValueChanged, ParamChangePrefixRemoval, 0},
		{"T%a", ParamValueChanged, ParamChangeSuffixRemoval, 0},
		{"T%%a", ParamValueChanged, ParamChangeSuffixRemoval, 0},
		{"T/a/b", ParamValueChanged, ParamChangeReplacement, 1},
		{"T//a/b", ParamValueChanged, ParamChangeReplacement, 1},
		{"T/a", ParamValueChanged, ParamChangeReplacement, 0},
		{"!T", ParamValueIndirect, ParamChangeUnset, 0},
		{"T:-d", ParamValueWhole, ParamChangeUnset, 1},
		{"T-d", ParamValueWhole, ParamChangeUnset, 1},
		{"T:=d", ParamValueWhole, ParamChangeUnset, 1},
		{"T=d", ParamValueWhole, ParamChangeUnset, 1},
		{"T:?d", ParamValueWhole, ParamChangeUnset, 0},
		{"a[0]", ParamValueWhole, ParamChangeUnset, 0},
		{"a[@]", ParamValueWhole, ParamChangeUnset, 0},
	} {
		src := "echo ${" + c.op + "}"
		p := firstParam(t, src)
		if p == nil {
			t.Errorf("%s: no ParamExpansion", c.op)
			continue
		}
		if got := p.Value(); got != c.value {
			t.Errorf("%s: Value %v, want %v", c.op, got, c.value)
		}
		if got := p.Change(); got != c.change {
			t.Errorf("%s: Change %v, want %v", c.op, got, c.change)
		}
		if got := len(p.ValueWords()); got != c.words {
			t.Errorf("%s: %d ValueWords, want %d", c.op, got, c.words)
		}
	}
}

// dumpArith writes an arithmetic expression on one line: its parts as
// dumpParts writes them, and its names, = after one it assigns.
func dumpArith(src string, a *Arithmetic) string {
	if a == nil {
		return "nil"
	}
	var b strings.Builder
	b.WriteString("[")
	dumpParts(&b, src, a.Parts)
	b.WriteString("]")
	for _, n := range a.Names {
		fmt.Fprintf(&b, " %s", n.Name)
		if n.Assigned {
			b.WriteString("=")
		}
	}
	return b.String()
}

func TestParseArithmetic(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`echo $(( a + $(c) ))`, `[Dlit: a +  Dsub{(simple [-lit:c])} Dlit: ] a`},
		{`echo $(( n = T + 1 ))`, `[Dlit: n = T + 1 ] n= T`},
		{`echo $(( n == T ))`, `[Dlit: n == T ] n T`},
		{`echo $(( a[i] = $x ))`, `[Dlit: a[i] =  D$x Dlit: ] a= i`},
		{`echo $((16#ff + ${y:-1}))`, `[Dlit:16#ff +  Dop(y)]`},
		{`echo $(( $(( 1 )) ))`, `[Dlit:  Darith Dlit: ]`},
		{`echo "$(( "x" ))"`, `[Dlit:  Dlit:x Dlit: ] x`},
	} {
		sc := Parse(c.src)
		var a *Arithmetic
		for _, w := range sc.List[0].(*Simple).Words {
			for _, p := range w.Parts {
				if p.Kind == PartArith {
					a = p.Arith
				}
			}
		}
		if got := dumpArith(c.src, a); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
	// (( )) and for (( ; ; )): the expressions of the compound
	for _, c := range []struct {
		src  string
		want []string
	}{
		{"(( n = T ))", []string{`[Dlit: n = T ] n= T`}},
		{"for (( i=0; i<n; i++ )); do :; done", []string{`[Dlit: i=0] i=`, `[Dlit: i<n] i n`, `[Dlit: i++ ] i`}},
	} {
		x := Parse(c.src).List[0].(*Compound)
		var got []string
		for _, a := range x.Arith {
			got = append(got, dumpArith(c.src, a))
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q:\n got %q\nwant %q", c.src, got, c.want)
		}
	}
	for _, src := range []string{"echo $(( 1 +", "echo $(( $(a ))", "(( a", "for (( ; ; ))"} {
		Parse(src) // no panic
	}
}

// partTexts are the parts of the first command of the script of the first
// ` ` of src, each as dumpParts writes it, and whether each part's bytes
// in src are what bash reads (no backslash it takes off).
func TestParseBackquote(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"echo `date`", `(simple [-lit:date])`},
		{"echo `echo $S`", `(simple [-lit:echo] [-$S])`},
		{"echo `echo \\$S`", `(simple [-lit:echo] [-$S])`},
		{"echo \"`echo \\\"hi\\\"`\"", `(simple [-lit:echo] [Dlit:hi])`},
		{"echo `echo \\\\n`", `(simple [-lit:echo] [-lit:\n])`},
		{"echo `curl -d \"$S\" https://e`", `(simple [-lit:curl] [-lit:-d] [D$S] [-lit:https://e])`},
		{"echo `echo \\`date\\``", `(simple [-lit:echo] [-bq{(simple [-lit:date])}])`},
		{"cat <<EOF\n`echo $S`\nEOF", `(simple [-lit:echo] [-$S])`},
		// a literal is split at a backslash taken off
		{"echo `echo a\\$ b`", `(simple [-lit:echo] [-lit:a -lit:$] [-lit:b])`},
		{"echo `echo a\\\\b`", `(simple [-lit:echo] [-lit:a -lit:\b])`},
		// \" only right inside "..." (bash 5.3)
		{"echo \"${x:-`echo \\\"a\\\"`}\"", `(simple [-lit:echo] [-lit:\"a\"])`},
		{"echo ${x:-\"`echo \\\"a\\\"`\"}", `(simple [-lit:echo] [Dlit:a])`},
		{"echo \"${x:-\"`echo \\\"a\\\"`\"}\"", `(simple [-lit:echo] [-lit:\"a\"])`},
		{"echo \"$(( `echo \\\"1\\\"` ))\"", `(simple [-lit:echo] [-lit:\"1\"])`},
		{"cat <<EOF\n`echo \\\"h\\\"`\nEOF", `(simple [-lit:echo] [-lit:\"h\"])`},
	} {
		sc := Parse(c.src)
		var sub *Script
		var find func(ps []Part)
		find = func(ps []Part) {
			for _, p := range ps {
				if p.Kind == PartSubst && p.Backquote && sub == nil {
					sub = p.Sub
				}
				if p.Param != nil {
					for _, w := range p.Param.Words {
						find(w.Parts)
					}
				}
				if p.Arith != nil {
					find(p.Arith.Parts)
				}
			}
		}
		for _, w := range sc.List[0].(*Simple).Words {
			find(w.Parts)
		}
		for _, r := range sc.List[0].(*Simple).Redirects {
			if r.Heredoc != nil {
				find(r.Heredoc.Parts)
			}
		}
		if sub == nil {
			t.Errorf("%q: no Sub", c.src)
			continue
		}
		if got := dump(c.src, sub); got != c.want {
			t.Errorf("%q:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
	// the script of a ` ` that is not one bash reads is not complete, and
	// the tree goes on (bash refuses it only when it runs the command)
	sc := Parse("echo `if`; echo b")
	if !sc.Complete || len(sc.List) != 2 {
		t.Errorf("echo `if`; echo b: %s", dump("echo `if`; echo b", sc))
	}
}

package shell

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// reaching is what reaches the read marked @ in src (the @ is taken
// away; the read is the parameter right after it): the text of each
// assignment, sorted, "unset" for an unset, "-" for an assignment with no
// value.
func reaching(t *testing.T, src string) []string {
	t.Helper()
	i := strings.Index(src, "@")
	if i < 0 {
		t.Fatalf("%q: no @", src)
	}
	script := src[:i] + src[i+1:]
	sc := Parse(script)
	v := oldNameVisibility(script, sc)
	var name VarName
	Walk(script, sc.List, Enclosing{}, Visitor{Part: func(p *Part, _ Enclosing) {
		if p.Span.Start == i && (p.Kind == PartParam || p.Kind == PartParamOp) {
			name = p.Name
		}
	}})
	if name.String() == "" {
		t.Fatalf("%q: no parameter at %d", src, i)
	}
	out := assignmentTexts(script, readFlow(script, sc).Reaching(name, Span{i, i}))
	if old := assignmentTexts(script, v.Reaching(name, Span{i, i})); fmt.Sprint(old) != fmt.Sprint(out) && flowDifferences[src] == "" {
		t.Errorf("%q: the flow reading gives %q, the old reading %q", src, out, old)
	}
	return out
}

// flowDifferences are the scripts on which the flow reading (readFlow) and
// the old reading answer differently, with what bash 5.3.15 and 5.2.37 did:
// the flow reading's answer.
var flowDifferences = map[string]string{
	"while c; do for y in a; do for y in b; do :; done; done; done; echo @$y": "after the inner for, whose word is a literal, y is b",
	"V=o; { V=safe; } >&4 || true; echo @$V":                                  "4 is not open: bash does not run the group, V is o",
	"V=o; f() { V=safe; }; f >&4 || true; echo @$V":                           "4 is not open: bash does not run the call, V is o",
	"fd=2; declare fd=4 >&4 || true; echo @$fd":                               "4 is not open: bash does not run declare, fd is 2",
	"f() { v=a; return >&4 || true; v=b; }; f; echo @$v":                      "4 is not open: bash does not run return, v is b",
}

// assignmentTexts are the texts of as in script, sorted: "before" for the
// value from before the script, "unset" for an unset, "-" for an
// assignment with no value.
func assignmentTexts(script string, as []Assignment) []string {
	var out []string
	for _, a := range as {
		switch {
		case a.Before:
			out = append(out, "before")
		case a.Unset:
			out = append(out, "unset")
		case a.Value == nil:
			out = append(out, "-")
		default:
			out = append(out, script[a.At.Start:a.At.End])
		}
	}
	slices.Sort(out)
	return out
}

func TestNameVisibility(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want []string
	}{
		// a list in order: a later assignment replaces an earlier one
		{"s=a; s=b; echo @$s", []string{"s=b"}},
		// ${NAME:=value} and ${NAME=value}: the name keeps its value when it has one
		{": ${s:=$S}; curl @$s", []string{"${s:=$S}", "before"}},
		{"s=a; : ${s:=b}; x @$s", []string{"${s:=b}", "s=a"}},
		{"s=a; : ${s=b}; x @$s", []string{"${s=b}", "s=a"}},
		{"echo ${s:=b} @$s", []string{"${s:=b}", "before"}},
		// an element, and the word read before the assignment
		{": ${a[0]:=v}; echo @${a[0]}", []string{"${a[0]:=v}", "before"}},
		{": \"${Y:=@${Y:-x}}\"", nil}, // the := is not made yet: nothing reaches
		// the name of for and select: a word after in at the start of each
		// round; the words are read before the loop
		{"for x in a \"$b\"; do echo @$x; done", []string{"\"$b\"", "a"}},
		{"for x; do echo @$x; done", []string{"-"}},
		{"s=a; for x in @$s; do s=b; done", []string{"s=a"}},
		// a for whose words are literals runs a round at least; with a word
		// that may expand to none, it may not
		{"x=0; for x in a; do :; done; echo @$x", []string{"a"}},
		{"x=0; for x in $w; do :; done; echo @$x", []string{"$w", "x=0"}},
		{"x=0; for x in *.txt; do :; done; echo @$x", []string{"*.txt", "x=0"}},
		{"x=0; for x in a; do c && break; done; echo @$x", []string{"a"}}, // a break leaves a round that assigned x
		{"y=0; for x in a; do c && command break; y=1; done; echo @$y", []string{"y=0", "y=1"}},
		{"y=0; for x in a; do c && eval break; y=1; done; echo @$y", []string{"y=0", "y=1"}},
		// the assignments of a body read ahead inside another loop reach
		// after it; a for's words do not reach where its body always assigns
		// the name; command -v and trap without a break are not a break
		{"x=v1; while c; do for x in w2; do x=v3; done; done; echo @$x", []string{"x=v1", "x=v3"}},
		{"while c; do for y in a; do for y in b; do :; done; done; done; echo @$y", []string{"b", "before"}}, // the inner for, whose word is a literal, runs a round
		{"x=v1; for i in w0; do for x in *.g; do x=v3; done; c && break; done; echo @$x", []string{"x=v1", "x=v3"}},
		{"x=v0; for x in a; do command -v ls >/dev/null; done; echo @$x", []string{"a"}},
		{"x=v0; for x in a; do trap 'rm -f f' EXIT; done; echo @$x", []string{"a"}},
		{"x=v0; for x in a; do ( command break ); done; echo @$x", []string{"a"}},
		{"x=v0; for x in a; do command -p break; done; echo @$x", []string{"a"}},
		// {name} before a redirect assigns the number of the descriptor, also
		// after a command that is not exec; >&- does not assign
		{"exec {fd}>>f; echo x >&@$fd", []string{"-"}}, // no value the script writes
		{"echo hi {fd}>f; echo x >&@$fd", []string{"-"}},
		{"fd=3; exec {fd}>&-; echo @$fd", []string{"fd=3"}},
		// on a compound command but ( ... ) and a coproc (bash 5.3)
		{"{ :; } {fd}>>f; echo x >&@$fd", []string{"-"}},
		{"while false; do :; done {fd}>>f; echo x >&@$fd", []string{"-"}},
		{"( : ) {fd}>>f; echo x >&@$fd", nil}, // the subshell assigns it
		{"s=a; echo @$s; s=b", []string{"s=a"}},
		{"echo @$out; out=x", nil}, // read before the assignment
		// branches: the union of what may reach
		{"s=a; c && s=b; echo @$s", []string{"s=a", "s=b"}},
		{"c && s=b; echo @$s", []string{"before", "s=b"}}, // on the other path, the value from before the script
		{"if c; then s=b; fi; echo @$s", []string{"before", "s=b"}},
		{"( s=a ) ; echo @$s", nil},
		{"s=a; c || s=b; echo @$s", []string{"s=a", "s=b"}},
		{"s=a; if c; then s=b; fi; echo @$s", []string{"s=a", "s=b"}},
		{"s=a; if c; then s=b; echo @$s; fi", []string{"s=b"}},
		// each branch of if: the union of their ends
		{"if c; then s=a; else s=b; fi; echo @$s", []string{"s=a", "s=b"}},
		{"if c; then s=a; elif d; then s=b; else s=c; fi; echo @$s", []string{"s=a", "s=b", "s=c"}},
		{"s=o; if c; then s=a; else echo @$s; fi", []string{"s=o"}},
		{"if s=a; then echo @$s; fi", []string{"s=a"}},
		// += appends to what reaches
		{"s=a; s+=b; echo @$s", []string{"s+=b"}}, // s=a is what s+=b appends to (Bases)
		{"s=a; if c; then s+=b; fi; echo @$s", []string{"s+=b", "s=a"}},
		{"a[0]=x; a[1]=y; echo @$a", []string{"a[0]=x", "a[1]=y", "before"}}, // an element leaves the others
		// an assignment word reads those before it in the command
		{"a=1 b=@$a", []string{"a=1"}},
		// one assignment once, however many times it is read
		{"f(){ s=a; }; f; f; if c; then f; fi; echo @$s", []string{"s=a"}},
		// return in a subshell or a loop ends neither the body nor the function
		{"f(){ ( return ); s=a; }; f; echo @$s", []string{"s=a"}},
		{"f(){ while false; do return; done; s=a; }; f; echo @$s", []string{"before", "s=a"}}, // the condition is not read: the return may run
		// declare -p prints, it declares nothing
		{"f(){ declare -p s; echo @$s; }; s=x; f", []string{"s=x"}},
		{"command export s=a; echo @$s", []string{"s=a"}},
		// exit ends the path; && and || join the paths that go on
		{"if c; then T=x; else exit 1; fi; echo @$T", []string{"T=x"}},
		{"c && T=x || exit 1; echo @$T", []string{"T=x"}},
		{"T=x || exit 1; echo @$T", []string{"T=x"}},
		{"( exit 1 ); T=x; echo @$T", []string{"T=x"}},
		// the condition of while runs at least once
		{"while read -r T; do :; done; echo @$T", []string{"-"}},
		{"s=o; while c; do s=a; done; echo @$s", []string{"s=a", "s=o"}},
		// local in a subshell of the body is the subshell's
		{"f(){ ( local s=x ); s=SEC; }; f; echo @$s", []string{"s=SEC"}},
		// command f runs no function
		{"f(){ s=a; }; command f; echo @$s", nil},
		// loops: the end of one round reaches the next
		{"for i in 1 2; do echo @$s; s=b; done", []string{"before", "s=b"}},
		// break, continue and return leave their paths, which meet after the
		// loop or the call
		{"v=4; for i in 1 2; do v=2; c && break; v=4; done; echo @$v", []string{"v=2", "v=4"}},
		{"while c; do v=a; d && continue; v=b; done; echo @$v", []string{"before", "v=a", "v=b"}},
		{"for i in 1 2; do v=a; break; v=b; done; echo @$v", []string{"v=a"}},
		{"B=break; for i in 1; do v=a; $B; v=b; done; echo @$v", []string{"v=a", "v=b"}},
		{"for i in 1 2; do v=a; continue; v=b; done; echo @$v", []string{"v=a"}},
		{"for i in 1 2; do for j in 1; do v=a; break 2; done; v=b; done; echo @$v", []string{"v=a"}},
		{"f() { w=a; c && return; w=b; }; f; echo @$w", []string{"w=a", "w=b"}},
		{"f() { w=a; return; w=b; }; f; echo @$w", []string{"w=a"}},
		{"f() { local w=a; c && return; }; w=o; f; echo @$w", []string{"w=o"}},
		{"for i in 1 2; do f() { v=a; break; }; f; v=b; done; echo @$v", []string{"v=b"}}, // a break in a function's body leaves no loop around the call
		// a command whose redirect may fail may not run; one whose redirect
		// fails on every path does not run
		{"V=o; { V=safe; } >&4 || true; echo @$V", []string{"V=o"}},
		{"V=o; f() { V=safe; }; f >&4 || true; echo @$V", []string{"V=o"}},
		{"exec 4>&2; V=o; { V=safe; } >&4; echo @$V", []string{"V=safe"}},
		{"fd=2; declare fd=4 >&4 || true; echo @$fd", []string{"fd=2"}},
		{"V=o; V=safe >&4; echo @$V", []string{"V=safe"}}, // bash assigns it
		{"V=o; if c; then exec 4>&2; fi; { V=safe; } >&4; echo @$V", []string{"V=o", "V=safe"}},
		// a function defined on some paths only
		{"V=o; if c; then f() { V=safe; }; fi; f; echo @$V", []string{"V=o", "V=safe"}},
		{"V=o; f() { V=safe; }; if c; then unset -f f; fi; f; echo @$V", []string{"V=o", "V=safe"}},
		{"V=o; f() { V=a; }; f; echo @$V", []string{"V=a"}},
		// a descriptor opened to read is open: a duplicate of it does not fail
		{"P=o; exec 3< f; read -r P <&3; echo @$P", []string{"-"}}, // read assigns P
		{"V=o; exec 3<<<x; { V=safe; } <&3; echo @$V", []string{"V=safe"}},
		// a return whose redirect fails does not return
		{"f() { v=a; return >&4 || true; v=b; }; f; echo @$v", []string{"v=b"}},
		// trap's action is read as a script
		{"X=o; f() { trap \"rm -f /tmp/returnfile\" EXIT; X=safe; }; f; echo @$X", []string{"X=safe"}},
		{"s=a; while c; do echo @$s; s=b; done", []string{"s=a", "s=b"}},
		{"s=a; while c; do s=b; done; echo @$s", []string{"s=a", "s=b"}},
		// subshells: what they assign stays in them
		{"( s=a ); echo @$s", nil},
		{"s=a | true; echo @$s", nil},
		{"true | s=a; echo @$s", nil},
		{"s=a & wait; echo @$s", nil},
		{"coproc { s=a; }; echo @$s", nil},
		{"x=$(s=a); echo @$s", nil},
		{"s=a; ( echo @$s )", []string{"s=a"}},
		{"shopt -s lastpipe; true | s=a; echo @$s", []string{"s=a"}},
		// the commands that assign
		{"export s=a; echo @$s", []string{"s=a"}},
		{"declare s=a; echo @$s", []string{"s=a"}},
		{"readonly s=a; echo @$s", []string{"s=a"}},
		{"s=a; export s; readonly s; declare s; typeset s; echo @$s", []string{"s=a"}},
		{"local s=x; echo @$s", nil}, // local outside a function is an error to bash
		{"read -r s; echo @$s", []string{"-"}},
		{"mapfile s < f; echo @$s", []string{"-"}},
		{"printf -v s %s x; echo @$s", []string{"-"}},
		{"s=a; unset s; echo @$s", []string{"unset"}},
		{"coproc c { :; }; echo @$c_PID", []string{"-"}},
		{"coproc { :; }; echo @$COPROC", []string{"-"}},
		{"s=a true; echo @$s", nil}, // before a command that is no function: its environment only
		// functions: dynamic scope, what a call leaves, local
		{"f(){ echo @$s; }; ( s=a; f )", []string{"s=a"}},
		{"f(){ echo @$s; }; s=a; f; s=b; f", []string{"s=a", "s=b"}},
		{"f(){ s=a; }; f; echo @$s", []string{"s=a"}},
		{"f(){ s=a; }; ( f ); echo @$s", nil},
		{"f(){ s=a; }; y=$(f); echo @$s", nil},
		{"f(){ :; }; s=a; f; s=b; f; echo @$s", []string{"s=b"}},
		{"f(){ echo @$s; }; s=a f", []string{"s=a"}},                // the assignment before the call is seen in the body
		{"f(){ :; }; s=o; s=a f; echo @$s", []string{"s=o"}},        // after the call, the value before it
		{"f(){ s=q; }; s=o; s=a f; echo @$s", []string{"s=o"}},      // nor what the body assigns to it
		{"f(){ local s; s=a; }; s=o; f; echo @$s", []string{"s=o"}}, // a local in the body does not reach after the call
		{"f(){ declare s; echo @$s; }; s=o; f", []string{"-"}},      // a new empty variable in the function
		{"f(){ return; s=a; }; f; echo @$s", nil},                   // return ends the body
		{"f(){ local s; g; echo @$s; }; g(){ s=G; }; s=o; f", []string{"s=G"}},
		{"f(){ local s; g; }; g(){ s=G; }; s=o; f; echo @$s", []string{"s=o"}},
		{"f(){ f; s=a; }; f; echo @$s", []string{"s=a"}}, // a recursion stops
		{"f(){ (s=a); }; f; echo @$s", nil},              // a body in ( ) is a subshell
		// an element of an array, which the tree gives as the command word:
		// the other elements keep their values
		{"a[0]=x; echo @${a[0]}", []string{"a[0]=x", "before"}},
		{"a=(o); a[$i]=x; echo @${a[1]}", []string{"a=(o)", "a[$i]=x"}},
		{"a[0]=x b=y; echo @$b", []string{"b=y"}},
		{"a[0]+=x; echo @$a", []string{"a[0]+=x", "before"}},
		{"declare a[1]=x; echo @$a", []string{"a[1]=x", "before"}},
		{"a[0]=x true; echo @$a", nil},                                // before a command: its environment only
		{"f(){ echo @${a[0]}; }; a=(o); a[0]=x f", []string{"a=(o)"}}, // bash does not assign an element before a call
		// a round of a loop reads what the rounds before it left, however
		// many: g defined in round 1 defines f in round 2, whose call in
		// round 3 assigns key
		{"f(){ :; }; g(){ :; }; for i in 1 2 3; do f; g; g(){ f(){ key=x; }; }; done; echo @$key", []string{"before", "key=x"}},
		{"f(){ :; }; g(){ :; }; while c; do f; g; g(){ f(){ key=x; }; }; done; echo @$key", []string{"before", "key=x"}},
		{"for i in 1 2 3; do echo @$c; c=$b; b=$a; a=x; done", []string{"before", "c=$b"}},
	} {
		if got := reaching(t, tc.src); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: %q, want %q", tc.src, got, tc.want)
		}
	}
}

// functionsAt are the definitions the command named name at @ calls.
func functionsAt(t *testing.T, src, name string) []string {
	t.Helper()
	i := strings.Index(src, "@")
	script := src[:i] + src[i+1:]
	texts := func(v *NameVisibility) []string {
		var out []string
		defs, _ := v.Functions(name, Span{i, i})
		for _, d := range defs {
			out = append(out, script[d.Span().Start:d.Span().End])
		}
		slices.Sort(out)
		return out
	}
	out := texts(NewNameVisibility(script, Parse(script)))
	if old := texts(oldNameVisibility(script, Parse(script))); fmt.Sprint(old) != fmt.Sprint(out) {
		t.Errorf("%q: the flow reading gives %q, the old reading %q", src, out, old)
	}
	return out
}

func TestNameVisibilityFunctions(t *testing.T) {
	for _, tc := range []struct {
		src, name string
		want      []string
	}{
		{"@f; f(){ a; }", "f", nil}, // called before it is defined
		{"f(){ a; }; @f", "f", []string{"f(){ a; }"}},
		{"f(){ a; }; @f \"$X\"", "f", []string{"f(){ a; }"}}, // words that are not literal
		{"f(){ a; }; f(){ b; }; @f", "f", []string{"f(){ b; }"}},
		{"f(){ a; }; c && f(){ b; }; @f", "f", []string{"f(){ a; }", "f(){ b; }"}},
		{"f(){ a; }; unset -f f; @f", "f", nil},
		{"( f(){ a; } ); @f", "f", nil},
		{"g(){ f(){ a; }; }; @f", "f", nil}, // defined when g is called
		{"g(){ f(){ a; }; }; g; @f", "f", []string{"f(){ a; }"}},
		{"g(){ :; }; f(){ a; }; for i in 1 2 3; do @f; g; g(){ f(){ b; }; }; done", "f", []string{"f(){ a; }", "f(){ b; }"}},
	} {
		if got := functionsAt(t, tc.src, tc.name); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: %q, want %q", tc.src, got, tc.want)
		}
	}
}

// TestNameVisibilityTime: nested loops and long lists are read in a time
// that grows as a small power of their size (not 2^depth rounds of nested
// loops, nor every command keeping every name). The test checks only the
// time, so it runs with ACTIONS_SCALE=1 only, as the time depends on the
// machine.
func TestNameVisibilityTime(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of NewNameVisibility on nested loops and long lists")
	}
	nest := func(kind string, d int) string {
		s := "s=x; echo $s"
		for i := range d {
			if kind == "for" {
				s = fmt.Sprintf("for i%d in 1 2; do s%d=x; %s; done", i, i, s)
			} else {
				s = fmt.Sprintf("while c%d; do s%d=x; %s; done", i, i, s)
			}
		}
		return s
	}
	var long strings.Builder
	for i := range 3000 {
		fmt.Fprintf(&long, "v%d=$X; echo \"$v%d\"\n", i, i)
	}
	for name, src := range map[string]string{"for": nest("for", 20), "while": nest("while", 20), "list": long.String()} {
		start := time.Now()
		NewNameVisibility(src, Parse(src))
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: %v", name, d)
		}
	}
}

// TestNameVisibilityCallsNotRead: past maxNameCalls, the body of a call is
// not read, and NameVisibility says where the first such call is.
func TestNameVisibilityCallsNotRead(t *testing.T) {
	var b strings.Builder
	b.WriteString("w(){ :; }\nf0(){ :; }\n")
	for i := 1; i <= 13; i++ {
		fmt.Fprintf(&b, "f%d(){ f%d; f%d; }\n", i, i-1, i-1)
	}
	b.WriteString("f13\nw\n")
	src := b.String()
	// the flow reading reads a body once for each state that reaches its
	// calls, so the calls that double with each level stay under the limit
	if n := NewNameVisibility(src, Parse(src)).CallsNotRead(); n.OK {
		t.Errorf("the flow reading past the limit: %v", n)
	}
	if n := oldNameVisibility(src, Parse(src)).CallsNotRead(); !n.OK || n.At.Start < 0 || n.At.End > len(src) || !strings.HasPrefix(src[n.At.Start:], "f0") {
		t.Errorf("past the limit: %v", n)
	}
	var n CallsNotRead
	Writes(src, Parse(src), WriteOptions{Target: isOut, NotRead: &n})
	if !n.OK || !strings.HasPrefix(src[n.At.Start:], "f") {
		t.Errorf("Writes past the limit: %v", n)
	}
	small := "f(){ :; }; f; f"
	if n := NewNameVisibility(small, Parse(small)).CallsNotRead(); n.OK {
		t.Errorf("%q: a call not read", small)
	}
	n = CallsNotRead{}
	Writes(small, Parse(small), WriteOptions{Target: isOut, NotRead: &n})
	if n.OK {
		t.Errorf("Writes %q: a call not read", small)
	}
}

// The word of the value of an assignment: the parts after the =, or the
// word after :=; Append for += and an element.
func TestAssignmentValue(t *testing.T) {
	for _, tc := range []struct {
		src, value string
		append     bool
	}{
		{"s=a; x @$s", "a", false},
		{"s=\"$A\"b; x @$s", "\"$A\"b", false},
		{"s=; x @$s", "", false},
		{"s+=a; x @$s", "a", true},
		{"s[0]=a; x @$s", "a", true},
		{"export s=$A; x @$s", "$A", false},
		{": ${s:=v$A}; x @$s", "v$A", false},
	} {
		i := strings.Index(tc.src, "@")
		script := tc.src[:i] + tc.src[i+1:]
		v := NewNameVisibility(script, Parse(script))
		var got []string
		for _, a := range v.Reaching(VarName{"s"}, Span{i, i}) {
			if a.Value != nil {
				got = append(got, fmt.Sprintf("%s %v", script[a.Value.Span.Start:a.Value.Span.End], a.Append))
			}
		}
		if want := fmt.Sprintf("%s %v", tc.value, tc.append); len(got) != 1 || got[0] != want {
			t.Errorf("%q: got %q, want %q", tc.src, got, want)
		}
	}
}

// TestNameVisibilityNotRunEnds: the readings again with the commands that
// may not run end, also where a value a later round assigns makes another
// redirect fail.
func TestNameVisibilityNotRunEnds(t *testing.T) {
	for _, src := range []string{
		"v=3; while c; do { :; } >&$v; v=4; done",
		"exec 3>&2; v=3; for i in 1 2 3; do { v=x; } >&$v || true; v=$((v+1)); done",
		"f() { { v=4; f; } >&$v; }; v=3; f",
		chainScript(300), // each read again may add one
	} {
		NewNameVisibility(src, Parse(src))
	}
}

// TestNameVisibilityBases: what an assignment v+=x appends to.
func TestNameVisibilityBases(t *testing.T) {
	src := "s=a; if c; then s=b; fi; s+=c; echo $s"
	v := NewNameVisibility(src, Parse(src))
	rs := v.Reaching(VarName{"s"}, Span{len(src) - 2, len(src) - 2})
	if len(rs) != 1 || !rs[0].Append {
		t.Fatalf("reaching %v, want s+=c alone", rs)
	}
	var got []string
	for _, b := range v.Bases(rs[0]) {
		got = append(got, src[b.At.Start:b.At.End])
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"s=a", "s=b"}) {
		t.Errorf("bases %q, want s=a and s=b", got)
	}
}

// chainScript is n commands each of whose redirect duplicates the
// descriptor the one before assigns.
func chainScript(n int) string {
	var b strings.Builder
	b.WriteString("x0=9; { x0=3; } >&5\n")
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "x%d=9; { x%d=3; } >&$x%d\n", i, i, i-1)
	}
	return b.String()
}

// declare "$n=value" assigns the variable whose name n holds, when n holds
// one literal name on every path; otherwise the assignment is not read.
func TestNameVisibilityDeclaredName(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want []string
	}{
		{"n=VAL; declare \"$n=$TITLE\"; echo @$VAL", []string{"\"$n=$TITLE\""}},
		{"n=VAL; declare \"$n=fixed\"; echo @$VAL", []string{"\"$n=fixed\""}},
		{"n=VAL; declare -g ${n}=x; echo @$VAL", []string{"${n}=x"}},
		{"n=VAL; export \"$n=x\"; echo @$VAL", []string{"\"$n=x\""}},
		{"n=VAL; readonly \"$n=x\"; echo @$VAL", []string{"\"$n=x\""}},
		{"f() { local n=VAL; local \"$n=x\"; echo @$VAL; }; f", []string{"\"$n=x\""}},
		{"f() { n=VAL; local \"$n=x\"; }; VAL=o; f; echo @$VAL", []string{"VAL=o"}}, // local: gone after the call
		// n unknown, or one of two names: not read
		{"declare \"$n=x\"; echo @$VAL", nil},
		{"n=$1; declare \"$n=x\"; echo @$VAL", nil},
		{"n=VAL; c && n=W; declare \"$n=x\"; echo @$VAL", nil},
		{"n=VAL; declare \"$n+=x\"; echo @$VAL", nil},
	} {
		i := strings.Index(tc.src, "@")
		script := tc.src[:i] + tc.src[i+1:]
		var name VarName
		Walk(script, Parse(script).List, Enclosing{}, Visitor{Part: func(p *Part, _ Enclosing) {
			if p.Span.Start == i && p.Kind == PartParam {
				name = p.Name
			}
		}})
		if got := assignmentTexts(script, readFlow(script, Parse(script)).Reaching(name, Span{i, i})); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: got %q, want %q", tc.src, got, tc.want)
		}
	}
}

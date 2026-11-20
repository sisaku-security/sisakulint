package shell

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

const (
	envTop      = ExecutionEnvironmentTop
	envSubshell = ExecutionEnvironmentSubshell
	envCoproc   = ExecutionEnvironmentCoproc
	envElement  = ExecutionEnvironmentPipelineElement
	envSubst    = ExecutionEnvironmentCommandSubstitution
	envProc     = ExecutionEnvironmentProcessSubstitution
)

// chain is the kinds of env and of its parents, env first.
func chain(env *ExecutionEnvironment) []ExecutionEnvironmentKind {
	var out []ExecutionEnvironmentKind
	for e := env; e != nil; e = e.Parent {
		out = append(out, e.Kind)
	}
	return out
}

// walkedCommands are the commands Walk gives, by their text, with the
// chains of their execution environments.
func walkedCommands(script string) map[string][]ExecutionEnvironmentKind {
	got := map[string][]ExecutionEnvironmentKind{}
	Walk(script, Parse(script).List, Enclosing{}, Visitor{Command: func(c Command, at Enclosing) bool {
		got[script[c.Span().Start:c.Span().End]] = chain(at.Env)
		return true
	}})
	return got
}

func TestWalkEnvironments(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   map[string][]ExecutionEnvironmentKind
	}{
		{"( a )", map[string][]ExecutionEnvironmentKind{"( a )": {envTop}, "a": {envSubshell, envTop}}},
		{"a | b", map[string][]ExecutionEnvironmentKind{"a | b": {envTop}, "a": {envElement, envTop}, "b": {envElement, envTop}}},
		{"coproc c { a; }", map[string][]ExecutionEnvironmentKind{"coproc c { a; }": {envTop}, "a": {envCoproc, envTop}}},
		{"x=$(a)", map[string][]ExecutionEnvironmentKind{"x=$(a)": {envTop}, "a": {envSubst, envTop}}},
		{"cat <(a) >(b)", map[string][]ExecutionEnvironmentKind{"cat <(a) >(b)": {envTop}, "a": {envProc, envTop}, "b": {envProc, envTop}}},
		{"f(){ a; }", map[string][]ExecutionEnvironmentKind{"f(){ a; }": {envTop}, "{ a; }": {envTop}, "a": {envTop}}},
		{"cat <<EOF\n$(a)\nEOF", map[string][]ExecutionEnvironmentKind{"cat <<EOF": {envTop}, "a": {envSubst, envTop}}},
		{"echo x > \"$(a)\"", map[string][]ExecutionEnvironmentKind{"echo x > \"$(a)\"": {envTop}, "a": {envSubst, envTop}}},
		{"( b | c )", map[string][]ExecutionEnvironmentKind{"( b | c )": {envTop}, "b | c": {envSubshell, envTop}, "b": {envElement, envSubshell, envTop}, "c": {envElement, envSubshell, envTop}}},
		{"a &", map[string][]ExecutionEnvironmentKind{"a": {ExecutionEnvironmentAsynchronous, envTop}}},
		{"x=$(a &)", map[string][]ExecutionEnvironmentKind{"a": {ExecutionEnvironmentAsynchronous, envSubst, envTop}}},
		{"f(){ a & }", map[string][]ExecutionEnvironmentKind{"a": {ExecutionEnvironmentAsynchronous, envTop}}},
		{"a | b &", map[string][]ExecutionEnvironmentKind{"b": {envElement, ExecutionEnvironmentAsynchronous, envTop}}},
		{"a && $(b)", map[string][]ExecutionEnvironmentKind{"a && $(b)": {envTop}, "a": {envTop}, "$(b)": {envTop}, "b": {envSubst, envTop}}},
		// the words of a ${ }: after its operator, its subscript, and nested
		{"echo ${x:-$(c)}", map[string][]ExecutionEnvironmentKind{"c": {envSubst, envTop}}},
		{"echo ${a:-${b:-$(c)}}", map[string][]ExecutionEnvironmentKind{"c": {envSubst, envTop}}},
		{"echo ${a[$(i)]:0:$(n)}", map[string][]ExecutionEnvironmentKind{"i": {envSubst, envTop}, "n": {envSubst, envTop}}},
		{"cat <<EOF\n${x/a/$(r)}\nEOF", map[string][]ExecutionEnvironmentKind{"r": {envSubst, envTop}}},
		// the words of for and select, in the shell that runs the loop
		{"for x in $(c); do d; done", map[string][]ExecutionEnvironmentKind{"c": {envSubst, envTop}, "d": {envTop}}},
		// the parts of an arithmetic expression
		{"echo $(( $(c) + 1 ))", map[string][]ExecutionEnvironmentKind{"c": {envSubst, envTop}}},
		{"(( n = $(c) ))", map[string][]ExecutionEnvironmentKind{"c": {envSubst, envTop}}},
		{"for (( i=$(a); i<$(b); i++ )); do :; done", map[string][]ExecutionEnvironmentKind{"a": {envSubst, envTop}, "b": {envSubst, envTop}}},
	} {
		got := walkedCommands(tc.script)
		for text, want := range tc.want {
			if g, ok := got[text]; !ok || !slices.Equal(g, want) {
				t.Errorf("%q: %q: environments %v, want %v (walked %v)", tc.script, text, g, want, got)
			}
		}
	}
}

// TestWalkCoprocName: the name of a coproc is expanded in the shell that
// starts the coproc.
func TestWalkCoprocName(t *testing.T) {
	script := "coproc $(n) { a; }"
	got := walkedCommands(script)
	if want := []ExecutionEnvironmentKind{envSubst, envTop}; !slices.Equal(got["n"], want) {
		t.Errorf("the name's substitution: %v, want %v", got["n"], want)
	}
}

func TestWalkFunc(t *testing.T) {
	script := "f(){ a; }; b"
	funcs := map[string]string{}
	Walk(script, Parse(script).List, Enclosing{}, Visitor{Command: func(c Command, at Enclosing) bool {
		name := ""
		if at.Func != nil {
			name = script[at.Func.Name.Span.Start:at.Func.Name.Span.End]
		}
		funcs[script[c.Span().Start:c.Span().End]] = name
		return true
	}})
	if funcs["a"] != "f" || funcs["b"] != "" {
		t.Errorf("the functions around a and b: %q", funcs)
	}
}

func TestWalkPipelineElement(t *testing.T) {
	script := "a | b; c"
	got := map[string]int{}
	Walk(script, Parse(script).List, Enclosing{}, Visitor{Command: func(c Command, at Enclosing) bool {
		i := at.Element
		if at.Pipeline == nil {
			i = -2
		}
		got[script[c.Span().Start:c.Span().End]] = i
		return true
	}})
	if want := map[string]int{"a | b": -2, "a": 0, "b": 1, "c": -2}; !mapsEqual(got, want) {
		t.Errorf("elements %v, want %v", got, want)
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// order is what Walk gives, in order: commands as their text, parts as
// "part:" and their text.
func order(script string) []string {
	var out []string
	Walk(script, Parse(script).List, Enclosing{}, Visitor{
		Command: func(c Command, _ Enclosing) bool {
			out = append(out, script[c.Span().Start:c.Span().End])
			return true
		},
		Part: func(p *Part, _ Enclosing) {
			out = append(out, "part:"+script[p.Span.Start:p.Span.End])
		},
	})
	return out
}

// TestWalkOrder: a heredoc's body is expanded when the command that has it
// runs; a compound's redirects before its body.
func TestWalkOrder(t *testing.T) {
	got := order("x=0; cat <<EOF\n$x\nEOF\nx=1")
	at := func(s string) int { return slices.Index(got, s) }
	if !(at("cat <<EOF") < at("part:$x") && at("part:$x") < at("x=1")) {
		t.Errorf("the body's $x is not between cat and x=1: %q", got)
	}
	got = order("x=$(a) true $(b) > \"$(c)\"")
	if !(at("b") < at("a") && at("a") < at("c")) {
		t.Errorf("not words, assignments, redirects: %q", got)
	}
	got = order("{ a; } <<EOF\n$(b)\nEOF")
	if !(at("b") >= 0 && at("b") < at("a")) {
		t.Errorf("the compound's heredoc is not before its body: %q", got)
	}
}

func TestWalkSkip(t *testing.T) {
	script := "( a ); b"
	var entered, left []string
	Walk(script, Parse(script).List, Enclosing{}, Visitor{
		Command: func(c Command, _ Enclosing) bool {
			text := script[c.Span().Start:c.Span().End]
			entered = append(entered, text)
			return text != "( a )"
		},
		Leave: func(c Command, _ Enclosing) {
			left = append(left, script[c.Span().Start:c.Span().End])
		},
	})
	if slices.Contains(entered, "a") {
		t.Errorf("a skipped command's body was walked: %q", entered)
	}
	if !slices.Equal(left, []string{"( a )", "b"}) {
		t.Errorf("left %q", left)
	}
}

// TestWalkRedirect: Redirect gets each redirect, with its target's parts
// after it.
func TestWalkRedirect(t *testing.T) {
	script := "a > \"$f\" 2>&1"
	var got []string
	Walk(script, Parse(script).List, Enclosing{}, Visitor{
		Redirect: func(r *Redirect, _ Enclosing) { got = append(got, "redirect:"+r.Op.String()) },
		Part:     func(p *Part, _ Enclosing) { got = append(got, "part:"+script[p.Span.Start:p.Span.End]) },
	})
	want := []string{"part:a", "redirect:RedirOut", "part:$f", "redirect:RedirDupOut", "part:1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestWalkFrom: a walk of a subtree starts in the environment given.
func TestWalkFrom(t *testing.T) {
	script := "( a | b )"
	sc := Parse(script)
	sub := &ExecutionEnvironment{Kind: envSubshell, Parent: &ExecutionEnvironment{Kind: envTop}}
	inner := sc.List[0].(*Compound).Body
	var got []ExecutionEnvironmentKind
	Walk(script, inner[0].(*Pipeline).Commands[:1], Enclosing{Env: sub}, Visitor{Command: func(c Command, at Enclosing) bool {
		got = chain(at.Env)
		return true
	}})
	if want := []ExecutionEnvironmentKind{envSubshell, envTop}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestWalkLastpipe(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   []ExecutionEnvironmentKind // the environments of b
	}{
		{"shopt -s lastpipe; a | b", []ExecutionEnvironmentKind{envTop}},
		{"a | b; shopt -s lastpipe", []ExecutionEnvironmentKind{envElement, envTop}},
		{"shopt -s lastpipe; shopt -u lastpipe; a | b", []ExecutionEnvironmentKind{envElement, envTop}},
		{"( shopt -s lastpipe ); a | b", []ExecutionEnvironmentKind{envElement, envTop}},
		{"shopt -s \"$o\"; a | b", []ExecutionEnvironmentKind{envElement, envTop}},
		{"{ shopt -s lastpipe; }; a | b", []ExecutionEnvironmentKind{envTop}},
		{"shopt -s lastpipe; ( a | b )", []ExecutionEnvironmentKind{envSubshell, envTop}},
		// a shopt that may not run is not followed
		{"if false; then shopt -s lastpipe; fi; a | b", []ExecutionEnvironmentKind{envElement, envTop}},
		{"false && shopt -s lastpipe; a | b", []ExecutionEnvironmentKind{envElement, envTop}},
	} {
		got := walkedCommands(tc.script)
		if !slices.Equal(got["b"], tc.want) {
			t.Errorf("%q: b runs in %v, want %v", tc.script, got["b"], tc.want)
		}
		if want := []ExecutionEnvironmentKind{envElement, envTop}; !strings.Contains(tc.script, "( a") && !slices.Equal(got["a"], want) {
			t.Errorf("%q: a runs in %v, want %v", tc.script, got["a"], want)
		}
	}
}

// stdouts are where the standard output of each command Walk gives goes,
// by the command's text.
func stdouts(script string) map[string]StdoutKind {
	got := map[string]StdoutKind{}
	Walk(script, Parse(script).List, Enclosing{}, Visitor{Descriptors: &DescriptorReading{}, Command: func(c Command, at Enclosing) bool {
		got[script[c.Span().Start:c.Span().End]] = at.Stdout
		return true
	}})
	return got
}

// calledStdouts is, for each command of script, where its standard output
// goes each time a reading with the script's NameVisibility gives it, and
// the calls that run it ("" where it is not in a body read at a call).
func calledStdouts(script string) map[string][]string {
	sc := Parse(script)
	r := newFdReading(script)
	r.vis = NewNameVisibility(script, sc)
	r.findNames(sc.List)
	got := map[string][]string{}
	Walk(script, sc.List, Enclosing{}, Visitor{Descriptors: &DescriptorReading{reading: r}, Command: func(c Command, at Enclosing) bool {
		call := ""
		if at.Call != nil {
			call = script[at.Call.Span().Start:at.Call.Span().End]
		}
		k := script[c.Span().Start:c.Span().End]
		got[k] = append(got[k], at.Stdout.String()+"@"+call)
		return true
	}})
	return got
}

// TestWalkStdoutPaths: a reading of descriptors gives where the standard
// output may go on the paths that reach a command.
func TestWalkStdoutPaths(t *testing.T) {
	for _, tc := range []struct {
		script, command string
		want            StdoutKind
	}{
		{"exec >/dev/null; if c; then exec >&2; fi; a", "a", StdoutLog},
		{"exec >/dev/null; c && exec >&2; a", "a", StdoutLog},
		{"exec >/dev/null; if c; then exec >f; else exec >g; fi; a", "a", StdoutFile},
		{"exec >/dev/null; for i in 1 2; do a; exec >&2; done", "a", StdoutLog},
		{"exec 4>&2; exec >/dev/null; while c; do a; exec >&4; done", "a", StdoutLog},
		{"exec >&4 || true; a", "a", StdoutLog},
		{"exec 3>&4; exec >&3; a", "a", StdoutLog},
		{"( exec >/dev/null ); a", "a", StdoutLog},
		{"x=$(exec >/dev/null); a", "a", StdoutLog},
		{"b | exec >/dev/null; a", "a", StdoutLog},
		{"{ exec >&2; a; } |& b", "a", StdoutPipe},
	} {
		if got := stdouts(tc.script)[tc.command]; got != tc.want {
			t.Errorf("%q: the standard output of %q goes to %v, want %v", tc.script, tc.command, got, tc.want)
		}
	}
}

// TestWalkCalls: with a NameVisibility, the body of a function is given
// where each call runs it, with the descriptors there.
func TestWalkCalls(t *testing.T) {
	for _, tc := range []struct {
		script, command string
		want            []string
	}{
		{"f() { a; }; f >/dev/null; f", "a", []string{"StdoutFile@f >/dev/null", "StdoutLog@f"}},
		{"f() { exec >/dev/null; }; f; a", "a", []string{"StdoutFile@"}},
		{"g() { a; }", "a", []string{"StdoutLog@"}},
		{"f() { f; a; }; f", "a", []string{"StdoutLog@f"}},
		{"f() { g; a; }; g() { f; }; f", "a", []string{"StdoutLog@f"}},
		{"g() { g() { a; }; g; }; g", "a", []string{"StdoutLog@g"}}, // a definition the body makes of its own name
	} {
		if got := calledStdouts(tc.script)[tc.command]; !slices.Equal(got, tc.want) {
			t.Errorf("%q: %q got %v, want %v", tc.script, tc.command, got, tc.want)
		}
	}
}

func TestWalkStdout(t *testing.T) {
	for _, tc := range []struct {
		script, command string
		want            StdoutKind
	}{
		{"a", "a", StdoutLog},
		{"a | b", "a", StdoutPipe},
		{"a | b", "b", StdoutLog},
		{"x=$(a)", "a", StdoutSubstitution},
		{"{ a; } > f", "a", StdoutFile},
		{"{ a; } > /dev/stdout", "a", StdoutLog},
		{"{ a; } >&2", "a", StdoutLog},
		{"{ a; } > /dev/null", "a", StdoutFile},
		{"( a ) > f; b", "b", StdoutLog},
		{"coproc { a; }", "a", StdoutPipe},
		{"exec > f; a", "a", StdoutFile},
		{"( exec > f ); a", "a", StdoutLog},
		// bash 5.3: exec -- and command exec keep their redirects in the shell,
		// builtin exec does not; >&3- moves 3 to 1 for the command alone
		{"exec -- > f; a", "a", StdoutFile},
		{"command exec > f; a", "a", StdoutFile},
		{"builtin exec > f; a", "a", StdoutLog},
		{"exec 3> f; { a; } >&3-", "a", StdoutFile},
		{"exec 3> f; b >&3-; a", "a", StdoutLog},
		{"{ exec > f; }; a", "a", StdoutFile},    // exec in a brace stays in the shell
		{"false && exec > f; a", "a", StdoutLog}, // an exec that may not run is not followed
		{"f(){ exec > g; }; a", "a", StdoutLog},
		{"cat <(a)", "a", StdoutPipe},
		{"tee >(a)", "a", StdoutLog},
		{"tee >(a) > f", "a", StdoutLog},
		{"x=$(a | b)", "b", StdoutSubstitution},
		{"{ exec >&2; a; } |& b", "a", StdoutPipe}, // |& joins 2 to the pipe after the element's redirects
		{"{ a; } 1>&2 |& b", "a", StdoutLog},       // 1 to where 2 is before |& joins it
		{"{ { a; } 1>&2; } |& b", "a", StdoutPipe},
		{"{ exec 2>/dev/null; } >&1; { a; } >&2", "a", StdoutFile}, // >&1 points 1 only
	} {
		if got := stdouts(tc.script)[tc.command]; got != tc.want {
			t.Errorf("%q: the standard output of %q goes to %v, want %v", tc.script, tc.command, got, tc.want)
		}
	}
}

// TestWalkSimple: the simple commands of a script, in the substitutions of
// a heredoc's body and of a redirect's target too.
func TestWalkSimple(t *testing.T) {
	for script, want := range map[string][]string{
		"a | b && c":                    {"a", "b", "c"},
		"x=$(a) b":                      {"x=$(a) b", "a"},
		"cat <<EOF\n$(curl x)\nEOF":     {"cat <<EOF", "curl x"},
		"echo a > \"$(curl x)\"":        {"echo a > \"$(curl x)\"", "curl x"},
		"f(){ a; }; coproc $(n) { b; }": {"a", "n", "b"},
	} {
		var got []string
		WalkSimple(Parse(script).List, func(s *Simple) {
			got = append(got, script[s.Span().Start:s.Span().End])
		})
		if !slices.Equal(got, want) {
			t.Errorf("%q: %q, want %q", script, got, want)
		}
	}
}

// TestWalkStdoutUnasked: a walk not asked for the descriptors does not read
// them, and gives StdoutUnset.
func TestWalkStdoutUnasked(t *testing.T) {
	got := StdoutLog
	Walk("exec >f; a", Parse("exec >f; a").List, Enclosing{}, Visitor{Command: func(c Command, at Enclosing) bool {
		got = at.Stdout
		return true
	}})
	if got != StdoutUnset {
		t.Errorf("got %v, want StdoutUnset", got)
	}
}

// TestWalkLeaveCall: a walk that reads descriptors gives each call of a
// function after the bodies it runs, and whether it read one.
func TestWalkLeaveCall(t *testing.T) {
	var nested strings.Builder
	for i := 1; i < 7; i++ {
		fmt.Fprintf(&nested, "f%d() { f%[2]d; f%[2]d; f%[2]d; f%[2]d; }\n", i, i+1)
	}
	nested.WriteString("f7() { :; }\nf1\nf7\n")
	for _, tc := range []struct {
		script string
		want   []string
	}{
		{"f() { :; }; f", []string{"f true"}},
		{"f() { f; }; f", []string{"f false", "f true"}}, // the inner call, read where the outer runs the body
		{"f() { :; }; f >&4", []string{"f >&4 false"}},
		{"echo a", nil},
		{"f() { a; }; f; a", []string{"a <", "f true", "a <"}},
	} {
		var got []string
		walkLeaveCall(tc.script, func(s string) { got = append(got, s) })
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.script, got, tc.want)
		}
	}
	var last string
	walkLeaveCall(nested.String(), func(s string) { last = s })
	if last != "f7 false" {
		t.Errorf("a call past the limit of calls: the last is %q, want f7 false", last)
	}
}

// walkLeaveCall walks script with its definitions and gives, in order, each
// LeaveCall as "text read", and each Leave of a simple command named a as
// "a <".
func walkLeaveCall(script string, give func(string)) {
	sc := Parse(script)
	r := newFdReading(script)
	r.vis = NewNameVisibility(script, sc)
	r.findNames(sc.List)
	Walk(script, sc.List, Enclosing{}, Visitor{
		Descriptors: &DescriptorReading{reading: r},
		Leave: func(c Command, at Enclosing) {
			if x, ok := c.(*Simple); ok && script[x.Span().Start:x.Span().End] == "a" {
				give("a <")
			}
		},
		LeaveCall: func(x *Simple, at Enclosing, read bool) {
			give(fmt.Sprintf("%s %v", script[x.Span().Start:x.Span().End], read))
		},
	})
}

// TestWalkPipeElements: the pipe of each command of a pipeline is a place
// of its own: a pipe inside a command of a pipeline is not the pipe of that
// command.
func TestWalkPipeElements(t *testing.T) {
	s := "{ echo a | tr a b; } | cat"
	sc := Parse(s)
	r := newFdReading(s)
	stdout := map[string]dests{}
	Walk(s, sc.List, Enclosing{}, Visitor{Descriptors: &DescriptorReading{reading: r}, Command: func(c Command, at Enclosing) bool {
		if x, ok := c.(*Simple); ok {
			stdout[s[x.Span().Start:x.Span().End]] = r.at(r.table(x.Redirects), 1)
		}
		return true
	}})
	echo, tr := stdout["echo a"], stdout["tr a b"]
	if len(echo) != 1 || len(tr) != 1 || !echo[0].pipe || !tr[0].pipe || echo[0].same(tr[0]) {
		t.Errorf("echo a writes to %+v, tr a b to %+v: want two pipes, not the same", echo, tr)
	}
}

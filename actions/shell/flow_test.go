package shell

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// flowReaching is what reaches the read marked @ in src by the flow reading
// (readFlow), as assignmentTexts gives it.
func flowReaching(t *testing.T, src string) []string {
	t.Helper()
	i := strings.Index(src, "@")
	script := src[:i] + src[i+1:]
	sc := Parse(script)
	var name VarName
	Walk(script, sc.List, Enclosing{}, Visitor{Part: func(p *Part, _ Enclosing) {
		if p.Span.Start == i && (p.Kind == PartParam || p.Kind == PartParamOp) {
			name = p.Name
		}
	}})
	if name.String() == "" {
		t.Fatalf("%q: no parameter at %d", src, i)
	}
	return assignmentTexts(script, readFlow(script, sc).Reaching(name, Span{i, i}))
}

// TestFlowLoops: the rounds of loops and the jumps out of them, as bash
// 5.3.15 runs them.
func TestFlowLoops(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want []string
	}{
		// the round before gives the round after its value
		{"for i in 1 2; do y=@$x; x=$i; done", []string{"before", "x=$i"}},
		// a break in a $( ) of a loop ends the script of the $( ) (bash: y is empty)
		{"for i in 1; do y=$(x=3; break; echo @$x); done", nil},
		{"while c; do x=1; break; x=2; done; echo @$x", []string{"before", "x=1"}},
		{"f() { x=1; return; x=2; }; f; echo @$x", []string{"x=1"}},
		// an assignment that 10 rounds take to reach (each round defines the
		// function the next round calls): the rounds are read until a round
		// adds nothing, not up to a number of rounds
		{nestedDefinitions(10) + "; echo @$key", []string{"before", "key=x"}},
	} {
		if got := flowReaching(t, tc.src); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: %q, want %q", tc.src, got, tc.want)
		}
	}
}

// TestFlowCallContext: a read in a body is answered for each call that
// runs the body (the call chain), and for all of them together.
func TestFlowCallContext(t *testing.T) {
	src := "f() { echo $v; }; v=1; f; v=2; f"
	sc := Parse(src)
	v := readFlow(src, sc)
	at := Span{strings.Index(src, "$v"), strings.Index(src, "$v")}
	var calls []*Simple
	Walk(src, sc.List, Enclosing{}, Visitor{Command: func(c Command, _ Enclosing) bool {
		if x, ok := c.(*Simple); ok && len(x.Words) == 1 && src[x.Span().Start:x.Span().End] == "f" {
			calls = append(calls, x)
		}
		return true
	}})
	if len(calls) != 2 {
		t.Fatalf("calls %d", len(calls))
	}
	for i, want := range []string{"[v=1]", "[v=2]"} {
		if got := fmt.Sprint(assignmentTexts(src, v.reachingIn(v.contextOf([]*Simple{calls[i]}), VarName{"v"}, at))); got != want {
			t.Errorf("call %d: %s, want %s", i, got, want)
		}
	}
	if got := fmt.Sprint(assignmentTexts(src, v.Reaching(VarName{"v"}, at))); got != "[v=1 v=2]" {
		t.Errorf("every call: %s", got)
	}
}

// TestFlowCallsLarge: the flow reading of many calls of functions, which
// it reads once for each state that reaches them: long bodies called many
// times, chains, many definitions of a name, recursive definitions, and
// descriptors opened on some paths. The test checks only the time, so it
// runs with ACTIONS_SCALE=1 only, as the time depends on the machine (run
// it alone, go test -p 1, without -race).
func TestFlowCallsLarge(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of the flow reading of many calls of functions")
	}
	body := "f() {\n" + strings.Repeat("  echo a\n", 4000) + "}\n"
	chain := ""
	for i := range 1000 {
		chain += fmt.Sprintf("g%d() { g%d; }\n", i, i+1)
	}
	var fds strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&fds, "c%d && : {fd}>/dev/null; echo \"$X\" >&$fd\n", i)
	}
	// 10 seconds: 3.8 s alone for the descriptors on some paths (2,000
	// descriptors open: each join of paths reads the table of them), more
	// on a machine that runs other tests; the old reading took 119 s
	for _, c := range []struct{ name, src string }{
		{"echo x | f", body + strings.Repeat("echo \"x\" | f\n", 4000)},
		{"a chain", chain + strings.Repeat("g0 | bash\necho \"x\"\n", 1000)},
		{"many definitions of one name", strings.Repeat("f() { eval \"$1\"; }\n", 2000) + strings.Repeat("f \"x\""+strings.Repeat(" a", 50)+"\n", 2000)},
		{"recursive definitions", strings.Repeat("f() { f \"$@\"; g; }\n", 2000) + strings.Repeat("f | bash\nf \"x\"\n", 2000)},
		{"descriptors on some paths", fds.String()},
	} {
		start := time.Now()
		readFlow(c.src, Parse(c.src))
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("%s: %v", c.name, d)
		}
	}
}

// nestedDefinitions is a loop whose round k calls dk, which round k-1
// defined: d1 defines d2, which defines d3, up to dn, which assigns key.
func nestedDefinitions(n int) string {
	body := "key=x"
	for k := n; k >= 1; k-- {
		body = fmt.Sprintf("d%d(){ %s; }", k, body)
	}
	var calls []string
	for k := n; k >= 1; k-- {
		calls = append(calls, fmt.Sprintf("d%d", k))
	}
	stubs := ""
	for k := 2; k <= n; k++ {
		stubs += fmt.Sprintf("d%d(){ :; }; ", k)
	}
	return stubs + body + "; while c; do " + strings.Join(calls, "; ") + "; done"
}

// TestFlowTime: the flow reading reads nested loops and long lists in a
// time that grows as a small power of their size. The test checks only the
// time, so it runs with ACTIONS_SCALE=1 only, as the time depends on the
// machine.
func TestFlowTime(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("ACTIONS_SCALE=1 compares the time of the flow reading of nested loops and long lists")
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
		readFlow(src, Parse(src))
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: %v", name, d)
		}
	}
}

// TestWritesCallContext: a body that prints to the descriptor a variable
// holds is read, at each call, with the value the variable has there
// (bash 5.3.15 prints nothing: 1 goes to /dev/null at the first call, 3 at
// the second).
func TestWritesCallContext(t *testing.T) {
	for _, tc := range []struct {
		src  string
		logs bool
	}{
		{"exec 3>/dev/null; f() { echo x >&\"$fd\"; }; fd=1; f >/dev/null; fd=3; f", false},
		{"exec 3>/dev/null; f() { echo x >&\"$fd\"; }; fd=1; f; fd=3; f", true},
	} {
		logs := false
		for _, w := range Writes(tc.src, Parse(tc.src), WriteOptions{Target: isOut, Log: true}) {
			logs = logs || w.Log
		}
		if logs != tc.logs {
			t.Errorf("%q: writes to the log %v, want %v", tc.src, logs, tc.logs)
		}
	}
}

// TestNameVisibilityIsFlow: NewNameVisibility gives the flow reading's
// answer where the old reading differs (a redirect that fails on every
// path).
func TestNameVisibilityIsFlow(t *testing.T) {
	src := "X=safe; { X=k; } 3>&9 || true; echo $X"
	at := Span{strings.LastIndex(src, "$X"), strings.LastIndex(src, "$X")}
	if got := fmt.Sprint(assignmentTexts(src, NewNameVisibility(src, Parse(src)).Reaching(VarName{"X"}, at))); got != "[X=safe]" {
		t.Errorf("%s", got)
	}
}

// TestFlowCutsAndDeepLoops: a body read while a call of it was cut does not
// answer a later call, and loops nested deeper than the commands read ahead
// allow are read in rounds (bash 5.3.15).
func TestFlowCutsAndDeepLoops(t *testing.T) {
	deep := ""
	for i := range 12 {
		deep += fmt.Sprintf("while c%d; do a%d=$b%d; b%d=${a%d}x; ", i, i, i, i, i)
	}
	for range 12 {
		deep += "done; "
	}
	// a chain of 18 definitions, each made by the one before when it runs;
	// p calls them all and then itself, so that each recursive call of p
	// defines one more
	chain, calls := "s=EVIL; ", ""
	for i := 17; i >= 0; i-- {
		chain = fmt.Sprintf("a%d() { %s}; ", i, chain)
		calls += fmt.Sprintf("a%d; ", i)
	}
	ring := ""
	for i := range 6 {
		ring += fmt.Sprintf(`f%d() { v%d=M%d; [ -n "$C" ] && f%d; [ -n "$D" ] && f%d; echo $v%d; }; `, i, i, i, (i+1)%6, (i+2)%6, i)
	}
	ring += "f0; "
	chain = "n=0; " + chain + "p() { " + calls + `n=$((n+1)); [ $n -lt 20 ] && p; }; p; echo @$s`
	for _, tc := range []struct {
		src  string
		want []string
	}{
		// a reading of f inside g (which cut the call of g in f) does not
		// answer the call of f outside g, which reads g
		{"f() { if c; then g; fi; eval @$x; }; g() { f; x='$(evil)'; }; if c; then g; else f; fi", []string{"before", "x='$(evil)'"}},
		// a recursive call (p from q from p) runs the body of p with what
		// reaches it: s=M4 reaches the read in the second run of p
		{`p() { for i in 1 2; do echo @$s; [ -n "$C" ] && break; s=M3; done; [ -n "$C" ] || q; }; q() { g() { s=M4; }; g; p; }; p`, []string{"before", "s=M3", "s=M4"}},
		// unset of a local of the calling function takes the local away: the
		// value before it was made local (bash 5.3.15 and 5.2.37)
		{"s=G; q() { local s=L; p; }; p() { unset s; echo @$s; }; q", []string{"s=G"}},
		// a reading of m, whose call of g took away the local of m, does not
		// answer the second call of m: s held another value before m made
		// it local (bash 5.3.15)
		{"s=A; g() { unset s; }; m() { local s=L; g; echo @$s; }; m; s=B; m", []string{"s=A", "s=B"}},
		{"s=A; g() { unset s; }; m() { local s=L; for i in 1 2; do echo @$s; g; done; }; m; s=B; m", []string{"s=A", "s=B", "s=L"}},
		// the body of p is read again until a reading adds nothing: the
		// definition 18 calls deep runs (bash 5.3.15)
		{chain, []string{"before", "s=EVIL"}},
		// functions that call each other in a ring do not spend the calls of
		// the run: the body of w after them is read
		{ring + `w() { t=M9; }; w; echo @$t`, []string{"t=M9"}},
		// a loop after loops nested deeper than the commands read ahead
		// allow still reads its rounds
		{deep + "while c; do eval @$y; y='$(evil)'; done", []string{"before", "y='$(evil)'"}},
	} {
		if got := flowReaching(t, tc.src); fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%q: %q, want %q", tc.src, got, tc.want)
		}
	}
}

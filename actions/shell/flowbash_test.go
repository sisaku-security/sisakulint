package shell

import (
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// flowStatements are the statements TestFlowWithBash makes scripts of: %
// is a mark of its own (an assignment's value, or a read's label), S a
// statement made the same way.
var flowStatements = []string{
	`s=M%`, `s=M%`, `local s=M%`, `read -r s </dev/null || true`, `unset s`, `: "${s:=M%}"`,
	`echo "R%=$s"`, `echo "R%=$s"`,
	`s=M% >&4 || true`, `{ s=M%; } >&4 || true`, `{ s=M%; } 2>/dev/null`, `declare s=M% >&4 || true`,
	`if [ -n "$C" ]; then S; fi`, `if [ -n "$C" ]; then S; else S; fi`, `[ -n "$C" ] && S`, `[ -n "$C" ] || S`,
	`[ -n "$C" ] && S || S`,
	`for i in 1 2; do S; done`, `for i in 1 2; do S; [ -n "$C" ] && break; S; done`,
	`for i in 1 2; do S; [ -n "$C" ] && continue; S; done`,
	`g() { S; }; g`, `g() { S; [ -n "$C" ] && return; S; }; g`, `g() { S; }; g; g`,
	`( S )`, `S | cat`, `x=$( S ); echo "$x"`, `h() { S; }`, `h`,
	// mutual recursion whose recursive call depends on the path, the callee
	// defined after the call
	`p() { [ -n "$C" ] && q; S; }; q() { p; S; }; if [ -n "$C" ]; then q; else p; fi`,
	`p() { S; [ -n "$C" ] || q; }; q() { S; p; }; p`,
}

// flowScript is a script of n statements from r, nested up to depth, its
// marks numbered from *k.
func flowScript(r *rand.Rand, n, depth int, k *int) string {
	var parts []string
	for range n {
		s := flowStatements[r.IntN(len(flowStatements))]
		for depth == 0 && strings.Contains(s, "S") {
			s = flowStatements[r.IntN(len(flowStatements))]
		}
		var b strings.Builder
		for _, c := range s {
			switch c {
			case '%':
				*k++
				fmt.Fprintf(&b, "%d", *k)
			case 'S':
				b.WriteString(flowScript(r, 1+r.IntN(2), depth-1, k))
			default:
				b.WriteRune(c)
			}
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, "; ")
}

var flowRead = regexp.MustCompile(`R([0-9]+)=(M[0-9]+)?`)

// TestFlowWithBash: on scripts made of flowStatements, each value bash
// reads at a read, with C empty and set, is one that NewNameVisibility says
// may reach it: the assignment of its mark, or, for an empty value, the
// value from before the script, an unset or an assignment with no value.
// The scripts where the old reading answers otherwise are counted.
func TestFlowWithBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	r := rand.New(rand.NewPCG(7, 11))
	differ, declared := 0, map[flowBashRead]int{}
	n := 300
	if os.Getenv("ACTIONS_SCALE") != "" {
		n = 3000
	}
	for i := range n {
		k := 0
		script := "f0() { :; }; " + flowScript(r, 2+r.IntN(4), 2, &k)
		sc := Parse(script)
		v := NewNameVisibility(script, sc)
		old := oldNameVisibility(script, sc)
		reads := map[string]Span{} // by the label of each read, its $s
		for _, m := range regexp.MustCompile(`R([0-9]+)=\$s`).FindAllStringSubmatchIndex(script, -1) {
			at := m[1] - 2
			reads[script[m[2]:m[3]]] = Span{at, at}
		}
		for label, at := range reads {
			if fmt.Sprint(assignmentTexts(script, v.Reaching(VarName{"s"}, at))) != fmt.Sprint(assignmentTexts(script, old.Reaching(VarName{"s"}, at))) {
				differ++
				break
			}
			_ = label
		}
		for _, c := range []string{"", "1"} {
			cmd := exec.Command("bash", "-c", script)
			cmd.Env = []string{"C=" + c, "PATH=/usr/bin:/bin", "FUNCNEST=20"} // a function that calls itself stops
			out, _ := cmd.Output()
			for _, m := range flowRead.FindAllStringSubmatch(string(out), -1) {
				at, ok := reads[m[1]]
				if !ok {
					continue
				}
				texts := assignmentTexts(script, v.Reaching(VarName{"s"}, at))
				var ok2 bool
				if m[2] == "" {
					// no assignment reaches (the value from before the script),
					// or one that leaves it empty
					ok2 = len(texts) == 0 || slices.ContainsFunc(texts, func(x string) bool { return x == "before" || x == "unset" || x == "-" })
				} else {
					ok2 = slices.ContainsFunc(texts, func(x string) bool { return regexp.MustCompile(`\b` + m[2] + `\b`).MatchString(x) })
				}
				switch {
				case ok2:
				case recursiveUnsetLocal[flowBashRead{i, c, m[1]}] > 0:
					declared[flowBashRead{i, c, m[1]}]++
				default:
					t.Errorf("script %d, C=%q: bash reads %q at R%s, the flow reading gives %q:\n%s", i, c, m[2], m[1], texts, script)
				}
			}
		}
	}
	t.Logf("%d of %d scripts where the old reading answers otherwise", differ, n)
	for r, want := range recursiveUnsetLocal {
		if r.script < n && declared[r] != want {
			t.Errorf("script %d, C=%q: bash reads %d values at R%s that the flow reading does not give, want %d (recursive-unset-local)", r.script, r.c, declared[r], r.label, want)
		}
	}
}

// flowBashRead is the read with the label label in the script made
// script-th by TestFlowWithBash, run with C set to c.
type flowBashRead struct {
	script int
	c      string
	label  string
}

// recursiveUnsetLocal are the reads of TestFlowWithBash where bash reads
// values the flow reading does not give, with how many times bash reads
// one there, of the form the rules declare as
// the undetected form recursive-unset-local: a function unsets a variable
// that a calling function made local, in a recursive call that the reading
// reads again from the outer call, without the calls in between.
var recursiveUnsetLocal = map[flowBashRead]int{
	// p() { g() { unset s; echo "R7=$s"; }; g; [ -n "$C" ] || echo "R8=$s"; s=M9; [ -n "$C" ] || q; };
	// q() { for i in 1 2; do h; local s=M10; done; h() { s=M11; }; p; }; p
	{734, "", "7"}: 9,
	{734, "", "8"}: 9,
}

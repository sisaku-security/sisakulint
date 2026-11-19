package shell

import (
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fdStatements are the statements TestDescriptorsWithBash makes scripts
// of: % is a print of a mark of its own, S a statement made the same way.
var fdStatements = []string{
	`echo %`, `echo % >&2`, `echo % >&3`, `echo % >&$fd`,
	`exec >>"$OUT"`, `exec 2>>"$OUT"`, `exec 2>/dev/null`, `exec >/dev/null`, `exec 3>&1`, `exec 3>>"$OUT"`,
	`exec >&3`, `exec >&4 || true`, `exec 2>/dev/null 3>&4 || true`, `exec {fd}>>"$OUT"`, `exec {fd}>&2`, `exec {fd}>&-`,
	`if [ -n "$C" ]; then S; fi`, `if [ -n "$C" ]; then S; else S; fi`, `[ -n "$C" ] && S`,
	`for i in 1 2; do S; done`, `for i in 1 2; do S; [ -n "$C" ] && break; S; done`,
	`g() { S; }; g`, `g() { S; [ -n "$C" ] && return; S; }; g`, `{ S; } >&4 || true`, `{ S; } 2>/dev/null`,
	// the writes that gather what the commands inside write
	`{ S; } >>"$OUT"`, `( S ) >>"$OUT"`, `h() { S; }; h >>"$OUT"`, `{ S; } | tee -a "$OUT" >/dev/null`,
	`h() { S; }; h | tee -a "$OUT" >/dev/null`, `h() { S; }; h >>"$OUT" | cat`,
}

var fdMark = regexp.MustCompile(`M[0-9]+`)

// fdScript is a script of n statements from r, nested up to depth, its
// marks numbered from *k.
func fdScript(r *rand.Rand, n, depth int, k *int) string {
	var parts []string
	for range n {
		s := fdStatements[r.IntN(len(fdStatements))]
		for depth == 0 && strings.Contains(s, "S") {
			s = fdStatements[r.IntN(len(fdStatements))]
		}
		var b strings.Builder
		for _, c := range s {
			switch c {
			case '%':
				*k++
				fmt.Fprintf(&b, "M%d", *k)
			case 'S':
				b.WriteString(fdScript(r, 1+r.IntN(2), depth-1, k))
			default:
				b.WriteRune(c)
			}
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, "; ")
}

// TestDescriptorsWithBash: where bash writes the marks of scripts made of
// fdStatements, the log (its standard output and error) and the file
// $OUT, Writes gives a write there, or, for $OUT, an exec before that
// points a descriptor there.
func TestDescriptorsWithBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	r := rand.New(rand.NewPCG(1, 2))
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	for range 300 {
		k := 0
		script := fdScript(r, 2+r.IntN(4), 2, &k)
		logged, filed := map[string]bool{}, map[string]bool{}
		for _, c := range []string{"", "1"} {
			os.Remove(out)
			cmd := exec.Command(bash, "-c", script)
			cmd.Dir = dir
			cmd.Env = []string{"OUT=" + out, "C=" + c, "PATH=" + os.Getenv("PATH")}
			b, _ := cmd.CombinedOutput()
			for _, m := range fdMark.FindAllString(string(b), -1) {
				logged[m] = true
			}
			f, _ := os.ReadFile(out)
			for _, m := range fdMark.FindAllString(string(f), -1) {
				filed[m] = true
			}
		}
		gotLog, gotFile := map[string]bool{}, map[string]bool{}
		execAt := -1 // where the first exec that points a descriptor at $OUT starts
		for _, w := range Writes(script, Parse(script), WriteOptions{Target: isOut, Log: true}) {
			into := gotFile
			if w.Log {
				into = gotLog
			}
			if w.Exec && (execAt < 0 || w.At.Span().Start < execAt) {
				execAt = w.At.Span().Start
			}
			for _, o := range w.Out {
				if o.Kind == OutLit {
					for _, m := range fdMark.FindAllString(o.Text, -1) {
						into[m] = true
					}
				}
			}
		}
		for m := range logged {
			if !gotLog[m] {
				t.Errorf("%q: bash writes %s to the log; Writes does not", script, m)
			}
		}
		for m := range filed {
			// an exec that points a descriptor at $OUT: what follows it goes
			// there (Write.Exec), which its readers read; a print before it
			// in the script that a loop runs after it is theirs to read
			if !gotFile[m] && execAt < 0 {
				t.Errorf("%q: bash writes %s to $OUT; Writes does not", script, m)
			}
		}
	}
}

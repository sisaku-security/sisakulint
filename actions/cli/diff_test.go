package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// patch applies the unified diff d of one file to a, as git apply would,
// for the tests: it trusts the hunks' lines, and checks what they remove.
func patch(t *testing.T, a, d string) string {
	t.Helper()
	if d == "" {
		return a
	}
	old := splitLines(a)
	var out []string
	pos := 0 // lines of old copied or removed
	lines := strings.SplitAfter(d, "\n")
	noEOL := func(i int) bool {
		return i+1 < len(lines) && strings.HasPrefix(lines[i+1], `\ No newline at end of file`)
	}
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		switch {
		case l == "" || strings.HasPrefix(l, "diff --git ") || strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "+++ ") || strings.HasPrefix(l, `\ `):
		case strings.HasPrefix(l, "@@ "):
			var s1, n1, s2, n2 int
			if _, err := fmtSscanHunk(l, &s1, &n1, &s2, &n2); err != nil {
				t.Fatalf("hunk header %q: %v", l, err)
			}
			start := s1 - 1
			if n1 == 0 {
				start = s1
			}
			out = append(out, old[pos:start]...)
			pos = start
		default:
			body := l[1:]
			if noEOL(i) {
				body = strings.TrimSuffix(body, "\n")
			}
			switch l[0] {
			case ' ':
				out = append(out, old[pos])
				pos++
			case '-':
				if old[pos] != body {
					t.Fatalf("the diff removes %q, but the line is %q", body, old[pos])
				}
				pos++
			case '+':
				out = append(out, body)
			default:
				t.Fatalf("a line of the diff %q", l)
			}
		}
	}
	return strings.Join(append(out, old[pos:]...), "")
}

func TestUnifiedDiff(t *testing.T) {
	long := strings.Repeat("x\n", 20)
	for _, c := range []struct{ name, a, b string }{
		{"same", "a\nb\n", "a\nb\n"},
		{"a line changed", "a\nb\nc\n", "a\nB\nc\n"},
		{"added at the end", "a\n", "a\nb\n"},
		{"added at the start", "b\n", "a\nb\n"},
		{"removed", "a\nb\nc\n", "a\nc\n"},
		{"from empty", "", "a\n"},
		{"to empty", "a\n", ""},
		{"two hunks", "a\n" + long + "b\n", "A\n" + long + "B\n"},
		{"no line break at the end", "a\nb", "a\nc"},
		{"a line break added at the end", "a", "a\n"},
		{"a line break taken away at the end", "a\n", "a"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := unifiedDiff("w.yml", []byte(c.a), []byte(c.b))
			if (d == "") != (c.a == c.b) {
				t.Fatalf("diff %q", d)
			}
			if got := patch(t, c.a, d); got != c.b {
				t.Errorf("patched %q, want %q; diff:\n%s", got, c.b, d)
			}
			if c.name == "two hunks" && strings.Count(d, "@@ -") != 2 {
				t.Errorf("hunks:\n%s", d)
			}
		})
	}
}

// git apply takes the diff as it is.
func TestUnifiedDiffGitApply(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	a, b := "on: push\njobs:\n  j:\n    steps:\n      - run: echo a\n", "on: push\njobs:\n  j:\n    steps:\n      - run: echo b\n        env:\n          X: y\n"
	if err := writeFileAtomic(filepath.Join(dir, "w.yml"), []byte(a)); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(git, "apply", "--check", "-")
	cmd.Dir = dir
	cmd.Stdin = strings.NewReader(unifiedDiff("w.yml", []byte(a), []byte(b)))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("git apply --check: %v %s", err, out)
	}
}

func FuzzUnifiedDiff(f *testing.F) {
	f.Add("a\nb\nc\n", "a\nB\nc\nd")
	f.Add("", "x")
	f.Fuzz(func(t *testing.T, a, b string) {
		if got := patch(t, a, unifiedDiff("f", []byte(a), []byte(b))); got != b {
			t.Fatalf("%q to %q: patched %q", a, b, got)
		}
	})
}

// fmtSscanHunk reads @@ -s1,n1 +s2,n2 @@.
func fmtSscanHunk(l string, s1, n1, s2, n2 *int) (int, error) {
	return fmt.Sscanf(l, "@@ -%d,%d +%d,%d @@", s1, n1, s2, n2)
}

// A name is written as git writes it, so that a name with a
// line break cannot point the patch at another file, and one with a tab or
// a space still applies.
func TestUnifiedDiffNames(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git")
	}
	for _, name := range []string{"sp ace/x.yml", "tab\there.yml", "X\n--- a/v.yml\n+++ b/v.yml", "ü.yml", `q"uote\.yml`} {
		dir := t.TempDir()
		for _, n := range []string{name, "v.yml"} {
			os.MkdirAll(filepath.Dir(filepath.Join(dir, n)), 0o755)
			if err := os.WriteFile(filepath.Join(dir, n), []byte("a\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command(git, "apply", "-")
		cmd.Dir, cmd.Stdin = dir, strings.NewReader(unifiedDiff(name, []byte("a\n"), []byte("b\n")))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%q: git apply: %v %s", name, err, out)
			continue
		}
		if b, _ := os.ReadFile(filepath.Join(dir, name)); string(b) != "b\n" {
			t.Errorf("%q: the file is %q", name, b)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "v.yml")); string(b) != "a\n" {
			t.Errorf("%q: another file changed: %q", name, b)
		}
	}
}

// Many changes take linear memory, not the square.
func TestUnifiedDiffLarge(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 20000; i++ {
		fmt.Fprintf(&a, "line %d\n", i)
		if i%2 == 0 {
			fmt.Fprintf(&b, "line %d changed\n", i)
		} else {
			fmt.Fprintf(&b, "line %d\n", i)
		}
	}
	res := testing.Benchmark(func(tb *testing.B) {
		for range tb.N {
			unifiedDiff("w.yml", []byte(a.String()), []byte(b.String()))
		}
	})
	if mb := res.AllocedBytesPerOp() >> 20; mb > 200 {
		t.Errorf("%d MB for 10000 changes", mb)
	}
	if got := patch(t, a.String(), unifiedDiff("w.yml", []byte(a.String()), []byte(b.String()))); got != b.String() {
		t.Error("the diff does not give b")
	}
}

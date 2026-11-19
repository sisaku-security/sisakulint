package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// initFile runs --init with a, and writes what it writes to a file.
func initFile(t *testing.T, a ...string) string {
	t.Helper()
	got := run(t, raw(append([]string{"--init"}, a...)...))
	if got.code != 0 || got.stderr != "" {
		t.Fatalf("--init %v: exit %d, stderr %q", a, got.code, got.stderr)
	}
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(got.stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTemplateEmpty: the template of --init alone is comments only, and
// read with --config it is a run without the file.
func TestTemplateEmpty(t *testing.T) {
	p := initFile(t)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			t.Errorf("a line that is not a comment: %q", l)
		}
	}
	dir := repo(t)
	want, got := run(t, args("--root", dir)), run(t, args("--root", dir, "--config", p))
	if got.code != want.code || got.stdout != want.stdout || got.stderr != want.stderr {
		t.Errorf("exit %d, stderr %q; want %d", got.code, got.stderr, want.code)
	}
}

// TestTemplateValues: the template of --init with flags, read with
// --config, is a run with the flags.
func TestTemplateValues(t *testing.T) {
	flags := []string{"--exclude", ".github/actions/build", "--fail-on", "high", "--skip-rule", "permissions", "--repo", "o/r", "--fact", "repo.public=false", "--no-assumptions"}
	p := initFile(t, flags...)
	dir := repo(t)
	want, got := run(t, args(append([]string{"--root", dir}, flags...)...)), run(t, args("--root", dir, "--config", p))
	if got.code != want.code || got.stdout != want.stdout || got.stderr != want.stderr || want.code >= ExitUsage {
		t.Errorf("exit %d, stderr %q; want %d, stderr %q", got.code, got.stderr, want.code, want.stderr)
	}
}

// TestTemplateQuoting: a value written by --init is read back the same.
func TestTemplateQuoting(t *testing.T) {
	values := []string{`a: b #c "d" \e`, "a\tb", "  lead", "日本", "x'y"}
	var flags []string
	for _, v := range values {
		flags = append(flags, "--exclude", v)
	}
	got, err := readConfigurationFile(initFile(t, flags...))
	if err != nil {
		t.Fatal(err)
	}
	var read []string
	for _, v := range got {
		read = append(read, v.value)
	}
	if !slices.Equal(read, values) {
		t.Errorf("read back %q, want %q", read, values)
	}
	if r := run(t, raw("--init", "--exclude", "a\xffb")); r.code != ExitUsage || r.stdout != "" {
		t.Errorf("a value that is not UTF-8: exit %d, want %d", r.code, ExitUsage)
	}
}

// TestTemplateEveryKey: the template names every key, in the order of
// configurationKeys.
func TestTemplateEveryKey(t *testing.T) {
	b, err := os.ReadFile(initFile(t))
	if err != nil {
		t.Fatal(err)
	}
	at := 0
	for _, k := range configurationKeys {
		i := strings.Index(string(b)[at:], "# "+k.name+":\n")
		if i < 0 {
			t.Errorf("the key %s is not in the template after the key before it", k.name)
			continue
		}
		at += i
	}
}

// TestInitUsage: --init takes only the flags of the keys whose values are
// not paths.
func TestInitUsage(t *testing.T) {
	for _, c := range []struct {
		args []string
		says string
	}{
		{[]string{"--init", "--accept", "a.json"}, "directory"},
		{[]string{"--init", "--facts", "f.json"}, "directory"},
		{[]string{"--init", "--format", "json"}, "--format"},
		{[]string{"--init", "--root", "d"}, "--root"},
		{[]string{"--init", "a.yml"}, "a.yml"},
		{[]string{"--init", "--config", "c.yaml"}, "--config"},
		{[]string{"--init", "--fail-on", "bogus"}, "bogus"},
	} {
		if got := run(t, raw(c.args...)); got.code != ExitUsage || got.stdout != "" || !strings.Contains(got.stderr, c.says) {
			t.Errorf("%v: exit %d, stderr %q; want %d and %q", c.args, got.code, got.stderr, ExitUsage, c.says)
		}
	}
}

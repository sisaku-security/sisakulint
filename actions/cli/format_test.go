package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFormatDefaultIsText(t *testing.T) {
	dir := repo(t)
	got := run(t, Env{Args: []string{"--root", dir}})
	if strings.HasPrefix(got.stdout, "{") || !strings.Contains(got.stdout, "commit-sha") {
		t.Errorf("the default is not text:\n%s", got.stdout)
	}
}

// The exit code is the same whatever the format.
func TestFormatSameExit(t *testing.T) {
	dir := repo(t)
	for _, a := range [][]string{
		{"--root", dir},
		{"--root", dir, ".github/workflows/ci.yml"},
		{"--root", dir, "--fail-on", "critical"},
		{"--root", textRepo},
	} {
		js := run(t, Env{Args: append([]string{"--format", "json"}, a...)})
		for _, d := range []string{"summary", "normal", "full"} {
			text := run(t, Env{Args: append([]string{"--format", "text", "--detail", d}, a...)})
			if text.code != js.code {
				t.Errorf("%v --detail %s: exit %d with text, %d with json", a, d, text.code, js.code)
			}
		}
		line := run(t, Env{Args: append([]string{"--format", "line"}, a...)})
		if line.code != js.code {
			t.Errorf("%v: exit %d with line, %d with json", a, line.code, js.code)
		}
	}
}

func TestReport(t *testing.T) {
	dir := repo(t)
	js := run(t, args("--root", dir))
	for _, format := range []string{"text", "line", "json"} {
		file := filepath.Join(t.TempDir(), "report.json")
		got := run(t, Env{Args: []string{"--format", format, "--root", dir, "--report", file}})
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != js.stdout || got.code != js.code {
			t.Errorf("--format %s --report: exit %d, the file\n%s\nwant exit %d and\n%s", format, got.code, b, js.code, js.stdout)
		}
	}
}

func TestReportFails(t *testing.T) {
	dir := repo(t)
	got := run(t, Env{Args: []string{"--root", dir, "--report", filepath.Join(t.TempDir(), "no/such/dir/r.json")}})
	if got.code != ExitIO || !strings.Contains(got.stderr, "--report") || got.stdout == "" {
		t.Errorf("exit %d, stderr %q; want %d, why, and the text on stdout", got.code, got.stderr, ExitIO)
	}
}

var escape = regexp.MustCompile("\x1b\\[")

func TestColor(t *testing.T) {
	dir := repo(t)
	for _, c := range []struct {
		name     string
		args     []string
		terminal bool
		noColor  string
		want     bool
	}{
		{"auto, not a terminal", nil, false, "", false},
		{"auto, a terminal", nil, true, "", true},
		{"auto, a terminal, NO_COLOR", nil, true, "1", false},
		{"always", []string{"--color", "always"}, false, "1", true},
		{"never", []string{"--color", "never"}, true, "", false},
		{"json, always", []string{"--color", "always", "--format", "json"}, true, "", false},
		{"line, always", []string{"--color", "always", "--format", "line"}, false, "", true},
		{"line, not a terminal", []string{"--format", "line"}, false, "", false},
	} {
		e := Env{Args: append(append([]string{}, c.args...), "--root", dir), Terminal: c.terminal,
			Getenv: func(k string) string {
				if k == "NO_COLOR" {
					return c.noColor
				}
				return ""
			}}
		got := run(t, e)
		if escape.MatchString(got.stdout) != c.want {
			t.Errorf("%s: color %v, want %v:\n%q", c.name, !c.want, c.want, got.stdout)
		}
	}
}

func TestFormatUsage(t *testing.T) {
	dir := repo(t)
	for _, c := range []struct {
		name string
		env  Env
	}{
		{"an unknown format", Env{Args: []string{"--root", dir, "--format", "xml"}}},
		{"an unknown color", Env{Args: []string{"--root", dir, "--color", "yes"}}},
		{"an empty report", Env{Args: []string{"--root", dir, "--report", ""}}},
		{"the registry as text", Env{Args: []string{"--registry", "--format", "text"}}},
		{"the registry and a report", Env{Args: []string{"--registry", "--report", "r.json"}}},
		{"an unknown detail", Env{Args: []string{"--root", dir, "--detail", "all"}}},
		{"-v and --detail summary", Env{Args: []string{"--root", dir, "-v", "--detail", "summary"}}},
		{"--verbose and --detail normal", Env{Args: []string{"--root", dir, "--detail", "normal", "--verbose"}}},
		{"the registry and a detail", Env{Args: []string{"--registry", "--detail", "full"}}},
		{"the registry as lines", Env{Args: []string{"--registry", "--format", "line"}}},
	} {
		got := run(t, c.env)
		if got.code != ExitUsage || got.stdout != "" {
			t.Errorf("%s: exit %d, stdout %q; want %d and nothing", c.name, got.code, got.stdout, ExitUsage)
		}
	}
}

// TestTextFixFails: the text says why the fixes failed; the exit code is 70.
func TestTextFixFails(t *testing.T) {
	dir, gh := repo(t), fakeGitHub(t)
	symlinked(t, dir) // fix_test.go: action.yml is a symlink, which --fix refuses to write
	got := run(t, Env{Args: []string{"--root", dir, "--online", "--github-api", gh.URL, "--fix"}})
	if got.code != ExitFix || !strings.Contains(got.stdout, "  error: ") || strings.Contains(got.stdout, "bits 70") {
		t.Errorf("exit %d; want %d, and the error in the text:\n%s", got.code, ExitFix, got.stdout)
	}
}

// TestTextStdoutFails: a standard output that fails to write is ExitIO,
// with why on the standard error.
func TestTextStdoutFails(t *testing.T) {
	got := run(t, Env{Args: []string{"--root", repo(t)}, Stdout: failingWriter{}})
	if got.code != ExitIO || got.stderr == "" {
		t.Errorf("exit %d, stderr %q; want %d and why", got.code, got.stderr, ExitIO)
	}
}

func TestVerbose(t *testing.T) {
	short := run(t, Env{Args: []string{"--root", textRepo}})
	long := run(t, Env{Args: []string{"--root", textRepo, "-v"}})
	if strings.Count(long.stdout, "\n") <= strings.Count(short.stdout, "\n") || strings.Contains(long.stdout, "(-v)\n    …") {
		t.Errorf("-v shows no more:\n%s", long.stdout)
	}
}

// -v is --detail full; with --format json, --detail does nothing.
func TestDetailFlag(t *testing.T) {
	full := run(t, Env{Args: []string{"--root", textRepo, "--detail", "full"}})
	for _, a := range [][]string{{"-v"}, {"--verbose"}, {"-v", "--detail", "full"}} {
		if got := run(t, Env{Args: append(a, "--root", textRepo)}); got.stdout != full.stdout || got.code != full.code {
			t.Errorf("%v is not --detail full:\n%s", a, got.stdout)
		}
	}
	js := run(t, Env{Args: []string{"--root", textRepo, "--format", "json"}})
	if got := run(t, Env{Args: []string{"--root", textRepo, "--format", "json", "--detail", "summary"}}); got.stdout != js.stdout {
		t.Errorf("--detail summary changed the JSON:\n%s", got.stdout)
	}
	line := run(t, Env{Args: []string{"--root", textRepo, "--format", "line"}})
	for _, a := range [][]string{{"--detail", "summary"}, {"-v"}} {
		if got := run(t, Env{Args: append([]string{"--root", textRepo, "--format", "line"}, a...)}); got.stdout != line.stdout || got.code != line.code {
			t.Errorf("--format line %v changed the lines:\n%s", a, got.stdout)
		}
	}
}

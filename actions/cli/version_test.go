package cli

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// TestVersion: --version writes the four lines, and takes no other flag
// and no PATH.
func TestVersion(t *testing.T) {
	got := run(t, raw("--version"))
	if got.code != 0 || got.stderr != "" {
		t.Fatalf("--version: %d, stderr %q", got.code, got.stderr)
	}
	lines := strings.Split(strings.TrimSuffix(got.stdout, "\n"), "\n")
	want := strings.Split(strings.TrimSuffix(versionText(debug.ReadBuildInfo()), "\n"), "\n")
	if len(lines) != 4 || strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("--version wrote\n%s\nwant\n%s", got.stdout, strings.Join(want, "\n"))
	}
	if !strings.HasPrefix(lines[0], "sisakulint ") {
		t.Errorf("first line %q", lines[0])
	}
	if c := "commit " + commit(debug.ReadBuildInfo()); lines[1] != c {
		t.Errorf("commit line %q, want %q (as --explain writes it)", lines[1], c)
	}
	if g := "go " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH; lines[2] != g {
		t.Errorf("go line %q, want %q", lines[2], g)
	}
	if s := "schemas sisakulint/report/v0 sisakulint/registry/v0 sisakulint/facts/v0 sisakulint/acceptances/v0"; lines[3] != s {
		t.Errorf("schemas line %q, want %q", lines[3], s)
	}
	for _, e := range []Env{raw("--version", "a.yml"), raw("--version", "--format=json"), raw("--registry", "--version")} {
		if got := run(t, e); got.code != ExitUsage || got.stdout != "" {
			t.Errorf("%v: %d, stdout %q; want %d and nothing", e.Args, got.code, got.stdout, ExitUsage)
		}
	}
}

func TestVersionText(t *testing.T) {
	for _, c := range []struct {
		name  string
		bi    *debug.BuildInfo
		ok    bool
		first string
	}{
		{"no build info", nil, false, "sisakulint unknown"},
		{"no version", &debug.BuildInfo{}, true, "sisakulint unknown"},
		{"a version", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true, "sisakulint v1.2.3"},
		{"go run", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "sisakulint unknown"},
	} {
		if got, _, _ := strings.Cut(versionText(c.bi, c.ok), "\n"); got != c.first {
			t.Errorf("%s: %q, want %q", c.name, got, c.first)
		}
	}
}

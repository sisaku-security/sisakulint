package shell

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestCodeWithPrograms puts an environment variable at a place Places
// reads as code, the way the fix of code-injection would write it, and runs
// the script with bash and the program: the program runs the value, so a
// fix there would leave the injection. The value makes the file PWNED.
func TestCodeWithPrograms(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	const shellValue = `touch PWNED`
	for _, c := range []struct {
		src, program, setup, put, value string
	}{
		{src: `echo "@@" | source /dev/stdin`, program: "bash", put: `${V}`, value: shellValue},
		{src: ". /dev/stdin <<EOF\n@@\nEOF", program: "bash", put: `${V}`, value: shellValue},
		{src: `builtin eval "@@"`, program: "bash", put: `${V}`, value: shellValue},
		{src: `a=(); [ -v "@@" ]`, program: "bash", put: `${V}`, value: `a[$(touch PWNED)]`},
		{src: `a=(); test -v "@@"`, program: "bash", put: `${V}`, value: `a[$(touch PWNED)]`},
		{src: `echo x | perl -ne "@@"`, program: "perl", put: `${V}`, value: `system("touch PWNED")`},
		{src: `echo x | ruby -ne "@@"`, program: "ruby", put: `${V}`, value: `system("touch PWNED")`},
		{src: `node --eval="@@"`, program: "node", put: `${V}`, value: `require("fs").writeFileSync("PWNED", "")`},
		{src: `git -c core.fsmonitor="@@" status`, program: "git", setup: "git init -q && touch f && git add f && ", put: `${V}`, value: `touch PWNED; true`},
	} {
		t.Run(c.src, func(t *testing.T) {
			if _, err := exec.LookPath(c.program); err != nil {
				t.Skipf("no %s", c.program)
			}
			src, at := marked(c.src)
			if got := Places(src, at)[0].Quoting; got != CommandString {
				t.Fatalf("%q is %v, want CommandString", c.src, got)
			}
			dir := t.TempDir()
			script := c.setup + src[:at[0]] + c.put + src[at[0]:]
			cmd := exec.Command(bash, "-c", script)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "V="+c.value, "HOME="+dir, "GIT_CONFIG_NOSYSTEM=1")
			out, _ := cmd.CombinedOutput()
			if _, err := os.Stat(filepath.Join(dir, "PWNED")); err != nil {
				t.Errorf("%s did not run the value %q: %s", script, c.value, out)
			}
		})
	}
}

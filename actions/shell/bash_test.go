package shell

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestWithBash puts an environment variable at a place, the way the fix of
// code-injection writes it, and runs the script with bash: the value comes
// out as it is, one word, neither split, globbed nor run.
func TestWithBash(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	const value = `a  b; echo INJECTED $(echo X) * "q" 'r' \n`
	for _, c := range bashCases {
		src, at := marked(c.src)
		got, rules := places(src, at)
		if got[0].Quoting != c.ctx || rules[0] != c.rule {
			t.Errorf("%q: %v by %v, want %v by %v", c.src, got[0].Quoting, rules[0], c.ctx, c.rule)
			continue
		}
		script := src[:at[0]] + c.put + src[at[0]:]
		cmd := exec.Command(bash, "-c", script)
		cmd.Env = append(os.Environ(), "V="+value)
		cmd.Dir = t.TempDir() // a glob that went through would list its files
		if err := os.WriteFile(cmd.Dir+"/file", nil, 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", script, err)
		}
		if strings.Contains(string(out), "INJECTED X") {
			t.Errorf("%s ran the value: %q", script, out)
		}
		if want := strings.ReplaceAll(c.want, "$V", value); string(out) != want {
			t.Errorf("%s printed %q, want %q", script, out, want)
		}
		if c.file != "" {
			b, err := os.ReadFile(cmd.Dir + "/" + value)
			if err != nil || string(b) != c.file {
				t.Errorf("%s: the file named by the value has %q (%v), want %q", script, b, err, c.file)
			}
		}
	}
}

// bashCases are the places TestWithBash runs (want: what is printed, $V for
// the value; file: what the file named by the value has). Every named rule
// of the classifier has one (TestRulesHaveBash).
var bashCases = []struct {
	src        string
	ctx        Quoting
	rule       rule
	put        string
	want, file string
}{
	{src: "printf '%s|' @@", ctx: Unquoted, put: `"${V}"`, want: "$V|"},
	{src: `printf '%s|' "pre @@ post"`, ctx: DoubleQuoted, put: `${V}`, want: "pre $V post|"},
	{src: "cat <<EOF\npre @@ post\nEOF", ctx: Heredoc, put: `${V}`, want: "pre $V post\n"},
	{src: `{ echo a; } >> @@""`, ctx: Unquoted, rule: ruleRedirectTarget, put: `"${V}"`, file: "a\n"},
	{src: `> @@"" echo a`, ctx: Unquoted, rule: ruleRedirectTarget, put: `"${V}"`, file: "a\n"},
	{src: "echo a \\\n#@@ b\necho c", ctx: Comment, put: `${V}`, want: "a\nc\n"},
	{src: "echo a \\\n#it's\nprintf '%s|' @@", ctx: Unquoted, put: `"${V}"`, want: "a\n$V|"},
	{src: "printf '%s|' @@ \\\n#it's", ctx: Unquoted, put: `"${V}"`, want: "$V|"},
	{src: `echo 0$(true)#@@ b`, ctx: Unquoted, put: `"${V}"`, want: "0#$V b\n"},
	{src: `echo a >@@ x`, ctx: Unquoted, rule: ruleRedirectTarget, put: `"${V}"`, file: "a x\n"},
	{src: `[[ @@"" == "$V" && -n x ]] && echo same`, ctx: Unquoted, rule: ruleCondOperand, put: `"${V}"`, want: "same\n"},
	{src: `[[ -n x && "@@" == "$V" ]] && echo same`, ctx: DoubleQuoted, rule: ruleCondOperand, put: `${V}`, want: "same\n"},
	{src: `[[ "$V" == @@"" ]] && echo same`, ctx: Unquoted, rule: ruleCondOperand, put: `"${V}"`, want: "same\n"},
	{src: `[[ "" < "@@" ]] && echo less; ls`, ctx: DoubleQuoted, rule: ruleCondOperand, put: `${V}`, want: "less\nfile\n"},
}

// Every named rule has a row of bashCases that it answers.
func TestRulesHaveBash(t *testing.T) {
	for r := ruleUnset + 1; int(r) < len(ruleNames); r++ {
		found := false
		for _, c := range bashCases {
			found = found || c.rule == r
		}
		if !found {
			t.Errorf("the rule %v has no row in bashCases", r)
		}
	}
}

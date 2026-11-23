package taint

import (
	"slices"
	"strings"
	"unicode"

	"github.com/gh-intel/sisakulint/actions/workflow"
)

// Shell is the shell a step's run runs in, as far as the rules need it.
type Shell uint8

const (
	ShellUnknown Shell = iota
	ShellBash
	ShellSh
	ShellPwsh // pwsh and powershell
)

var shellNames = [...]string{"ShellUnknown", "ShellBash", "ShellSh", "ShellPwsh"}

func (s Shell) String() string { return shellNames[s] }

// setShell sets the Shell and XTrace of the run of s.
func (s *Sink) setShell(w *workflow.Workflow) {
	inv := ShellInvocationOf(w, s.Job, s.Step)
	s.Shell, s.XTrace = inv.Shell, inv.XTrace
}

// ShellOf is the shell the run of the step s of job runs in:
// ShellInvocationOf(w, job, s).Shell.
func ShellOf(w *workflow.Workflow, job *workflow.Job, s workflow.Step) Shell {
	return ShellInvocationOf(w, job, s).Shell
}

// ShellInvocation is how the runner starts the shell of a run, as far as
// the rules and attackrun read it: the shell, whether xtrace is on when
// the script starts, and the words the runner gives the shell before the
// path of the script (OptionWords) and after the path (PositionalWords).
// The two lists of words are nil for ShellPwsh and ShellUnknown.
type ShellInvocation struct {
	Shell           Shell
	XTrace          bool
	OptionWords     []string
	PositionalWords []string
}

// ShellInvocationOf is the ShellInvocation of the run of the step s of job:
// its shell, the job's defaults.run.shell, the workflow's, or the runner's
// (bash -e on ubuntu and macos, pwsh on windows). job is nil for a step of
// a composite action, which says its shell. A command named by its path
// (/bin/bash, /usr/bin/sh) is read only on a runner that has the path:
// /bin/bash and /bin/sh on ubuntu and macos, /usr/bin/bash and
// /usr/bin/sh on ubuntu (observed on 2026-11-15; elsewhere the step fails).
//
// A value of shell is read as actions/runner reads it (ScriptHandler.cs
// and ScriptHandlerHelpers.cs of
// https://github.com/actions/runner/tree/8cfa1049f86781d141056082d73802d56cd2b433):
// the blanks around it are gone before the runner gets it (observed on
// 2026-11-16 on ubuntu-latest and macos-latest); the first word up to a
// space is the command, and the rest is the template of the arguments,
// split into words at spaces and tabs (.NET 8 ParseArgumentsIntoList), with
// {0} for the path of the script. A template is read only when its options are ones the
// rules know do not change the reading of the script (bashOptions,
// shOptions); a template the rules do not read is ShellUnknown.
func ShellInvocationOf(w *workflow.Workflow, job *workflow.Job, s workflow.Step) ShellInvocation {
	fields := []workflow.Field[workflow.String]{s.Shell}
	if job != nil { // a composite step says its shell
		fields = append(fields, job.DefaultShell)
		if w != nil {
			fields = append(fields, w.DefaultShell)
		}
	}
	label := runnerLabel(job)
	for _, f := range fields {
		switch {
		case f.Status == workflow.Absent:
			continue
		case f.Status != workflow.Present || f.Value.Parts != nil:
			return ShellInvocation{}
		}
		return readShellValue(strings.TrimSpace(f.Value.AsString()), label)
	}
	switch {
	case job == nil:
		return ShellInvocation{}
	case strings.HasPrefix(label, "ubuntu-"), strings.HasPrefix(label, "macos-"):
		return ShellInvocation{Shell: ShellBash, OptionWords: []string{"-e"}}
	case strings.HasPrefix(label, "windows-"):
		return ShellInvocation{Shell: ShellPwsh}
	}
	return ShellInvocation{}
}

// runnerLabel is the label of the runner of job when runs-on names one
// label, "" otherwise.
func runnerLabel(job *workflow.Job) string {
	if job == nil {
		return ""
	}
	if l := job.RunsOn; l.Status == workflow.Present && len(l.Value.Items) == 1 {
		return l.Value.Items[0].Text()
	}
	return ""
}

// readShellValue is the ShellInvocation of the value text of shell on a
// runner of the label (or "").
func readShellValue(text, label string) ShellInvocation {
	command, template, _ := strings.Cut(text, " ")
	template = strings.TrimLeftFunc(template, unicode.IsSpace)
	if template == "" {
		switch command {
		case "bash":
			return ShellInvocation{Shell: ShellBash, OptionWords: []string{"--noprofile", "--norc", "-e", "-o", "pipefail"}}
		case "sh":
			return ShellInvocation{Shell: ShellSh, OptionWords: []string{"-e"}}
		case "pwsh", "powershell":
			return ShellInvocation{Shell: ShellPwsh}
		}
		return ShellInvocation{}
	}
	ubuntu, macos := strings.HasPrefix(label, "ubuntu-"), strings.HasPrefix(label, "macos-")
	var g *shellOptions
	switch {
	case command == "bash", command == "/bin/bash" && (ubuntu || macos), command == "/usr/bin/bash" && ubuntu:
		g = &bashOptions
	case command == "sh", command == "/bin/sh" && (ubuntu || macos), command == "/usr/bin/sh" && ubuntu:
		g = &shOptions
	default:
		return ShellInvocation{}
	}
	inv, ok := g.read(strings.FieldsFunc(template, func(r rune) bool { return r == ' ' || r == '\t' }))
	if !ok {
		return ShellInvocation{}
	}
	return inv
}

// shellOptions are the options of a shell that the rules read in a
// template: options that change only how the shell fails or traps (-e, -u,
// pipefail, -E, -T), the startup files read before the script (--noprofile,
// --norc, --login, -l) or line editing (--noediting), and xtrace, which the
// rules read. An option that may change the syntax, the commands that run
// or the writes to files (-c, -s, -n, -r, -i, -O, --posix and the like), or
// that prints the lines of the script on the standard error, where the
// runner reads workflow commands (-v), is not here, and a template with
// one is not read.
type shellOptions struct {
	shell   Shell
	long    []string // the long options, before the single-character ones
	letters string   // the single-character options after - or + (o and x apart)
	values  []string // the values of -o and +o
}

var (
	bashOptions = shellOptions{shell: ShellBash, long: []string{"--noprofile", "--norc", "--login", "--noediting"}, letters: "eulET", values: []string{"errexit", "nounset", "pipefail", "xtrace", "errtrace", "functrace"}}
	shOptions   = shellOptions{shell: ShellSh, letters: "eu", values: []string{"errexit", "nounset", "xtrace"}}
)

// read is the ShellInvocation of the words of a template, false when a
// word is not one of g's options before {0}, or a word after {0} has a
// quote, a backslash or a brace (other than {0}).
func (g shellOptions) read(words []string) (ShellInvocation, bool) {
	inv := ShellInvocation{Shell: g.shell}
	long := true
	i := 0
options:
	for ; i < len(words); i++ {
		w := words[i]
		switch {
		case w == "{0}":
			break options
		case w == "--", w == "-":
			if i+1 < len(words) && words[i+1] == "{0}" {
				i++
				break options
			}
			return ShellInvocation{}, false
		case strings.HasPrefix(w, "--"):
			if !long || !slices.Contains(g.long, w) {
				return ShellInvocation{}, false
			}
			continue
		case len(w) < 2 || w[0] != '-' && w[0] != '+':
			return ShellInvocation{}, false
		}
		long = false
		on, valued := w[0] == '-', false
		for _, r := range w[1:] {
			switch {
			case r == 'o' && !valued:
				valued = true
				i++
				if i >= len(words) || !slices.Contains(g.values, words[i]) {
					return ShellInvocation{}, false
				}
				if words[i] == "xtrace" {
					inv.XTrace = on
				}
			case r == 'x':
				inv.XTrace = on
			case r != 'o' && strings.ContainsRune(g.letters, r):
			default:
				return ShellInvocation{}, false
			}
		}
	}
	if i >= len(words) {
		return ShellInvocation{}, false // no {0}
	}
	for _, w := range words[i+1:] {
		if w != "{0}" && strings.ContainsAny(w, "\"'\\{}") {
			return ShellInvocation{}, false
		}
	}
	inv.OptionWords = slices.Clone(words[:i])
	if len(words) > i+1 {
		inv.PositionalWords = slices.Clone(words[i+1:])
	}
	return inv, true
}

// Masked is the script of v with each ${{ }} put as letters of the same
// length: the shell never sees the ${{ }}, which the runner replaces, and
// would take its ${ for an expansion.
func Masked(v workflow.String) string {
	b := []byte(v.Text())
	for _, p := range v.Parts {
		if p.Expr {
			for i := p.Span.Start; i < p.Span.End; i++ {
				b[i] = 'x'
			}
		}
	}
	return string(b)
}

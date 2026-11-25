package taint

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/shell"
)

// nestedScripts reads into s, a run of bash or sh, what the scripts that
// other shells run from the code after -c of its commands
// (shell.NestedScripts) write to $GITHUB_ENV, $GITHUB_OUTPUT and
// $GITHUB_PATH, the requests they send, and, in bash, the variables of env
// they read as code, as the run's own: the code keeps its positions in the
// run. Such a shell has the variables the run exports, so a variable of env
// has its value there only where the command does not give it another
// (hidden): the requests of the run keep their numbers, and those of the
// nested scripts come after them.
func (c scope) nestedScripts(s *Sink) {
	f := s.secretFlow
	seen := map[string]int{}
	for _, r := range s.Requests {
		seen[r.Command]++
	}
	for _, n := range shell.NestedScripts(f.text, f.script) {
		x := *s
		x.nested = n.Text(f.text)
		x.Shell = ShellSh
		if n.Shell == "bash" {
			x.Shell = ShellBash
		}
		x.EnvironmentFileWrites, x.InconclusiveWrites, x.Requests, x.VariableCodes = nil, nil, nil, nil
		x.CallsNotRead = shell.CallsNotRead{}
		c.fileCommands(&x)
		x.secretFlow = c.secretFlowOf(&x)
		c.requests(&x, x.secretFlow)
		if x.Shell == ShellBash {
			c.variableCodes(&x, x.secretFlow)
		}
		hidden := f.hiddenIn(n)
		for _, v := range x.VariableCodes {
			if !hidden(v.Var) {
				s.VariableCodes = append(s.VariableCodes, v)
			}
		}
		for _, w := range x.EnvironmentFileWrites {
			if w.RefIndex >= 0 || !hidden(w.Var) {
				w.Nested = true
				s.EnvironmentFileWrites = append(s.EnvironmentFileWrites, w)
			}
		}
		s.InconclusiveWrites = append(s.InconclusiveWrites, x.InconclusiveWrites...)
		for _, r := range x.Requests {
			r.Secrets = slices.DeleteFunc(r.Secrets, func(cs CarriedSecret) bool { return cs.Var != (shell.VarName{}) && hidden(cs.Var) })
			drop := func(a CommandArgument) bool { return a.RefIndex < 0 && hidden(a.Var) }
			r.HostRefs = slices.DeleteFunc(r.HostRefs, drop)
			r.PathRefs = slices.DeleteFunc(r.PathRefs, drop)
			seen[r.Command]++
			r.Occurrence = seen[r.Command]
			s.Requests = append(s.Requests, r)
		}
		s.CallsNotRead.Join(x.CallsNotRead)
	}
}

// hiddenIn is whether the shell of n does not get the value of env of a
// variable: the command gives it a value (T=x bash -c, env T=x bash -c),
// env -u takes it off, the command clears the environment (env -i, sudo),
// the run assigns it before the command (its new value is not followed:
// the undetected form env-variable-nested), or the shell that runs the
// command, or one around it, takes the export off it before
// (export -n T, declare +x T; not one in a subshell).
func (f *secretFlow) hiddenIn(n shell.NestedScript) func(shell.VarName) bool {
	at := n.Command.Span().Start
	type off struct {
		env  *shell.ExecutionEnvironment
		name string
	}
	var offs []off
	var cmdEnv *shell.ExecutionEnvironment
	shell.Walk(f.text, f.script.List, shell.Enclosing{}, shell.Visitor{Command: func(c shell.Command, e shell.Enclosing) bool {
		x, ok := c.(*shell.Simple)
		if !ok {
			return true
		}
		if x == n.Command {
			cmdEnv = e.Env
		}
		if x.Span().Start >= at {
			return true
		}
		words := shell.WordsOf(f.text, x)
		if len(words) == 0 || !words[0].Known {
			return true
		}
		drop := false
		switch words[0].Text {
		case "export", "declare", "typeset", "local", "readonly":
		default:
			return true
		}
		for _, w := range words[1:] {
			switch {
			case !w.Known:
			case words[0].Text == "export" && strings.HasPrefix(w.Text, "-") && strings.Contains(w.Text, "n"):
				drop = true
			case strings.HasPrefix(w.Text, "+") && strings.Contains(w.Text, "x"):
				drop = true
			case drop:
				name, _, _ := strings.Cut(w.Text, "=")
				offs = append(offs, off{e.Env, name})
			}
		}
		return true
	}})
	unexported := map[string]bool{}
	for _, o := range offs {
		for p := cmdEnv; ; p = p.Parent {
			if p == o.env {
				unexported[o.name] = true
				break
			}
			if p == nil {
				break
			}
		}
	}
	return func(v shell.VarName) bool {
		name := v.String()
		return n.Clears || slices.Contains(n.Assigns, v) || unexported[name] || f.assigned(name, at)
	}
}

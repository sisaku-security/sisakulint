package taint

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/shell"
)

// nestedScripts reads into s, a run of bash or sh, what the scripts that
// other shells run from the code after -c of its commands
// (shell.NestedScripts) write to $GITHUB_ENV, $GITHUB_OUTPUT and
// $GITHUB_PATH, the requests they send, and, in bash, the variables of env
// they read as code, as the run's own: the code keeps its positions in the
// run. Such a shell has the variables the run exports, so a variable of env
// has its value there unless the run assigns it before the command.
func (c scope) nestedScripts(s *Sink) {
	before := len(s.Requests)
	c.nestedIn(s, s.secretFlow)
	if len(s.Requests) == before {
		return
	}
	slices.SortStableFunc(s.Requests, func(a, b RequestSite) int { return a.CommandSpan.Start - b.CommandSpan.Start })
	seen := map[string]int{}
	for i := range s.Requests {
		seen[s.Requests[i].Command]++
		s.Requests[i].Occurrence = seen[s.Requests[i].Command]
	}
}

// nestedIn reads into s the nested scripts of the script f reads. The
// code of one is in single quotes, so a script nested in it is not (its
// code cannot be one word in single quotes).
func (c scope) nestedIn(s *Sink, f *secretFlow) {
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
		at := n.Command.Span().Start
		for _, v := range x.VariableCodes {
			if !f.assigned(v.Var.String(), at) {
				s.VariableCodes = append(s.VariableCodes, v)
			}
		}
		s.EnvironmentFileWrites = append(s.EnvironmentFileWrites, x.EnvironmentFileWrites...)
		s.InconclusiveWrites = append(s.InconclusiveWrites, x.InconclusiveWrites...)
		s.Requests = append(s.Requests, x.Requests...)
		s.CallsNotRead.Join(x.CallsNotRead)
	}
}

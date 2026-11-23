package taint

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/shell"
)

// AuthoredCommand is a workflow command whose name is in the text of a run
// script and that the run prints to its log: its name and where the name
// is in the run.
type AuthoredCommand struct {
	Name analysis.AuthoredCommandName
	Span shell.Span
}

// authoredCommands are the workflow commands of analysis.AuthoredCommandName
// that the run of f prints to its log (shell.AuthoredCommands).
func authoredCommands(f *secretFlow) []AuthoredCommand {
	all := analysis.AuthoredCommandNames()
	names := make([]string, len(all))
	for i, n := range all {
		names[i] = n.Command()
	}
	var out []AuthoredCommand
	for _, c := range shell.AuthoredCommands(f.text, f.logWrites(), names) {
		out = append(out, AuthoredCommand{Name: all[c.Name], Span: c.Span})
	}
	return out
}

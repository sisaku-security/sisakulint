package prcode

import (
	"path"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/shell"
)

// PermissionRunsTree is whether the command of words, an agent's
// permission of a command, runs code of the workspace by the table of
// tools, read as a run of the tree at the workspace's root in the
// workspace's root, past the wrappers of the table of commands (timeout,
// env, sudo). open is whether the agent chooses the words after them: it
// may then add a command of the tool that runs code, a word of needs, an
// option that changes its directory and one that undoes a stop
// (tool.runsCode). A command by its path and an interpreter are not read
// here.
func PermissionRunsTree(words []string, open bool) bool {
	ws := make([]runWord, len(words))
	for i, w := range words {
		ws[i] = literalWord(w)
	}
	if m := shell.LookupCommand(commandWords(ws)); len(m.Wrappers) > 0 {
		if m.Command < 0 {
			return false
		}
		ws = ws[m.Command:]
	}
	if len(ws) == 0 || ws[0].isPath() && !strings.HasPrefix(ws[0].lookup, "/") {
		return false
	}
	name := path.Base(ws[0].lookup)
	i := slices.IndexFunc(tools, func(t tool) bool { return slices.Contains(t.names, name) })
	if i < 0 {
		return false
	}
	root := workspacePlacement(relDir{path: ".", known: true})
	return tools[i].runsCode(ws[1:], literalWord("."), root, open)
}

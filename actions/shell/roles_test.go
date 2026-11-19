package shell

import (
	"slices"
	"testing"
)

func TestArgumentRoles(t *testing.T) {
	k := func(s string) CommandWord { return CommandWord{Text: s, Known: true} }
	a := CommandWord{MayBeOption: true}
	u := CommandWord{}
	const (
		C = ArgumentRoleCommand
		O = ArgumentRoleOption
		V = ArgumentRoleOptionValue
		P = ArgumentRoleOperand
		D = ArgumentRoleUndecided
		X = ArgumentRoleUnread
	)
	for _, c := range []struct {
		name  string
		words []CommandWord
		cmd   string
		roles []ArgumentRole
	}{
		{"tar after operand", []CommandWord{k("tar"), k("-xf"), k("a.tar"), k("f"), a}, "tar", []ArgumentRole{C, O, V, O, O}},
		{"tar option value", []CommandWord{k("tar"), k("-xf"), a}, "tar", []ArgumentRole{C, O, V}},
		{"after --", []CommandWord{k("tar"), k("-xf"), k("a.tar"), k("--"), a}, "tar", []ArgumentRole{C, O, V, O, P}},
		{"sed -i joined only", []CommandWord{k("sed"), k("-i"), a, k("s.txt")}, "sed", []ArgumentRole{C, O, O, O}},
		{"make operand then option", []CommandWord{k("make"), k("all"), a}, "make", []ArgumentRole{C, O, O}},
		{"ls-remote stops at operand", []CommandWord{k("git"), k("ls-remote"), k("/tmp/r"), a}, "git ls-remote", []ArgumentRole{C, C, O, P}},
		{"ls-remote before operand", []CommandWord{k("git"), k("ls-remote"), a, k("/tmp/r")}, "git ls-remote", []ArgumentRole{C, C, O, O}},
		{"fetch after operand", []CommandWord{k("git"), k("fetch"), k("/tmp/r"), a}, "git fetch", []ArgumentRole{C, C, O, O}},
		{"end-of-options", []CommandWord{k("git"), k("fetch"), k("--end-of-options"), a}, "git fetch", []ArgumentRole{C, C, O, P}},
		{"git option before the subcommand", []CommandWord{k("git"), k("-C"), k("d"), k("fetch"), a}, "git fetch", []ArgumentRole{C, C, C, C, O}},
		{"undeclared option", []CommandWord{k("tar"), k("--frobnicate"), a}, "tar", []ArgumentRole{C, O, D}},
		{"undeclared long with =", []CommandWord{k("tar"), k("--frobnicate=1"), a}, "tar", []ArgumentRole{C, O, O}},
		{"wrapper", []CommandWord{k("sudo"), k("-u"), k("root"), k("tar"), k("-xf"), k("a.tar"), k("f"), a}, "tar", []ArgumentRole{C, C, C, C, O, V, O, O}},
		{"timeout's operand", []CommandWord{k("timeout"), k("30"), k("make"), a}, "make", []ArgumentRole{C, C, C, O}},
		{"unknown word before", []CommandWord{k("tar"), k("-xf"), k("a.tar"), u, a}, "tar", []ArgumentRole{C, O, V, O, O}},
		{"bash stops at its script", []CommandWord{k("bash"), k("x.sh"), a}, "bash", []ArgumentRole{C, O, P}},
		{"bash before its script", []CommandWord{k("bash"), a, k("x.sh")}, "bash", []ArgumentRole{C, O, O}},
		{"path of the command", []CommandWord{k("/usr/bin/tar"), k("-xf"), k("a.tar"), a}, "tar", []ArgumentRole{C, O, V, O}},
		{"not in the table", []CommandWord{k("frob"), a}, "frob", []ArgumentRole{C, O}},
		{"not in the table, after its operand", []CommandWord{k("frob"), k("x"), a}, "frob", []ArgumentRole{C, O, P}},
		{"command not known", []CommandWord{a, k("x")}, "", []ArgumentRole{X, X}},
		{"subcommand not known", []CommandWord{k("git"), a, k("fetch")}, "git", []ArgumentRole{C, O, O}},
		{"subcommand the table does not have", []CommandWord{k("git"), k("rebase"), a}, "git", []ArgumentRole{C, O, P}},
		// the code of -c ends the options
		// the code of -c is the operand the options end at
		{"python -c then a word", []CommandWord{k("python3"), k("-c"), k("import sys"), a}, "python3", []ArgumentRole{C, O, P, P}},
		{"bash -c then a word", []CommandWord{k("bash"), k("-c"), k("echo"), a}, "bash", []ArgumentRole{C, O, P, P}},
		{"bash -c and the value", []CommandWord{k("bash"), k("-c"), a}, "bash", []ArgumentRole{C, O, P}},
		// the code of -c is the first word after the options and their values
		{"bash -c -x and the value", []CommandWord{k("bash"), k("-c"), k("-x"), a}, "bash", []ArgumentRole{C, O, O, P}},
		{"bash -c -o pipefail and the value", []CommandWord{k("bash"), k("-c"), k("-o"), k("pipefail"), a}, "bash", []ArgumentRole{C, O, O, V, P}},
		{"bash -co pipefail and the value", []CommandWord{k("bash"), k("-co"), k("pipefail"), a}, "bash", []ArgumentRole{C, O, V, P}},
		{"bash -c - and the value", []CommandWord{k("bash"), k("-c"), k("-"), a}, "bash", []ArgumentRole{C, O, O, P}},
		// after an option the table does not declare, a command whose options
		// end at its first operand may have its operand there
		{"python -u then a script", []CommandWord{k("python3"), k("-u"), k("x.py"), a}, "python3", []ArgumentRole{C, O, D, D}},
		{"ls-remote --heads", []CommandWord{k("git"), k("ls-remote"), k("--heads"), k("origin"), a}, "git ls-remote", []ArgumentRole{C, C, O, O, P}},
		{"node -e then a word", []CommandWord{k("node"), k("-e"), k("1"), a}, "node", []ArgumentRole{C, O, V, O}},
		// test and [ read by the number of arguments (bash.1)
		{"test", []CommandWord{k("test"), k("-n"), a}, "test", []ArgumentRole{C, P, P}},
		{"[", []CommandWord{k("["), a, k("="), k("x"), k("]")}, "[", []ArgumentRole{C, P, P, P, P}},
		// -- after an option the table does not declare
		{"-- after an undeclared option", []CommandWord{k("tar"), k("-xf"), k("a.tar"), k("--no-same-owner"), k("--"), a}, "tar", []ArgumentRole{C, O, V, O, D, D}},
		{"sudo --", []CommandWord{k("sudo"), k("--"), k("tar"), k("-xf"), k("a.tar"), a}, "tar", []ArgumentRole{C, C, C, O, V, O}},
	} {
		got := ArgumentRoles(c.words)
		if got.Name != c.cmd || !slices.Equal(got.Roles, c.roles) {
			t.Errorf("%s: %q %v, want %q %v", c.name, got.Name, got.Roles, c.cmd, c.roles)
		}
	}
}

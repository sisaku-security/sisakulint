package rules

import "github.com/sisaku-security/sisakulint/actions/lint"

// The forms of the table of tools (prcode's) that the rules reading the
// steps that run the code of a checkout, of a download or of an agent
// share: directly, through the step of actions/labeler that runs after a
// step the attacker can make fail, or through an agent's permission of a
// command.

// npmAbbreviation is the undetected form of an abbreviation of an npm
// command; kinds are those of the rule the step would make.
func npmAbbreviation(kinds ...lint.FindingKindID) lint.UndetectedForm {
	return lint.UndetectedForm{ID: lint.MustUndetectedFormID("npm-abbreviation"),
		Text:         "a command that runs npm followed by an abbreviation of the name of an npm command that runs code of the checked out tree (for example, npm tes for npm test), in a run step or in a permission of an agent. npm runs a word as an npm command when the word is the beginning of exactly one command name or alias name of the npm release that the job uses. The rule does not read abbreviations of npm command names.",
		FindingKinds: kinds, Disposition: lint.Limitation(lint.DeciderRunTime)}
}

// npmOptionValueCommand is the undetected form of the value of an option
// of npm that names an npm command, which the table reads as the command.
func npmOptionValueCommand(kinds ...lint.FindingKindID) lint.UndetectedForm {
	return lint.UndetectedForm{ID: lint.MustUndetectedFormID("npm-option-value-command"),
		Text:         "a command that runs npm with an option placed before the npm command, when the value of the option is the name of an npm command and the npm command runs code of the checked out tree (for example, npm --cache view ci, in which view is the name of a directory), in a run step or in a permission of an agent. The rule reads the first word after npm, other than the value of the option --prefix or -C, that is the name or the alias name of an npm command as the npm command, and so reads the value view as the npm command.",
		FindingKinds: kinds, Disposition: lint.Limitation(lint.DeciderRunTime)}
}

// npmUnknownCommand is the false positive form of a word that names no
// npm command before one that does, where npm stops with an error.
func npmUnknownCommand(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("npm-unknown-command"),
		Text:         "a command that runs npm with a word that is not an option and is not the name, an alias name, or the beginning of exactly one name of an npm command, before the name of an npm command that runs code of the checked out tree (for example, npm web ci), in a run step or in a permission of an agent. npm stops with an error at the first word that is not an option when the word is not the name of an npm command, and runs no code of the tree. The rule reads the first word after npm, other than the value of the option --prefix or -C, that is the name or the alias name of an npm command as the npm command.",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// cdOutOfTree is the false positive form of a tool that a step runs after
// changing its directory out of the tree, which the table reads as a tool
// that may run anywhere.
func cdOutOfTree(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("cd-out-of-tree"),
		Text:         "a run step with a command that changes the directory of the shell or of a tool (cd, pushd, popd, env -C, sudo -D, and in pwsh a word that is Set-Location or one of its aliases), in which a tool runs in a directory out of the checked out tree (for example, cd ${{ runner.temp }} && npm ci, after a checkout of the tree into the directory pr). The rule does not read the directory that the command changes to, and reads every tool of the step as a tool that may run in any directory.",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// ignoredPnpmfile is the false positive form of a run of pnpm that loads
// no pnpmfile of the tree.
func ignoredPnpmfile(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("ignored-pnpmfile"),
		Text:         "a command that runs a pnpm command that runs no code of the checked out tree, with the pnpm setting ignore-pnpmfile set to true (for example, pnpm --config.ignore-pnpmfile=true store prune), in a run step or in a permission of an agent. pnpm loads no .pnpmfile.cjs of the tree when the pnpm setting ignore-pnpmfile is true. The rule reads every run of pnpm as a run that runs code of the tree.",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// absolutePathOutOfTree is the false positive form of an absolute path
// out of the tree, which the table reads as a path that may be in it.
func absolutePathOutOfTree(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("absolute-path-out-of-tree"),
		Text:         "a command that runs a tool in a directory, or runs a file, that a path out of the checked out tree names, when the path is an absolute path that names the directory of a tool or a file given to an interpreter, or a path that leaves the workspace by .. (for example, pnpm --dir /opt/tool install, bash /opt/x.sh, or npm --prefix ../other ci after a checkout of the tree into the directory pr), in a run step or in a permission of an agent. The rule reads an absolute path, and a path that leaves the workspace by .., as a path that may name a directory of the tree, because the workspace that holds the tree also has an absolute path, and a path that leaves the workspace by .. may come back into the workspace.",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// pytestPathOutOfTree is the false positive form of pytest run in the tree
// on paths out of it only.
func pytestPathOutOfTree(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("pytest-path-out-of-tree"),
		Text:         "a command that runs pytest, in a directory of the checked out tree or in a directory that holds the tree, with only paths out of the tree as its arguments (for example, pytest /opt/tests run in the root of the tree, or pytest tests run in the root of the workspace when the tree is in the directory pr), in a run step or in a permission of an agent. In that case, pytest collects no test and loads no conftest.py of the tree. The rule reads the directory that pytest runs in, and every directory under it, as directories whose tests pytest collects.",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// toolDirectoryOutOfTree is the false positive form of a tool whose
// directory is out of the tree, which the table also reads from the root
// of the workspace.
func toolDirectoryOutOfTree(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("tool-directory-out-of-tree"),
		Text:         "a command that runs a tool, or runs a file by a relative path, in a directory out of the checked out tree that the working-directory of the step, the defaults of the job or of the workflow, or an option of the tool names (for example, npm ci with the working-directory ${{ runner.temp }}, or pnpm -C ${{ runner.temp }}/tool install), in a run step or in a permission of an agent. The rule also reads the tool as a tool that may run in the root of the workspace, because the tool may read the tree in a way that the rule does not read.",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// npmOptionValueOperand is the false positive form of an npm command that
// needs an operand, given only an option whose value the table reads as
// one.
func npmOptionValueOperand(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("npm-option-value-operand"),
		Text:         "a command that runs npm version, npm uninstall, npm explore or npm edit with no operand, but with an option whose value the rule reads as an operand (for example, npm version --preid beta), in a run step or in a permission of an agent. In that case, npm runs no code of the checked out tree. The rule reads every word after the npm command that is not an option, other than the value of the option --prefix or -C, as an operand.",
		FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

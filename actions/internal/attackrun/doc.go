// Package attackrun puts the attack value of an example (its notes'
// attack-value, lint.AttackValue) into the example where its carrier
// stands in ${{ }}, and runs the steps that it reaches in bash, shut in,
// to see whether the harm of the example's rule shows.
//
// GitHub replaces ${{ }} with the value's text before the shell reads the
// script, so a step is run with the text put in, not with a variable
// standing for it; an env entry is set to its value with the text put in.
// How the runner runs a script and reads the files of the file commands
// is that of actions/runner v2.337.0
// (397b032cbf865e9c3ddfab89d533ec19325e1273):
// src/Runner.Worker/Handlers/ScriptHandler.cs and ScriptHandlerHelpers.cs
// (a step without shell runs as bash -e, one with shell: bash as bash
// --noprofile --norc -e -o pipefail), and src/Runner.Worker/FileCommandManager.cs
// (EnvFileKeyValuePairs, AddPathFileCommand). A step with a custom shell
// (bash -x {0}) runs with the words of its options as the rules read them
// (taint.ShellInvocationOf), and each {0} after the script as the path of
// the script; a login shell (-l, --login) gets --noprofile, as its startup
// files would be those of this machine, not those of the runner. The env of a step here has fewer variables than on the
// runner, so a step under -u (nounset) that reads a variable the runner
// sets, such as GITHUB_SHA, stops where it would not on the runner.
//
// Where things are:
//
//	substitute.go  how a carrier and an expression are compared; Substitute
//	prepare.go     Marker, UnrunReason, Prepare: the steps the value reaches and why one is not run;
//	               Check: what to show of whether a test runs the value
//	run.go         Run: the steps in bash, shut in; Seen and what shows the harm
//	envfile.go     the runner's reading of GITHUB_ENV, GITHUB_OUTPUT and GITHUB_PATH
package attackrun

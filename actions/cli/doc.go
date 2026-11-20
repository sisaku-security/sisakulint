// Package cli is the command sisakulint: it reads a repository's
// workflows and action.yml files, runs the rules on them (actions/lint),
// and writes the report on stdout: as text for people by default, a line
// for each finding with --format line, as JSON with --format json, or as SARIF
// 2.1.0, for GitHub code scanning, with --format sarif. --report writes
// the JSON to a file too, and --sarif the SARIF. --html writes the report view (actions/reportview)
// to a file too, and --serve serves it on a loopback address until
// interrupted. With --registry, it writes the registry of the
// rules instead, and reads nothing; with --explain, the rules asked as
// Markdown for people, or what their words mean with --explain=terms. With
// --version, it writes the version of the binary and reads nothing; with
// --init, a configuration file for --config, and reads nothing; with --init
// and --legacy-configuration, it reads that configuration file of
// sisakulint 0.x and the files under --root, and writes the entries of the
// file as values of the key fact. With
// --read-all and PATHs, it reads the whole repository and reports only the
// places of the PATHs. With --remote, it reads a repository of GitHub
// instead of --root, one file at a time through the git API, without a
// clone (actions/remote). With
// --examples, it runs the examples of the rules with the facts each has,
// and writes them as a catalog (--html) or serves it (--serve), reading
// nothing. With --fix
// and --dry-run, it writes nothing, and on stdout the diff of what --fix
// would write, which git apply takes, instead of the report.
//
// Main takes its arguments as a process does, so that another command can
// take it in as a subcommand and behave the same. It reads no environment
// but Env, and it touches the file system only to read --root, the files
// of facts, the file of acceptances (--accept), the configuration file (--config), the legacy configuration file (--legacy-configuration), the directory of
// --write-snapshot (the files --remote read), and the files --fix (not with --dry-run), --report,
// --sarif, --write-facts and --html write; it listens on the network only for
// --serve, on a loopback address. It asks the GitHub API (--github-api: an
// https URL, or an http URL of a loopback address; with
// GITHUB_TOKEN) only for --online and --remote.
//
// The exit code is the sum of the bits of lint.Classify (0 to 31) when the
// report is on stdout and all that was asked is done; otherwise it is one
// of these:
//
//	64 ExitUsage    the arguments are wrong; nothing on stdout
//	66 ExitNoInput  the inputs, the file of facts, the file of acceptances or the configuration file (--config) or the legacy configuration file (--legacy-configuration) cannot be read, or is not valid, or the repository, the commit or the pull request of --remote cannot be read; nothing on stdout
//	70 ExitFix      the fixes are not all written (with --dry-run: they do not apply); the report says why (fix), or stderr
//	74 ExitIO       the file of facts, the report file, the SARIF file, the report view or stdout cannot be written, the SARIF cannot be made, or --serve cannot listen
//	75 ExitTempFail the head of the pull request is not --pull-request-head; nothing on stdout
//
// Where things are:
//
//	cli.go      Env, Main, the exit codes, the flags
//	configuration.go the keys of the configuration file and their flags (configurationKeys); --config: reading the file, and merging it with the flags
//	template.go --init: the configuration file it writes
//	legacy.go   --legacy-configuration: reading the configuration file of sisakulint 0.x
//	legacyimport.go action-list and config-variables of that file, as facts; the notes of what is not written
//	legacyhost.go secret-exfiltration.allowed-hosts and the directives, as request.destination-trusted for the pairs of now
//	legacydirective.go the directives of a workflow, at the places --init writes
//	legacyrun.go --init with --legacy-configuration: the run of secret-exfiltration that counts the pairs, and the template
//	explain.go  --explain: the rules asked or the terms, the commit of the binary
//	version.go  --version: the version, the commit, the Go release and the schemas
//	input.go    which inputs are read, under an os.Root, and which are reported (--read-all)
//	selection.go --rule and --skip-rule: the rules that run
//	facts.go    where the answers come from: --fact, --facts, --online or offline, the assumptions (--no-assumptions); --write-facts
//	fact.go     --fact: KIND[ARG=VALUE,...]=VALUE
//	runsusing.go the runs.using of an action's metadata, which --online answers action.runs-using with
//	fix.go      --fix: the fixes applied, checked, and written; what came of it; --dry-run
//	diff.go     the diff of --dry-run, as git diff writes it
//	atomic.go   writing a file next to its old one, then renaming it over
//	serve.go    --serve: the address it takes; --registry and --registry=full; --examples: the catalog, written or served
//	text.go     the text: the sections, in order
//	line.go     --format line: a line for each finding, then the inputs, the errors and the fixes that failed
//	sarif.go    --format sarif and --sarif: the report as SARIF 2.1.0, as GitHub code scanning reads it
//	group.go    the groups of the text: confirmed findings in folds of one kind and rows of one message, conditional ones by what decides them, inputs by why; worst
//	snippet.go  the line of the source and the carets under a place
//	escape.go   what of the bytes of an attacker a terminal may be shown
package cli

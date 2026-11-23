// Package taint is what the injection rules share: which contexts an
// attacker controls, when (Lookup, TableEvents), and where a workflow
// or an action.yml writes them into code (Analyze); and what the rules of
// secrets share: where a run carries a secret, to a request or to its log.
// A rule reads it and does not keep a list of its own.
//
// Analyze finds the sinks (a step's run, the script of
// actions/github-script) and, for each reference written out in their
// ${{ }}, whether an attacker controls it: on the attacker's events the
// step can run on (the events of on, narrowed by their types and by the
// ifs of the job and the step as far as they are known before the run;
// for a reusable workflow and a composite action, the events its callers
// run it on when the inputs have all of its callers (Callers), else every
// attacker's event),
// through env set in the workflow, or inconclusive (the outputs of steps
// and jobs, inputs, a matrix not written out, an env the workflow does not
// set). An inconclusive place is of a kind (InconclusiveRefKind) by what would decide it:
// the form of the step or the job whose outputs it reads (a script, an
// action of the same repository or of another, a Docker image; a job of
// steps, or one that calls a reusable workflow), whether a dispatch gives
// the inputs, and why env is not known. Outputs of a step or a job that
// the runner gives empty (no step before has the id, a job not in needs,
// needs in an action.yml) are not controlled, not inconclusive places.
//
// A reference that the if of the job, or the if of a step that runs a
// script, lets be only strings it compares the reference with
// (attacker.Narrowing) is not controlled, nor inconclusive: the attacker
// chooses no more than the case of its letters. The if of a step that uses
// an action does not narrow the step's with and env, which the pre step of
// the action evaluates whatever the if.
//
// For a run of bash or sh, Analyze also reads what it writes to
// $GITHUB_ENV and $GITHUB_OUTPUT (filecmd.go), as the runner reads the file
// after the step: by lines split at \n alone, each line by its first = or
// <<. A
// reference an attacker writes with line breaks (ExprRef.Lines: the events on
// which the table says ControlArbitrary) is EnvironmentFileWrite where it lands: after the =
// of a line, before it, or in the body of name<<DELIM whose delimiter an
// attacker can write. A ${{ }} and a variable of env ($NAME, with its case)
// are read; a variable no env sets is not. What cannot be read (a command
// not known, a $( ) whose line breaks are not taken away, exec, a script
// not followed) is a InconclusiveWrite.
// A run whose readings stopped reading the bodies of functions at their
// limit of calls has the first such call in Sink.CallsNotRead.
//
// What an attacker controls of github.event comes from the OpenAPI
// description of GitHub's webhooks, @octokit/openapi-webhooks v12.2.0
// (592754e9bee3fab1f3c11f51bcde825eb2d19112,
// packages/openapi-webhooks/generated/api.github.com.json, sha256
// 375906eeeace26486c6aecf5869a5e5ad4bba72c6571481ef54fa8c1cada3aae;
// schema/api.github.com.json.gz), for each event an attacker triggers and
// each of its activity types; what the schema cannot tell, and the names below
// github other than event, are in schema/overrides.tsv, each with its
// reason. go generate writes the table (table_gen.go).
//
// Where things are:
//
//	analyze.go      Analyze, AnalyzeIn, Analysis, Sink, ExprRef: the sinks and their references (Verdict and InconclusiveRefKind are of actions/analysis);
//	                WrittenRefs: the references whose value a ${{ }} writes out; StepValues: other values of a step,
//	                read as those of a sink; ReadScript
//	callers.go      Callers, NewCallers, NewCallersIn: the events and the inputs of a called workflow or composite action, read from its callers;
//	                a remote called workflow (calls.Node) runs on its caller's events alone; ValuePartOn: the events on which a value
//	                a step gives may hold a variable or a secret that the attacker of a run that adds one writes
//	written.go      how a ${{ }} writes the value of each reference (text, the items of join, all of it as toJSON),
//	                and what an attacker writes of it so
//	events.go       EventsOf, EventsOn, EventsAll, Filter, FilterCode, FilterEventOnly (of analysis.EventActivity): the events of on
//	                (the attacker's, or those named), and the ifs that leave some out (by the attacker's runs, or by the
//	                event alone)
//	shell.go        Shell, ShellInvocation, ShellOf, ShellInvocationOf, Masked: the shell of a run,
//	                how the runner starts the shell, and its script as the shell sees it
//	arguments.go    CommandArgument: the words of the commands of a run with a value an attacker may control in them, and how the command reads each
//	filecmd.go      EnvironmentFileWrite (of analysis.EnvironmentFile and Side), DelimWrite, InconclusiveWrite, RandomDelim: what a run writes to $GITHUB_ENV, $GITHUB_OUTPUT and $GITHUB_PATH
//	runnervar.go    RunnerVariable, RunnerValue, WindowsRunner: the variables the runner writes in every step, over env
//	authored.go     AuthoredCommand: the workflow commands whose names a run script writes to its log
//	varcode.go      VariableCode: the variables of env whose value an attacker may control and that a
//	                run of bash reads as code (shell.VariableCodes)
//	logwrite.go     UnsecureFlag, LogWrite: ACTIONS_ALLOW_UNSECURE_COMMANDS, and the references an attacker may control
//	                that a run prints to its log
//	secretflow.go   SecretRef, SecretRefs, JobTokenRef, CarriedSecret, DestinationOrigin: the secrets a reference reads, the secrets a
//	                word of a run carries, and where the host of a request comes from
//	secretfile.go   the secrets a run writes to $GITHUB_ENV and $GITHUB_OUTPUT, for the steps after it
//	secretlog.go    SecretLeak, PrintedOutput, PrintedOutputs: a value made from a secret that a run prints to its log,
//	                and an output of one that the runner prints
//	request.go      RequestSite: a request a command of a run sends, what an attacker may decide of its destination,
//	                and the secrets it carries there
//	requestaction.go RequestActionSite, RequestActionSites: the inputs of a step of an action that sends its credential
//	                where the input says
//	table.go        Control, Lookup, LookupText, LeadingDash, RepoName, TableEvents, ActivityTypes
//	table_gen.go    the table, made by go generate (internal/tablegen)
//	schema/         the webhooks' description, and the overrides
//	BENCH.md        what Analyze and Lookup cost
//
// Tests:
//
//	written_test.go     what a ${{ }} writes of a reference through the functions and operators
//	analyze_test.go     events, ifs, types, env, functions, what is inconclusive and its kinds
//	                    (outputs of steps and jobs, inputs, env), the script of github-script,
//	                    reusable workflows and composite actions
//	table_test.go       what Lookup says of payloads, objects, activity types and names below github
//	filecmd_test.go     the side of each value, heredocs and their delimiters, the fix's delimiter,
//	                    the case of a variable, Lines, the shell
//	arguments_test.go   CommandArgument, and whether the value starts its word
//	values_test.go      StepValues, read as the values of a sink are
//	events_test.go      EventsOf, EventsOn, and the activity types of each event
//	narrow_test.go      the ifs that narrow a reference (attacker.Narrowing), also through env and callers
//	callers_test.go     the events and the inputs a called workflow reads from its callers, and the worst case
//	parallel_test.go    the outputs of a step that the steps of its parallel group do not see
//	readscript_test.go  the tree a script read with its places has is that of shell.Parse; an analysis with a Memo
//	runnervar_test.go   the variables the runner writes, and their reading over env
//	logwrite_test.go    UnsecureFlag, and the references a run prints to its log
//	varcode_test.go     VariableCodes: the levels of env, the case of a key, an assignment before, sh,
//	                    the variables the runner writes, the events of the command word and arithmetic
//	secretflow_test.go  the secrets a word carries through env, assignments and substitutions; DestinationOrigin
//	secretlog_test.go   SecretLeak, PrintedOutputs
//	request_test.go     RequestSite of curl, wget and gh api
//	requestaction_test.go RequestActionSites
//	callsnotread_test.go  Sink.CallsNotRead: the first call whose body a limit of calls kept from being read
//	copies_test.go      TestThirdPartyCopies: the files and the sha256 of the copy of zizmor under testdata
//	deps_test.go        what it depends on
//	bench_test.go       Analyze against the model alone (BENCH.md)
//	internal/tablegen   table_gen.go is up to date; how schemas map to capabilities; overrides
package taint

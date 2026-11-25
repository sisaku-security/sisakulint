// Package shell reads bash and sh scripts. Parse gives the tree of a
// script: its lists, pipelines and commands, the words of each and their
// parts (the quotes they are in, the parameters they expand, the scripts
// inside $( ), <( ) and >( )), the redirects of simple and compound
// commands, and the bodies of heredocs. Quotings and Places tell, from that
// tree, how a place of a script is read: outside quotes, inside "..." or
// '...', in the body of a heredoc, in a comment, or in what another program
// reads as code. code-injection uses them to know where a value of an
// environment variable can stand in for a ${{ }} without changing what the
// script does. It reads strings, not YAML, and knows nothing of expressions.
//
// VariableCodes tells, from the same tree, where bash or a program reads
// the value of a variable as code: in an argument a command reads as code,
// unquoted in the command word, in the input of a command that runs its
// input as code, and in arithmetic. Unlike Places, it answers for the value
// a variable holds, not for text written at the place, and only where a
// test ran the command with the value and saw it run (ValueReading and
// InputValueCode of commands.json). It reads the inside of $( ), ` `,
// $(( )), (( )) and the words after the operator of ${ } from the tree.
//
// Writes tells, from the same tree, what a script writes to files its
// caller names: literal bytes, the parameters and the substitutions in
// them, the ranges the caller fills before the script runs, and the
// commands whose output it does not know. LineFree tells a substitution
// whose line breaks are taken away. envvar-injection and output-clobbering
// read them for $GITHUB_ENV and $GITHUB_OUTPUT.
//
// Walk gives every node of the tree, in the order bash runs and expands
// them, with what encloses it (Enclosing): the shell that runs it
// (ExecutionEnvironment: the script's shell, or a subshell of ( ... ), a
// coproc, a command of a pipeline, a command ended by & (Asynchronous), a
// $( ), a <( ) or >( )), the function whose body it is in, its place in a
// pipeline, and where its standard output goes (StdoutKind). It follows
// what a literal exec does to the descriptors and whether a literal shopt
// sets lastpipe. The parts of this package and the analyses that read the
// tree walk it with Walk, not with type switches of their own.
// PipeSources tells which commands of a pipeline write into the pipe a
// later command reads, and how the commands between pass it (PipePassage);
// PipeReaders tells which commands of a command of a pipeline read that
// pipe, and whether it has places the tree does not follow.
//
// NameVisibility tells, at a place of a script, which assignments a read
// of a variable may get its value from (on each path, the last; the value
// from before the script on a path with none), and which definitions a
// command name may call: a subshell gives nothing back, a function's body
// is read where it is called with what reaches the call (dynamic scope),
// the branches of if are read apart and joined after it, and the rounds of
// a loop are read until a round adds nothing. It is read on the paths the
// descriptors are read on, in one walk that carries the variables, the
// definitions and the descriptors together (readFlow): a command whose
// redirect fails on every path does not run, and a body is read once for
// each state its calls reach it in, answered also for each chain of calls.
//
// What it does not follow stops the tree (Script.Complete is false, and
// the tree ends at Stop), and its places are QuotingUnknown, so that a fix is not
// given there:
//   - a case inside $( ), whose patterns close it early;
//   - a heredoc on a line continued with a backslash, or begun inside $( )
//     or $(( )) (so a << inside $(( )) stops it);
//   - a line of an unquoted heredoc's body continued with a backslash;
//   - $[ ];
//   - commands and substitutions nested deeper than maxDepth;
//   - an and-or list that is not a script (a construct not closed, a pipe
//     with no command after it), which bash reads whole before it runs it;
//   - a script it cannot follow to its end (an open quote, a heredoc not
//     closed), all of whose places are QuotingUnknown, as bash refuses to run it.
//
// The tree does not read the inside of the ( ) of an array's assignment
// and of case (TextParams gives the parameters of their bytes). It reads
// the operator of a ${ } and the words after it (ParamExpansion), the
// expressions of $(( )), (( )) and for (( ; ; )) (Arithmetic), the name
// and the words after in of for and select (Compound.Var, Compound.In),
// the name of a {name} redirect (Redirect.Var), and the script of ` `, its
// backslashes taken off, with the positions of the script (backquote).
// A place inside $( ), <( ), >( ) and ` ` is read by the tree: by the
// quotes of the part it is in and the role of the word around it inside,
// and as code where a word around it outside is code (the command word, an
// argument of eval, -c and the like). The words of :-, :=, :? and :+ of a
// ${ } and the quoted words after in of for and select are read as their
// quotes say; the words after in outside quotes are QuotingUnknown (the
// list a loop goes over is not one quoted word). Arithmetic, a subscript,
// the offset and the length of a ${ }, and the name of for and select are
// code; where a variable may have the integer attribute, so are a value
// assigned by := and = and the arguments of export and readonly, and a
// value assigned by for is QuotingUnknown (code inside a substitution).
// The places of
// a pattern and a replacement of a ${ } are QuotingUnknown. In a line of an
// unquoted heredoc's body, a place outside an expansion is of the body, and
// one inside it is read as inside a substitution, but the words after the
// operator of a ${ } there are QuotingUnknown. The places inside a <( ) are
// QuotingUnknown, but where a reader of code reads its file. The body of a
// heredoc and the text of a here-string to a descriptor other than 0 are
// code: a command can make the descriptor its input.
//
// What is code to another program is known from commands.json, the
// declared table of commands (CommandEntry): the commands that run the
// words after them (sudo, env, timeout and the like), that read their
// arguments as code or as names of variables (eval, source, read), that
// read their standard input as code (the shells, the interpreters, source),
// and the options whose value is code (-c of a shell, -e of perl) or names
// a program (git -c). A command it does not list is read as one that reads
// its arguments as data. Inside [[ ]], the operands of arithmetic (-eq and
// the like) and of -v are code, quoted or not; the others are strings. A
// command word that is not literal, or that has outside quotes a brace
// expansion or a pattern ({bash,-c}, /bin/ba?h), names a command known only
// when it runs: its arguments and its standard input are code. The code of
// -c of a shell is the first word after the options and their values (bash
// -c -x code, bash -co pipefail code); an argument with a brace expansion
// or a pattern outside quotes that may start with - may be an option whose
// value is code or names a program (bash {-c,} code). A call of a function
// that the script defines (any definition of the name) is read through the
// body: a body that reads its input makes the call a reader of a pipe, a
// heredoc or a here-string; the bodies that a command before a reader of
// code, or a substitution read as code, may run are code; and where a body,
// or a body it calls, has a place read as code, every argument and the
// standard input of the call are code. Where a coproc's command reads its
// input, a command with a redirect for output to an element of the
// coproc's array (>&${NAME[1]}, > /dev/fd/${NAME[1]}) is read as what a
// pipe carries to the coproc's command; a descriptor copied from the array
// (exec 4>&${NAME[1]}) and a variable that holds one are not followed. LookupCommand finds the
// CommandEntry of the command a simple command runs, past its wrappers.
//
// Where things are:
//
//	tree.go      Parse's tree: Script, Command and the commands (Asynchronous among them), Redirect,
//	             HeredocBody, Word, Part
//	walk.go      Walk, Visitor, Enclosing, ExecutionEnvironment, StdoutKind: the shared walk of the tree,
//	             with the lastpipe of each shell, and, asked by DescriptorReading, where the descriptors point
//	             (fds.go) and the bodies of functions given where each call runs them
//	fds.go       DescriptorReading: where the descriptors of each shell point, a set of places for the
//	             paths that reach a command: exec, the redirects of compound commands and calls, {name},
//	             if, && and ||, loops read ahead in rounds, break, continue, return and exit
//	output.go    OutputReading: the readings of descriptors of a reader of outputs (a pipe, the value
//	             of a $( )), which nest at the $( ) of words and share the guard of a recursion and the
//	             limits of calls
//	pipe.go      PipeSources, PipeSource, PipePassage, PipeReaders: what reaches a command through the
//	             pipes of a pipeline, and which of its commands read the pipe
//	visibility.go NameVisibility, Assignment, AssignedName, CallsNotRead: which assignments and
//	             definitions reach a place, and the first call whose body a limit kept from being read
//	flow.go      readFlow: the reading of descriptors that records the assignments and the definitions
//	             (the commands that assign, local, {name}, ${NAME:=value}, for and select), the bodies
//	             read once for each state, and the answers for each chain of calls
//	token.go     the tokenizer: words, operators, redirects, heredocs, and the quotes of each place
//	param.go     ParamExpansion, ParamOperator, ParamValue: a ${ } with an operator, the words after it,
//	             and what it writes of the value of its name
//	arith.go     Arithmetic, ArithName, ArithmeticOf: an arithmetic expression, its parts and its names
//	backquote.go the script of ` `: its backslashes taken off, its positions written back
//	parse.go     Parse: the tree of the tokens
//	classify.go  Quotings, Places, Quoting, Place: the roles of the words of each command, and the rules
//	cond.go      how bash reads the words of [[ ]]: operators, strings and arithmetic
//	commands.go  CommandEntry, CommandOption, CommandTrait, ArgumentReading, AttackSpelling,
//	             RequestReading: the table of commands.json
//	commands.json the table of commands; schema/commands.json, its schema
//	commands_gen.go the table, made from commands.json by go generate (internal/commandgen)
//	enum_gen.go  the values of the enumerations of schema/commands.json, made by go generate
//	             (actions/internal/enumgen)
//	lookup.go    LookupCommand, WordsOf, CommandMatch: the entry of the command a simple command runs
//	roles.go     ArgumentRoles, ArgumentRole, CommandRoles: how a command reads each of its words, past the
//	             words whose text is not known (an option, an option's value, an operand); WalkSimple
//	remote.go    RemoteKind, RemoteKindOf, CommandRoles.FirstOperand: where the program of git's
//	             --upload-pack runs, by the repository the command names
//	writes.go    Writes, LineFree, Params, PartParams, TextParams, Literal: what a script writes to a file, the parameters
//	             of commands, the text of a word of literals
//	authored.go  AuthoredCommand, AuthoredCommands: the workflow commands whose names a script writes to its log
//	request.go   RequestWord, RequestRoles: what each word of a command that sends a request is to
//	             the request
//	read.go      Read, ReadAt, Memo: a script tokenized once for its tree and its places, and kept
//	             so that the analyses of an input read it once
//	nested.go    NestedScripts, NestedScript: the code after -c of bash and sh in single quotes, which
//	             another shell reads as a script of its own
//	varcode.go   VariableCodes, VariableCode, CodeReading: where bash or a program reads the value of a
//	             variable as code
//
// Tests:
//
//	tree_test.go    the tree of each form, redirects, where it stops, positions in Sub, deep nesting, |&
//	param_test.go   the ParamExpansion of each operator, its words, nesting, forms not read; Arithmetic; ` `
//	walk_test.go    the environment, order, function, place in a pipeline and standard output Walk gives
//	                each node; lastpipe; WalkSimple
//	pipe_test.go    PipeSources and PipeReaders against what bash reads through a pipe
//	fdbash_test.go  TestDescriptorsWithBash: where bash writes the prints of scripts made of exec,
//	                {name}, if, &&, loops, break and calls, against what Writes gives
//	visibility_test.go  NameVisibility: paths, branches, loops, subshells, functions, the forms that assign;
//	                the time of nested loops and long lists; CallsNotRead past the limits of calls; each
//	                answer against the reading before the flow reading (visibility_old_test.go)
//	flow_test.go    the flow reading: loops, jumps in $( ), calls in each context, the time of many
//	                calls of functions, Writes in the context of each call
//	flowbash_test.go  TestFlowWithBash: on generated scripts, each value bash reads is one the flow
//	                reading says may reach the read
//	quote_test.go   each context, the command word, heredocs, substitutions, scripts that do not
//	                end, a script of 1 MB
//	places_test.go  the delimiter of a place in a heredoc's body
//	bash_test.go    places against bash, and one for each named rule
//	commands_test.go  the values of the enumerations, names and spellings, the sources of the quotes (ACTIONS_UPSTREAM=1),
//	                and how a source that cannot be fetched is asked again and reported
//	lookup_test.go    wrappers, options, subcommands, where it stops
//	roles_test.go     the role of each word: options and their values, --, operands, wrappers, subcommands
//	programs_test.go  places read as code, against the programs that run them
//	writes_test.go  what each command writes, the target by the last redirect, dash's echo,
//	                substitutions that take the line breaks away
//	authored_test.go  the workflow commands a script writes to its log
//	request_test.go   RequestRoles
//	commands_request_test.go  the values of RequestReading, and the options and operands of the
//	                commands that send requests
//	read_test.go    FuzzReadAtTree: ReadAt gives the tree of Parse; the places of Places; a Memo
//	                reads once
//	varcode_test.go  VariableCodes against bash: where the value runs and where it does not, and
//	                that Places gives no fix where it reads a variable as code
//	varcode_fuzz_test.go  FuzzVariableCodes: the spans of the variables it gives
//	internal/commandgen  commands_gen.go is up to date; what the generator rejects
//	fuzz_test.go    FuzzContexts: one context for each place; FuzzParse: spans inside the script
//	                and their parents; FuzzWalk: Walk gives spans inside the script and leaves each
//	                command; FuzzWrites: the spans of what is written
//	bench_test.go   Places on a script of 1 MB
//	deps_test.go    it depends on neither YAML nor actions/expr
package shell

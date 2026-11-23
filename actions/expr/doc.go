// Package expr reads the ${{ }} expressions of GitHub Actions: where they
// are in a string, and their syntax trees. It reads strings, not YAML; the
// positions it returns are byte offsets in the string it was given, and the
// package actions/workflow maps them back to the input.
//
// What GitHub does is the reference.
// The code follows the runner's parser, actions/runner
// v2.337.0, src/Sdk/Expressions (the lexer
// and parser) and src/Sdk/DTObjectTemplating (TemplateReader.ParseScalar);
// actions/languageservices release-v0.3.61
// (expressions/src, workflow-parser/src/templates/template-reader.ts) is
// the second reference.
// Where the runner and GitHub differ, GitHub wins: names compare with each
// character lowered, not OrdinalIgnoreCase.
//
// The runner has two copies of the expression code. It evaluates with
// src/Sdk/DTExpressions2; it evaluates with src/Sdk/Expressions only when a
// feature flag or the environment variable
// ACTIONS_RUNNER_COMPARE_WORKFLOW_PARSER is set, to compare the two results,
// and it uses the result of src/Sdk/DTExpressions2 even then
// (https://github.com/actions/runner/blob/v2.337.0/src/Runner.Worker/ExecutionContext.cs,
// ToPipelineTemplateEvaluator;
// https://github.com/actions/runner/blob/v2.337.0/src/Runner.Worker/PipelineTemplateEvaluatorWrapper.cs,
// EvaluateAndCompare). The runner also checks the syntax of action.yml with
// src/Sdk/DTExpressions2. In v2.337.0 the two copies have the same code for
// the lexer and the parser, and give the same values for all that this
// package evaluates (comparisons, numbers from strings, contains, startsWith,
// endsWith, format of strings, case, and fromJSON with its default options).
// So a reference to a file of src/Sdk/Expressions in this package holds for
// the file of the same name in src/Sdk/DTExpressions2/Expressions2. GitHub's
// server checks the syntax of a workflow and evaluates other expressions,
// such as the if of a job, runs-on and strategy; the code of the server is
// not public.
//
// Parse checks the syntax. CheckNames checks what else GitHub's parser
// rejects: a context or a function the place does not allow, and the number
// of arguments; the
// package actions/workflow gives it the names each place allows.
//
// Where things are:
//
//	error.go   Span, Error, ErrorCode
//	scan.go    Scan: text and ${{ }} in a string
//	lexer.go   tokens, and which token may follow which (LexicalAnalyzer)
//	parser.go  Parse, the Node kinds, Children, the depth and length limits
//	path.go    AccessPath, HasPrefix, PathIs, IsPath, EqualName, FoldName
//	names.go   Names, ContextName, ScopedFunc, CheckNames: the contexts and the functions a place allows
//	partial.go Partial, Value, Truth: what an expression is known to be before the run
//	types.go   Type, TypeOfExpr, ValueType: what an expression may be when it runs; CallMistakes:
//	           the calls that fail when it runs
//
// Tests:
//
//	scan_test.go    segments, }} in strings, unclosed and empty expressions
//	lexer_test.go   token kinds, numbers, strings, the grammar checks of the lexer
//	parser_test.go  precedence, errors, the depth and length limits, spans, Children
//	path_test.go    AccessPath, HasPrefix, PathIs, EqualName, FoldName
//	names_test.go   CheckNames: contexts, functions and their arities, case; Names.Union
//	partial_test.go Partial: comparisons, Kleene's logic, functions,
//	                one evaluation of each node
//	types_test.go   TypeOfExpr: literals, functions, && and ||, stars; CallMistakes: format, case,
//	                fromJSON, the calls never reached, upstream's inputs of case
//	fuzz_test.go    FuzzScan, FuzzFoldName, FuzzParse
//	corpus_test.go  every ${{ }} of yaml/corpus; those of workflows that run on GitHub parse
//	                (ACTIONS_CORPUS=full: all files; otherwise one in seven)
package expr

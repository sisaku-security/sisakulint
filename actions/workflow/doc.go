// Package workflow reads a GitHub Actions workflow file (Parse) and an
// action.yml (ParseActionMetadata) into typed elements; the steps of both are
// Step. Each element keeps its cst node, so a rule reports where it is
// and a fix rewrites its bytes with the package edit; the positions of the
// ${{ }} in a value map back to the input through String.Source.
//
// A value is Absent, Present, Dynamic (a ${{ }} stands where a mapping or
// a sequence belongs) or Invalid (it does not fit the schema, and a
// Diagnostic says why), so that a rule can tell "not there" from "not
// known". Aliases are followed; an element reached through one records it
// in Base.Via, since its bytes are shared.
//
// What GitHub does is the reference. Keys and values
// are checked, the way the template reader does, against the schema of
// actions/languageservices release-v0.3.61,
// workflow-parser/src/workflow-v1.0.json (schema/workflow-v1.0.json,
// sha256 ba07953f8becf1eae45c56efdbc2577b8121db9f57ed065a4c43edbfaf444c66),
// with its on replaced by the on-new of actions/runner
// v2.337.0,
// src/Sdk/WorkflowParser/workflow-v1.0.json (schema/runner-workflow-v1.0.json,
// sha256 37599daaf45dd1f53743f708f9b8427f90f06e3f889567ff988a09f5ef24bfb8):
// GitHub checks event names and reads what is in an event loosely.
// Elements the model does not type are kept as nodes, and what is inside
// them is not checked.
//
// An action.yml is read by the runner, not by GitHub's server; what the
// hosted runner 2.337.0 does is the reference. It is checked
// against actions/runner v2.337.0 (397b032cbf865e9c3ddfab89d533ec19325e1273),
// src/Runner.Worker/action_yaml.json (schema/runner-action_yaml.json,
// sha256 96bee1395cc79325210563142a0637f6a95d03a6b0958d88dd43e451f2d2cf57),
// whose definitions are in the table with the prefix action:.
//
// Where things are:
//
//	parse.go      Parse, Status, Field, Base, Map, List, Code, Diagnostic; reading keys and
//	              values against the schema, aliases; readDocument, shared with ParseActionMetadata
//	string.go     String, Part: a scalar's value and its ${{ }}
//	workflow.go   Workflow, and the jobs a job needs (NeedClosure)
//	action.go     ParseActionMetadata, ActionMetadata, ActionInput, ActionOutput, Runs: action.yml
//	on.go         On, Event, Input, Secret, Output
//	event.go      EventName: the name of an event; its values are the constants of on-string
//	              (schema_gen.go)
//	job.go        Job: runner jobs and calls of reusable workflows, strategy.matrix and the types of
//	              its values, secrets, the labels of runs-on, defaults.run and Concurrency (of the
//	              workflow too)
//	container.go  Container: a job's container or one of its services
//	image.go      ImageReference, ImageReferenceOf, DockerImageOf: an image as written
//	runner_label.go RunnerLabelName, SelfHostedLabel, LinuxLabel, WindowsLabel, MacOSLabel,
//	              HostedRunnerLabelsSource, HostedWindowsLabels: a label of runs-on, compared in
//	              any case, and the labels GitHub gives runners
//	envname.go    EnvName, EnvNameOf: the name of an environment variable
//	inputname.go  InputName, InputNameOf: the name of an input of an action or a called workflow, as a with gives it
//	permissions.go Permissions
//	step.go       Step, StepPlace: the steps of a job and of the runs of a composite action, a
//	              parallel group's in its place
//	order.go      StepOrder: when steps that run alongside others are done
//	uses.go       Uses, Piece: the forms of uses
//	if.go         If: the forms of if, which differ in an action.yml, and whether an if is
//	              a folded ${{ 'x' }} (Folded)
//	check.go      checkRest: the values the typed reading leaves, checked against the schema
//	readerchecks.go what GitHub's reader rejects beyond the schema: step ids, the graph of needs,
//	              the calls of reusable workflows (CheckCall), and parallel groups, wait-all,
//	              wait and cancel
//	schema.go     the schema's table: definitions, properties, one-of
//	schema_gen.go the table, made by go generate from the three schemas and the schema additions
//	              (additions.json) under schema/
//	internal/schemagen  the program that makes schema_gen.go
//
// Tests:
//
//	parse_test.go   Field states, keys, duplicates, aliases, where ${{ }} is allowed,
//	                details of the template reader (keys from ${{ }}, diagnostics of an empty file)
//	on_test.go      the three forms of on, filters, inputs of workflow_dispatch and workflow_call
//	event_test.go   the names ParseEventName accepts; a constant for each name of on-string
//	job_test.go     kinds of job, fields, calls, matrix, job ids, runs-on, defaults.run.shell
//	                and the diagnostics of their values
//	matrix_test.go  the values a matrix gives each name, and the diagnostics of include and exclude
//	container_test.go the string form and the mapping of a container and of services, their env
//	image_test.go   ImageReference and DockerImageOf
//	runner_label_test.go RunnerLabelName, and how runs-on is written
//	envname_test.go EnvNameOf
//	inputname_test.go InputNameOf
//	names_test.go   the contexts and the functions of the ${{ }} at each place
//	experiments_test.go the files of the experiments on expressions and on parallel steps
//	                (testdata/observed): a file GitHub rejected has diagnostics, one GitHub read
//	                has none
//	exprkeys_test.go the keys the quality rule expression reads, the types of the matrix's values
//	permissions_test.go  the forms of permissions and the access of scopes
//	order_test.go   DoneBefore, MayRunAfter and DoneAt for groups, background steps and waits; a
//	                parallel group's steps
//	step_test.go    kinds of step, fields, with, script, run positions, aliases
//	uses_test.go    each form of uses and where its pieces are, $/path
//	if_test.go    the forms of if
//	action_test.go  action.yml: root, inputs, outputs, the kinds of runs, composite steps and
//	                their if, the test data of actionlint and zizmor
//	string_test.go  positions of ${{ }} in each scalar style, IsExpr, AsString
//	rules_test.go   what GitHub's reader checks beyond the schema: tags, format() length, job ids
//	readerchecks_test.go step ids, needs, CheckCall; parallel groups, wait-all, wait and
//	                cancel; ids folded
//	                from a string literal in ${{ }}
//	cachemode_test.go  cache-mode, a schema addition: where it is taken and which values
//	check_test.go   the values of keys kept as nodes are checked once, where each alias uses them,
//	                and the values the typed reading reads (cancel, wait-all) are not checked twice
//	reader_test.go  the reader tests of languageservices (copied in testdata/languageservices), and
//	                why some differ
//	copies_test.go  TestThirdPartyCopies: the files and the sha256 of the copies under testdata
//	corpus_test.go  every file of yaml/corpus, read by Parse and ParseActionMetadata: no panic, spans
//	                in the input; the workflows and action.yml files of real-world and org
//	                get no diagnostic
//	                (ACTIONS_CORPUS=full: all files; otherwise one in seven)
//	fuzz_test.go    FuzzWorkflow, FuzzAction
//	scale_test.go   reading takes time linear in the keys of a mapping and the items of a sequence
//	bench_test.go   the model against cst alone; results in BENCH.md
//	internal/schemagen  schema_gen.go is up to date; the two workflow schemas are merged; the
//	                action schema is added with its prefix
package workflow

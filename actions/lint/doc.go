// Package lint runs rules over workflows and action.yml files and writes
// what they find as a report other systems can rely on
// (schema/report-v0.json):
//   - the severity of a finding comes from the registry of rules
//     (schema/registry-v0.json), never from the rule's code;
//   - a finding that rests on a fact that could not be found out
//     (package facts) is conditional, with its condition, instead of
//     disappearing;
//   - a rule that fixes gives a fix or says why there is none;
//   - what a rule does not detect is said: the forms it does not detect in
//     its Meta (UndetectedForms), and each place where it cannot decide
//     whether the workflow departs from Meta.Expected or whether harm can
//     occur, in the report as a finding whose certainty is inconclusive
//     (CertaintyInconclusive, of an InconclusiveKind), each
//     with why as it is judged now (Disposition);
//   - the forms on which a rule reports a finding whose consequence does
//     not occur are said in its Meta (FalsePositiveForms);
//   - the exit code (Classify) says whether anything was found, left
//     undecided, or went wrong.
//
// A rule asks the Resolver of its RuleContext about the world outside the
// input; the engine asks each fact once and puts the answers in the
// report, so that the same inputs and the same file of facts give the
// same bytes. The inputs are found the way GitHub and the runner find them.
//
// Where things are:
//
//	input.go       Input, Inputs, InputBytes, Enumerate, Files, Single, InputSet, WithReported
//	cond.go        Condition, All, Any, FactEq, FactAbsent, InputPresent, Eval: Kleene's logic
//	               (expr.Truth)
//	finding.go     FindingDraft, Location, At, AtSpan, Fix, NoFix, Severity, InputKind, Safety
//	registry.go    Meta, FindingText, FindingKind, FixKind, UndetectedForm, InconclusiveKind,
//	               FalsePositiveForm, Example, Registry, NewRegistry
//	argument.go    KindArgument, KindArgumentName: the arguments a kind of finding declares
//	quality.go     QualityRule, QualityMeta, QualityFindingKind, QualityFinding: the quality
//	               rules, whose findings set no bit of the exit code
//	defaultrun.go  DefaultRun, FactSources: whether a rule runs in a run that does not name it
//	select.go      Selector, Selection, Only, Skip: which rules run (--rule, --skip-rule)
//	facets.go      Weakness, AttackMeans, Facet, FacetAxes: the axes the rules are sorted by
//	example.go     Example.Inputs: an example as the inputs of a run
//	examplenotes.go ExampleNotes, AttackValue: the comments an example starts with (a true positive's
//	               added attackers among them)
//	advisory.go    AdvisoryID, AdvisoryPage: the page of an advisory an example cites (# advisory:)
//	source.go      SourceFile: the file of a repository at a commit an example cites (# source:)
//	checkexamples.go ExampleWhat, ExampleRun, ExampleCheck, Registry.CheckExamples, RunExample,
//	               RunExampleAdded, RunExampleMarked, RunExampleAs, TrueNegativeText: each example of
//	               each declaration, run and compared with what it says
//	explain.go     Registry.Explain: the rules as Markdown for people (sisakulint --explain);
//	               Registry.ExplainRule, a rule or a quality rule without its
//	               examples; MarkdownText,
//	               MarkdownCodeBlock: Markdown that reads as it shows
//	terms.go       Terms: what the item names of --explain and the values of the schemas mean
//	               (--explain=terms)
//	definitions.go Definition, ValueGroup, TermDefinitions, Definitions: what the terms say, which
//	               Terms writes and an example catalog shows
//	termpaths.go   RegistryPath, MetricName, TermPaths: which terms are of which keys of the JSON
//	               of a rule
//	disposition.go Disposition, Need, Decider: why a rule does not report a form or a kind of
//	               place
//	threat.go      Threat, Actor, Attacker, Gain, Precondition, Observation, Incident, and
//	               Date, Version, CVEID
//	added.go       AddedAttacker, AddedAttackers, Registry.WithBarriers, RunAdded: the attackers a run
//	               counts only when the user adds them, and the places only they give, marked
//	enum_gen.go    the values of the enumerations of the schemas, and their names and JSON,
//	               made by go generate (actions/internal/enumgen) from the $defs where they
//	               are defined
//	cvss.go        CVSS, Metric and the metrics, ExploitMaturity; the table that finds a
//	               severity from them (FindingKind.Severity, SeverityBasis); ScoreRating,
//	               the rating of the scores of package cvss4 the registry writes
//	ids.go         RuleID, FixKindID, FindingKindID, UndetectedFormID, InconclusiveKindID,
//	               FalsePositiveFormID, PreconditionID, IncidentID, Fingerprint, Citation:
//	               identifiers that cannot be made wrong
//	run.go         Rule, RuleContext, InconclusiveDraft, Run, RunWithBarriers: the engine, and the check of each fix after it
//	               is applied
//	checker.go     the rules run on each file (checker): Check, finish and the check of the
//	               fixes (checkApplied) of each rule on each input, and on each remote called
//	               workflow
//	remote.go      the remote called workflows (a reusable workflow of another repository that
//	               workflow.definition answers), whose findings, inconclusive ones too, are moved
//	               to the uses of the job of the input that calls them; RemoteCalleeForm,
//	               RemoteCalleeUnknownKind
//	view.go        ViewRule, WithView: a rule that reads the IR through a view; RuleContext.At
//	eventpolicy.go Meta.AttackerEvents; the condition repo.pull-request-target-allowed that
//	               the engine adds to a finding of a workflow whose on has pull_request_target
//	               and no other event, and the check that a kind declares the fact
//	appchecks.go   AppChecksFact; the condition repo.fork-pr-app-checks or
//	               repo.merge-commit-app-checks that the engine adds to a finding of a
//	               workflow whose on has only events among status, check_suite and
//	               check_run, and the check that a kind that declares a fact has its attacker
//	               with them
//	apply.go       ApplyFixes: the fixes of a report applied together, and checked again
//	               (actions/cli writes them, and what came of it, Report.Fix)
//	unchecked.go   Unchecked, Changed, FixBy: a rule that did not run, a field of whose
//	               summaries the fixes change, so that --fix did not check the fixes against it
//	unread.go      UnreadUses: the uses of other repositories whose definition the run did
//	               not ask, which set no bit
//	fingerprint.go the fingerprint and the path of keys it rests on
//	report.go      Report, Finding, Certainty, RunError, FixResult, and their JSON; ReportedInputs, Narrow,
//	               FindingsWith, Finding.FixInput, Finding.KindText, InconclusiveKindText
//	classify.go    Classify: the exit code
//	acceptance.go  Acceptance, LoadAcceptances, Accept: the places of inconclusive findings a
//	               person accepted (sisakulint --accept), which set no bit
//	schema/        report-v0.json and registry-v0.json; they refer to
//	               actions/facts/schema/facts-v0.json as facts-v0.json. acceptances-v0.json,
//	               the file of acceptances
//
// Tests:
//
//	cond_test.go        the table of Kleene's logic, the leaves, the JSON of conditions
//	registry_test.go    what the registry of rules accepts; the rule of the tests (testRule)
//	exampled_test.go    an ExampledRule: its examples read only when the registry shows them, and
//	                    checked then
//	explain_test.go     the Markdown of Explain: the escapes, each field, the rules asked for,
//	                    a rule without its examples
//	disposition_test.go the JSON of each Disposition, and what a Disposition keeps of what it
//	                    is made of
//	cvss_test.go        the vector, and every cell of the table of severities
//	ids_test.go         what each identifier accepts
//	threat_test.go      what a threat needs to rest on, and its JSON
//	input_test.go       what Enumerate, Files and Single read, names, Lookup,
//	                    the directories Enumerate skips
//	run_test.go         the engine: conditions, errors and panics, fixes, rules that misbehave,
//	                    what a rule reported is not changed after
//	remote_test.go      the remote called workflows: their events and inputs from their one
//	                    caller, the chains, the jobs that call an input
//	eventpolicy_test.go the condition repo.pull-request-target-allowed: on which workflows the
//	                    engine adds it, kept with the rule's own; the check of its declaration
//	appchecks_test.go   the condition repo.fork-pr-app-checks or repo.merge-commit-app-checks:
//	                    on which workflows the engine adds it, one fact or any of the two;
//	                    the check of its declaration
//	inconclusive_test.go the inconclusive places: their order, and the rules that break the
//	                    contract with them
//	enum_test.go        every value of enum_gen.go, written and read as its $defs has it
//	reparse_test.go     the check of each fix, its bounds (fixes, bytes and reports
//	                    read again), and its determinism; a fix that findings share,
//	                    checked once
//	apply_test.go       ApplyFixes
//	scale_test.go       the time of the checks of fixes (ACTIONS_SCALE=1, alone with
//	                    go test -p 1: a real workflow, and the bound on one of 500 KB)
//	fingerprint_test.go paths, what keeps and what changes a fingerprint, aliases
//	report_test.go      the golden report (testdata/, -update), the schemas, a replay from a
//	                    file of facts
//	classify_test.go    the bits of the exit code
//	acceptance_test.go  what names an inconclusive place (its key path and texts), the file of
//	                    acceptances, which places an acceptance matches
//	quality_test.go     the quality rules: what the registry takes and refuses, their run,
//	                    their JSON, Select
//	defaultrun_test.go  DefaultRun: what Select leaves out, and default_run in the JSON
//	select_test.go      ParseSelector, Select, what it refuses, and a skipped rule's facts not asked
//	facets_test.go      the axes of a rule, and what NewRegistry needs of them
//	falsepositive_test.go what NewRegistry takes of a false positive form and of an example,
//	                    and an example of several files
//	checkexamples_test.go CheckExamples on a form of no-added-gain that gives an inconclusive place
//	examplenotes_test.go ParseExampleNotes, and that the old mark # reviewed: is no key
//	source_test.go      ParseSourceFile: the URLs of a file at a commit it takes and refuses
//	terms_test.go       the golden terms (testdata/), their shape, and that they cover the schemas
//	definitions_test.go the order of the value groups, and that each is a definition of the schema
//	termpaths_test.go   which terms each path of the JSON of a rule has, against the schema
//	view_test.go        WithView: the reads a rule declares, one IR for the rules of an input,
//	                    the check of a fix on the fixed IR
//	view_location_test.go Location's position and line, the parts of a condition
//	unchecked_test.go   when a rule that did not run is said, and by which fix
//	callers_test.go     the check of a fix of a caller runs the rules on what it calls; an
//	                    input not read may be a caller
//	calldiag_test.go    the diagnostics of a call of a workflow among the inputs
//	labeler_test.go     a run reads the configuration of actions/labeler from the repository
//	probe_test.go       the validity experiments, run as the repositories they were
//	refs_test.go        the schemas, and the comments of this package and of actions/facts,
//	                    name no path into the documents of this repository
//	corpus_test.go      every repository of yaml/corpus real-world, org, sisakuintel and labeler-token: no internal
//	                    error, the report fits its schema (ACTIONS_CORPUS=full: all; otherwise
//	                    one in seven)
package lint

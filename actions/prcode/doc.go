// Package prcode is where a workflow or an action.yml brings the code of a
// pull request with actions/checkout, or the artifact of a run a pull
// request drives with actions/download-artifact or
// dawidd6/action-download-artifact, and the
// context of that job the rules of untrusted checkouts and of artifact
// poisoning read: the privileged events it can run on, whether
// the release of actions/checkout refuses a fork's code, what makes a
// person approve the run, the steps after it that run the code, and those
// that save the code to the cache.
//
// It reads the events of on and the ifs that leave some out, the references
// written in ${{ }} and the shell of a run as actions/taint does, and the
// commands of a run by actions/shell's tree. It asks no fact: what the
// YAML cannot tell (whether a pinned commit has the guard, whether an
// environment has required reviewers, whether the code runs) is for the
// rules to put in their conditions.
//
// Where things are:
//
//	site.go      CheckoutSite (of analysis.CheckoutCode, Guard and Approval), CodeRunStep, Cite; Analyze, and
//	             AnalyzeComposite, which reads the steps of the composite actions a step runs too
//	tree.go      CheckoutRef (of analysis.CheckoutInput): what a checkout's with brings, and its guard
//	tables.go    the privileged events, the references to a pull request's code, the
//	             releases and the commits of the guard
//	approval.go  a label or an environment that approves the run
//	evidence.go  the steps after a checkout or a download that run what it brings (codeRuns), and the table of tools:
//	             the directories a tool reads, the commands that run code and the settings that stop it
//	stepdir.go   the directory a run step starts in (working-directory, defaults.run), cd, and paths from it
//	permission.go  PermissionRunsTree: an agent's permission of a command, read by the table of tools
//	placement.go Placement: where a step puts files, a directory under the workspace or under runner.temp
//	runword.go   the words of a run as codeRuns reads them: the ${{ }} and the variables of bash and pwsh by their syntax
//	checkoutplace.go  CheckoutPlacement: where a checkout puts the tree, or that it fails on its path
//	checkoutv1.go     the refs of actions/checkout v1, which moves github.workspace
//	download.go  DownloadSite, PRRunRef: the run a download takes, the token's scope, where it puts the files
//	downloadtables.go  the commits of the releases of the two download actions
//	samerun.go   SameRunUpload: the uploads of the current run, after a checkout of a pull request's code, that a download of the current run takes:
//	             those of actions/upload-artifact, of a composite action of the inputs, of a ./ reusable workflow, and of
//	             actions/upload-artifact/merge (mergeUploads: one upload for each merge step, first upload and
//	             unread cause, up to mergeReadMax reads); upload: those uploads, and the unread ones of uses whose
//	             uploads are not known
//	minimatch.go matchArtifactName: the names that a pattern of the merge or the download takes, as minimatch reads it
//	             (the brace expansion, the parts between /, matchParts); minimatch_ast.go the regular expression of a
//	             part (src/ast.ts of minimatch), minimatch_regexp.go which it runs by backtracking
//	cache.go     CacheSaveStep, CacheActionOf: the steps that save to the cache what a checkout brings,
//	             those of the composite actions a step runs (Inner, of actions/composite), and the
//	             uses of other repositories on the way with no answer (UnansweredCall)
//	pathline.go  PathLines, PathLine: the lines of a value of paths, with the workspace and
//	             runner.temp read from the syntax of their ${{ }}
//	dispatch.go  the inputs of workflow_dispatch that choose what a checkout or a download takes
//	commit.go    MissingCommit
//
// Tests:
//
//	tree_test.go      the references of each form, refs/pull/<n>/…, the guard
//	site_test.go      the events and the ifs, the path of a step
//	approval_test.go  a label alone, a label with other types, an environment and its name
//	evidence_test.go  each row of the table of tools, paths of the tree, the checkout's path, other shells, the roots of a download
//	stepdir_test.go   working-directory and defaults.run key by key, composite steps, cd, the options of a tool's directory
//	permission_test.go  permissions of commands, past wrappers, and with a *
//	placement_test.go the directory of a Placement
//	runword_test.go   the words of bash and pwsh: runner.temp, github.workspace, other ${{ }}, escapes, quotes
//	checkoutplace_test.go  the path of a checkout: runner.temp, v1, the runner, the steps before
//	samerun_test.go   the lines of the path of an upload, and a checkout that fails on its path
//	minimatch_test.go the cases of the tests of minimatch and of the runs of the actions (testdata/minimatch), and the brace expansion
//	download_test.go  each row of the tables of downloads, destinations, the token's scope, the tables of releases, the uploads of the current run
//	cache_test.go     the steps that save to the cache the tree a checkout brings
//	pathline_test.go  the workspace and runner.temp in their spellings, the other ${{ }}, folded literals
//	callers_test.go   the events of a checkout or a download of a called workflow, read from its callers
//	composite_test.go the cache steps of the composite actions a step runs, and the uses with no answer
//	dispatch_test.go  a checkout or a download whose inputs an input of workflow_dispatch gives
//	parallel_test.go  the steps of a parallel group: what runs after a checkout, and its path
//	misread_test.go   forms of refs, forks and later checkouts that the analysis once read wrongly
//	scale_test.go     the time of a job of many checkouts (ACTIONS_SCALE=1)
//	upstream_test.go  each release published after the tables were taken is in them (ACTIONS_UPSTREAM=1)
//	deps_test.go      what it depends on, and that actions/taint does not read it
package prcode

// Package rules is the rules of sisakulint, each in a file of its own,
// on the contract layer of actions/lint: a rule asks the facts it needs of
// actions/facts and never does I/O itself. actions/lint does not import
// this package; a caller puts All in a lint.Registry. A rule must be safe
// to run from several lint.Run calls on other inputs at once: the tests of
// the package run them in parallel.
//
// Where things are:
//
//	actionlist.go  action-list: a uses that the repository's own list of allowed uses
//	              (repo.action-list) does not allow
//	aiactionexcessivetools.go  ai-action-excessive-tools: what an AI agent's tools give an
//	              attacker
//	aiactionexecutionorder.go  ai-action-execution-order: a step after an AI agent's step that
//	              runs what the agent leaves
//	aiactionpromptinjection.go  ai-action-prompt-injection: what an attacker writes reaching an
//	              AI agent
//	aiactionunrestrictedtrigger.go  ai-action-unrestricted-trigger: a step of an AI agent action an
//	              outsider starts
//	aiactionunsafesandbox.go  ai-action-unsafe-sandbox: a setting of an AI agent action that
//	              takes a layer of its sandbox off
//	artipacked.go  artipacked: a git credential left in .git/config that an upload of
//	              actions/upload-artifact puts in an artifact
//	secretexposure.go  secret-exposure: a ${{ }} that reads the secrets without naming one,
//	              for which GitHub sends the job every secret
//	secretsinartifacts.go  secrets-in-artifacts: a credential left in another file of the
//	              workspace that an upload puts in an artifact
//	selfhostedrunner.go  self-hosted-runner: a job of a public repository on a self-hosted runner
//	unmaskedsecretexposure.go  unmasked-secret-exposure: a value taken out of a secret by fromJSON
//	              where the runner prints it, unmasked
//	unpinnedimages.go  unpinned-images: an image to run that no digest pins
//	artifact.go   what artipacked and secrets-in-artifacts share, on actions/artifact
//	codeinjection.go  code-injection: a value an attacker controls written into code by
//	              ${{ }}, on actions/taint
//	envvarinjection.go  envvar-injection: a value an attacker writes with line breaks, written
//	              to $GITHUB_ENV
//	outputclobbering.go  output-clobbering: the same, written to $GITHUB_OUTPUT
//	filecommand.go  what the two check, on the writes actions/taint reads
//	injection.go  what the three injection rules share: attackers, preconditions, undetected
//	              forms, inconclusive kinds
//	internal/stepfix/  the fix of a step, the same for every injection rule that reports in it
//	dangeroustriggers.go  dangerous-triggers: a job an attacker's privileged event runs, unapproved,
//	              with a token that may write or secrets
//	permissions.go  permissions: a job whose GITHUB_TOKEN has write-all or the repository's
//	              default, which the code of others it runs holds
//	secretsinherit.go  secrets-inherit: a job that lets the reusable workflow it calls reference every secret
//	              with secrets: inherit
//	credentials.go  credentials: the password of a registry written in the workflow
//	commitsha.go  commit-sha: uses pinned to a full commit SHA
//	impostorcommit.go  impostor-commit: a step's SHA that no branch or tag has
//	untrustedcheckout.go  untrusted-checkout: a privileged job that no one approves checks out
//	              a pull request's code
//	untrustedcheckouttoctou.go  untrusted-checkout-toctou: a job a person approves checks out
//	              what the pull request's author can move after the approval
//	artifactpoisoning.go  artifact-poisoning: a privileged job downloads the artifact of a run
//	              a pull request drives, into its workspace or where a step runs it, on
//	              actions/prcode
//	checkout.go   what the rules of checkouts share, on actions/prcode
//	appcheck.go   what the rules that read status, check_suite and check_run share: the
//	              precondition app-status-check, the forms of the runs of an outside app,
//	              and repo.fork-pr-app-checks and repo.merge-commit-app-checks of the
//	              kinds (withAppChecks)
//	botconditions.go  bot-conditions: an if that lets only Dependabot in by the actor,
//	              which an attacker passes by having Dependabot push to their pull
//	              request, on actions/attacker
//	unsoundcontains.go  unsound-contains: contains of a string in an if, which a part of
//	              the string passes
//	ifs.go        the undetected forms of an if the rules that filter by it share
//	uses.go       the remote uses of an input, for both
//	meta.go       what their Meta share
//	schema/findings-v0.json  the kinds of findings and their arguments; findingsgen makes
//	              their Go types (finding_gen.go)
//	args.go       what the generated types share
//	examples.go   the examples of the rules' declarations, embedded, given to their Metas
//	examples/<what>/<rule>/  the inputs of the declarations of a rule: true-positive and
//	              true-negative for each kind of finding, false-positive, undetected and
//	              inconclusive for each form and kind of place (examples_test.go checks each
//	              against what its declaration says); <id> is the main one, <id>.<label>
//	              another; an example of the form of an advisory has the note
//	              # advisory: <URL>
//	review.go     ReviewDocuments, Review: the Markdown a person reads to approve a rule
//	              (review documents), and whether the approved documents are those now,
//	              by the checks of every example (AllExampleChecks, CheckAllExamples)
//	approved/<rule>/  the approved documents: a rule's meta.md and <what>/<id>.md as a
//	              person approved them by merging a review batch (actions/internal/reviewpr)
//	testdata/registry.golden.json  the registry of All: every rule's IDs, of its fixes,
//	              undetected forms, inconclusive kinds and false positive forms, and their examples (sisakulint --registry)
//	testdata/explain.golden.md  the same as Markdown for people (sisakulint --explain=all),
//	              with a fixed commit
//	testdata/all-rules/  the all-rules example: workflows with every kind of finding
//	              of every rule and fixes of several rules in one step (example_test.go
//	              keeps it up to date)
package rules

import "github.com/gh-intel/sisakulint/actions/lint"

//go:generate go run ./internal/findingsgen

// Quality are the quality rules, by ID, one on a line: rules whose finding
// alone gives no attacker a gain (lint.QualityRule).
func Quality() []lint.QualityRule {
	return []lint.QualityRule{
		AllowedActions,
		ArchivedUses,
		CacheBloat,
		Cond,
		DependabotGitHubActions,
		DependencyReviewSettings,
		DeprecatedCommands,
		DeprecatedNodeRuntime,
		EnvVarRule,
		ExpressionRule,
		MissingTimeoutMinutes,
		UnsetConfigurationVariable,
		UsesPath,
	}
}

// All is every rule. Each is a lint.ExampledRule: its Meta has no
// examples, and its ExampledMeta has those of examples/.
func All() []lint.Rule {
	return []lint.Rule{
		AIActionExcessiveTools,
		AIActionExecutionOrder,
		AIActionPromptInjection,
		AIActionUnrestrictedTrigger,
		AIActionUnsafeSandbox,
		ActionList,
		ArgumentInjection,
		ArtifactPoisoning,
		Artipacked,
		BotConditions,
		CachePoisoning,
		CodeInjection,
		CommitSHA,
		Credentials,
		DangerousTriggers,
		EnvpathInjection,
		EnvvarInjection,
		ImpostorCommit,
		KnownVulnerableActions,
		OutputClobbering,
		Permissions,
		RequestForgery,
		SecretExfiltration,
		SecretExposure,
		SecretInLog,
		SecretsInArtifacts,
		SecretsInherit,
		SelfHostedRunner,
		SetOutputInjection,
		UnmaskedSecretExposure,
		UnpinnedImages,
		UnsecureCommands,
		UnsoundContains,
		UntrustedCheckout,
		UntrustedCheckoutToctou,
	}
}

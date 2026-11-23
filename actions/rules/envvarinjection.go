package rules

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"slices"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// EnvvarInjection is the rule envvar-injection: a value an attacker writes
// with line breaks, written to $GITHUB_ENV, where a line break sets other
// variables of the steps after it; BASH_ENV among them runs code in their
// bash.
var EnvvarInjection lint.Rule = withExamples(lint.WithView[ir.FileCommandReader](fileCommand{
	file: analysis.EnvironmentFileEnv, meta: &envvarInjectionMeta,
	controlled: func(ref string, evs []workflow.EventName) lint.FindingArgs {
		return EnvvarInjectionControlled{ExprRef: ref, ControlledOn: evs}
	},
	wiki: func(ref string) lint.FindingArgs { return EnvvarInjectionWiki{ExprRef: ref} },
}, ir.FileCommandView))

// EnvvarInjectionID is the ID of envvar-injection.
var EnvvarInjectionID = lint.MustRuleID("envvar-injection")

var envvarInjectionMeta = lint.Meta{
	ID:       EnvvarInjectionID,
	Problem:  "a value an attacker writes with line breaks is written to $GITHUB_ENV, where each line break starts another variable of the steps after it",
	Expected: "no value an attacker writes with line breaks is written to $GITHUB_ENV with its line breaks, or with a delimiter an attacker can write",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessEnvironmentFileInjection}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: fileKinds(textEnvvarInjectionControlled, textEnvvarInjectionWiki, fileEnvBase,
		metric(lint.ExploitMaturityProofOfConcept, "GitHub Security Lab showed a pull request's artifact with a line break and LD_PRELOAD written to $GITHUB_ENV in a workflow_run workflow of Feign (GHSL-2024-173); the value came through a variable the script sets, which this rule does not follow (script-var)", ghsl2024173),
		bashEnv),
	Threat: lint.Threat{
		Actors:        injectionActors([]lint.Gain{lint.GainSetEnv, lint.GainRunCode, lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainWriteCache}),
		Preconditions: []lint.Precondition{runnerReadsLinesPre, attackerWritesLinesPre, attackerEventPre, callersEventsPre, wikiOpenPre, wikiTitleLinesPre, bashEnvPre, appStatusCheckPre},
	},
	Citations:          []lint.Citation{cvss},
	Targets:            []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FixKinds:           []lint.FixKind{stepFixKinds[1]},
	UndetectedForms:    withRemoteCallee(append(slices.Clone(fileLimits), fileContentLimit("$GITHUB_ENV"), forkReviewLimit, callAfterExecLimit, substitutionPipeEndLimit, lint.UndetectedForm{ID: lint.MustUndetectedFormID("github-output"), Text: "a value written to $GITHUB_OUTPUT", Disposition: lint.OtherRule(OutputClobberingID)}, insiderAssociationLimit, splitEnvNameLimit, wikiSummaryLimit)),
	InconclusiveKinds:  withRemoteCalleeUnknown(withCallBodyUnknown(fileGaps)),
	FalsePositiveForms: withCallee(append(append(injectionFalsePositives(kindEnvvarInjectionControlled, kindEnvvarInjectionWiki), fileCommandFalsePositives(kindEnvvarInjectionControlled)...), reassignedEnvFalsePositive("$GITHUB_ENV", "X=safe; echo \"A=$X\" >> \"$GITHUB_ENV\"", kindEnvvarInjectionControlled), backgroundWriteFalsePositive("$GITHUB_ENV", "(sleep 5; echo \"A=$X\" >> \"$GITHUB_ENV\") &", kindEnvvarInjectionControlled, kindEnvvarInjectionWiki)), kindEnvvarInjectionControlled, kindEnvvarInjectionWiki),
}

// substitutionPipeEndLimit is a print inside a $( ) whose redirect
// duplicates a descriptor that the script closed before the $( ): bash
// places an end of the pipe of the $( ) there, and the rule reads the
// descriptor as closed.
var substitutionPipeEndLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("substitution-pipe-end"), Text: "a print inside a $( ) with a redirect that duplicates file descriptor 0 or file descriptor 2, where the script closed that file descriptor before the $( ) and bash places an end of the pipe of the $( ) on that file descriptor (exec 2>&-; echo \"$( echo \"V=$V\" >>\"$GITHUB_ENV\" 3>&2 )\"): bash opens the pipe of the $( ) on the lowest closed file descriptors and does not close an end of the pipe that is file descriptor 0, 1 or 2 inside the $( ), so the redirect that duplicates the file descriptor does not fail and bash runs the print; the rule reads file descriptor 0 or file descriptor 2 inside the $( ) as closed, and reads the print as a command that bash does not run because the redirect that duplicates the file descriptor fails", Disposition: lint.Todo(lint.NeedSameFile)}

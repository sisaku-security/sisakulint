package rules

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// OutputClobbering is the rule output-clobbering: a value an attacker
// writes with line breaks, written to $GITHUB_OUTPUT, where a line break
// sets other outputs of the step, which the steps and jobs after it take as
// its own.
var OutputClobbering lint.Rule = withExamples(lint.WithView[ir.FileCommandReader](fileCommand{
	file: analysis.EnvironmentFileOutput, meta: &outputClobberingMeta,
	controlled: func(ref string, evs []workflow.EventName) lint.FindingArgs {
		return OutputClobberingControlled{ExprRef: ref, ControlledOn: evs}
	},
	wiki: func(ref string) lint.FindingArgs { return OutputClobberingWiki{ExprRef: ref} },
}, ir.FileCommandView))

// OutputClobberingID is the ID of output-clobbering.
var OutputClobberingID = lint.MustRuleID("output-clobbering")

var outputClobberingMeta = lint.Meta{
	ID:       OutputClobberingID,
	Problem:  "a value an attacker writes with line breaks is written to $GITHUB_OUTPUT, where each line break starts another output of the step",
	Expected: "no value an attacker writes with line breaks is written to $GITHUB_OUTPUT with its line breaks, or with a delimiter an attacker can write",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessEnvironmentFileInjection}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString}},
	FindingKinds: fileKinds(textOutputClobberingControlled, textOutputClobberingWiki, fileOutputBase,
		metric(lint.ExploitMaturityProofOfConcept, "GitHub Security Lab showed a working attack on a reusable workflow of ipdxco/unified-github-workflows called on pull_request_target (GHSL-2026-229): a step read a version from the file version.json of a pull request and wrote the version to $GITHUB_OUTPUT, a line break in the version replaced the value of another output of the step, and a later step ran the replaced output as the script of sed. The version came through a variable that the script sets, which this rule does not follow (the undetected form script-var). An issue of oorabona/docker-containers (#1549) describes the same form", ghsl2026229)),
	Threat: lint.Threat{
		Actors:        injectionActors([]lint.Gain{lint.GainSetOutputs}),
		Preconditions: []lint.Precondition{runnerReadsLinesPre, attackerWritesLinesPre, attackerEventPre, callersEventsPre, wikiOpenPre, wikiTitleLinesPre, appStatusCheckPre},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FixKinds:  []lint.FixKind{stepFixKinds[1]},
	UndetectedForms: withRemoteCallee(append(slices.Clone(fileLimits), fileContentLimit("$GITHUB_OUTPUT"), forkReviewLimit, lint.UndetectedForm{ID: lint.MustUndetectedFormID("github-env"), Text: "a value written to $GITHUB_ENV", Disposition: lint.OtherRule(EnvvarInjectionID)}, insiderAssociationLimit, splitEnvNameLimit, wikiSummaryLimit,
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("log-command"), Text: "a value an attacker controls that a step prints to its log, with ##[set-output name=…;] anywhere in a line: the runner reads the line as set-output, which needs no ACTIONS_ALLOW_UNSECURE_COMMANDS, and sets an output of the step; the rule reads what the step writes to $GITHUB_OUTPUT", Disposition: lint.OtherRule(SetOutputInjectionID)})),
	InconclusiveKinds:  withRemoteCalleeUnknown(withCallBodyUnknown(fileGaps)),
	FalsePositiveForms: withNamedCaller(append(append(injectionFalsePositives(kindOutputClobberingControlled, kindOutputClobberingWiki), fileCommandFalsePositives(kindOutputClobberingControlled)...), reassignedEnvFalsePositive("$GITHUB_OUTPUT", "X=safe; echo \"a=$X\" >> \"$GITHUB_OUTPUT\"", kindOutputClobberingControlled), backgroundWriteFalsePositive("$GITHUB_OUTPUT", "(sleep 5; echo \"a=$X\" >> \"$GITHUB_OUTPUT\") &", kindOutputClobberingControlled, kindOutputClobberingWiki), unreadOutputs("output-clobbering also reports a step with no id, and the runner sets no output of such a step, so such a step is of this form", kindOutputClobberingControlled, kindOutputClobberingWiki)), kindOutputClobberingControlled, kindOutputClobberingWiki),
}

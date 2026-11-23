package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// Cond is the quality rule cond: an if that GitHub reads as a string, text
// and ${{ }} together, which is true whatever its expressions give. The harm of
// such an if that guards a job from an attacker is the security rules',
// which read it as true in an attacker run; this rule says why the if does
// not guard.
var Cond lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.CondReader](cond{}, ir.CondView))

// CondID is the ID of cond.
var CondID = lint.MustRuleID("cond")

type cond struct{}

func (cond) QualityMeta() lint.QualityMeta { return condMeta }

func (cond) Check(_ context.Context, c *lint.RuleContext, v ir.CondReader) error {
	for _, m := range v.MixedIfs() {
		c.Report(lint.FindingDraft{Location: c.At(m.At()), Args: CondMixedText{Condition: m.Condition(), StatusFunctions: m.StatusFunctions()}})
	}
	return nil
}

// githubDocs is the version of github/docs that the validity rules were
// checked against.
const githubDocs = "https://github.com/github/docs/blob/44a609d0382839fdfe455de859774cfebb7f2d83/"

// runnerValidity is the version of actions/runner that the validity rules
// were checked against.
const runnerValidity = "https://github.com/actions/runner/blob/v2.337.0/"

var condMeta = lint.QualityMeta{
	ID:       CondID,
	Problem:  "an if has text outside its ${{ }} (white space counts as text in an action.yml, not in a workflow), or more than one ${{ }}, and GitHub reads such an if as a string, which is true whatever the expressions in the if give",
	Expected: "every if of a job or a step is one ${{ }}, with at most white space around the ${{ }} in a workflow and nothing around the ${{ }} in an action.yml, or a condition written without ${{ }}, in a workflow and in an action.yml",
	Citations: []lint.Citation{
		lint.MustCitation(githubDocs + "content/actions/reference/workflows-and-actions/workflow-syntax.md"),
		lint.MustCitation(runnerValidity + "src/Sdk/WorkflowParser/Conversion/WorkflowTemplateConverter.cs"),
	},
	Targets:         []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(nil),
	FindingKinds:    []lint.QualityFindingKind{{FindingText: textCondMixedText}},
}

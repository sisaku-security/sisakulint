package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// DependencyReviewSettings is the quality rule dependency-review-settings:
// settings of actions/dependency-review-action that turn off what the step
// checks, or ask for a comment its token cannot write. The settings
// whose defaults are the strictest (fail-on-severity), and the counts of
// exceptions, are not reported.
var DependencyReviewSettings lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.DependencyReviewSettingsReader](dependencyReviewSettings{}, ir.DependencyReviewSettingsView))

// DependencyReviewSettingsID is the ID of dependency-review-settings.
var DependencyReviewSettingsID = lint.MustRuleID("dependency-review-settings")

type dependencyReviewSettings struct{}

func (dependencyReviewSettings) QualityMeta() lint.QualityMeta { return dependencyReviewSettingsMeta }

func (dependencyReviewSettings) Check(_ context.Context, c *lint.RuleContext, v ir.DependencyReviewSettingsReader) error {
	for _, s := range v.DependencyReviewSteps() {
		if s.WarnOnly() == analysis.ActionBooleanTrue {
			c.Report(lint.FindingDraft{Location: c.At(s.WarnOnlyAt()), Args: DependencyReviewSettingsWarnOnly{}})
		}
		if s.VulnerabilityCheck() == analysis.ActionBooleanFalse {
			c.Report(lint.FindingDraft{Location: c.At(s.VulnerabilityCheckAt()), Args: DependencyReviewSettingsVulnerabilityCheckOff{}})
		}
		if s.LicenseCheck() == analysis.ActionBooleanFalse && s.LicensePolicy() {
			c.Report(lint.FindingDraft{Location: c.At(s.LicenseCheckAt()), Args: DependencyReviewSettingsLicensePolicyOff{}})
		}
		if !s.CommentRequested() {
			continue
		}
		switch s.PullRequestsWrite() {
		case analysis.PullRequestsWriteNo:
			c.Report(lint.FindingDraft{Location: c.At(s.CommentAt()), Args: DependencyReviewSettingsCommentWithoutPermission{}})
		case analysis.PullRequestsWriteUnwritten:
			c.Report(lint.FindingDraft{Location: c.At(s.CommentAt()), Args: DependencyReviewSettingsCommentWithoutPermission{},
				Condition: factCond(facts.RepoDefaultTokenWrite{Repo: c.Repo()}, false)})
		}
	}
	return nil
}

// dependencyReviewSource is the commit of actions/dependency-review-action
// that the rule was checked against.
const dependencyReviewSource = "https://github.com/actions/dependency-review-action/blob/2f920dad77d7f4f2ea876b66287b896de40dda79/"

var dependencyReviewSettingsMeta = lint.QualityMeta{
	ID:       DependencyReviewSettingsID,
	Problem:  "a step of actions/dependency-review-action turns off a check of the action, or asks for a pull request comment that the GITHUB_TOKEN of the job cannot write",
	Expected: "the step checks vulnerabilities and the license policy written for the step, fails when a check finds a problem, and asks for a comment only when the job has pull-requests: write",
	Citations: []lint.Citation{
		lint.MustCitation(dependencyReviewSource + "action.yml"),
		lint.MustCitation(dependencyReviewSource + "src/schemas.ts"),
		lint.MustCitation(dependencyReviewSource + "src/config.ts"),
		lint.MustCitation(dependencyReviewSource + "src/comment-pr.ts"),
	},
	Targets: []lint.InputKind{lint.InputKindWorkflow},
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textDependencyReviewSettingsCommentWithoutPermission, FactKinds: []facts.Kind{facts.KindRepoDefaultTokenWrite}},
		{FindingText: textDependencyReviewSettingsLicensePolicyOff},
		{FindingText: textDependencyReviewSettingsVulnerabilityCheckOff},
		{FindingText: textDependencyReviewSettingsWarnOnly},
	},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("config-file"), Text: "a setting written in the file that config-file names; the with of the step overrides the file, and the rule does not read the file", Disposition: lint.Todo(lint.NeedRepoFile, lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("expression-value"), Text: "a value of the with written as a ${{ }}, whose result is known only when the workflow runs", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("fork-pull-request"), Text: "a comment asked for with pull-requests: write, in the run of a pull request from a fork; GitHub can give such a run a GITHUB_TOKEN that only reads, and then the step cannot write the comment", Disposition: lint.Todo(lint.NeedFact)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("old-version"), Text: "a version of the action that does not read the input: warn-only before v4.1.0, comment-summary-in-pr before v3.0.4, vulnerability-check and license-check before v3.0.0",
			FindingKinds: []lint.FindingKindID{kindDependencyReviewSettingsCommentWithoutPermission, kindDependencyReviewSettingsLicensePolicyOff, kindDependencyReviewSettingsVulnerabilityCheckOff, kindDependencyReviewSettingsWarnOnly},
			Disposition:  lint.Todo(lint.NeedFact)},
	},
}

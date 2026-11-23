package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// MissingTimeoutMinutes is the quality rule missing-timeout-minutes: a job
// on a runner without timeout-minutes, which runs for 360 minutes when it
// hangs.
// A step is not reported: the job's timeout stops it.
var MissingTimeoutMinutes lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.MissingTimeoutMinutesReader](missingTimeoutMinutes{}, ir.MissingTimeoutMinutesView))

// MissingTimeoutMinutesID is the ID of missing-timeout-minutes.
var MissingTimeoutMinutesID = lint.MustRuleID("missing-timeout-minutes")

type missingTimeoutMinutes struct{}

func (missingTimeoutMinutes) QualityMeta() lint.QualityMeta { return missingTimeoutMinutesMeta }

func (missingTimeoutMinutes) Check(_ context.Context, c *lint.RuleContext, v ir.MissingTimeoutMinutesReader) error {
	for _, j := range v.JobTimeouts() {
		if !j.Written() {
			c.Report(lint.FindingDraft{Location: c.At(j.At()), Args: MissingTimeoutMinutesJob{Job: j.Job()}})
		}
	}
	return nil
}

var missingTimeoutMinutesMeta = lint.QualityMeta{
	ID:       MissingTimeoutMinutesID,
	Problem:  "a job on a runner writes no timeout-minutes, so a job that stops making progress runs for 360 minutes before GitHub cancels the job",
	Expected: "every job on a runner writes timeout-minutes",
	Citations: []lint.Citation{
		lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idtimeout-minutes"),
		lint.MustCitation("https://docs.github.com/en/actions/reference/limits"),
	},
	Targets:         []lint.InputKind{lint.InputKindWorkflow},
	UndetectedForms: withRemoteCallee(nil),
	FindingKinds:    []lint.QualityFindingKind{{FindingText: textMissingTimeoutMinutesJob}},
	// Writing no timeout-minutes is a choice of operation, not a defect: the
	// default of 360 minutes does for many repositories, so the rule runs
	// for those whose policy asks for a timeout, as upstream's did.
	DefaultRun: lint.DefaultRunNamed(),
}

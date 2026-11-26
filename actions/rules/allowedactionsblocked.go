package rules

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// The setting of allowed actions of GitHub can stop a run before any job
// starts, or fail a job before any step runs: a uses that the setting does
// not allow, or a uses of an action by a tag where the setting requires a
// full commit SHA (the quality rule allowed-actions). A finding whose
// consequence needs the run or the job to run is then a false positive,
// which each rule declares by withAllowedActionsBlocked; the rules do not
// read repo.allowed-actions.

var actionsNotAllowed = lint.MustFalsePositiveFormID("actions-not-allowed")

const actionsNotAllowedText = "a workflow whose run GitHub does not start, or a job that GitHub fails in the step \"Set up job\", because of the setting of allowed actions of GitHub (the fact repo.allowed-actions, which the quality rule allowed-actions reads): GitHub does not start a run of a workflow that has a uses, or that calls a reusable workflow that has a uses, that the setting does not allow, and fails a job before any step of the job runs when a step of a composite action that the job runs has a uses that the setting does not allow, or when the setting requires a full commit SHA and a step names an action by a tag or a branch. The harm that the finding reports happens only when GitHub runs the workflow or the job, and the rule does not read repo.allowed-actions"

// runIndependentKinds are the kinds whose consequence does not need a run
// of the workflow: a password written in the file is read from the file,
// and a password kept in a configuration variable is read from the REST API.
var runIndependentKinds = []lint.FindingKindID{kindCredentialsPublic, kindCredentialsPrivate, kindCredentialsConfigurationVariable}

// withAllowedActionsBlocked is m with the false positive form
// actions-not-allowed of each kind of m but runIndependentKinds; m itself
// when no kind is left.
func withAllowedActionsBlocked(m lint.Meta) lint.Meta {
	var kinds []lint.FindingKindID
	for _, k := range m.FindingKinds {
		if !slices.Contains(runIndependentKinds, k.ID) {
			kinds = append(kinds, k.ID)
		}
	}
	if len(kinds) == 0 {
		return m
	}
	m.FalsePositiveForms = append(slices.Clip(m.FalsePositiveForms),
		lint.FalsePositiveForm{ID: actionsNotAllowed, Text: actionsNotAllowedText, FindingKinds: kinds, Disposition: lint.Todo(lint.NeedFact)})
	return m
}

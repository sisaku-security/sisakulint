package rules

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// withRemoteCallee is fs and lint.RemoteCalleeForm, which each rule that
// reads workflows declares: the engine runs the rule on a reusable
// workflow of another repository only when workflow.definition answers it.
func withRemoteCallee(fs []lint.UndetectedForm) []lint.UndetectedForm {
	return append(slices.Clone(fs), lint.RemoteCalleeForm)
}

// withRemoteCalleeUnknown is ks and lint.RemoteCalleeUnknownKind, which each
// rule that reads workflows and is not a quality rule declares: the engine
// reports one at the uses of a job whose reusable workflow of another
// repository was asked of workflow.definition and has no answer.
func withRemoteCalleeUnknown(ks []lint.InconclusiveKind) []lint.InconclusiveKind {
	return append(slices.Clone(ks), lint.RemoteCalleeUnknownKind)
}

// callBodyUnknownKind is the kind of inconclusive place of the rules that
// read a run through the readings of shell that follow calls of functions
// up to a limit (shell.CallsNotRead): the first call whose body a reading
// did not read.
var callBodyUnknownKind = lint.InconclusiveKind{ID: lint.MustInconclusiveKindID("call-body-unknown"),
	Text:        "a call of a function after the rule has read the bodies of the functions at 4,096 calls in the script, such as a call after a chain of functions in which each function calls the next function twice (f1() { f0; f0; }; ... f13() { f12; f12; }; f13; w): the rule does not read the bodies of the functions at the calls past the 4,096 calls, so the rule does not decide the assignments, the writes, the prints and the requests in the bodies of the functions at the calls past the 4,096 calls",
	Disposition: lint.Todo(lint.NeedSameFile)}

// withCallBodyUnknown is ks with callBodyUnknownKind.
func withCallBodyUnknown(ks []lint.InconclusiveKind) []lint.InconclusiveKind {
	return append(slices.Clone(ks), callBodyUnknownKind)
}

// reportCallsNotRead reports, of a run, the first call whose body the
// readings of the run did not read past their limit of calls.
func reportCallsNotRead(c *lint.RuleContext, calls []ir.CallsNotRead) {
	for _, n := range calls {
		c.Inconclusive(lint.InconclusiveDraft{KindID: callBodyUnknownKind.ID, Location: c.At(n.At),
			Note: "the rule does not read the bodies of the functions at this call and at the calls after this call, as the rule has read the bodies of the functions at 4,096 calls in the script"})
	}
}

// remoteCompositeStepsLimit is the undetected form remote-composite-steps:
// what, in a step of a composite action of another repository, which the
// rule does not read even when action.definition gives the action.yml.
// note, when not empty, follows as a sentence of its own.
func remoteCompositeStepsLimit(what, note string) lint.UndetectedForm {
	text := what + ", in a step inside the action.yml of a composite action of another repository that a uses names (owner/repo@ref or owner/repo/path@ref; a step of that composite action, not the uses that names the composite action): the rule does not read the steps of a composite action of another repository, even when the fact action.definition gives the action.yml"
	if note != "" {
		text += ". " + note
	}
	return lint.UndetectedForm{ID: lint.MustUndetectedFormID("remote-composite-steps"), Text: text, Disposition: lint.Todo(lint.NeedFact)}
}

// checkedOutLocalLimits are the undetected forms checked-out-local and
// checked-out-local-moving: what, in a step inside the action.yml of a
// local action (./) whose directory a checkout of another repository
// filled, which is not a file that the linter reads. The first is a
// checkout at a full commit SHA, whose commit decides the action.yml; the
// second a checkout at a branch, a tag, the default branch or a ${{ }},
// whose commit is decided when the job runs.
func checkedOutLocalLimits(what string) []lint.UndetectedForm {
	const where = ", in a step inside the action.yml of a composite action that a uses names by a path that starts with ./, when an earlier step of the job checks out another repository into the workspace (actions/checkout with repository: of another repository) "
	const callee = ": the action.yml is a file of the repository that the step checks out, and the linter reads only the files of the repository of the workflow. A ./ uses in a step of a reusable workflow of another repository also names the workspace of the job: by default, actions/checkout in the reusable workflow checks out the repository of the calling workflow, not the repository of the reusable workflow, so the ./ uses names an action.yml of the repository of the calling workflow, which the linter reads when the files of the repository of the calling workflow are given to the linter"
	return []lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("checked-out-local"), Text: what + where + "at a full commit SHA" + callee + ". The commit decides the action.yml, and the linter does not ask action.definition for the action", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("checked-out-local-moving"), Text: what + where + "at a branch, at a tag, at the default branch (no ref:) or at a ref given by a ${{ }}" + callee + ". The commit that the checkout reads, and so the action.yml, is decided when the job runs", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}
}

// namedCallerEventsForm is the false positive form, of kinds, of a reusable
// workflow that a workflow of the same repository calls by its name
// (owner/repo/.github/workflows/<file>@<ref>) on events that no attacker
// triggers: the call by the name is not resolved to the file, so the rules
// that read the events of the callers read the reusable workflow on every
// event.
func namedCallerEventsForm(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("named-caller-events"), Text: "a reusable workflow that a workflow of the same repository calls only on events that no attacker of the finding kind triggers, such as push, by the name owner/repo/.github/workflows/<file>@<ref> of the repository (the repository that --repo names) instead of the path ./.github/workflows/<file>: the rule does not resolve the call by the name to the file, so the rule reads the reusable workflow on every event", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)}
}

// withNamedCaller is fs and the form named-caller-events of kinds.
func withNamedCaller(fs []lint.FalsePositiveForm, kinds ...lint.FindingKindID) []lint.FalsePositiveForm {
	return append(slices.Clip(fs), namedCallerEventsForm(kinds...))
}

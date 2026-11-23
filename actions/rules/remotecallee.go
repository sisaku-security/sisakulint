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

// withCallee is fs and the form callee of kinds (calleeFalsePositive),
// which each rule that reads the events of the callers of a reusable
// workflow or a composite action declares (the precondition callers-events).
func withCallee(fs []lint.FalsePositiveForm, kinds ...lint.FindingKindID) []lint.FalsePositiveForm {
	return append(slices.Clip(fs), calleeFalsePositive(kinds...))
}

// calleeFalsePositive is the false positive form callee, of kinds: a rule
// may read a reusable workflow or a composite action on every event when
// the rule does not know all of the callers, on its own path or on the path
// of a caller of a caller (taint.Callers, calls.Graph.Coverage), and the
// form is a reusable workflow or a composite action for which reading on
// the events of the workflows that run it in the same repository would give
// no finding of kinds. withCallee is the one place that declares it.
func calleeFalsePositive(kinds ...lint.FindingKindID) lint.FalsePositiveForm {
	return lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("callee"), Text: "a reusable workflow or a composite action when all of the following are true: the rule does not know all of the callers of the reusable workflow or the composite action; every workflow that runs the reusable workflow or the composite action (directly, or through another reusable workflow or composite action) is a workflow in the same repository; and the rule would report no finding of the finding kind if the rule read the reusable workflow or the composite action only on the events on which the workflows in the same repository run the reusable workflow or the composite action (for example, every workflow that runs the reusable workflow or the composite action runs only on push). When the rule does not know all of the callers, the rule can read the reusable workflow or the composite action on every event (the worst case). For example, the rule does not know all of the callers when no caller is among the inputs; when the inputs are not the whole repository; for a composite action, when an input is excluded or cannot be read; when a caller names the reusable workflow or the composite action by a name of the form owner/repo/path@ref instead of by a ./ path, in which owner/repo is the repository that the --repo flag names, or is any repository when no --repo flag is given; when a step names the composite action by a ./ path, and either no checkout step runs before that step or the last checkout step before that step is not a plain checkout step (a plain checkout step has no ref input, no repository input and no path input); when a step inside a composite action names another composite action by a ./ path; or when the rule does not know all of the callers of a caller", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedRepoFile)}
}

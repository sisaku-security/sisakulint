package rules

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// The labeled runs of the rules that read pull_request_target on labeled
// as an approval, when a workflow of the same repository runs
// actions/labeler on an attacker's pull request with a token other than
// the GITHUB_TOKEN (actions/labeler): a label the attacker gets that way
// approves nothing that a person read.

// labelerAddedLabel is what the declarations below say of a label that a
// workflow adds, and labeledJob of the job that the label starts.
const (
	labelerAddedLabel = "a label that a workflow of the repository of the job adds to the pull request of an attacker by running actions/labeler with a token other than the GITHUB_TOKEN"
	labeledJob        = "a job on pull_request_target with the activity type labeled, where the run of the job starts when a workflow of the repository of the job adds a label to the pull request of an attacker by running actions/labeler with a token other than the GITHUB_TOKEN (a label that a step adds with a token other than the GITHUB_TOKEN starts a run with the activity type labeled)"
)

var (
	triggerWorkflow = lint.MustCitation("https://github.com/github/docs/blob/481d4e35beb53953e277d0b11ba4a18f8c8ade4f/content/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow.md")
	labelerConfigs  = lint.MustCitation("https://github.com/actions/labeler/blob/bf12e9b00b37c5c0ca2b87b79b2daf7891dbda13/src/api/get-label-configs.ts")

	labelPaths      = lint.MustInconclusiveKindID("label-paths")
	labelBaseBranch = lint.MustInconclusiveKindID("label-base-branch")
	labelSet        = lint.MustInconclusiveKindID("label-set")
	labelerUnknown  = lint.MustInconclusiveKindID("labeler-unknown")

	// automaticLabelKinds are the inconclusive kinds of an automatic label
	// that leaves the approval undecided.
	automaticLabelKinds = []lint.InconclusiveKind{
		{ID: labelPaths, Text: labeledJob + ", where actions/labeler adds the label only when every file that the pull request changes matches globs of the configuration of actions/labeler: the rule does not read whether the job runs code from the files under the globs", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: labelBaseBranch, Text: labeledJob + ", where actions/labeler adds the label only when the name of the base branch of the pull request matches the configuration of actions/labeler: the attacker chooses the base branch among the branches of the repository, and the linter does not know the branches of the repository", Disposition: lint.Todo(lint.NeedFact)},
		{ID: labelSet, Text: labeledJob + ", where the if of the job requires both the label that starts the run and another label, and one run of actions/labeler adds both labels: GitHub's documents do not say, and the authors of the rule did not observe, whether the labels of the pull request in the payload of the labeled run include the other label", Disposition: lint.Todo(lint.NeedFact)},
		{ID: labelerUnknown, Text: labeledJob + ", where the linter does not know at least one of the following: the release of actions/labeler; the path or the syntax of the configuration of actions/labeler; the pull request that actions/labeler labels; the source of the token of actions/labeler; whether a step of actions/checkout before the step of actions/labeler checks out the code of the pull request of the attacker; whether the step of actions/checkout runs; whether the step of actions/checkout fails and stops the job; when the if of the step of actions/labeler is true only when a step that runs before the step of actions/labeler, in the job that runs actions/labeler, has failed or the run of the workflow that runs actions/labeler is cancelled (for example, if: failure()), whether the attacker can make a step that runs before the step of actions/labeler fail, or can make the run of the workflow that runs actions/labeler cancelled; when the if of the job that runs actions/labeler, or the if of a job that the job that runs actions/labeler depends on through the needs key (directly or through other jobs), is true only when a job that the job with the if depends on through the needs key has not succeeded or the run of the workflow that runs actions/labeler is cancelled (for example, if: failure()), whether the attacker can make a job that the job with the if depends on through the needs key fail, be skipped, or be cancelled, or can make the run of the workflow that runs actions/labeler cancelled; or, when the step of actions/labeler has an if that runs the step of actions/labeler only in a cancelled run, such as cancelled(), whether the attacker can make the run of the workflow that runs actions/labeler cancelled", Disposition: lint.Todo(lint.NeedSameFile)},
	}

	// The forms of a label that a bot adds from what an attacker wrote and
	// that the rules do not read.
	scriptLabelLimit        = lint.UndetectedForm{ID: lint.MustUndetectedFormID("script-label"), Text: "a label that a workflow of the same repository adds from what an attacker wrote, with a token other than the GITHUB_TOKEN, by a script (gh pr edit --add-label, the labels endpoint of the REST API through gh api, addLabels of actions/github-script) or by an action other than actions/labeler: the label is on the pull request or the issue of the attacker, and the rule does not read the scripts and the actions that add labels", Disposition: lint.Todo(lint.NeedRepoFile)}
	outsideBotLabelLimit    = lint.UndetectedForm{ID: lint.MustUndetectedFormID("outside-bot-label"), Text: "a label that a bot outside the repository adds, such as a bot that adds a label for a command in a comment: the settings of the bot are outside the repository, and the rule does not read whether the bot adds the label for a comment of any user", Disposition: lint.Todo(lint.NeedFact)}
	labelerPullRequestLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("labeler-pull-request"), Text: "actions/labeler in a workflow on pull_request with a token other than the GITHUB_TOKEN: a run on the event pull_request for a pull request from a fork gets the secret of the token only when a private repository sends secrets to the runs of pull requests from forks (repo.fork-pr-secrets), and the rule does not read the workflows on pull_request that add labels", Disposition: lint.Todo(lint.NeedFact)}
	labelerOtherEventLimit  = lint.UndetectedForm{ID: lint.MustUndetectedFormID("labeler-other-event"), Text: "actions/labeler in a workflow on an event that is not an event of a pull request (workflow_run, schedule), with the number of a pull request in pr-number: the step that finds the number of the pull request and gives the number to pr-number decides which pull request actions/labeler labels, and the rule does not read the step that finds the number", Disposition: lint.Todo(lint.NeedSameFile)}
	labelerNotInputLimit    = lint.UndetectedForm{ID: lint.MustUndetectedFormID("labeler-not-input"), Text: "an execution of the linter on a list of files, not on the whole repository: the rule does not read the workflows that are not in the list, and so does not read a step of actions/labeler in a workflow that is not in the list", Disposition: lint.Todo(lint.NeedRepoFile)}

	automaticLabelForms = []lint.UndetectedForm{scriptLabelLimit, outsideBotLabelLimit, labelerPullRequestLimit, labelerOtherEventLimit, labelerNotInputLimit}
)

// automaticLabelFalsePositives are the false positive forms of an
// automatic label, for the finding kinds of a rule.
func automaticLabelFalsePositives(kinds ...lint.FindingKindID) []lint.FalsePositiveForm {
	return []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("unmatchable-pattern"), Text: "a label of the configuration of actions/labeler whose globs or regular expressions match no path or no branch name, such as the glob pages/** together with the negated glob !pages/**: the rule reads each glob and each regular expression as one that a pull request can match", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("labeled-actor-if"), Text: "an if that compares the actor or the sender of the labeled run with a name or a type, such as github.event.sender.login == 'release-bot' or github.event.sender.type != 'Bot': the actor of a labeled run whose label actions/labeler adds is the account or the app of the token of actions/labeler, the linter does not know the name or the type of the actor, and the rule reads the if as one that the labeled run passes", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedFact)},
		// GitHub skips a job after a skipped or failed job in the chain of
		// needs, also after a job whose if calls a status function: "If a run contains a
		// series of jobs that need each other, a failure or skip applies to
		// all jobs in the dependency chain from the point of failure or skip
		// onwards." (line 1 of
		// https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/data/reusables/actions/jobs/section-using-jobs-in-a-workflow-needs.md),
		// as observed in https://github.com/actions/runner/issues/2205.
		{ID: lint.MustFalsePositiveFormID("labeler-skipped-need"), Text: "a job whose if calls no status function, that runs actions/labeler or waits for the label that actions/labeler adds (on the activity type labeled, in the job itself or in a job of a reusable workflow that the job calls), and that depends through the needs key on a job whose if calls a status function (for example, if: always()), where the job whose if calls a status function depends through the needs key, directly or through other jobs, on a job that GitHub skips, or that fails, in the run on the pull request of the attacker. GitHub applies a failure or a skip to every job after the skipped or failed job in the chain of the needs key, also after the job whose if calls a status function, so GitHub skips the job that runs actions/labeler or waits for the label, and the step of actions/labeler in a skipped job adds no label. The rule reads the ifs of the chain of the needs key only up to the job whose if calls a status function, and reads the job that runs actions/labeler or waits for the label as a job that runs.", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)},
		// observed on 2026-11-16 on ubuntu-latest: the code that sudo -u nobody
		// runs cannot send a signal to sudo or to the shell of the step
		// ("kill: Operation not permitted"), and the step with || true
		// succeeds.
		{ID: lint.MustFalsePositiveFormID("labeler-other-user"), Text: "a step of actions/labeler whose if is true only when a step before the step of actions/labeler has failed (for example, if: failure()), after a step that has no timeout-minutes and that runs the code of the pull request of the attacker as a user that is neither root nor the user of the shell of the step (for example, sudo -u nobody, or su nobody -c), where a failure of the code does not end the step (for example, the left of || true, or the condition of an if statement of the shell script). The code of the attacker runs as a user that is not the user of the shell of the step, so the code of the attacker cannot stop the shell of the step by a signal, and the step does not fail. The rule reads the step that runs the code of the attacker as a step that the attacker can make fail, so the rule reads the step of actions/labeler as a step that runs after a failure.", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("label-combination"), Text: "a label that actions/labeler adds only together with another label whose presence makes the if of the job false, such as a label blocked that the if excludes with !contains(github.event.pull_request.labels.*.name, 'blocked') and that actions/labeler adds on the same condition as the label that the job waits for; or a label that actions/labeler does not add, because the labels that actions/labeler would add together with the label are more than changed-files-labels-limit allows: the rule evaluates the if with the one label that the job waits for", FindingKinds: kinds, Disposition: lint.Todo(lint.NeedSameFile)},
	}
}

var automaticLabelInconclusive = map[analysis.AutomaticLabel]lint.InconclusiveKindID{
	analysis.AutomaticLabelPaths:      labelPaths,
	analysis.AutomaticLabelBaseBranch: labelBaseBranch,
	analysis.AutomaticLabelLabelSet:   labelSet,
	analysis.AutomaticLabelUnknown:    labelerUnknown,
}

// freeLabel is whether the attacker gets into the labeled runs with any
// files of their choice, reporting nothing: the attacker of the run adds
// a label themselves (analysis.BarrierLabelApproval), or a lets them in.
func freeLabel(c *lint.RuleContext, a ir.AutomaticApproval) bool {
	return c.Barriers().Passes(analysis.BarrierLabelApproval) || slices.Contains(a.AutomaticLabels, analysis.AutomaticLabelFree)
}

// automaticLabelFree is whether the attacker gets into the labeled runs
// with any files of their choice: the attacker of the run adds a label
// themselves, or a lets them in. When a leaves the approval undecided, it
// reports at at, on what (a noun phrase that names the job or the step,
// such as "the job" or what stepRef makes), one inconclusive place of each
// kind, and is false. The related places of each are related, the places
// of the finding that a free label would give other than at, and the step
// of actions/labeler.
func automaticLabelFree(c *lint.RuleContext, a ir.AutomaticApproval, at ir.Handle, what string, related []lint.Related) bool {
	if freeLabel(c, a) {
		return true
	}
	related = append(slices.Clone(related), undecidedLabelerRelated(c, a)...)
	for _, l := range a.AutomaticLabels {
		c.Inconclusive(lint.InconclusiveDraft{KindID: automaticLabelInconclusive[l], Location: c.At(at), Related: related,
			Note: what + " runs in a run of pull_request_target with the activity type labeled, and the step of actions/labeler in " + a.At.InputName() + " adds " + labelRef(a) + "; " + undecidedWhy[l]})
	}
	return false
}

// undecidedLabelerRelated is the step of actions/labeler of a, for an
// inconclusive place of a label that a leaves undecided; none when a has
// no step of actions/labeler.
func undecidedLabelerRelated(c *lint.RuleContext, a ir.AutomaticApproval) []lint.Related {
	if len(a.AutomaticLabels) == 0 {
		return nil
	}
	return []lint.Related{{Location: c.At(a.At), Note: "the step of actions/labeler that may add " + labelRef(a) + " to the pull request"}}
}

// stepRef names, for the note of an inconclusive place, the step that runs
// the action of the uses text uses.
func stepRef(uses string) string { return "the step that runs " + uses }

// undecidedWhy is, for each automatic label that leaves the approval
// undecided, why the rule does not decide the approval.
var undecidedWhy = map[analysis.AutomaticLabel]string{
	analysis.AutomaticLabelPaths:      "the configuration adds the label only when every file that the pull request changes matches globs",
	analysis.AutomaticLabelBaseBranch: "the configuration adds the label only when the name of the base branch of the pull request matches the configuration",
	analysis.AutomaticLabelLabelSet:   "the configuration adds the label together with another label, and the if of the job requires both labels",
	analysis.AutomaticLabelUnknown:    "the linter does not know at least one of the following: the release of actions/labeler; the configuration of actions/labeler; the pull request that actions/labeler labels; the source of the token of actions/labeler; whether a step of actions/checkout before actions/labeler checks out the code of the pull request of the attacker; whether the step of actions/checkout runs; whether the step of actions/checkout fails and stops the job; when the if of the step of actions/labeler is true only when a step that runs before the step of actions/labeler, in the job that runs actions/labeler, has failed or the run of the workflow that runs actions/labeler is cancelled (for example, if: failure()), whether the attacker can make a step that runs before the step of actions/labeler fail, or can make the run of the workflow that runs actions/labeler cancelled; when the if of the job that runs actions/labeler, or the if of a job that the job that runs actions/labeler depends on through the needs key (directly or through other jobs), is true only when a job that the job with the if depends on through the needs key has not succeeded or the run of the workflow that runs actions/labeler is cancelled (for example, if: failure()), whether the attacker can make a job that the job with the if depends on through the needs key fail, be skipped, or be cancelled, or can make the run of the workflow that runs actions/labeler cancelled; or, when the step of actions/labeler has an if that runs the step of actions/labeler only in a cancelled run, such as cancelled(), whether the attacker can make the run of the workflow that runs actions/labeler cancelled",
}

// labelRef names the labels of a, or the label that the job waits for when
// the labels are not known.
func labelRef(a ir.AutomaticApproval) string {
	if len(a.LabelNames) == 0 {
		return "the label that the if of the job requires"
	}
	return "the label " + labelNames(a)
}

// labelNames are the labels of a, joined by commas.
func labelNames(a ir.AutomaticApproval) string {
	names := make([]string, len(a.LabelNames))
	for i, n := range a.LabelNames {
		names[i] = n.String()
	}
	return strings.Join(names, ", ")
}

// automaticLabelRelated is the step of actions/labeler of a, for a
// finding; none when no step of actions/labeler lets the attacker in (the
// attacker of the run adds the label themselves).
func automaticLabelRelated(c *lint.RuleContext, a ir.AutomaticApproval) []lint.Related {
	if !slices.Contains(a.AutomaticLabels, analysis.AutomaticLabelFree) {
		return nil
	}
	return []lint.Related{{Location: c.At(a.At), Note: "the configuration of actions/labeler in this step adds " + labelRef(a) + ", with a token other than the GITHUB_TOKEN, to a pull request that the attacker opens from a fork"}}
}

// approvalCond is the condition of a finding on a run that approval
// approves (env, the environment of ApprovalEnvironment), and false for a
// run that a person approves: a label that auto does not let the attacker
// get freely, after which it reports at, on what, the undecided kinds,
// with related (automaticLabelFree).
func approvalCond(c *lint.RuleContext, approval analysis.Approval, env facts.EnvironmentName, auto ir.AutomaticApproval, at ir.Handle, what string, related []lint.Related) (*lint.Condition, bool) {
	switch approval {
	case analysis.ApprovalEnvironment:
		return environmentCond(c, approval, env), true
	case analysis.ApprovalLabel:
		if !automaticLabelFree(c, auto, at, what, related) {
			return nil, false
		}
		if auto.Environment != (facts.EnvironmentName{}) && !c.Barriers().Passes(analysis.BarrierLabelApproval) {
			return environmentCond(c, analysis.ApprovalEnvironment, auto.Environment), true
		}
	}
	return nil, true
}

// labelerRelated is the step of actions/labeler of auto when approval is a
// label, for a finding.
func labelerRelated(c *lint.RuleContext, approval analysis.Approval, auto ir.AutomaticApproval) []lint.Related {
	if approval != analysis.ApprovalLabel {
		return nil
	}
	return automaticLabelRelated(c, auto)
}

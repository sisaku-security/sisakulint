package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// AllowedActions is the quality rule allowed-actions: a uses of an action,
// a reusable workflow or a Docker image that the setting of allowed actions
// of GitHub (the fact repo.allowed-actions) does not allow, and a uses of an
// action by a tag or a branch where the setting requires a full commit SHA.
// GitHub does not start such a run, or fails such a job, so the code of the
// action never runs: no attacker gains, and the rule is a quality rule. The
// rule runs only where the setting has an answer (DefaultRunGivenFacts):
// --online answers it only with a token that may read the Actions settings
// of the repository, which the GITHUB_TOKEN of a run may not.
var AllowedActions lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.AllowedActionsReader](allowedActions{}, ir.AllowedActionsView))

// AllowedActionsID is the ID of allowed-actions.
var AllowedActionsID = lint.MustRuleID("allowed-actions")

type allowedActions struct{}

func (allowedActions) QualityMeta() lint.QualityMeta { return allowedActionsMeta }

func (allowedActions) Check(ctx context.Context, c *lint.RuleContext, v ir.AllowedActionsReader) error {
	q := facts.RepoAllowedActions{Repo: c.Repo()}
	a := q.Ask(ctx, c.Resolver)
	if a.State != facts.StateFound {
		return nil // Actions disabled, or no answer (list-unknown)
	}
	cond, err := lint.FactEq(q, a.Value)
	if err != nil {
		return err
	}
	setting := a.Value
	notAllowed := func(uses ...string) bool {
		for _, u := range uses {
			if setting.Allows(c.Repo(), u) == facts.AllowedActionsNotAllowed {
				return true
			}
		}
		return false
	}
	unpinned := func(ref string) bool {
		_, err := facts.ParseSHA(ref)
		return setting.PinningRequired() && err != nil
	}
	report := func(d lint.FindingDraft) {
		d.Condition = &cond
		c.Report(d)
	}
	// a uses of a step of an action.yml fails the job that runs the
	// composite action; a uses of a workflow or of a reusable workflow it
	// calls stops the run
	notAllowedArgs := func(uses string) lint.FindingArgs {
		if c.ActionMetadata() {
			return AllowedActionsFailedJob{Uses: uses}
		}
		return AllowedActionsUnstartedRun{Uses: uses}
	}
	for _, u := range v.Uses() {
		if notAllowed(u.RunUses()...) {
			report(lint.FindingDraft{Location: c.At(u.RefAt()), Args: notAllowedArgs(u.UsesText())})
		}
		// a step of a reusable workflow of another repository that a job
		// calls is not checked for its pin (remote-called-pinning)
		if u.Level() == ir.UsesInStep && !c.RemoteCalled() && unpinned(u.Ref()) {
			report(lint.FindingDraft{Location: c.At(u.RefAt()), Anchor: pinningAnchor, Args: AllowedActionsUnpinnedAction{Uses: u.UsesText()}})
		}
	}
	for _, s := range v.ImageSites() {
		if s.Site() != analysis.ImageSiteKindStep {
			continue // GitHub's setting does not check the container or the services of a job
		}
		if c.ActionMetadata() {
			continue // a docker:// step of a composite action (composite-image)
		}
		for _, img := range s.Images() {
			if uses := "docker://" + img.Text; notAllowed(uses) {
				report(lint.FindingDraft{Location: c.At(img.At), Args: notAllowedArgs(uses)})
			}
		}
	}
	// the steps of the composite actions of other repositories the steps
	// run (action.definition), at the uses of the input: GitHub checks them
	// with the setting of the repository of the run, and fails the job
	for _, call := range v.CompositeCalls() {
		for _, s := range call.Steps() {
			if s.Query == nil {
				continue // a step of an action.yml of the inputs is that input's
			}
			ev := []lint.Related{{Location: c.At(s.At), Note: "the step of the composite action " + s.Chain[len(s.Chain)-1].Uses + " whose uses the finding names"}}
			if notAllowed(s.RunUses...) {
				report(lint.FindingDraft{Location: c.At(call.At()), Anchor: placeAnchor(c, s.Chain, s.At), Args: AllowedActionsFailedJob{Uses: s.UsesText}, Evidence: ev})
			}
			if s.Repo != "" && unpinned(s.Ref) {
				report(lint.FindingDraft{Location: c.At(call.At()), Anchor: placeAnchor(c, s.Chain, s.At) + " " + pinningAnchor, Args: AllowedActionsUnpinnedAction{Uses: s.UsesText}, Evidence: ev})
			}
		}
	}
	return nil
}

// pinningAnchor tells an unpinned-action apart from the unstarted-run or
// the failed-job of the same uses, which has the same place.
const pinningAnchor = "sha_pinning_required"

// allowedActionsDocs is github/docs at the commit the rule cites
// (2026-11-03).
const allowedActionsDocs = "https://github.com/github/docs/blob/7fa55a0ac28d01b5cb6f9cbebff06fbee1e2408f/"

var (
	// the forms allowed-actions declares, beside those of action-list it
	// shares (list-unknown, remote-composite, outside-actions-directory,
	// self-outside, metadata-image)
	verifiedCreator       = lint.MustUndetectedFormID("verified-creator")
	ownerUnknown          = lint.MustFalsePositiveFormID("owner-unknown")
	lockfileTag           = lint.MustUndetectedFormID("lockfile-tag")
	sameEnterprise        = lint.MustFalsePositiveFormID("same-enterprise")
	lockfileSHA           = lint.MustFalsePositiveFormID("lockfile-sha")
	lockfilePinned        = lint.MustFalsePositiveFormID("lockfile-pinned")
	jobNeverRuns          = lint.MustFalsePositiveFormID("job-never-runs")
	compositeImage        = lint.MustUndetectedFormID("composite-image")
	remoteCalledPinning   = lint.MustUndetectedFormID("remote-called-pinning")
	otherRepositoryCaller = lint.MustFalsePositiveFormID("other-repository-caller")
)

var allowedActionsMeta = lint.QualityMeta{
	ID:       AllowedActionsID,
	Problem:  "a uses names an action, a reusable workflow or a Docker image that the setting of allowed actions of GitHub (the fact repo.allowed-actions) does not allow, or names an action by a tag or a branch where the setting requires a full commit SHA: GitHub does not start the run of a workflow that has a uses that the setting does not allow, and fails the job when a step of a composite action that the job runs has a uses that the setting does not allow, or when any step of the job names an action by a tag or a branch where the setting requires a full commit SHA",
	Expected: "every uses of another repository and every uses of a Docker image is one that the setting of allowed actions of GitHub allows, and, when the setting requires a full commit SHA, every uses of an action names a full commit SHA",
	Citations: []lint.Citation{
		lint.MustCitation(allowedActionsDocs + "data/reusables/actions/allow-specific-actions-intro.md"),
		lint.MustCitation(allowedActionsDocs + "data/reusables/actions/actions-use-policy-settings.md"),
		lint.MustCitation("https://docs.github.com/en/rest/actions/permissions#get-github-actions-permissions-for-a-repository"),
	},
	Targets:    []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	DefaultRun: lint.DefaultRunGivenFacts(facts.KindRepoAllowedActions),
	FindingKinds: []lint.QualityFindingKind{
		// unstarted-run first: the examples of remote-callee are made of
		// the first true positive (remoteSource), and a step of a reusable
		// workflow of another repository is not checked for its pin
		{FindingText: textAllowedActionsUnstartedRun, FactKinds: []facts.Kind{facts.KindRepoAllowedActions}},
		{FindingText: textAllowedActionsFailedJob, FactKinds: []facts.Kind{facts.KindRepoAllowedActions}},
		{FindingText: textAllowedActionsUnpinnedAction, FactKinds: []facts.Kind{facts.KindRepoAllowedActions}},
	},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: listUnknown, Text: "a run that names the rule with --rule but has no answer of repo.allowed-actions: the rule has no setting to compare the uses with, and reports nothing", Disposition: lint.Todo(lint.NeedFact)},
		{ID: verifiedCreator, Text: "a uses of an action that only the option of the setting for the verified creators of GitHub Marketplace (verified_allowed) could allow: the workflow does not say whether GitHub verified the creator of the action, so the rule does not report the uses", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnstartedRun, kindAllowedActionsFailedJob}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lockfileTag, Text: "a workflow that a dependency lockfile of the repository covers, and a uses by a tag that a pattern of the setting names by the same tag: GitHub compares a locked uses by the commit SHA of the lockfile, not by the tag, so the pattern does not allow the uses, and the rule, which does not read the lockfile, reads the uses as allowed", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnstartedRun, kindAllowedActionsFailedJob}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: remoteComposite, Text: "a uses inside the action.yml of a composite action of another repository when action.definition has no answer for the composite action: the rule reads the steps of a composite action of another repository only from the answer of the fact action.definition", Disposition: lint.Todo(lint.NeedFact)},
		{ID: outsideActionsDirectory, Text: "a uses whose path uses .. to name a directory above the directory where the runner puts the actions of the job (_actions): the directory that the path points to is decided when the job runs", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnstartedRun, kindAllowedActionsFailedJob}, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: selfOutside, Text: "a $/ uses whose path goes with .. above the root of the repository into the directory of another action, which runs the code of another repository: the rule does not compare such a uses with the setting", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnstartedRun, kindAllowedActionsFailedJob}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: compositeImage, Text: "a docker:// step of a composite action, of the repository or of another repository: the authors of the rule did not try whether the setting of allowed actions of GitHub checks the image of such a step, so the rule does not compare such an image with the setting. The authors of the rule saw that a docker:// step of a workflow by a tag runs when the setting requires a full commit SHA, but did not try a docker:// step of a composite action", Disposition: lint.Todo(lint.NeedFact)},
		{ID: remoteCalledPinning, Text: "a step, in a reusable workflow of another repository that a job calls, that names an action by a tag or a branch where the setting of allowed actions of GitHub requires a full commit SHA: the authors of the rule did not try whether GitHub requires the pin of such a step by the setting of the repository of the caller, so the rule does not report such a step as unpinned", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnpinnedAction}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: metadataImage, Text: "the runs.image (docker://) of the action metadata file of a Docker container action: the authors of the rule did not try whether the setting of allowed actions of GitHub checks the image that a Docker container action runs, so the rule does not compare the runs.image with the setting", Disposition: lint.Todo(lint.NeedFact)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: ownerUnknown, Text: "a run without --repo, and a uses of an action or a reusable workflow of another repository of the same owner: the setting allows each action and each reusable workflow of the same owner, and without the name of the repository the rule does not know the owner, so the rule reports the uses; pass --repo to the linter", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnstartedRun, kindAllowedActionsFailedJob}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: sameEnterprise, Text: "a repository of an organization of an enterprise of GitHub Enterprise Cloud, and a uses of a repository of another organization of the same enterprise: the setting allows each action of the enterprise, and the rule, which knows only the owner of the repository, reports the uses", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnstartedRun, kindAllowedActionsFailedJob}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lockfileSHA, Text: "a workflow that a dependency lockfile of the repository covers, and a uses by a tag, where a pattern of the setting names the commit SHA to which the lockfile locks the tag: GitHub compares a locked uses by the commit SHA of the lockfile, so the pattern allows the uses, and the rule, which does not read the lockfile, reports the uses", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnstartedRun, kindAllowedActionsFailedJob}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lockfilePinned, Text: "a workflow that a dependency lockfile of the repository covers, and a uses of an action by a tag or a branch that the lockfile locks, where the setting requires a full commit SHA: a locked uses satisfies the requirement of a full commit SHA, so GitHub runs the job, and the rule, which does not read the lockfile, reports the uses", FindingKinds: []lint.FindingKindID{kindAllowedActionsUnpinnedAction}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: jobNeverRuns, Text: "a uses in a job whose if is always false, such as if: false on the job: GitHub skips the job, so the step \"Set up job\" of the job does not run and the job does not fail; the rule does not read the if. A uses of the workflow itself that the setting does not allow still stops the run, since GitHub checks such a uses before the run starts", FindingKinds: []lint.FindingKindID{kindAllowedActionsFailedJob, kindAllowedActionsUnpinnedAction}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: otherRepositoryCaller, Text: "an action metadata file of the repository that only the workflows of other repositories use: GitHub compares the uses of the steps of the action with the setting of the repository of the workflow that runs the action, not with the setting of the repository of the action", FindingKinds: []lint.FindingKindID{kindAllowedActionsFailedJob, kindAllowedActionsUnpinnedAction}, Disposition: lint.Todo(lint.NeedFact)},
	},
}

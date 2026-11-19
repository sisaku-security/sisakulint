package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// ActionList is the rule action-list: a uses of an action, a reusable
// workflow or a Docker image, or the image of the container or of a
// service of a job, that the repository's own list of the uses it allows
// (the fact repo.action-list) does not allow. The maintainer of
// such an action, or the publisher of such an image, writes code that runs
// in the job with its secrets and token, though the repository did not say
// that it trusts them. The rule runs only where the list has an answer
// (DefaultRunGivenFacts): the list is the repository's own, and --online
// does not answer it.
var ActionList lint.Rule = withExamples(lint.WithView[ir.ActionListReader](actionList{}, ir.ActionListView))

// ActionListID is the ID of action-list.
var ActionListID = lint.MustRuleID("action-list")

type actionList struct{}

func (actionList) Meta() lint.Meta { return actionListMeta }

func (actionList) Check(ctx context.Context, c *lint.RuleContext, v ir.ActionListReader) error {
	a := facts.RepoActionList{}.Ask(ctx, c.Resolver)
	if a.State != facts.StateFound {
		return nil // no list, or no answer (list-unknown): nothing to compare with
	}
	cond, err := lint.FactEq(facts.RepoActionList{}, a.Value)
	if err != nil {
		return err
	}
	unlisted := func(uses ...string) bool {
		for _, u := range uses {
			if !facts.ActionListAllows(a.Value, u) {
				return true
			}
		}
		return false
	}
	report := func(d lint.FindingDraft) {
		d.Condition = &cond
		c.Report(d)
	}
	for _, u := range v.Uses() {
		// one reading when the path stays in its repository, every reading
		// when it goes above the root, none above the directory of actions
		// (outside-actions-directory)
		if unlisted(u.RunUses()...) {
			report(lint.FindingDraft{Location: c.At(u.RefAt()), Args: ActionListUnlisted{Uses: u.UsesText()}})
		}
	}
	// the images of docker:// steps, of the containers and the services of
	// jobs, as docker:// and the image; not runs.image (metadata-image)
	for _, s := range v.ImageSites() {
		site := s.Site()
		if site == analysis.ImageSiteKindAction {
			continue
		}
		for _, img := range s.Images() {
			uses := "docker://" + img.Text
			switch {
			case !unlisted(uses):
			case site == analysis.ImageSiteKindService:
				// the image of a service may be a value of the matrix that
				// the container or another service names too: the anchor
				// tells the findings at that value apart
				report(lint.FindingDraft{Location: c.At(img.At), Anchor: "service " + s.ServiceName(), Args: ActionListUnlistedService{Uses: uses, Service: s.ServiceName()}})
			default:
				report(lint.FindingDraft{Location: c.At(img.At), Args: ActionListUnlistedImage{Uses: uses}})
			}
		}
		for _, g := range s.InconclusiveImages() {
			if g.Dispatch {
				c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(g.At), Note: g.Text + " refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses; the rule does not determine the image that the value names, and does not compare the image with repo.action-list"})
				continue
			}
			c.Inconclusive(lint.InconclusiveDraft{KindID: imageExpr, Location: c.At(g.At), Note: g.Text + " has a ${{ }} that the rule does not read as values written in the matrix; the rule does not determine the image that the value names, and does not compare the image with repo.action-list"})
		}
	}
	// the steps of the composite actions of other repositories the steps run
	// (action.definition), and the steps of the reusable workflows of other
	// repositories the jobs call (workflow.definition), at the uses of the
	// input; the steps of an action.yml of the inputs are that input's
	steps := func(at ir.Handle, chainOf string, ss []ir.CompositeStep) {
		for _, s := range ss {
			if s.Query == nil {
				continue
			}
			ev := []lint.Related{{Location: c.At(s.At), Note: "the step of " + chainOf + " " + s.Chain[len(s.Chain)-1].Uses + " whose uses the finding names"}}
			if unlisted(s.RunUses...) {
				report(lint.FindingDraft{Location: c.At(at), Anchor: placeAnchor(c, s.Chain, s.At), Args: ActionListUnlisted{Uses: s.UsesText}, Evidence: ev})
			}
			for _, img := range s.Images {
				if uses := "docker://" + img.Text; unlisted(uses) {
					report(lint.FindingDraft{Location: c.At(at), Anchor: placeAnchor(c, s.Chain, img.At), Args: ActionListUnlistedImage{Uses: uses}, Evidence: ev})
				}
			}
		}
	}
	for _, call := range v.CompositeCalls() {
		steps(call.At(), "the composite action", call.Steps())
		// the runs.image of the Docker container actions of other
		// repositories the step runs
		for _, act := range call.Actions() {
			if act.Query == nil {
				continue // an action.yml of the inputs (metadata-image)
			}
			for _, img := range act.Images {
				if uses := "docker://" + img.Text; unlisted(uses) {
					report(lint.FindingDraft{Location: c.At(call.At()), Anchor: placeAnchor(c, act.Chain, img.At), Args: ActionListUnlistedImage{Uses: uses},
						Evidence: []lint.Related{{Location: c.At(img.At), Note: "the runs.image of the Docker container action " + act.Chain[len(act.Chain)-1].Uses + " of another repository, which the answer of the fact action.definition holds"}}})
				}
			}
		}
	}
	// the reusable workflows of other repositories the jobs call
	// (workflow.definition) are read where the engine runs the rule on them
	// (a remote called workflow), and reported at the uses of the calling job
	return nil
}

var (
	// the preconditions of action-list's threat
	listedTrust = lint.MustPreconditionID("listed-trust")
	imageInJob  = lint.MustPreconditionID("image-in-job")

	// the forms action-list declares
	listUnknown             = lint.MustUndetectedFormID("list-unknown")
	outsideActionsDirectory = lint.MustUndetectedFormID("outside-actions-directory")
	selfOutside             = lint.MustUndetectedFormID("self-outside")
	checkedOutLocal         = lint.MustUndetectedFormID("checked-out-local")
	metadataImage           = lint.MustUndetectedFormID("metadata-image")
	imageAlias              = lint.MustUndetectedFormID("image-alias")
	wildcardCase            = lint.MustFalsePositiveFormID("wildcard-case")
	imageAliasListed        = lint.MustFalsePositiveFormID("image-alias-listed")
	blockedCase             = lint.MustFalsePositiveFormID("blocked-case")
	neverRuns               = lint.MustFalsePositiveFormID("never-runs")
)

var actionListMeta = lint.Meta{
	ID:         ActionListID,
	Problem:    "a uses names an action, a reusable workflow or a Docker image, or a job names the image of its container or of a service, that the repository's list of allowed uses (the fact repo.action-list) does not allow, so that code of someone the repository did not list as trusted can run in the job, or in a service container beside the job",
	Expected:   "every uses of another repository, every uses of a Docker image, and docker:// followed by the image of each container and each service of a job, matches a pattern of repo.action-list that does not start with !, and matches no pattern that starts with !",
	Facets:     lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedReference}, AttackMeans: []lint.AttackMeans{lint.AttackMeansCode, lint.AttackMeansOperation}},
	DefaultRun: lint.DefaultRunGivenFacts(facts.KindRepoActionList),
	FindingKinds: []lint.FindingKind{
		{
			FindingText:   textActionListUnlisted,
			Attackers:     []lint.Attacker{lint.AttackerMaintainerOfCalled},
			Preconditions: []lint.PreconditionID{listedTrust},
			Incidents:     []lint.IncidentID{agentkit2025},
			FactKinds:     []facts.Kind{facts.KindRepoActionList},
			CVSS: lint.CVSS{
				AV: metric(lint.AttackVectorNetwork, "the attacker pushes to the repository of the action or the reusable workflow, over the network"),
				AC: metric(lint.AttackComplexityLow, "writing the code of the commit that the uses names, or moving the tag or the branch that the uses names, needs only the right to push to the repository"),
				AT: metric(lint.AttackRequirementsPresent, "the attacker must control the repository of the action or the reusable workflow (maintain the repository, or have taken over an account that does), which the repository of the workflow does not decide"),
				PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository of the workflow is needed"),
				UI: metric(lint.UserInteractionPassive, "the workflow runs on its usual events; nobody does anything unusual"),
				VC: metric(lint.ImpactHigh, "the code reads the secrets of the job and the GITHUB_TOKEN of the job; tj-actions/changed-files printed the secrets and the GITHUB_TOKEN to the log of the job", tjActions),
				VI: metric(lint.ImpactHigh, "with the token of the job the code can push, and write releases, artifacts and caches"),
				VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
				SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
				SI: metric(lint.ImpactHigh, "what the job publishes (releases, packages) reaches those who use it"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityAttacked, "in 2025 an attacker pointed the tag v39 of tj-actions/changed-files to a malicious commit, and the pull_request workflow of coinbase/agentkit ran the commit and leaked a GITHUB_TOKEN that could write (agentkit-2025)", unit42),
		},
		{
			FindingText:   textActionListUnlistedImage,
			Attackers:     []lint.Attacker{lint.AttackerImagePublisher},
			Preconditions: []lint.PreconditionID{listedTrust, imageInJob},
			Incidents:     []lint.IncidentID{trivyImage2026},
			FactKinds:     []facts.Kind{facts.KindRepoActionList},
			CVSS: lint.CVSS{
				AV: imageAV, AC: imageAC, AT: imageAT, PR: imagePR, UI: imageUI,
				VC: metric(lint.ImpactHigh, "a docker:// step's image gets the workspace, the docker socket and the environment of the step: the code of the image reads the secrets and the GITHUB_TOKEN given to the step", containerDocs),
				VI: metric(lint.ImpactHigh, "with the token given to the step the code can push, and write releases and artifacts"),
				VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
				SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
				SI: metric(lint.ImpactHigh, "what the job publishes (releases, packages) reaches those who use it"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			},
			ExploitMaturity: imageEM,
		},
		{
			FindingText:   textActionListUnlistedService,
			Attackers:     []lint.Attacker{lint.AttackerImagePublisher},
			Preconditions: []lint.PreconditionID{listedTrust, imageInJob},
			FactKinds:     []facts.Kind{facts.KindRepoActionList},
			CVSS: lint.CVSS{
				AV: imageAV, AC: imageAC, AT: imageAT, PR: imagePR, UI: imageUI,
				VC: metric(lint.ImpactLow, "a service gets the environment variables of the service and what the job sends to the service over the network; the runner mounts the workspace and the docker socket in the container of the job only"),
				VI: metric(lint.ImpactLow, "the service sends its responses to the job, which may build or test on what the service sends"),
				VA: metric(lint.ImpactLow, "the service can fail or stop what the job asks of the service"),
				SC: metric(lint.ImpactLow, "the service reaches the network of the job and of the runner"),
				SI: metric(lint.ImpactLow, "what the job publishes may carry what the service sent"),
				SA: metric(lint.ImpactNone, "no availability outside the job is lost"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "the reports found are of images that the steps ran in (trivy-image-2026, kics-image-2026), not of the image of a service"),
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{
			{
				Attacker: lint.AttackerMaintainerOfCalled,
				Via:      "writes the code that the uses runs: when the uses names a full SHA, the code of that commit, which the maintainer wrote before the uses named the commit and cannot change after; when the uses names a tag or a branch, the code of the commit that the tag or the branch names, which the maintainer can move to another commit at any time",
				Gains:    jobGains,
			},
			{
				Attacker: lint.AttackerImagePublisher,
				Via:      "publishes the image that the docker:// uses names: an image under the tag that the uses names, or a new latest",
				Gains:    jobGains,
			},
		},
		Preconditions: []lint.Precondition{
			{ID: listedTrust, Text: "the action that a uses of a step names runs in the job, with the secrets of the repository that the job can read and the GITHUB_TOKEN of the job; the reusable workflow that a uses of a job names runs its own jobs, with the GITHUB_TOKEN of the run and the secrets that the calling job passes; repo.action-list is the list of the uses that the repository trusts, as the user who answers the fact says, and the rule does not check why the list allows a uses",
				Cites: []lint.Citation{secureUse, reusingDocs}},
			{ID: imageInJob, Text: "the runner pulls the image of a docker:// step, of the container of a job and of a service of a job by the name written, when the job runs; the runner runs the image of a docker:// step as the step, runs the steps of the job in the container of the job, and starts each service beside the job", Cites: []lint.Citation{containerDocs}},
		},
		Incidents: []lint.Incident{agentkitIncident, trivyImageIncident},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: inputDispatch, Text: "an image of the container or of a service of a job whose reference has a ${{ }} that refers to an input of workflow_dispatch (inputs, github.event.inputs), alone or in a string with other text: " + dispatcherChooses, Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: imageExpr, Text: "an image of the container or of a service of a job with a ${{ }} that refers to no input of workflow_dispatch and that the rule does not read as values written in the matrix, such as an input of workflow_call, fromJSON, or a value of the matrix in a string with other text (the rule reads the values of the matrix only for an image that is a ${{ matrix.<name> }} alone)", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: listUnknown, Text: "a run that names the rule with --rule but has no answer of repo.action-list: the rule has no list to compare the uses with, and reports nothing", Disposition: lint.Todo(lint.NeedFact)},
		{ID: remoteComposite, Text: "a uses inside the action.yml of a composite action of another repository (a step of that composite action, not the uses that names the composite action) when action.definition has no answer for the composite action (a run without --online and without the answer in --facts, an answer of unknown, or an action deeper than the 4 levels of actions the linter reads): the rule reads the steps of a composite action of another repository only from the answer of the fact action.definition", Disposition: lint.Todo(lint.NeedFact)},
		{ID: outsideActionsDirectory, Text: "a uses whose path goes with .. above the directory where the runner puts the actions of the job (_actions), or a ./ uses whose path goes above the workspace: what the path names is decided when the job runs", FindingKinds: []lint.FindingKindID{kindActionListUnlisted}, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: selfOutside, Text: "a $/ uses (an action in the repository of the workflow, at the commit that runs) whose path goes with .. above the root of the repository into the directory of another action, which runs the code of another repository", FindingKinds: []lint.FindingKindID{kindActionListUnlisted}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: checkedOutLocal, Text: "a ./ uses after a step checks out another repository into the workspace (actions/checkout with repository of another repository): the code of the repository checked out runs, and the rule does not compare a ./ uses with repo.action-list", FindingKinds: []lint.FindingKindID{kindActionListUnlisted}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: imageAlias, Text: "a docker:// uses that names an image by other text than a pattern with ! names the image by, such as docker://docker.io/library/alpine:3, docker://alpine (the tag latest) or docker://alpine@sha256:<digest> for the pattern !docker://alpine:*: the rule compares the text of the image as written, and Docker reads those names as the same image", FindingKinds: []lint.FindingKindID{kindActionListUnlistedImage}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: metadataImage, Text: "the runs.image (docker://) in the action metadata file of a Docker container action in the repository that the linter checks: the image runs as the action, and the rule does not compare that runs.image with repo.action-list; the rule compares the runs.image of a Docker container action of another repository, which the answer of the fact action.definition holds", FindingKinds: []lint.FindingKindID{kindActionListUnlistedImage}, Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: wildcardCase, Text: "a pattern without ! that writes letters of the owner or of the name of the repository after a * in upper case, such as */Octocat@*: the rule compares the owner and the name of a uses in lower case and the letters after the first * of a pattern as written, so the pattern matches no uses with those letters, whatever case the uses writes the letters in (space/octocat@v1 or space/Octocat@v1), though GitHub compares the owner and the name without case", FindingKinds: []lint.FindingKindID{kindActionListUnlisted}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: imageAliasListed, Text: "a docker:// uses that names an image that a pattern without ! allows, by other text than the pattern names the image by, such as docker://docker.io/library/alpine:3 for the pattern docker://alpine:*: Docker reads the two names as the same image, which the repository listed as trusted, and the rule compares the text of the image as written", FindingKinds: []lint.FindingKindID{kindActionListUnlistedImage}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: blockedCase, Text: "a pattern with ! that names a ref or a path in one case, such as !actions/checkout@V4, and a uses that writes the ref or the path in another case, such as actions/checkout@v4: the rule compares a pattern with ! without case, so the pattern blocks the uses, though git and the runner read v4 as another ref than V4", FindingKinds: []lint.FindingKindID{kindActionListUnlisted}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: neverRuns, Text: "a uses, or the image of the container or of a service, in a step or a job whose if is always false, such as if: false: the code of the uses or of the image never runs, and the rule does not read the if", FindingKinds: []lint.FindingKindID{kindActionListUnlisted, kindActionListUnlistedImage, kindActionListUnlistedService}, Disposition: lint.Todo(lint.NeedSameFile)},
	},
}

package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// UnpinnedImages is the rule unpinned-images: an image to run that no
// digest pins, whose tag whoever can push to it moves. The
// steps of a job run in its container and a docker:// image; a service
// runs beside the job and gets less, so it is a kind of its own.
var UnpinnedImages lint.Rule = withExamples(lint.WithView[ir.UnpinnedImagesReader](unpinnedImages{}, ir.UnpinnedImagesView))

// UnpinnedImagesID is the ID of unpinned-images.
var UnpinnedImagesID = lint.MustRuleID("unpinned-images")

type unpinnedImages struct{}

func (unpinnedImages) Meta() lint.Meta { return unpinnedImagesMeta }

var imageExpr = lint.MustInconclusiveKindID("image-expr")

func (unpinnedImages) Check(_ context.Context, c *lint.RuleContext, v ir.UnpinnedImagesReader) error {
	for _, s := range v.ImageSites() {
		for _, img := range s.Images() {
			if img.Pinned {
				continue
			}
			d := lint.FindingDraft{Location: c.At(img.At), Args: UnpinnedImagesMutable{Image: img.Text, Tag: img.Tag, Site: s.Site()}}
			if s.Site() == analysis.ImageSiteKindService {
				// the image of a service may be a value of the matrix that
				// the container or another service names too: the anchor
				// tells the findings at that value apart
				d.Anchor, d.Args = "service "+s.ServiceName(), UnpinnedImagesService{Image: img.Text, Tag: img.Tag, Service: s.ServiceName()}
			}
			c.Report(d)
		}
		for _, g := range s.InconclusiveImages() {
			if g.Dispatch {
				c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(g.At), Note: g.Text + " refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses; the rule does not determine the image that the value names"})
				continue
			}
			c.Inconclusive(lint.InconclusiveDraft{KindID: imageExpr, Location: c.At(g.At), Note: g.Text + " has a ${{ }} that the rule does not read as values written in the matrix; the rule does not determine the image that the value names"})
		}
	}
	// the runs.image of the actions of other repositories the steps run,
	// and the docker:// steps of their composite actions
	// (action.definition), at the uses of the step
	for _, call := range v.CompositeCalls() {
		substituted := map[string]bool{} // the chains of the actions reported as archive-substituted
		report := func(chain []composite.Hop, isSubstituted bool, images []ir.Image, site analysis.ImageSiteKind, what string) {
			uses := chain[len(chain)-1].Uses
			if isSubstituted {
				if hops := hopsText(chain); !substituted[hops] {
					substituted[hops] = true
					c.Inconclusive(lint.InconclusiveDraft{KindID: archiveSubstituted, Location: c.At(call.At()),
						Note: "the archive the runner downloads of " + uses + " has the file of the action unlike its blob (export-subst), so the image the runner pulls may differ from the one the linter read: compare the archive with the blob"})
				}
				return
			}
			for _, img := range images {
				if img.Pinned {
					continue
				}
				c.Report(lint.FindingDraft{Location: c.At(call.At()), Anchor: placeAnchor(c, chain, img.At),
					Args:     UnpinnedImagesMutable{Image: img.Text, Tag: img.Tag, Site: site},
					Evidence: []lint.Related{{Location: c.At(img.At), Note: what + uses}}})
			}
		}
		for _, a := range call.Actions() {
			if a.Query != nil && len(a.Images) != 0 {
				report(a.Chain, a.Substituted, a.Images, analysis.ImageSiteKindAction, "the runs.image of ")
			}
		}
		for _, st := range call.Steps() {
			if st.Query != nil && len(st.Images) != 0 {
				report(st.Chain, st.Substituted, st.Images, analysis.ImageSiteKindStep, "the uses of a step of the composite action ")
			}
		}
		for _, u := range call.Unanswered() {
			if u.Asked {
				c.Inconclusive(lint.InconclusiveDraft{KindID: remoteUnknown, Location: c.At(call.At()),
					Note: "the action " + u.Chain[len(u.Chain)-1].Uses + " was asked of action.definition and has no answer (" + u.Reason + "): whether the images the action runs (its runs.image, or the docker:// steps of a composite action) are pinned by their digests is not known"})
			}
		}
	}
	return nil
}

var (
	movableTag     = lint.MustPreconditionID("movable-tag")
	pulledAtRun    = lint.MustPreconditionID("pulled-at-run")
	trivyImage2026 = lint.MustIncidentID("trivy-image-2026")
	kicsImage2026  = lint.MustIncidentID("kics-image-2026")
	trivyImage     = lint.MustCitation("https://www.docker.com/blog/trivy-supply-chain-compromise-what-docker-hub-users-should-know/")
	kicsImage      = lint.MustCitation("https://socket.dev/blog/checkmarx-supply-chain-compromise")
	containerDocs  = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idcontainer")
	observedImage  = lint.MustDate("2026-10-04")
	pullByDigest   = lint.MustCitation("https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier")
)

// trivyImageIncident is the attack on aquasec/trivy on Docker Hub, which
// unpinned-images and action-list cite.
var trivyImageIncident = lint.Incident{ID: trivyImage2026, Date: lint.MustDate("2026-03-19"), Advisory: trivyImage,
	Compromised: repos("aquasecurity/trivy"),
	Summary:     "with stolen credentials, images that steal the secrets of CI were pushed to aquasec/trivy on Docker Hub as 0.69.4 to 0.69.6, and latest was re-pointed to them; workflows that ran docker://aquasec/trivy or a container of aquasec/trivy pulled them"}

// the likelihood of the two kinds: the attacker pushes to the image's
// repository, which the workflow does not decide
var (
	imageAV = metric(lint.AttackVectorNetwork, "the attacker pushes to the image's repository in its registry, over the network")
	imageAC = metric(lint.AttackComplexityLow, "pushing an image under the tag, or a new latest, needs only the right to push to it")
	imageAT = metric(lint.AttackRequirementsPresent, "the attacker must control the image's repository (maintain it, or have taken over an account or a token that pushes to it), which the workflow's repository does not decide")
	imagePR = metric(lint.PrivilegesRequiredNone, "nothing of the workflow's repository is needed")
	imageUI = metric(lint.UserInteractionPassive, "the workflow runs on its usual events; nobody does anything unusual")
	imageEM = metric(lint.ExploitMaturityAttacked, "in 2026 the latest of aquasec/trivy was re-pointed to an image that steals the secrets of CI, and tags of checkmarx/kics were overwritten", trivyImage, kicsImage)
)

var unpinnedImagesMeta = lint.Meta{
	ID:       UnpinnedImagesID,
	Problem:  "an image to run (a job's container or service, a step's docker://, an action's runs.image) is named by a tag or by nothing, which whoever can push to the image's repository moves to another image",
	Expected: "the image is pinned by its digest",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedReference}, AttackMeans: []lint.AttackMeans{lint.AttackMeansOperation}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:   textUnpinnedImagesMutable,
			Attackers:     []lint.Attacker{lint.AttackerImagePublisher},
			Preconditions: []lint.PreconditionID{movableTag, pulledAtRun},
			Incidents:     []lint.IncidentID{trivyImage2026, kicsImage2026},
			CVSS: lint.CVSS{
				AV: imageAV, AC: imageAC, AT: imageAT, PR: imagePR, UI: imageUI,
				VC: metric(lint.ImpactHigh, "the steps of the job run in its container, and a docker:// step's image gets the workspace, the docker socket and the step's environment: the image's code reads the secrets and the GITHUB_TOKEN given to them", containerDocs),
				VI: metric(lint.ImpactHigh, "with the job's token the code can push, and write releases, artifacts and caches"),
				VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
				SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
				SI: metric(lint.ImpactHigh, "what the job publishes (releases, packages) reaches those who use it"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			},
			ExploitMaturity: imageEM,
		},
		{
			FindingText:   textUnpinnedImagesService,
			Attackers:     []lint.Attacker{lint.AttackerImagePublisher},
			Preconditions: []lint.PreconditionID{movableTag, pulledAtRun},
			CVSS: lint.CVSS{
				AV: imageAV, AC: imageAC, AT: imageAT, PR: imagePR, UI: imageUI,
				VC: metric(lint.ImpactLow, "a service gets its own env and what the job sends it over the network; the runner mounts the workspace and the docker socket in the job's container only"),
				VI: metric(lint.ImpactLow, "it answers the job, which may build or test on what it answers"),
				VA: metric(lint.ImpactLow, "it can fail or stop what the job asks of it"),
				SC: metric(lint.ImpactLow, "it reaches the network of the job and of the runner"),
				SI: metric(lint.ImpactLow, "what the job publishes may carry what it answered"),
				SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "the reports found are of images the steps ran in (trivy-image-2026, kics-image-2026), not of a service's"),
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerImagePublisher,
			Via:      "pushes an image of theirs under the tag the workflow names, or as a new latest; a service's image gets only what the job sends it, not its secrets or token (the kind service)",
			Gains:    jobGains,
		}},
		Preconditions: []lint.Precondition{
			{ID: movableTag, Text: "a tag names whatever image was last pushed under it, and no tag is latest; a digest is the hash of the image, which docker pulls by when the reference has one, a tag beside it or not",
				Observed: []lint.Observation{{Date: observedImage, Runner: runner, What: "a job's container and a step's docker:// of alpine:3.18 with the digest of 3.20 ran 3.20.10"}},
				Cites:    []lint.Citation{pullByDigest}},
			{ID: pulledAtRun, Text: "the runner pulls the image by the name written when the job runs, after docker:// is taken off", Cites: []lint.Citation{containerDocs}},
		},
		Incidents: []lint.Incident{
			trivyImageIncident,
			{ID: kicsImage2026, Date: lint.MustDate("2026-04-22"), Advisory: kicsImage,
				Compromised: repos("Checkmarx/kics"),
				Summary:     "the tags v2.1.20, alpine and latest of checkmarx/kics on Docker Hub were overwritten with an image that sends the scan's report out; kics-github-action took it in the FROM of its Dockerfile"},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("dockerfile"), Text: "the FROM of the Dockerfile of an action whose runs.image is a Dockerfile, as kics-github-action took checkmarx/kics:v2.1.20", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("run-command"), Text: "an image a run pulls or runs: docker run, docker pull", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("build-dockerfile"), Text: "an image that the FROM or the COPY --from of a Dockerfile in the repository of the workflow names (the Dockerfile at the commit that runs), when a step builds an image from the Dockerfile (such as docker build or docker buildx build in the script of a step, or docker/build-push-action): the rule does not read the Dockerfile, which is a file of the repository other than the workflow", FindingKinds: []lint.FindingKindID{kindUnpinnedImagesMutable}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("script-dockerfile"), Text: "an image that the FROM or the COPY --from of a Dockerfile names, when the script of a step writes the Dockerfile from text written in the workflow (printf, or a heredoc to a file or to the standard input of docker build) and the same step or a later step builds an image from the Dockerfile: the rule does not read the text that the script writes", FindingKinds: []lint.FindingKindID{kindUnpinnedImagesMutable}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("checkout-dockerfile"), Text: "an image that the FROM or the COPY --from of a Dockerfile of another repository names, when a checkout of the repository or a Git URL given as the context of docker build or of docker/build-push-action names a full commit SHA, and a step builds an image from the Dockerfile: the commit decides the content of the Dockerfile, and no fact gives the rule a file of another repository other than the file of an action or of a reusable workflow", FindingKinds: []lint.FindingKindID{kindUnpinnedImagesMutable}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("generated-dockerfile"), Text: "an image that the FROM or the COPY --from of a Dockerfile names, when the job downloads the Dockerfile (curl, wget, an artifact, or a checkout of another repository or a Git URL given as the context of docker build or of docker/build-push-action, at a branch or a tag) or makes the Dockerfile from values known only when the job runs, and then builds an image from the Dockerfile: the content of the Dockerfile is decided when the job runs", FindingKinds: []lint.FindingKindID{kindUnpinnedImagesMutable}, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("action-input-image"), Text: "an image named in the with: of a step, in an input that the action reads as the image of a container that the action starts (such as image= in the input driver-opts of docker/setup-buildx-action, the image of BuildKit): the rule reads only the images of jobs.<id>.container and jobs.<id>.services, of docker:// in uses, and of runs.image in an action metadata file (action.yml) that the linter reads", FindingKinds: []lint.FindingKindID{kindUnpinnedImagesMutable}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("remote-action"), Text: "the runs.image of an action of another repository a step uses, or the image of a docker:// step of a composite action of another repository, when action.definition has no answer for the action (a run without --online and without the answer in --facts): the rule reads the file of an action of another repository only from the answer", Disposition: lint.Todo(lint.NeedFact)},
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: inputDispatch, Text: "an image of a container (of a step with docker://, the container or a service of a job, or runs.image of an action) whose reference has a ${{ }} that refers to an input of workflow_dispatch (inputs, github.event.inputs), alone or in a string with other text: " + dispatcherChooses, Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: imageExpr, Text: "an image with a ${{ }} that refers to no input of workflow_dispatch and that the rule does not read as values written in the matrix, such as an input of workflow_call, fromJSON, or a value of the matrix in a string with other text (the rule reads the values of the matrix only for an image that is a ${{ matrix.<name> }} alone)", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: remoteUnknown, Text: "an action of another repository a step uses, whose action.definition was asked and has no answer (the archive is larger than the limit, the run has used up the requests it may send to the GitHub API, the token cannot read the repository, or the action is deeper than the 4 levels of actions the linter reads): whether the images the action runs (its runs.image, or the docker:// steps of a composite action) are pinned by their digests is not known", Disposition: lint.Todo(lint.NeedFact)},
		{ID: archiveSubstituted, Text: "a Docker container action, or a composite action with a docker:// step, of another repository, whose action.yml (or action.yaml) in the archive the runner downloads is unlike its blob (export-subst): placeholders such as %d and %(describe) take the names of refs created after the commit, so the image the runner pulls may differ from the one the linter read", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("matrix-exclude"), Text: "an image of a matrix that its exclude takes out, so no job runs it", FindingKinds: []lint.FindingKindID{kindUnpinnedImagesMutable}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("immutable-tag"), Text: "a tag the registry keeps from moving, such as one of a repository of Amazon ECR with tag immutability: the setting is not read", FindingKinds: []lint.FindingKindID{kindUnpinnedImagesMutable, kindUnpinnedImagesService}, Disposition: lint.Todo(lint.NeedFact)},
	},
}

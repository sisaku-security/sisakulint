package rules

import (
	"context"
	"regexp"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// CommitSHA is the rule commit-sha: a uses of another repository (an
// action, in a workflow or in a composite action, or a reusable workflow)
// that names a tag, a branch or a shortened SHA runs whatever that name
// points to when the job runs, which its maintainer can change. The fix
// writes the full SHA the runner runs now for the name, with the name in
// a comment.
var CommitSHA lint.Rule = withExamples(lint.WithView[ir.CommitSHAReader](commitSHA{}, ir.CommitSHAView))

// CommitSHAID is the ID of commit-sha, and PinSHAID the kind of its fix:
// the names to refer to them by, rather than their text.
var (
	CommitSHAID = lint.MustRuleID("commit-sha")
	PinSHAID    = lint.MustFixKindID("pin-sha")
)

type commitSHA struct{}

var (
	fullSHA = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	hexRef  = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
)

func (commitSHA) Meta() lint.Meta { return commitSHAMeta }

func (commitSHA) Check(ctx context.Context, c *lint.RuleContext, v ir.CommitSHAReader) error {
	for _, u := range v.Uses() {
		switch {
		case u.Outside():
			// another uses above the root may go into the directory of this
			// ref and run its code; a finding of the action that runs comes
			// first, as one uses has one finding, and once that uses is
			// written without .., its ref is read as any uses' is
			if f, ok := outsideFinding(c, u); ok {
				c.Report(f)
			} else if u.ReadByOutside() && !fullSHA.MatchString(u.Ref()) {
				c.Report(finding(ctx, c, u))
			}
		case !fullSHA.MatchString(u.Ref()):
			c.Report(finding(ctx, c, u))
		}
	}
	// a uses pinned to a full SHA whose action's file in the archive the
	// runner downloads is unlike its blob (export-subst, action.definition):
	// what runs can change after the pin
	for _, call := range v.CompositeCalls() {
		for _, a := range call.Actions() {
			if len(a.Chain) != 1 || a.Query == nil || !a.Substituted {
				continue
			}
			if _, ref, _ := strings.Cut(a.Chain[0].Uses, "@"); !fullSHA.MatchString(ref) {
				continue // a ref that moves is unpinned
			}
			c.Inconclusive(lint.InconclusiveDraft{KindID: archiveSubstituted, Location: c.At(call.At()),
				Note: "the archive the runner downloads of " + a.Chain[0].Uses + " has the file of the action unlike its blob (export-subst): a tag created after the commit can change the action that runs, though the uses is pinned to a full SHA; compare the archive with the blob"})
		}
	}
	return nil
}

// outsideFinding is the finding of a uses whose path goes above the root of
// its repository: the runner runs the action of the directory the path
// names, so the ref after @ does not decide the code. When another
// uses of the same steps downloads that action, the rule reads that uses;
// else a reading of RunActions whose ref is no full SHA is reported as
// unpinned-path-action, with no fix: the uses to pin is not this one.
func outsideFinding(c *lint.RuleContext, u ir.CommitSHAOfUses) (lint.FindingDraft, bool) {
	for _, r := range u.RunActions() {
		if _, ref, _ := strings.Cut(r, "@"); fullSHA.MatchString(ref) {
			continue
		}
		return lint.FindingDraft{Location: c.At(u.PathAt()), Args: CommitSHAUnpinnedPathAction{Uses: u.UsesText(), Action: r}}, true
	}
	return lint.FindingDraft{}, false
}

// finding is the finding of the uses u, with its fix or why there is none.
func finding(ctx context.Context, c *lint.RuleContext, u ir.CommitSHAOfUses) lint.FindingDraft {
	name, ref, at := u.Repo(), u.Ref(), u.RefAt()
	f := lint.FindingDraft{
		Location: c.At(at),
		Args:     CommitSHAUnpinned{Uses: u.UsesText(), Repo: name, Ref: ref},
	}
	if !u.Exact() {
		f.NoFix = &lint.NoFix{Reason: ir.NoFixReasonForm, Note: "the ref is written with an escape; write it plainly, then pin it to a full commit SHA"}
		return f
	}
	if u.ReadByOutside() {
		f.NoFix = &lint.NoFix{Reason: ir.NoFixReasonManual, Note: "another uses of the steps goes with .. into the directory where the runner puts the action of this uses at this ref; the runner names that directory by the ref, so a pin of this uses changes the name of the directory, and the job fails before the steps run because the uses that goes into the directory finds no action; write the uses that goes into the directory as owner/repo/path@ref, without .., and then pin each of the two uses that is not pinned"}
		return f
	}
	repo, err := facts.ParseRepo(name)
	if err != nil {
		f.NoFix = &lint.NoFix{Reason: ir.NoFixReasonForm, Note: name + " is not the name of a repository GitHub can have"}
		return f
	}
	q := facts.GitRefCommit{Repo: repo, Ref: ref}
	a := q.Ask(ctx, c.Resolver)
	switch a.State {
	case facts.StateUnknown:
		f.NoFix = &lint.NoFix{Reason: ir.NoFixReasonFact, Queries: []facts.Query{q},
			// what to do is the resolver's to say: its reason names the way
			// of the command that ran it, which the rule does not know
			Note: "the commit of the ref is not known (" + a.Reason + ")"}
		return f
	case facts.StateAbsent:
		note := ref + " is not in the repository " + name + " as a tag, a branch or a full commit SHA"
		if hexRef.MatchString(ref) {
			note = ref + " is a shortened SHA, which the runner refuses; write the full SHA of the commit"
		}
		f.NoFix = &lint.NoFix{Reason: ir.NoFixReasonManual, Note: note}
		return f
	}
	pin, err := at.Replace(a.Value.SHA.String())
	if err != nil {
		f.NoFix = &lint.NoFix{Reason: ir.NoFixReasonForm, Note: "the ref cannot be written in place (" + err.Error() + "); pin it by hand"}
		return f
	}
	edits := []edit.Edit{pin}
	// the name as a comment, for people and for tools that update pins
	// (Dependabot); hex digits say nothing of a version
	if !hexRef.MatchString(ref) {
		if cm, ok := at.CommentAtEnd(ref); ok {
			edits = append(edits, cm)
		}
	}
	f.Fix = &lint.Fix{KindID: PinSHAID, Title: "pin " + name + "@" + ref + " to " + a.Value.SHA.String(), Edits: edits}
	return f
}

var (
	observed = lint.MustDate("2026-09-24")

	tjActions = lint.MustCitation("https://github.com/advisories/GHSA-mrrh-fwg8-r2c3")
	reviewdog = lint.MustCitation("https://github.com/advisories/GHSA-qmg3-hpqr-gqvc")
	cisa      = lint.MustCitation("https://www.cisa.gov/news-events/alerts/2025/03/18/supply-chain-compromise-third-party-tj-actionschanged-files-cve-2025-30066-and-reviewdogaction")

	// the preconditions and the incidents of commit-sha's threat
	movableRef    = lint.MustPreconditionID("movable-ref")
	readAtRun     = lint.MustPreconditionID("read-at-run")
	reviewdog2025 = lint.MustIncidentID("reviewdog-2025")
	tjActions2025 = lint.MustIncidentID("tj-actions-2025")
)

// unpinnedKind is the kind commit-sha.unpinned: a uses whose ref is not a
// full commit SHA.
var unpinnedKind = lint.FindingKind{
	FindingText:   textCommitSHAUnpinned,
	Attackers:     []lint.Attacker{lint.AttackerMaintainerOfCalled},
	Preconditions: []lint.PreconditionID{movableRef, readAtRun},
	Incidents:     []lint.IncidentID{reviewdog2025, tjActions2025, agentkit2025},
	Fixes:         []lint.FixKindID{PinSHAID},
	CVSS: lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker pushes to the repository called, over the network"),
		AC: metric(lint.AttackComplexityLow, "moving a tag or a branch needs only the right to push to it"),
		AT: metric(lint.AttackRequirementsPresent, "the attacker must control the repository called (maintain it, or have taken over an account that does), which the calling repository does not decide"),
		PR: metric(lint.PrivilegesRequiredNone, "nothing of the calling repository is needed"),
		UI: metric(lint.UserInteractionPassive, "the calling workflow runs on its usual events; nobody does anything unusual"),
		VC: metric(lint.ImpactHigh, "the code reads the job's secrets and GITHUB_TOKEN; tj-actions/changed-files printed them to the job's log", tjActions),
		VI: metric(lint.ImpactHigh, "with the job's token the code can push, and write releases, artifacts and caches"),
		VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
		SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
		SI: metric(lint.ImpactHigh, "what the job publishes (releases, packages) reaches those who use it"),
		SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
	},
	ExploitMaturity: metric(lint.ExploitMaturityAttacked, "tags were moved to malicious commits in the wild in 2025; CISA lists both in its Known Exploited Vulnerabilities", cisa),
}

// unpinnedPathActionKind is the kind commit-sha.unpinned-path-action: a
// uses whose path goes with .. above the root of its repository and runs an
// action whose ref is not a full commit SHA. The threat is that of
// unpinned; there is no fix, as the uses to pin is not this one.
var unpinnedPathActionKind = func() lint.FindingKind {
	k := unpinnedKind
	k.FindingText, k.Fixes = textCommitSHAUnpinnedPathAction, nil
	return k
}()

var commitSHAMeta = lint.Meta{
	ID:           CommitSHAID,
	Problem:      "a uses of another repository names its ref by anything but a full commit SHA (a tag, a branch, a shortened SHA); a tag or a branch can be moved to other code by whoever controls that repository",
	Expected:     "the uses is pinned to a full commit SHA",
	Facets:       lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedReference}, AttackMeans: []lint.AttackMeans{lint.AttackMeansOperation}},
	FindingKinds: []lint.FindingKind{unpinnedKind, unpinnedPathActionKind},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerMaintainerOfCalled,
			Via:      "moves the tag or the branch the caller names to a commit of theirs",
			Gains:    jobGains,
		}},
		Preconditions: []lint.Precondition{
			{
				ID:   movableRef,
				Text: "the caller names a tag, a branch or a shortened SHA; a full SHA is a ref that cannot be moved",
				Observed: []lint.Observation{
					{Date: observed, What: "GitHub refuses to create a branch or a tag whose name is 40 or 64 hexadecimal digits, in upper case as in lower (the push is refused, GH002)"},
					{Date: observed, Runner: runner, What: "the runner runs the commit of an upper-case full SHA as of the lower-case one"},
					{Date: observed, Runner: runner, What: "the runner refuses a shortened SHA"},
				},
				Cites: []lint.Citation{secureUse},
			},
			{
				ID:   readAtRun,
				Text: "the name is read when the job runs",
				Observed: []lint.Observation{
					{Date: observed, Runner: runner, What: "the runner runs the tag when a branch and a tag have the same name, and the commit an annotated tag points to"},
					{Date: observedRefConfusion, Runner: runner, What: "a reusable workflow, too, ran the tag when a branch and a tag had the same name"},
				},
			},
		},
		Incidents: []lint.Incident{
			reviewdog2025Incident,
			tjActions2025Incident,
			agentkitIncident,
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("export-subst"), Text: "a uses pinned to a full SHA of an action of another repository whose repository gives the metadata file of the action the attribute export-subst: the archive the runner downloads can put the name of a tag created after the commit into a step, so the action that runs can change after the pin; the rule does not find the attribute in a run with no answer of action.definition for the action (a run without --online and without the answer in --facts)", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("docker"), Text: "a uses of a Docker image (docker://): unpinned-images reports it when no digest pins it", Disposition: lint.OtherRule(UnpinnedImagesID)},
		{ID: lint.MustUndetectedFormID("outside-actions-directory"), Text: "a uses whose path goes with .. above the directory where the runner puts the actions of the job (_actions): what the path names is decided when the job runs: on a GitHub-hosted runner the workspace is empty when the runner reads the actions, so a path into the workspace makes the job fail before the steps run (seen on 2026-10-21), and on a self-hosted runner the path may name files that an earlier job left (not seen)", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustUndetectedFormID("self-outside"), Text: "a $/ uses (an action in the repository of the workflow, at the commit that runs) whose path goes with .. above the root of the repository into the directory of another action", Disposition: lint.Todo(lint.NeedSameFile)},
		remoteCompositeStepsLimit(commitSHAInStepText, ""),
	}, checkedOutLocalLimits(commitSHAInStepText)...)),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: archiveSubstituted, Text: "a uses pinned to a full SHA of an action of another repository whose action.yml (or action.yaml) in the archive the runner downloads is unlike its blob (export-subst): placeholders such as %d and %(describe) take the names of refs created after the commit, so the action that runs can change after the pin; a file whose placeholders are only %H does not change, and the rule does not distinguish a file with placeholders of refs from a file whose placeholders are only %H", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}),
	FixKinds: []lint.FixKind{{
		ID:        PinSHAID,
		Title:     "pin the ref to the full SHA of the commit the runner runs for it now",
		FactKinds: []facts.Kind{facts.KindGitRefCommit},
		Safety:    lint.SafetySafe,
	}},
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("immutable-release"), Text: "the tag of an immutable release, which no one can move or delete while the release is there: the rule does not ask", FindingKinds: []lint.FindingKindID{kindCommitSHAUnpinned}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("lockfile"), Text: "a workflow onboarded to the repository's workflow dependency lockfile (.github/workflows/actions.lock, a preview of GitHub since 2026-10-12): the commit the lockfile records runs, wherever the tag points; the rule does not read the lockfile", FindingKinds: []lint.FindingKindID{kindCommitSHAUnpinned}, Disposition: lint.Todo(lint.NeedRepoFile)},
	},
}

// commitSHAInStepText is what the undetected forms of commit-sha about a
// step of a composite action that the rule does not read name.
const commitSHAInStepText = "a uses of an action of another repository that names its ref by anything but a full commit SHA"

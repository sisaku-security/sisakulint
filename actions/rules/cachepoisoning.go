package rules

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// CachePoisoning is the rule cache-poisoning: a job that an attacker's
// privileged event runs and no one approves, whose cache-mode lets it save
// to the cache of the default branch's scope, which later runs of the
// repository restore and run; and, in such a job, what an attacker puts
// in that cache with no code of theirs run: the tree of their pull request
// saved, or a key or a path they write.
var CachePoisoning lint.Rule = withExamples(lint.WithView[ir.CachePoisoningReader](cachePoisoning{}, ir.CachePoisoningView))

// CachePoisoningID is the ID of cache-poisoning, and CacheModeNoWriteID
// the kind of its fix.
var (
	CachePoisoningID   = lint.MustRuleID("cache-poisoning")
	CacheModeNoWriteID = lint.MustFixKindID(ir.FixCacheModeNoWrite.String())
)

type cachePoisoning struct{}

func (cachePoisoning) Meta() lint.Meta { return cachePoisoningMeta }

func (cachePoisoning) Check(_ context.Context, c *lint.RuleContext, v ir.CachePoisoningReader) error {
	for _, j := range v.Jobs() {
		evs := j.CacheWriteOn()
		if len(evs) == 0 {
			continue
		}
		cond, ok := approvalCond(c, j.CacheApproval(), j.Environment(), j.AutomaticApproval(), j.CacheModeAt(), "the job that may save to the cache", nil)
		if !ok {
			continue
		}
		// the workflow's cache-mode is the place of each job it lets save
		f := lint.FindingDraft{Location: c.At(j.CacheModeAt()), Anchor: j.Key().Path(), Args: CachePoisoningWritableJob{CacheMode: j.CacheModeText(), CacheWriteOn: eventsOf(evs)},
			Condition: cond, Related: labelerRelated(c, j.CacheApproval(), j.AutomaticApproval())}
		f.Fix, f.NoFix = fixOf(j.CacheModeNoWrite())
		c.Report(f)
	}
	// the steps whose path an attacker writes: attacker-path reports them,
	// and whether the path has the tree is no question
	attackerPaths := map[ir.Key]bool{}
	for _, s := range v.CacheSaves() {
		if slices.ContainsFunc(s.PathRefs(), func(r ir.ExprRef) bool { return controlledOn(r, s.CacheWriteOn()) != nil }) {
			attackerPaths[s.Key()] = true
		}
	}
	unknownPaths := map[string]bool{} // one question of a step, whichever checkout
	remoteGaps := map[string]bool{}   // one question of a uses with no answer or of a step in a substituted action
	for _, s := range v.CheckoutSites() {
		// before the approval: a run of workflow_dispatch has no label
		if s.DispatchInput() && len(s.DispatchCacheOn()) > 0 && (len(s.CacheSaves()) > 0 || len(s.CodeRunSteps()) > 0) {
			c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(s.At()), Related: cacheSaveRelated(c, s, false),
				Note: "the ref or the repository of " + s.UsesText() + " refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses, and the job may save to the cache of the scope of the ref of the run, by a step that saves what the checkout brings or by the code that a step after the checkout runs; the rule does not determine the code that the value names"})
		}
		if s.CheckoutCode() != analysis.CodePR || len(s.CacheSaves())+len(s.UnansweredCalls()) == 0 || len(s.CacheWriteOn()) == 0 {
			continue
		}
		approval, ok := approvalCond(c, s.Approval(), s.Environment(), s.AutomaticApproval(), s.At(), stepRef(s.UsesText()),
			append([]lint.Related{{Location: c.At(s.Refs()[0].At), Note: "checks out the pull request's code"}}, cacheSaveRelated(c, s, true)...))
		if !ok {
			continue
		}
		ref := s.Refs()[0]
		refPlace := lint.Related{Location: c.At(ref.At), Note: "checks out the pull request's code"}
		for _, x := range s.CacheSaves() {
			evs, guard, ok := guarded(x.SaveOn, s.Guard(), s.SHA())
			if !ok || len(evs) == 0 {
				continue // the release refuses the fork's code, or the step does not save on the attacker's events
			}
			save, inner := x.Name, ""
			if len(x.Via) > 0 {
				// a step of a composite action the step of the job runs
				save = x.Name + " of " + x.Via[len(x.Via)-1].Uses
				inner = " " + placeAnchor(c, x.Via, x.PathAt)
			}
			if x.Substituted {
				if q := x.Step.Path() + inner; !remoteGaps[q] {
					remoteGaps[q] = true
					c.Inconclusive(lint.InconclusiveDraft{KindID: archiveSubstituted, Location: c.At(x.At), Related: slices.Concat([]lint.Related{refPlace}, labelerRelated(c, s.Approval(), s.AutomaticApproval())),
						Note: fmt.Sprintf("%s saves %s to the cache after %s checks out %s; the archive the runner downloads of %s has the file of the action unlike its blob (export-subst), so the step the runner runs may differ from the step the linter read: compare the archive with the blob", save, x.Line, s.UsesText(), ref.Text, x.Via[len(x.Via)-1].Uses)})
				}
				continue
			}
			if !x.Known {
				q := x.Step.Path() + inner
				if len(x.Via) == 0 && attackerPaths[x.Step] || unknownPaths[q] {
					continue
				}
				unknownPaths[q] = true
				rel := []lint.Related{refPlace}
				if len(x.Via) > 0 {
					rel = append(rel, lint.Related{Location: c.At(x.PathAt), Note: "the path that " + save + " saves to the cache"})
				}
				c.Inconclusive(lint.InconclusiveDraft{KindID: cachePathUnknown, Location: c.At(x.At), Related: slices.Concat(rel, labelerRelated(c, s.Approval(), s.AutomaticApproval())),
					Note: fmt.Sprintf("%s saves %s to the cache after %s checks out %s; whether it has the checked out tree is not known", save, x.Line, s.UsesText(), ref.Text)})
				continue
			}
			evidence := []lint.Related{refPlace}
			if len(x.Via) > 0 {
				evidence = append(evidence, lint.Related{Location: c.At(x.PathAt), Note: "the path that " + save + " saves to the cache"})
			}
			// two checkouts of the same reference into two places saved by one step
			c.Report(lint.FindingDraft{Location: c.At(x.At), Anchor: ref.Text + "@" + s.Key().Path() + inner,
				Args:      CachePoisoningSavedCheckout{Uses: s.UsesText(), CheckoutRef: ref.Text, Save: save, Path: x.Line, CacheWriteOn: eventsOf(evs)},
				Evidence:  evidence,
				Related:   labelerRelated(c, s.Approval(), s.AutomaticApproval()),
				Condition: allOf(approval, guard)})
		}
		for _, u := range s.UnansweredCalls() {
			q := hopsText(u.Via)
			if remoteGaps[q] {
				continue
			}
			remoteGaps[q] = true
			c.Inconclusive(lint.InconclusiveDraft{KindID: remoteUnknown, Location: c.At(u.At), Related: slices.Concat([]lint.Related{refPlace}, labelerRelated(c, s.Approval(), s.AutomaticApproval())),
				Note: fmt.Sprintf("the action %s, which runs after %s checks out %s in a job that may save to the cache of the default branch's scope, was asked of action.definition and has no answer (%s): whether a step of the action saves the checked out tree is not known", u.Via[len(u.Via)-1].Uses, s.UsesText(), ref.Text, u.Reason)})
		}
	}
	for _, s := range v.CacheSaves() {
		// before the approval: a run of workflow_dispatch has no label
		dispatched := len(s.DispatchOn()) > 0
		if dispatched {
			for i, refs := range [][]ir.ExprRef{s.KeyRefs(), s.PathRefs()} {
				what := [...]string{"key", "path"}[i]
				for _, r := range refs {
					if r.Verdict == analysis.Inconclusive && r.InconclusiveKind == analysis.InconclusiveRefInputDispatch {
						c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(r.At),
							Note: fmt.Sprintf("%s is in the %s of %s, which saves to the cache of the scope of the ref of the run; the one who dispatches the workflow chooses the value and the ref", r.Text, what, s.UsesText())})
					}
				}
			}
		}
		if len(s.CacheWriteOn()) == 0 {
			continue
		}
		cond, ok := approvalCond(c, s.CacheApproval(), s.Environment(), s.AutomaticApproval(), s.At(), stepRef(s.UsesText()), nil)
		if !ok {
			continue
		}
		labeler := labelerRelated(c, s.CacheApproval(), s.AutomaticApproval())
		seen := anchors{}
		report := func(refs []ir.ExprRef, args func(r ir.ExprRef, on []analysis.EventActivity) lint.FindingArgs, what string) {
			for _, r := range refs {
				at := c.At(r.At)
				switch r.Verdict {
				case analysis.Controlled:
					on := controlledOn(r, s.CacheWriteOn())
					if len(on) == 0 {
						continue
					}
					evidence, related := valueEvidence(c, r, r.Text)
					c.Report(lint.FindingDraft{Location: at, Anchor: seen.next(what+" "+r.Text, ir.FixPlan{}), Args: args(r, on), Evidence: evidence, Related: append(related, labeler...), Condition: cond})
				case analysis.Inconclusive:
					if dispatched && r.InconclusiveKind == analysis.InconclusiveRefInputDispatch {
						continue // reported above
					}
					c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(r.InconclusiveKind), Location: at,
						Note: fmt.Sprintf("%s is in the %s of %s, which saves to the cache of the default branch's scope; whether an attacker controls it is not analyzed (%s)", r.Text, what, s.UsesText(), r.InconclusiveKind)})
				}
			}
		}
		report(s.KeyRefs(), func(r ir.ExprRef, on []analysis.EventActivity) lint.FindingArgs {
			return CachePoisoningAttackerKey{Uses: s.UsesText(), Expression: r.Text, CacheWriteOn: eventsOf(on)}
		}, "key")
		report(s.PathRefs(), func(r ir.ExprRef, on []analysis.EventActivity) lint.FindingArgs {
			return CachePoisoningAttackerPath{Uses: s.UsesText(), Expression: r.Text, CacheWriteOn: eventsOf(on)}
		}, "path")
	}
	return nil
}

// cacheSaveRelated are the steps of the checkout s that save the checked
// out tree to the cache, with the path in a composite action that saves
// it. pr leaves out, as the findings of the checkout of a pull request's
// code do, the steps that save on no event of a pull request that the
// release of actions/checkout does not refuse.
func cacheSaveRelated(c *lint.RuleContext, s ir.CachePoisoningOfCheckoutSite, pr bool) []lint.Related {
	var out []lint.Related
	for _, x := range s.CacheSaves() {
		if !x.Known || x.Substituted {
			continue
		}
		if evs, _, ok := guarded(x.SaveOn, s.Guard(), s.SHA()); pr && (!ok || len(evs) == 0) {
			continue
		}
		save := x.Name
		if len(x.Via) > 0 {
			save = x.Name + " of " + x.Via[len(x.Via)-1].Uses
			out = append(out, lint.Related{Location: c.At(x.PathAt), Note: "the path that " + save + " saves to the cache"})
		}
		out = append(out, lint.Related{Location: c.At(x.At), Note: save + " saves " + x.Line + " to the cache"})
	}
	return out
}

// hopsText is the uses of hops, as written, joined by " > ".
func hopsText(hops []composite.Hop) string {
	var parts []string
	for _, h := range hops {
		parts = append(parts, h.Uses)
	}
	return strings.Join(parts, " > ")
}

// hopsAnchor is hopsText without the refs of the uses: the part of an
// anchor that tells the actions on the way apart, which a fix that pins
// the ref of the first uses (commit-sha's pin-sha) does not change.
func hopsAnchor(hops []composite.Hop) string {
	var parts []string
	for _, h := range hops {
		u, _, _ := strings.Cut(h.Uses, "@")
		parts = append(parts, u)
	}
	return strings.Join(parts, " > ")
}

// placeAnchor is the part of an anchor that tells apart the places of the
// actions and workflows of other repositories a step or a job runs, all
// at the uses of the step or the job: the actions on the way (hopsAnchor)
// and the path of the place at in the file it is written in.
func placeAnchor(c *lint.RuleContext, hops []composite.Hop, at ir.Handle) string {
	return hopsAnchor(hops) + " " + c.At(at).KeyPath().String()
}

// controlledOn are the events of evs on which an attacker controls r.
func controlledOn(r ir.ExprRef, evs []analysis.EventActivity) []analysis.EventActivity {
	if r.Verdict != analysis.Controlled {
		return nil
	}
	return slices.DeleteFunc(slices.Clone(r.ControlledOn), func(e analysis.EventActivity) bool { return !slices.Contains(evs, e) })
}

// environmentCond is the condition of a job approved by its environment:
// that the environment has no required reviewers (repo.environment-protected).
func environmentCond(c *lint.RuleContext, a analysis.Approval, env facts.EnvironmentName) *lint.Condition {
	if a != analysis.ApprovalEnvironment || c.Barriers().Passes(analysis.BarrierEnvironmentApproval) {
		return nil
	}
	return factCond(facts.RepoEnvironmentProtected{Repo: c.Repo(), Environment: env}, false)
}

var (
	observedCache = lint.MustDate("2026-10-13")
	cachingDocs   = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching")
	// the list of the triggers that may save to the default branch's scope
	cachingTriggers = lint.MustCitation("https://github.com/github/docs/blob/5815d11586b0796688963a98c889680e60d72dc4/content/actions/reference/workflows-and-actions/dependency-caching.md")
	cacheract       = lint.MustCitation("https://github.com/AdnaneKhan/Cacheract/blob/10f00b0cfba6a416c86a16145698720281436358/README.md")
	tanstack        = lint.MustCitation("https://tanstack.com/blog/npm-supply-chain-compromise-postmortem")

	cacheWrites     = lint.MustPreconditionID("cache-writes")
	restoredLater   = lint.MustPreconditionID("restored-later")
	savesTree       = lint.MustPreconditionID("saves-tree")
	attackerCacheIn = lint.MustPreconditionID("attacker-cache-input")
	tanstack2026    = lint.MustIncidentID("tanstack-2026")

	cachePathUnknown   = lint.MustInconclusiveKindID("cache-path-unknown")
	remoteUnknown      = lint.MustInconclusiveKindID("remote-unknown")
	archiveSubstituted = lint.MustInconclusiveKindID("archive-substituted")
)

// the CVSS of the kinds: a later run restores what the attacker saves
var (
	writableJobBase = lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker opens an issue, a comment or a pull request over the network"),
		AC: metric(lint.AttackComplexityLow, "once a flaw runs their code in the job, it saves to the cache as the job may, with no action of the cache needed (Cacheract)", cacheract),
		AT: metric(lint.AttackRequirementsPresent, "a flaw has to run the attacker's code in the job, and a later run has to restore the entry they save"),
		PR: metric(lint.PrivilegesRequiredNone, "on a public repository anyone opens an issue or a pull request from a fork"),
		UI: metric(lint.UserInteractionNone, "the event runs the job with nobody doing anything"),
		VC: metric(lint.ImpactNone, "the cache gives the run nothing to read that the job does not"),
		VI: metric(lint.ImpactLow, "the entries of the cache change; the repository does not as such"),
		VA: metric(lint.ImpactLow, "entries the attacker saves can push others out of the cache"),
		SC: metric(lint.ImpactHigh, "a later run that restores the entry runs it with its own secrets: in the TanStack incident a release run minted a token to publish", tanstack),
		SI: metric(lint.ImpactHigh, "what that run builds and publishes reaches those who use the repository: 84 versions of npm packages in the TanStack incident", tanstack),
		SA: metric(lint.ImpactNone, "nothing past the repository is made unavailable by this as such"),
	}
	savedCheckoutBase = lint.CVSS{
		AV: writableJobBase.AV, PR: writableJobBase.PR, UI: writableJobBase.UI, VC: writableJobBase.VC, VA: writableJobBase.VA, SC: writableJobBase.SC, SI: writableJobBase.SI, SA: writableJobBase.SA,
		AC: metric(lint.AttackComplexityLow, "a change of the files of the pull request under the path saved is all it takes"),
		AT: metric(lint.AttackRequirementsPresent, "a later run has to restore the entry, under the key the job saves it"),
		VI: metric(lint.ImpactLow, "the entry of the cache is the pull request's files; the repository does not change as such"),
	}
	attackerKeyBase = lint.CVSS{
		AV: writableJobBase.AV, PR: writableJobBase.PR, UI: writableJobBase.UI, VC: writableJobBase.VC, VA: writableJobBase.VA, SC: writableJobBase.SC, SI: writableJobBase.SI, SA: writableJobBase.SA,
		AC: metric(lint.AttackComplexityLow, "the attacker writes the key in the title, the branch's name or the comment the key reads"),
		AT: metric(lint.AttackRequirementsPresent, "a later run has to look up the key they choose before the job saves it itself, and restore what the job saves there"),
		VI: metric(lint.ImpactLow, "an entry of the cache is saved under the key they choose; the repository does not change as such"),
	}
	attackerPathBase = lint.CVSS{
		AV: writableJobBase.AV, PR: writableJobBase.PR, UI: writableJobBase.UI, VA: writableJobBase.VA, SI: writableJobBase.SI, SA: writableJobBase.SA,
		AC: metric(lint.AttackComplexityLow, "the attacker writes the path in the value the path reads"),
		AT: metric(lint.AttackRequirementsPresent, "what the job holds at the path they choose has to be worth reading or restoring: a credential a step left in the workspace, or files a later run runs"),
		VC: metric(lint.ImpactHigh, "anyone who can open a pull request reads the caches of the default branch, and so what the job saved: the credential a checkout leaves in .git/config among them", cachingDocs),
		VI: metric(lint.ImpactLow, "an entry of the cache has the files they choose; the repository does not change as such"),
		SC: metric(lint.ImpactLow, "a credential saved works for as long as it lasts: the GITHUB_TOKEN of the job until the job ends"),
	}
)

var cacheActors = withMergedCommitAppEvents(withAppCommitEventsAdded(exposureActorsWith([]lint.Gain{lint.GainWriteCache})))

// cacheValueAttackers are the attackers of the kinds of a value that an
// attacker writes: those of exposureAttackers, and the author of a merged
// commit, whose message the runs of status and check_suite have
// (withMergedCommitAppEvents).
var cacheValueAttackers = append(slices.Clone(exposureAttackers), lint.AttackerMergedCommitAuthor)

var cachePoisoningMeta = lint.Meta{
	ID:       CachePoisoningID,
	Problem:  "a job that an attacker's event runs, which no one approves, has a cache-mode that saves to the cache of the default branch's scope: what the attacker saves there, through a flaw that runs their code or by the job's own steps, later runs of the repository restore and run",
	Expected: "a job of an attacker's event whose cache-mode is read or none, or that has no cache-mode, which GitHub reads as read on such an event (on workflow_dispatch, a job with no cache-mode saves); the cache saved by a workflow whose key, path and checkout no attacker decides: a workflow that the attacker does not trigger, or a workflow on workflow_dispatch whose key, path and ref of the checkout no input of workflow_dispatch decides",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessExcessivePrivilege, lint.WeaknessUntrustedCodeExecution}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone, lint.AttackMeansCode, lint.AttackMeansString}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textCachePoisoningWritableJob,
			Attackers:       exposureAttackers,
			Preconditions:   []lint.PreconditionID{privilegedJob, noApproval, cacheWrites, flawInJob, restoredLater, appStatusCheck, callersEvents},
			Incidents:       []lint.IncidentID{tanstack2026},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected},
			Fixes:           []lint.FixKindID{CacheModeNoWriteID},
			CVSS:            writableJobBase,
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "Cacheract saves a cache from any code run in a job that may; the TanStack incident ran in a job that saved before GitHub made the attacker's events read the cache only, not through cache-mode", cacheract, tanstack),
		},
		{
			FindingText:     textCachePoisoningSavedCheckout,
			Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor, lint.AttackerCommenter},
			Preconditions:   []lint.PreconditionID{privilegedJob, noApproval, cacheWrites, prTree, noGuard, savesTree, restoredLater, appStatusCheck, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected, facts.KindGitCommitContains},
			CVSS:            savedCheckoutBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "the reports found save a cache through code run in the job (TanStack), not the tree of a pull request as it is"),
		},
		{
			FindingText:     textCachePoisoningAttackerKey,
			Attackers:       cacheValueAttackers,
			Preconditions:   []lint.PreconditionID{privilegedJob, noApproval, cacheWrites, attackerCacheIn, restoredLater, appStatusCheck, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected},
			CVSS:            attackerKeyBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report found saves under a key an attacker writes"),
		},
		{
			FindingText:     textCachePoisoningAttackerPath,
			Attackers:       cacheValueAttackers,
			Preconditions:   []lint.PreconditionID{privilegedJob, noApproval, cacheWrites, attackerCacheIn, appStatusCheck, callersEvents},
			FactKinds:       []facts.Kind{facts.KindRepoEnvironmentProtected},
			CVSS:            attackerPathBase,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report found saves a path an attacker writes"),
		},
	},
	Threat: lint.Threat{
		Actors: cacheActors,
		Preconditions: []lint.Precondition{
			appStatusCheckPre,
			callersEventsPre,
			{ID: privilegedJob, Text: "the job runs on an event that one without write access triggers, which runs on the default branch: pull_request_target, workflow_run, issue_comment, issues, discussion, discussion_comment, fork; status, check_suite and check_run where an app outside GitHub Actions makes a commit status or a check run for a commit whose message an attacker writes (the precondition app-status-check); not pull_request, whose caches are of the merge ref, with cache-mode write too; not pull_request_review and pull_request_review_comment, whose caches the rule reads as of the merge ref too (the undetected form review-event); not workflow_dispatch, which one with write access to the permission Actions dispatches and for which the one who dispatches the workflow chooses only a branch or a tag of the repository and the inputs: the run builds the repository's code, and a key, a path or a checkout that an input of workflow_dispatch decides is the inconclusive kind input-dispatch",
				Observed: []lint.Observation{{Date: observedCache, Runner: runner, What: "a pull_request run saved its caches to refs/pull/<n>/merge, with cache-mode: write too"}},
				Cites:    []lint.Citation{cachingDocs}},
			{ID: noApproval, Text: "no one approves the run: either the job runs on at least one event other than pull_request_target with the activity type labeled, and a run on the other event starts with no label added, or no person adds the label that starts the run, as the label is " + labelerAddedLabel + "; and the job has no environment that has required reviewers (repo.environment-protected, assumed false: an environment is made with no protection rules)",
				Observed: []lint.Observation{{Date: observedCheckout, Runner: runner, What: "a push after the label ran no labeled run, and ran pull_request_target on synchronize"}}},
			{ID: cacheWrites, Text: "the job's cache-mode, or else the workflow's, is write or write-only: on those events GitHub lets a job save to the cache of the default branch's scope only then; a reusable workflow's, when the job that calls it writes none",
				Observed: []lint.Observation{{Date: observedCache, Runner: runner, What: "on pull_request_target, issue_comment and workflow_run, a job with cache-mode write or write-only saved a cache to the default branch's scope, and one without it was denied"}},
				Cites:    []lint.Citation{cachingDocs, cachingTriggers}},
			{ID: flawInJob, Text: "a flaw runs the attacker's code in the job: an injection, a checkout of their code; the code saves to the cache with no action of the cache needed; the rule does not look for it, the other rules report those they see", Cites: []lint.Citation{cacheract}},
			{ID: restoredLater, Text: "a later run of the repository restores the entry and runs what it has: any workflow of the default branch restores its caches, and the attacker can save under a key that run looks up next", Cites: []lint.Citation{cachingDocs, tanstack}},
			prTreePre,
			noGuardPre,
			{ID: savesTree, Text: "actions/cache, at the end of the job, or actions/cache/save after the checkout, saves a path that is the tree, in it or above it: a path in the workspace, no clean checkout of the same place done in between", Cites: []lint.Citation{cachingDocs}},
			{ID: attackerCacheIn, Text: "the key or the path of actions/cache or actions/cache/save has a value the attacker writes on the event: the title, the body or the branch of the pull request or the issue, the comment", Cites: []lint.Citation{cachingDocs}},
		},
		Incidents: []lint.Incident{
			{ID: tanstack2026, Date: lint.MustDate("2026-05-11"), Advisory: tanstack,
				Compromised: repos("TanStack/router"),
				Summary:     "a pull request ran its code in a pull_request_target job, whose actions/cache saved the pnpm store the code changed to the default branch's scope under the key of the release workflow; the release workflow restored it and published 84 versions of npm packages"},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow},
	UndetectedForms: withRemoteCallee(append([]lint.UndetectedForm{
		mergedCommitPush(kindCachePoisoningAttackerKey, kindCachePoisoningAttackerPath),
		{ID: lint.MustUndetectedFormID("restore-keys"), Text: "restore-keys with a value an attacker writes: it chooses what is restored among the entries of the default branch's scope, which only the repository's runs or another flaw save; it saves nothing", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("remote-composite-unanswered"), Text: "a step of a composite action of another repository, run after a checkout of the pull request's code, that saves the checked out tree to the cache, when action.definition has no answer and the run did not ask GitHub (a run without --online and without the answer in --facts): the rule does not read the action; on the job the rule reports writable-job, not saved-checkout", FindingKinds: []lint.FindingKindID{kindCachePoisoningSavedCheckout}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("default-cache"), Text: "a job with no cache-mode that runs on one of the events of an attacker that the rule reads (pull_request_target, workflow_run, issue_comment, issues, discussion, discussion_comment, fork, status, check_suite, check_run): GitHub gives a run of an event other than push, workflow_dispatch, repository_dispatch, delete, registry_package, page_build and schedule read access only to the cache of the default branch's scope, so GitHub denies the save of actions/cache without failing the step", Disposition: lint.NoAddedGain()},
		reviewCacheLimit, repositoryDispatchLimit, deploymentStatusLimit, dispatchRelayLimit, dispatchInputCallLimit, dispatchDerivedLimit,
		npmAbbreviation(),
		npmOptionValueCommand(),
		{ID: lint.MustUndetectedFormID("dispatch-job"), Text: "a job on workflow_dispatch that saves to the cache, or runs, the code of a ref of the repository, with no input of workflow_dispatch in the ref and the repository of its checkout: the one who dispatches the workflow chooses as the ref of the run only a branch or a tag of the repository, so the job saves what those who can write to the repository pushed", Disposition: lint.NoAddedGain()},
	}, automaticLabelForms...)),
	FalsePositiveForms: withCallee(append([]lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("cache-mode-over-request"), Text: "a job that calls a reusable workflow with cache-mode write-only, where the job of the reusable workflow writes cache-mode write: cache-mode write-only of the calling job does not grant the restore that cache-mode write asks for, so GitHub does not start the run, but the rule reads cache-mode write-only of the calling job as a mode that lets the reusable workflow save to the cache",
			FindingKinds: []lint.FindingKindID{kindCachePoisoningWritableJob, kindCachePoisoningSavedCheckout}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("nested-caller-limit"), Text: "a reusable workflow called through another one, whose first caller writes cache-mode read or none: that limit holds for every workflow it calls, and GitHub does not start a run that asks for more; the rule reads the limit of the caller next to the workflow only",
			FindingKinds: []lint.FindingKindID{kindCachePoisoningWritableJob, kindCachePoisoningSavedCheckout, kindCachePoisoningAttackerKey, kindCachePoisoningAttackerPath}, Disposition: lint.Todo(lint.NeedRepoFile)},
		writerString(kindCachePoisoningAttackerKey, kindCachePoisoningAttackerPath), ifUnnarrowedFalsePositive(kindCachePoisoningAttackerKey, kindCachePoisoningAttackerPath),
	}, automaticLabelFalsePositives(kindCachePoisoningWritableJob, kindCachePoisoningSavedCheckout, kindCachePoisoningAttackerKey, kindCachePoisoningAttackerPath)...), kindCachePoisoningWritableJob, kindCachePoisoningSavedCheckout, kindCachePoisoningAttackerKey, kindCachePoisoningAttackerPath),
	InconclusiveKinds: withRemoteCalleeUnknown(append(append(slices.Clone(valueGaps), automaticLabelKinds...),
		lint.InconclusiveKind{ID: cachePathUnknown, Text: "the path of a step that saves to the cache after a checkout of a pull request's code, whose line a ${{ }} that is not the workspace's decides: whether it has the tree is not known", Disposition: lint.Todo(lint.NeedSameFile)},
		lint.InconclusiveKind{ID: remoteUnknown, Text: "a uses of another repository, run by a step that may save to the cache what a checkout of a pull request's code brings, whose action.definition was asked and has no answer (the archive is larger than the limit, the run has used up the requests it may send to the GitHub API, the token cannot read the repository, or the action is deeper than the 4 levels of actions the linter reads): whether a step of the action saves the checked out tree is not known.", Disposition: lint.Todo(lint.NeedFact)},
		lint.InconclusiveKind{ID: archiveSubstituted, Text: "a step of a composite action of another repository that saves to the cache what a checkout of a pull request's code brings, whose action.yml (or action.yaml) in the archive the runner downloads is unlike its blob (export-subst): placeholders such as %d and %(describe) take the names of refs created after the commit, so the step the runner runs may differ from the step the linter read", Disposition: lint.Limitation(lint.DeciderRunTime)})),
	FixKinds: []lint.FixKind{{
		ID:                  CacheModeNoWriteID,
		Title:               "save nothing to the cache on the attacker's events: cache-mode read (or none for write-only)",
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectCacheNotSaved},
	}},
}

// reviewCacheLimit is the form of the review events, which the rule does
// not read: a run of a review saves a cache to the merge ref of its pull
// request, as the documents say of a run on a pull request.
var reviewCacheLimit = lint.UndetectedForm{ID: lint.MustUndetectedFormID("review-event"), Text: "a job with cache-mode write or write-only that runs on pull_request_review or pull_request_review_comment: the rule reads the caches of a run of a review as saved to the merge ref of the pull request (refs/pull/<n>/merge), not to the scope of the default branch, as GitHub's documentation says of the caches of a run on a pull request; the authors of the linter saw no run of a review save a cache, and did not see whether a later run of the pull request, which has the secrets of the repository, restores such a cache", Disposition: lint.Todo(lint.NeedSameFile, lint.NeedFact)}

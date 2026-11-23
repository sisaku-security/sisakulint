package rules

import (
	"context"
	"sync"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// ImpostorCommit is the rule impostor-commit: a step's uses of another
// repository pinned to a full SHA that no branch and no tag of that
// repository has. Forks share their objects with the repository, so a
// commit pushed to anyone's fork can be named by the repository's name, and
// the runner runs it. It has no fix: which commit of the repository to pin
// to is not known from the workflow.
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var ImpostorCommit lint.Rule = withExamples(lint.WithView[ir.ImpostorCommitReader](impostorCommit{}, ir.ImpostorCommitView))

// ImpostorCommitID is the ID of impostor-commit.
var ImpostorCommitID = lint.MustRuleID("impostor-commit")

type impostorCommit struct{}

// maxAsked is how many facts one Check asks at once.
const maxAsked = 8

func (impostorCommit) Meta() lint.Meta { return impostorCommitMeta }

// A reusable workflow's uses is not looked at: GitHub refuses one whose
// commit no branch or tag of the repository has.
func (impostorCommit) Check(ctx context.Context, c *lint.RuleContext, v ir.ImpostorCommitReader) error {
	type pinned struct {
		u ir.ImpostorCommitOfUses
		q facts.GitCommitRef
	}
	var all []pinned
	for _, u := range v.Uses() {
		if u.AlwaysSkipped() {
			continue // GitHub skips its job in every run
		}
		if u.Level() != ir.UsesInStep || !fullSHA.MatchString(u.Ref()) || u.Outside() && !u.ReadByOutside() {
			continue // a uses above the root of its repository runs another directory: the commit is fetched, and runs only when another uses goes into its directory
		}
		repo, err := facts.ParseRepo(u.Repo())
		if err != nil {
			continue // not a repository GitHub can have: the runner cannot fetch it
		}
		sha, _ := facts.ParseSHA(u.Ref())
		all = append(all, pinned{u, facts.GitCommitRef{Repo: repo, SHA: sha}})
	}
	// The engine evaluates the conditions one at a time, and a question can
	// take seconds; asked here at once, the answers wait in c.Resolver.
	asked := map[facts.GitCommitRef]bool{}
	sem := make(chan struct{}, maxAsked)
	var wg sync.WaitGroup
	for _, p := range all {
		if asked[p.q] {
			continue
		}
		asked[p.q] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p.q.Ask(ctx, c.Resolver)
		}()
	}
	wg.Wait()
	for _, p := range all {
		cond := lint.FactAbsent(p.q)
		c.Report(lint.FindingDraft{
			Location:  c.At(p.u.RefAt()),
			Args:      ImpostorCommitForkCommit{Uses: p.u.UsesText(), Repo: p.u.Repo(), SHA: p.q.SHA},
			Condition: &cond,
		})
	}
	return nil
}

var (
	observedForks    = lint.MustDate("2026-09-25")
	observedLockfile = lint.MustDate("2026-10-14")

	chainguard = lint.MustCitation("https://www.chainguard.dev/unchained/what-the-fork-imposter-commits-in-github-actions-and-ci-cd")
	trivy      = lint.MustCitation("https://github.com/advisories/GHSA-69fq-xp46-6x23")
	trivyKEV   = lint.MustCitation("https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-33634")

	// the preconditions and the incident of impostor-commit's threat
	forkCommitRuns  = lint.MustPreconditionID("fork-commit-runs")
	callerWritesSHA = lint.MustPreconditionID("caller-writes-sha")
	notReusable     = lint.MustPreconditionID("not-reusable")
	trivy2026       = lint.MustIncidentID("trivy-2026")
)

var impostorCommitMeta = lint.Meta{
	ID:       ImpostorCommitID,
	Problem:  "a step's uses is pinned to a full SHA that no branch and no tag of the repository it names has, such as a commit only in a fork",
	Expected: "the SHA is of a commit that a branch or a tag of the repository it names has",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedReference}, AttackMeans: []lint.AttackMeans{lint.AttackMeansOperation}},
	FindingKinds: []lint.FindingKind{{
		FindingText:   textImpostorCommitForkCommit,
		Attackers:     []lint.Attacker{lint.AttackerForkerOfCalled},
		Preconditions: []lint.PreconditionID{forkCommitRuns, callerWritesSHA, notReusable},
		Incidents:     []lint.IncidentID{trivy2026},
		FactKinds:     []facts.Kind{facts.KindGitCommitRef},
		CVSS: lint.CVSS{
			AV: metric(lint.AttackVectorNetwork, "the attacker pushes to a fork, over the network"),
			AC: metric(lint.AttackComplexityLow, "a fork and a push are all it takes"),
			AT: metric(lint.AttackRequirementsNone, "anyone can fork a public repository; nothing of the repository called is needed"),
			PR: metric(lint.PrivilegesRequiredNone, "nothing of the calling repository is needed"),
			UI: metric(lint.UserInteractionActive, "someone of the calling repository merges the change that writes the SHA", chainguard),
			VC: metric(lint.ImpactHigh, "the code reads the job's secrets and GITHUB_TOKEN"),
			VI: metric(lint.ImpactHigh, "with the job's token the code can push, and write releases, artifacts and caches; in the Trivy incident the impostor put malicious code in a release", trivy),
			VA: metric(lint.ImpactLow, "the code can fail or stop the job"),
			SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
			SI: metric(lint.ImpactHigh, "what the job publishes (releases, packages) reaches those who use it"),
			SA: metric(lint.ImpactNone, "nothing past the job is made unavailable by this as such"),
		},
		ExploitMaturity: metric(lint.ExploitMaturityAttacked, "in the Trivy incident of 2026-03 the attacker swapped actions/checkout for an impostor commit in a workflow; CISA lists it in its Known Exploited Vulnerabilities", trivy, trivyKEV),
	}},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerForkerOfCalled,
			Via:      "pushes a commit to a fork, and has its SHA written in a change the caller merges",
			Gains:    jobGains,
		}},
		Preconditions: []lint.Precondition{
			{
				ID:   forkCommitRuns,
				Text: "a commit only in a fork is fetched and run by the repository's name",
				Observed: []lint.Observation{
					{Date: observedForks, Runner: runner, What: "a step's uses, and one in a composite action, ran a commit pushed only to a fork, the head of a pull request from a fork, and a commit left by a deleted branch, all by the name of the repository forked"},
					{Date: observedLockfile, Runner: runner, What: "a step's uses of a commit only in a fork, by its SHA, ran it with the workflow onboarded to the repository's workflow dependency lockfile (.github/workflows/actions.lock) and the lockfile recording that SHA as both its ref and its commit"},
				},
				Cites: []lint.Citation{chainguard},
			},
			{
				ID:    callerWritesSHA,
				Text:  "the caller writes that SHA, which looks like any other: a change that pins actions to SHAs, with one of them a fork's, is merged",
				Cites: []lint.Citation{chainguard, secureUse},
			},
			{
				ID:   notReusable,
				Text: "not a reusable workflow: GitHub refuses one whose commit no branch or tag of the repository has",
				Observed: []lint.Observation{
					{Date: observedForks, What: "a reusable workflow pinned to a commit of a fork, of a pull request's head, of a deleted branch or to a tag object failed the whole run; one pinned under a branch or at a tag ran"},
				},
			},
		},
		Incidents: []lint.Incident{
			trivy2026Incident,
		},
	},
	Citations: []lint.Citation{cvss},
	// Offline, every step's uses pinned to a full SHA would be conditional,
	// with nothing to tell one SHA from another: the rule runs by default
	// only where an answer of git.commit-ref can come (as archived-uses).
	DefaultRun:        lint.DefaultRunFacts(facts.KindGitCommitRef),
	Targets:           []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	InconclusiveKinds: withRemoteCalleeUnknown(nil),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("reusable-workflow"), Text: "a job's uses (a reusable workflow): GitHub refuses one whose commit no branch or tag of the repository has, so the run never starts", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("sha256"), Text: "a ref of 64 hexadecimal digits (a SHA-256 repository): commit-sha reports it as not pinned", Disposition: lint.OtherRule(CommitSHAID)},
		{ID: lint.MustUndetectedFormID("not-sha"), Text: "a ref that is not a full SHA (a tag, a branch, a shortened SHA): commit-sha reports it", Disposition: lint.OtherRule(CommitSHAID)},
	}),
}

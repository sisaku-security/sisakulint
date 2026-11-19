package rules

import (
	"context"
	"strings"
	"sync"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// KnownVulnerableActions is the rule known-vulnerable-actions: a uses of
// another repository whose version is in the range of an advisory of the
// GitHub Advisory Database. The version is the most precise version tag
// that points to the commit the runner runs, and GitHub compares it with
// the ranges. A finding's kind is the severity GitHub rates the advisory,
// which is not the Severity of the kind. The fix, of a uses pinned to a
// full SHA, pins the commit of the first version that fixes every advisory
// found and is in the range of no advisory of the package.
var KnownVulnerableActions lint.Rule = withExamples(lint.WithView[ir.KnownVulnerableActionsReader](knownVulnerableActions{}, ir.KnownVulnerableActionsView))

// KnownVulnerableActionsID is the ID of known-vulnerable-actions, and
// UpgradeVersionID the kind of its fix.
var (
	KnownVulnerableActionsID = lint.MustRuleID("known-vulnerable-actions")
	UpgradeVersionID         = lint.MustFixKindID("upgrade-version")
)

type knownVulnerableActions struct{}

func (knownVulnerableActions) Meta() lint.Meta { return knownVulnerableActionsMeta }

// usesRef is a uses the rule reads: a summary of the input
// (ir.KnownVulnerableActionsOfUses), or a step of a composite action of
// another repository (innerUses).
type usesRef interface {
	UsesText() string
	Ref() string
	Repo() string
	Path() string
	Exact() bool
	ReadByOutside() bool
	RefAt() ir.Handle
}

// innerUses is the uses of a step of a composite action of another
// repository that a step of the input runs (ir.CompositeStep): RefAt is
// the uses of that step of the input, where its findings are.
type innerUses struct {
	s  ir.CompositeStep
	at ir.Handle
}

func (u innerUses) UsesText() string    { return u.s.UsesText }
func (u innerUses) Ref() string         { return u.s.Ref }
func (u innerUses) Repo() string        { return u.s.Repo }
func (u innerUses) Path() string        { return u.s.Path }
func (u innerUses) Exact() bool         { return false }
func (u innerUses) ReadByOutside() bool { return false }
func (u innerUses) RefAt() ir.Handle    { return u.at }

// vulnerableUses is a uses the rule reads, and the packages it names:
// owner/repo, and owner/repo/path when it has a path. inside is, for the
// step of a composite action of another repository, that composite
// action's uses; empty for a uses of the input.
type vulnerableUses struct {
	u        usesRef
	inner    *ir.CompositeStep
	repo     facts.Repo
	packages []facts.PackageName
}

func (knownVulnerableActions) Check(ctx context.Context, c *lint.RuleContext, v ir.KnownVulnerableActionsReader) error {
	var all []vulnerableUses
	add := func(u usesRef, inner *ir.CompositeStep) {
		repo, err := facts.ParseRepo(u.Repo())
		if err != nil {
			return // not a repository GitHub can have: the runner cannot fetch it
		}
		root, err := facts.ParsePackageName(u.Repo())
		if err != nil {
			return
		}
		vu := vulnerableUses{u: u, inner: inner, repo: repo, packages: []facts.PackageName{root}}
		if u.Path() != "" {
			if p, err := facts.ParsePackageName(u.Repo() + "/" + u.Path()); err == nil {
				vu.packages = append(vu.packages, p)
			}
		}
		all = append(all, vu)
	}
	for _, u := range v.Uses() {
		if u.Outside() {
			continue // owner/repo does not run; what runs is another uses' or a composite action's (remote-composite)
		}
		add(u, nil)
	}
	// the uses inside the composite actions of other repositories the
	// steps run (action.definition); those of an action.yml of the inputs
	// are the findings of that input
	for _, call := range v.CompositeCalls() {
		substituted := map[string]bool{}
		for _, s := range call.Steps() {
			switch {
			case s.Query == nil || s.Repo == "":
			case s.Substituted:
				// the step the runner runs may differ from the step the linter read
				if q := hopsText(s.Chain); !substituted[q] {
					substituted[q] = true
					c.Inconclusive(lint.InconclusiveDraft{KindID: archiveSubstituted, Location: c.At(call.At()),
						Related: []lint.Related{{Location: c.At(s.At), Note: "the step of the composite action " + s.Chain[len(s.Chain)-1].Uses + " that uses " + s.UsesText}},
						Note:    "the archive the runner downloads of the composite action " + s.Chain[len(s.Chain)-1].Uses + " has the file of the action unlike its blob (export-subst), so the actions its steps use may differ from those read: compare the archive with the blob"})
				}
			default:
				add(innerUses{s: s, at: call.At()}, &s)
			}
		}
		for _, u := range call.Unanswered() {
			if u.Asked {
				c.Inconclusive(lint.InconclusiveDraft{KindID: remoteUnknown, Location: c.At(call.At()),
					Note: "the action " + u.Chain[len(u.Chain)-1].Uses + " was asked of action.definition and has no answer (" + u.Reason + "): whether a step of the action uses a vulnerable action is not known"})
			}
		}
	}
	// The engine evaluates one uses at a time, and a question can take
	// seconds; the first question of each uses, asked here at once, waits
	// in c.Resolver. Most packages have no advisory and stop there.
	var first []facts.Query
	for _, vu := range all {
		for _, p := range vu.packages {
			first = append(first, facts.PackageAdvisories{Package: p})
		}
	}
	askAll(ctx, c, first)
	for _, vu := range all {
		checkUses(ctx, c, vu)
	}
	return nil
}

// askAll asks qs, each once and at most maxAsked at a time.
func askAll(ctx context.Context, c *lint.RuleContext, qs []facts.Query) {
	asked := map[facts.Query]bool{}
	sem := make(chan struct{}, maxAsked)
	var wg sync.WaitGroup
	for _, q := range qs {
		if asked[q] {
			continue
		}
		asked[q] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c.Resolver.Resolve(ctx, q)
		}()
	}
	wg.Wait()
}

func checkUses(ctx context.Context, c *lint.RuleContext, vu vulnerableUses) {
	at := c.At(vu.u.RefAt())
	anchor, inside := "", ""
	var evidence []lint.Related
	if s := vu.inner; s != nil {
		inside = s.Chain[len(s.Chain)-1].Uses
		anchor = " " + placeAnchor(c, s.Chain, s.At)
		evidence = []lint.Related{{Location: c.At(s.At), Note: "the step of the composite action " + inside + " that uses " + vu.u.UsesText()}}
	}
	inconclusive := func(k lint.InconclusiveKindID, note string) {
		if inside != "" {
			note = vu.u.UsesText() + ", a step of the composite action " + inside + ": " + note
		}
		c.Inconclusive(lint.InconclusiveDraft{KindID: k, Location: at, Related: evidence, Note: note})
	}
	// the packages that have advisories, and all their advisories
	var advised []facts.PackageName
	var all []facts.Advisory
	for _, p := range vu.packages {
		a := facts.PackageAdvisories{Package: p}.Ask(ctx, c.Resolver)
		switch a.State {
		case facts.StateUnknown:
			inconclusive(advisoriesUnknown, "the advisories of "+p.String()+" are not known ("+a.Reason+")")
			return
		case facts.StateFound:
			if len(a.Value) > 0 {
				advised = append(advised, p)
				all = append(all, a.Value...)
			}
		}
	}
	if len(advised) == 0 {
		return
	}
	sha, ok, why := runCommit(ctx, c, vu)
	switch {
	case !ok:
		return // the ref is not in the repository: the runner refuses it
	case why != "":
		inconclusive(versionUnknown, why)
		return
	}
	version, why := versionOf(ctx, c, vu.repo, sha)
	if why != "" {
		inconclusive(versionUnknown, why)
		return
	}
	if imprecise(version, all) {
		inconclusive(versionUnknown, "only "+version.String()+" names the version of "+sha.String()+", which GitHub compares as "+version.String()+".0.0, while a range of the advisories of the package has a bound within it")
		return
	}
	// GitHub answers with each advisory that affects the version, and all
	// its vulnerabilities of the package: one advisory may have several
	// ranges (GHSA-vqf5-2xx6-9wfm has one of 3.x and one of 2.x), of which
	// the one that has the version is the one to report and to fix.
	var found []vulnerability
	index := map[facts.GHSAID]int{}
	for _, p := range advised {
		a := facts.PackageAdvisories{Package: p, Version: version}.Ask(ctx, c.Resolver)
		if a.State != facts.StateFound {
			inconclusive(advisoriesUnknown, "the advisories of "+p.String()+"@"+version.String()+" are not known ("+a.Reason+")")
			return
		}
		for _, adv := range a.Value {
			has, err := rangeHas(adv.VulnerableVersionRange, version)
			i, seen := index[adv.GHSAID]
			switch {
			case !seen:
				index[adv.GHSAID] = len(found)
				found = append(found, vulnerability{adv: adv, pkg: p, matched: has && err == nil})
			case has && err == nil && !found[i].matched:
				found[i] = vulnerability{adv: adv, pkg: p, matched: true}
			}
		}
	}
	if len(found) == 0 {
		return
	}
	fix, noFix := upgrade(ctx, c, vu, version, found, all)
	for _, f := range found {
		c.Report(lint.FindingDraft{Location: at, Anchor: f.adv.GHSAID.String() + anchor, Args: advisoryArgs(vu.u.UsesText(), f.pkg, f.adv, version), Evidence: evidence, Fix: fix, NoFix: noFix})
	}
}

// vulnerability is an advisory of a uses, with the range of the package
// it was found of; matched is whether the rule reads that range as having
// the version too.
type vulnerability struct {
	adv     facts.Advisory
	pkg     facts.PackageName
	matched bool
}

// runCommit is the commit the runner runs for the uses: its ref when it is
// a full SHA, else the commit git.ref-commit answers. ok is false when the
// ref is not in the repository; why says why the commit is not known.
func runCommit(ctx context.Context, c *lint.RuleContext, vu vulnerableUses) (sha facts.SHA, ok bool, why string) {
	if fullSHA.MatchString(vu.u.Ref()) {
		s, _ := facts.ParseSHA(vu.u.Ref())
		return s, true, ""
	}
	a := facts.GitRefCommit{Repo: vu.repo, Ref: vu.u.Ref()}.Ask(ctx, c.Resolver)
	switch a.State {
	case facts.StateAbsent:
		return facts.SHA{}, false, ""
	case facts.StateUnknown:
		return facts.SHA{}, true, "the commit of " + vu.u.Ref() + " is not known (" + a.Reason + ")"
	}
	return a.Value.SHA, true, ""
}

// versionOf is the version of the commit sha of repo: of the tags that
// point to it whose names are versions, the one with the most numbers,
// and of those the greatest. A version of a major number alone, which
// GitHub compares as major.0.0, is taken only when there is no other.
func versionOf(ctx context.Context, c *lint.RuleContext, repo facts.Repo, sha facts.SHA) (facts.PackageVersion, string) {
	a := facts.GitCommitTags{Repo: repo, SHA: sha}.Ask(ctx, c.Resolver)
	if a.State != facts.StateFound {
		return facts.PackageVersion{}, "the tags of " + sha.String() + " are not known (" + a.Reason + ")"
	}
	var best facts.PackageVersion
	for _, n := range a.Value {
		name, ok := strings.CutPrefix(n.String(), "refs/tags/")
		if !ok {
			continue
		}
		v, err := facts.ParsePackageVersion(name)
		if err != nil {
			continue
		}
		if best.IsZero() || v.Parts() > best.Parts() || v.Parts() == best.Parts() && facts.ComparePackageVersions(v, best) > 0 {
			best = v
		}
	}
	if best.IsZero() {
		return best, "no version tag points to " + sha.String() + " (the head of a branch, or a commit between releases)"
	}
	return best, ""
}

// advisoryArgs are the arguments of the finding of adv, of the kind of its
// severity.
func advisoryArgs(uses string, p facts.PackageName, adv facts.Advisory, v facts.PackageVersion) lint.FindingArgs {
	switch adv.Severity {
	case facts.AdvisorySeverityCritical:
		return KnownVulnerableActionsAdvisoryCritical{Uses: uses, Package: p, GHSAID: adv.GHSAID, Version: v, VulnerableVersionRange: adv.VulnerableVersionRange.String()}
	case facts.AdvisorySeverityHigh:
		return KnownVulnerableActionsAdvisoryHigh{Uses: uses, Package: p, GHSAID: adv.GHSAID, Version: v, VulnerableVersionRange: adv.VulnerableVersionRange.String()}
	case facts.AdvisorySeverityMedium:
		return KnownVulnerableActionsAdvisoryMedium{Uses: uses, Package: p, GHSAID: adv.GHSAID, Version: v, VulnerableVersionRange: adv.VulnerableVersionRange.String()}
	case facts.AdvisorySeverityLow:
		return KnownVulnerableActionsAdvisoryLow{Uses: uses, Package: p, GHSAID: adv.GHSAID, Version: v, VulnerableVersionRange: adv.VulnerableVersionRange.String()}
	}
	// AdvisorySeverityUnknown: an Advisory has a severity (facts.Advisory's
	// UnmarshalJSON), so this is the one left
	return KnownVulnerableActionsAdvisoryUnknown{Uses: uses, Package: p, GHSAID: adv.GHSAID, Version: v, VulnerableVersionRange: adv.VulnerableVersionRange.String()}
}

// upgrade is the fix of the findings of the uses, or why there is none.
// Only a uses pinned to a full SHA is fixed: on a tag or a branch,
// commit-sha's fix writes a SHA in the same place, and two fixes of one
// place cannot both be applied.
func upgrade(ctx context.Context, c *lint.RuleContext, vu vulnerableUses, version facts.PackageVersion, found []vulnerability, all []facts.Advisory) (*lint.Fix, *lint.NoFix) {
	if s := vu.inner; s != nil {
		return nil, &lint.NoFix{Reason: ir.NoFixReasonManual, Note: vu.u.UsesText() + " is a step of the composite action " + s.Chain[len(s.Chain)-1].Uses + " of another repository, which this repository does not write: upgrade the composite action to a version whose step uses a version that fixes the advisories, or ask its maintainers to"}
	}
	if vu.u.ReadByOutside() {
		return nil, &lint.NoFix{Reason: ir.NoFixReasonManual, Note: "another uses of the steps goes with .. into the directory where the runner puts the action of this uses at this ref; the runner names that directory by the ref, so an upgrade of this uses changes the name of the directory, and the job fails before the steps run because the uses that goes into the directory finds no action; write the uses that goes into the directory as owner/repo/path@ref, without .., and then upgrade this uses"}
	}
	var target facts.PackageVersion
	for _, f := range found {
		adv := f.adv
		if !f.matched {
			return nil, &lint.NoFix{Reason: ir.NoFixReasonManual, Note: "no range of " + adv.GHSAID.String() + " reads as having " + version.String() + " (" + adv.VulnerableVersionRange.String() + "), though GitHub says it affects it; read the advisory for the version that fixes it"}
		}
		if adv.FirstPatchedVersion.IsZero() {
			return nil, &lint.NoFix{Reason: ir.NoFixReasonManual, Note: adv.GHSAID.String() + " names no version that fixes it; use another action, or a commit you have checked"}
		}
		if target.IsZero() || facts.ComparePackageVersions(adv.FirstPatchedVersion, target) > 0 {
			target = adv.FirstPatchedVersion
		}
	}
	// the version upgraded to must not be in the range of another
	// advisory of the package: while it is, it moves to the first patched
	// version of that advisory, which is greater, so the loop ends
	for moved := true; moved; {
		moved = false
		for _, a := range all {
			has, err := rangeHas(a.VulnerableVersionRange, target)
			switch {
			case err == nil && !has:
			case err == nil && !a.FirstPatchedVersion.IsZero() && facts.ComparePackageVersions(a.FirstPatchedVersion, target) > 0:
				target, moved = a.FirstPatchedVersion, true
			default:
				return nil, &lint.NoFix{Reason: ir.NoFixReasonManual, Note: target.String() + ", which fixes the advisories found, is in the range of " + a.GHSAID.String() + " (" + a.VulnerableVersionRange.String() + ") and " + a.GHSAID.String() + " names no later version that fixes it, or the range of " + a.GHSAID.String() + " is not read; choose a version that no advisory names"}
			}
		}
	}
	switch {
	case !vu.u.Exact():
		return nil, &lint.NoFix{Reason: ir.NoFixReasonForm, Note: "the ref is written with an escape; write it plainly, then upgrade it to " + target.String() + " or later"}
	case !fullSHA.MatchString(vu.u.Ref()):
		return nil, &lint.NoFix{Reason: ir.NoFixReasonManual, Note: "pin " + vu.u.UsesText() + " to a full commit SHA (the fix of commit-sha), and this fix then upgrades the pin; or write a version tag of " + target.String() + " or later"}
	}
	plain := strings.TrimPrefix(target.String(), "v")
	var asked []facts.Query
	for _, ref := range []string{"v" + plain, plain} {
		q := facts.GitRefCommit{Repo: vu.repo, Ref: ref}
		asked = append(asked, q)
		a := q.Ask(ctx, c.Resolver)
		switch a.State {
		case facts.StateUnknown:
			return nil, &lint.NoFix{Reason: ir.NoFixReasonFact, Queries: asked, Note: "the commit of the tag " + ref + " is not known (" + a.Reason + ")"}
		case facts.StateAbsent:
			continue
		}
		tag, ok := strings.CutPrefix(a.Value.Ref.String(), "refs/tags/")
		if !ok {
			continue // a branch of that name: not a release
		}
		pin, err := vu.u.RefAt().Replace(a.Value.SHA.String())
		if err != nil {
			return nil, &lint.NoFix{Reason: ir.NoFixReasonForm, Note: "the ref cannot be written in place (" + err.Error() + "); upgrade it to " + tag + " by hand"}
		}
		edits := []edit.Edit{pin}
		// the version as the comment, for people and for tools that update
		// pins (Dependabot); the old one names the version no longer run
		if cm, ok := vu.u.RefAt().SetCommentAtEnd(tag); ok {
			edits = append(edits, cm)
		}
		return &lint.Fix{KindID: UpgradeVersionID, Title: "upgrade " + vu.u.Repo() + " to " + tag + " (" + a.Value.SHA.String() + ")", Edits: edits, SideEffects: []ir.SideEffect{ir.SideEffectVersionChanged}}, nil
	}
	return nil, &lint.NoFix{Reason: ir.NoFixReasonManual, Note: vu.repo.String() + " has no tag v" + plain + " or " + plain + "; upgrade it to a release at or after " + target.String() + " by hand"}
}

var (
	observedAdvisories   = lint.MustDate("2026-10-15")
	observedRefConfusion = lint.MustDate("2026-10-15")

	restAdvisories = lint.MustCitation("https://github.com/github/rest-api-description/blob/507b88ecbdccb4789ce77228fa2f2fde4bdeaf1f/descriptions/api.github.com/api.github.com.json")
	xygeniAdvisory = lint.MustCitation("https://github.com/advisories/GHSA-f8q5-h5qh-33mh")
	dawidd6Advisor = lint.MustCitation("https://github.com/advisories/GHSA-5xr6-xhww-33m4")
	lycheeAdvisory = lint.MustCitation("https://github.com/advisories/GHSA-65rg-554r-9j5x")
	hardenAdvisory = lint.MustCitation("https://github.com/advisories/GHSA-g85v-wf27-67xc")
	trivyAction    = lint.MustCitation("https://github.com/advisories/GHSA-69fq-xp46-6x23")

	affectsVersion = lint.MustPreconditionID("affects-version")
	tagRuns        = lint.MustPreconditionID("tag-runs")

	advisoriesUnknown = lint.MustInconclusiveKindID("advisories-unknown")
	versionUnknown    = lint.MustInconclusiveKindID("version-unknown")
)

// advisoryCVSS is the CVSS of a kind of known-vulnerable-actions: the
// CVSS v4.0 vector of the advisory cited, the heaviest by the table of
// lint.FindingKind.Severity of the advisories GitHub rated rating in the
// actions ecosystem on 2026-10-15.
func advisoryCVSS(rating string, cite lint.Citation, v lint.CVSS) lint.CVSS {
	why := "as the CVSS v4.0 vector of " + cite.String() + ", the heaviest by this repository's table of the advisories GitHub rated " + rating + " in the actions ecosystem on 2026-10-15"
	set := func(r *string, cs *[]lint.Citation) { *r, *cs = why, []lint.Citation{cite} }
	set(&v.AV.Reason, &v.AV.Cites)
	set(&v.AC.Reason, &v.AC.Cites)
	set(&v.AT.Reason, &v.AT.Cites)
	set(&v.PR.Reason, &v.PR.Cites)
	set(&v.UI.Reason, &v.UI.Cites)
	set(&v.VC.Reason, &v.VC.Cites)
	set(&v.VI.Reason, &v.VI.Cites)
	set(&v.VA.Reason, &v.VA.Cites)
	set(&v.SC.Reason, &v.SC.Cites)
	set(&v.SI.Reason, &v.SI.Cites)
	set(&v.SA.Reason, &v.SA.Cites)
	return v
}

// vector is the metrics of a CVSS v4.0 vector, with no reason yet.
func vector(av lint.AttackVector, ac lint.AttackComplexity, at lint.AttackRequirements, pr lint.PrivilegesRequired, ui lint.UserInteraction, vc, vi, va, sc, si, sa lint.Impact) lint.CVSS {
	return lint.CVSS{
		AV: lint.Metric[lint.AttackVector]{Value: av}, AC: lint.Metric[lint.AttackComplexity]{Value: ac}, AT: lint.Metric[lint.AttackRequirements]{Value: at},
		PR: lint.Metric[lint.PrivilegesRequired]{Value: pr}, UI: lint.Metric[lint.UserInteraction]{Value: ui},
		VC: lint.Metric[lint.Impact]{Value: vc}, VI: lint.Metric[lint.Impact]{Value: vi}, VA: lint.Metric[lint.Impact]{Value: va},
		SC: lint.Metric[lint.Impact]{Value: sc}, SI: lint.Metric[lint.Impact]{Value: si}, SA: lint.Metric[lint.Impact]{Value: sa},
	}
}

var (
	// GHSA-f8q5-h5qh-33mh: AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
	worstAdvisory = advisoryCVSS("critical", xygeniAdvisory, vector(lint.AttackVectorNetwork, lint.AttackComplexityLow, lint.AttackRequirementsNone, lint.PrivilegesRequiredNone, lint.UserInteractionNone,
		lint.ImpactHigh, lint.ImpactHigh, lint.ImpactHigh, lint.ImpactNone, lint.ImpactNone, lint.ImpactNone))
	// GHSA-5xr6-xhww-33m4: AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N
	highAdvisory = advisoryCVSS("high", dawidd6Advisor, vector(lint.AttackVectorNetwork, lint.AttackComplexityLow, lint.AttackRequirementsNone, lint.PrivilegesRequiredNone, lint.UserInteractionNone,
		lint.ImpactNone, lint.ImpactHigh, lint.ImpactNone, lint.ImpactNone, lint.ImpactNone, lint.ImpactNone))
	// GHSA-65rg-554r-9j5x: AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N
	mediumAdvisory = advisoryCVSS("medium", lycheeAdvisory, vector(lint.AttackVectorNetwork, lint.AttackComplexityHigh, lint.AttackRequirementsNone, lint.PrivilegesRequiredNone, lint.UserInteractionNone,
		lint.ImpactHigh, lint.ImpactHigh, lint.ImpactNone, lint.ImpactNone, lint.ImpactNone, lint.ImpactNone))
	// GHSA-g85v-wf27-67xc: AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N
	lowAdvisory = advisoryCVSS("low", hardenAdvisory, vector(lint.AttackVectorNetwork, lint.AttackComplexityLow, lint.AttackRequirementsNone, lint.PrivilegesRequiredNone, lint.UserInteractionNone,
		lint.ImpactLow, lint.ImpactLow, lint.ImpactLow, lint.ImpactNone, lint.ImpactNone, lint.ImpactNone))
)

// advisoryKind is a kind of known-vulnerable-actions.
func advisoryKind(text lint.FindingText, cvss lint.CVSS, maturity lint.Metric[lint.ExploitMaturity], incidents ...lint.IncidentID) lint.FindingKind {
	return lint.FindingKind{
		FindingText:     text,
		Attackers:       []lint.Attacker{lint.AttackerAdvisoryAttacker},
		Preconditions:   []lint.PreconditionID{affectsVersion, tagRuns},
		Incidents:       incidents,
		Fixes:           []lint.FixKindID{UpgradeVersionID},
		CVSS:            cvss,
		ExploitMaturity: maturity,
	}
}

var knownVulnerableActionsMeta = lint.Meta{
	ID:       KnownVulnerableActionsID,
	Problem:  "a uses of another repository runs a version that an advisory of the GitHub Advisory Database says is vulnerable",
	Expected: "every uses runs a version no advisory names, or one the advisories say is fixed",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedReference}, AttackMeans: []lint.AttackMeans{lint.AttackMeansString, lint.AttackMeansCode, lint.AttackMeansOperation}},
	FindingKinds: []lint.FindingKind{
		advisoryKind(textKnownVulnerableActionsAdvisoryCritical, worstAdvisory,
			metric(lint.ExploitMaturityAttacked, "GHSA-69fq-xp46-6x23, which GitHub rates critical, is of the tags of aquasecurity/trivy-action moved to credential-stealing code in 2026; CISA lists it in its Known Exploited Vulnerabilities", trivyAction, trivyKEV), trivy2026),
		advisoryKind(textKnownVulnerableActionsAdvisoryHigh, highAdvisory,
			metric(lint.ExploitMaturityAttacked, "GHSA-mrrh-fwg8-r2c3 and GHSA-qmg3-hpqr-gqvc, which GitHub rates high, are of the tags of tj-actions/changed-files and reviewdog/action-setup moved in 2025; CISA lists both in its Known Exploited Vulnerabilities", tjActions, reviewdog, cisa), tjActions2025, reviewdog2025),
		advisoryKind(textKnownVulnerableActionsAdvisoryMedium, mediumAdvisory,
			metric(lint.ExploitMaturityUnreported, "the advisory cited for the CVSS says E:U in its own vector", lycheeAdvisory)),
		advisoryKind(textKnownVulnerableActionsAdvisoryLow, lowAdvisory,
			metric(lint.ExploitMaturityUnreported, "the advisory cited for the CVSS says E:U in its own vector", hardenAdvisory)),
		advisoryKind(textKnownVulnerableActionsAdvisoryUnknown, worstAdvisory,
			metric(lint.ExploitMaturityUnreported, "GET /advisories of the actions ecosystem gave no advisory GitHub had not rated on 2026-10-15, so none unrated is reported attacked")),
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerAdvisoryAttacker,
			Via:      "uses the vulnerability an advisory describes, in the way the advisory describes",
			Gains:    jobGains,
		}},
		Preconditions: []lint.Precondition{
			{
				ID:   affectsVersion,
				Text: "GitHub answers affects=package@version with the advisories whose range has that version; it reads a version of a major number alone as major.0.0, so the rule asks the most precise version tag of the commit",
				Observed: []lint.Observation{
					{Date: observedAdvisories, What: "affects=actions/download-artifact@v4, @4 and @4.1.2 gave GHSA-cxww-7g56-2vh6 (>= 4.0.0, < 4.1.3), @4.1.3 none; affects=tj-actions/changed-files@main gave none; the package was compared without case, and a version with or without v alike"},
				},
				Cites: []lint.Citation{restAdvisories},
			},
			{
				ID:   tagRuns,
				Text: "the runner runs the tag when a branch and a tag have the same name, for the uses of a step and of a job, so the version is read of the tag's commit",
				Observed: []lint.Observation{
					{Date: observedRefConfusion, Runner: runner, What: "a step's action and a reusable workflow, both named by a branch and a tag of one name, ran the commit of the tag"},
				},
			},
		},
		Incidents: []lint.Incident{tjActions2025Incident, reviewdog2025Incident, trivy2026Incident},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	// Offline, every uses is advisories-unknown: the rule runs by default
	// only where an answer of package.advisories can come.
	DefaultRun: lint.DefaultRunFacts(facts.KindPackageAdvisories),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: advisoriesUnknown, Text: "the advisories of the package are not known: no file of facts answers, and --online was not given or failed", Disposition: lint.Todo(lint.NeedFact)},
		{ID: remoteUnknown, Text: "a uses of another repository that a step reaches through composite actions, whose action.definition was asked and has no answer (the archive is larger than the limit, the run has used up the requests it may send to the GitHub API, the token cannot read the repository, or the action is deeper than the 4 levels of actions the linter reads): whether a step of the action uses a vulnerable action is not known", Disposition: lint.Todo(lint.NeedFact)},
		{ID: archiveSubstituted, Text: "a composite action of another repository whose action.yml (or action.yaml) in the archive the runner downloads is unlike its blob (export-subst): placeholders such as %d and %(describe) take the names of refs created after the commit, so the actions its steps use may differ from those read", Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: versionUnknown, Text: "the package has advisories, but the version the uses runs is not known: no version tag points to its commit (the head of a branch, a commit between releases), only a major tag does (v2) while a range has a bound within that major (< 2.7.5), or the commit or its tags are not known", Disposition: lint.Todo(lint.NeedFact)},
	}),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("url-package"), Text: "an advisory whose package is named by a URL (https://github.com/owner/repo/path) rather than owner/repo: GitHub does not give it for affects=owner/repo, and the rule does not ask by URL", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("remote-composite"), Text: "a vulnerable action that a composite action of another repository uses, when action.definition has no answer for the composite action (a run without --online and without the answer in --facts): the rule reads the steps of a composite action of another repository only from the answer", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("outside-other-path"), Text: "a uses whose path goes with .. above the root of its repository into the directory where the runner puts another uses' action, and names an action at another path there: the rule reads the other uses, not the action at that path", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("docker"), Text: "a uses of a Docker image (docker://): the actions ecosystem of the GitHub Advisory Database names packages by repository, not by image", Disposition: lint.NoAddedGain()},
		{ID: lint.MustUndetectedFormID("installed-version"), Text: "an action whose code installs a tool at the version that an input of the step gives, not at the version that the version tag of the action gives, where the version of the tool is in the range of an advisory and the version tag of the action is not (tmatens/compose-lint from v0.18.0 installs the version of the compose-lint package that the input whose name is version gives): the rule compares the ranges of the advisories with the version tag of the action, and does not read the code of the action, though the code of the action decides the version of the tool that the step installs", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("compromise-window"), Text: "an advisory of tags that were moved to malicious commits for a time and then moved back: its range has the versions whose tags were moved, though the commits they name now are not malicious (the advisory of tj-actions/changed-files says the tags are safe to use again)", FindingKinds: allAdvisoryKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("other-path"), Text: "an advisory of owner/repo, of the action at the root of the repository, read of an action at a path of the same repository whose code the vulnerability is not in", FindingKinds: allAdvisoryKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("repository-workflow"), Text: "an advisory whose vulnerability is in a workflow of the repository of the action, not in action.yml or the code that action.yml runs: a step that uses the action runs action.yml and the code that action.yml runs, not the workflows of the repository of the action, so the step does not run the vulnerable workflow; the answer of the GitHub Advisory Database does not say where the vulnerability is (the field vulnerable_functions is empty), so the rule cannot tell such an advisory from an advisory whose vulnerability is in action.yml or the code that action.yml runs", FindingKinds: allAdvisoryKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("installed-version"), Text: "an action whose code installs a tool at the version that an input of the step gives, or at the newest version in the registry of the tool when the job runs, not at the version that the version tag of the action gives, where the version tag of the action is in the range of an advisory and the version of the tool is not (tmatens/compose-lint from v0.18.0 with the input whose name is version set to latest, and tmatens/compose-lint up to v0.17.0 without the input whose name is version, install the newest version of the compose-lint package): the rule compares the ranges of the advisories with the version tag of the action, and does not read the code of the action, though the code of the action decides the version of the tool that the step installs", FindingKinds: allAdvisoryKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
		{ID: lint.MustFalsePositiveFormID("advisory-condition"), Text: "an advisory whose vulnerability needs an input, an event or a setting the step does not have: the rule does not read what the advisory says it needs", FindingKinds: allAdvisoryKinds, Disposition: lint.Limitation(lint.DeciderRunTime)},
	},
	FixKinds: []lint.FixKind{{
		ID:                  UpgradeVersionID,
		Title:               "pin a uses pinned to a full SHA to the commit of the first version that fixes every advisory found and is in the range of no advisory of the package, and name the version of the commit in the comment at the end of the line of the uses",
		FactKinds:           []facts.Kind{facts.KindGitRefCommit},
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectVersionChanged},
	}},
}

var allAdvisoryKinds = []lint.FindingKindID{kindKnownVulnerableActionsAdvisoryCritical, kindKnownVulnerableActionsAdvisoryHigh, kindKnownVulnerableActionsAdvisoryMedium, kindKnownVulnerableActionsAdvisoryLow, kindKnownVulnerableActionsAdvisoryUnknown}

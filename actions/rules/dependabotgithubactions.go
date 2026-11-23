package rules

import (
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// DependabotGitHubActions is the quality rule dependabot-github-actions:
// a file whose uses no update tool keeps current, when Dependabot version
// updates do not read the file and Renovate does not update the uses. Dependabot
// updates a uses pinned to a commit SHA too, so the rule counts those; and
// Renovate skips a SHA with no comment that names its version.
var DependabotGitHubActions lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.DependabotGitHubActionsReader](dependabotGitHubActions{}, ir.DependabotGitHubActionsView))

// DependabotGitHubActionsID is the ID of dependabot-github-actions.
var DependabotGitHubActionsID = lint.MustRuleID("dependabot-github-actions")

type dependabotGitHubActions struct{}

func (dependabotGitHubActions) QualityMeta() lint.QualityMeta { return dependabotGitHubActionsMeta }

var (
	// dependabotSHARe is a ref Dependabot reads as a commit SHA
	// (git_commit_checker.rb of dependabot-core).
	dependabotSHARe = regexp.MustCompile(`^[0-9a-f]{6,40}$`)
	// dependabotVersionRe is a ref Dependabot reads as a version
	// (VERSION_REGEX of git_commit_checker.rb; its look-behind ^v is
	// dependabotVPrefixRe).
	dependabotVersionRe = regexp.MustCompile(`(?i)(?:[12][0-9]{3}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])|[0-9]+\.[0-9]+(?:\.[a-z0-9-]+)*)$`)
	dependabotVPrefixRe = regexp.MustCompile(`(?i)^v[0-9]+(?:-[a-z0-9]+)?$`)
	// renovateSHARe is a ref Renovate reads as a commit SHA, whole or short
	// (parse.ts of the manager github-actions of renovate).
	renovateSHARe = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{6,7})$`)
	// renovatePinTokenRe and renovateBareTokenRe are the comments Renovate
	// reads as the version of a pinned SHA (parseComment of parse.ts).
	renovatePinTokenRe  = regexp.MustCompile(`^\s*(?:(?:renovate\s*:\s*)?(?:pin\s+|tag\s*=\s*)?|ratchet:[\w-]+/[.\w-]+(?:/[.\w-]+)*)?@?(?:[\w-]*[-/])?v?\d+(?:\.\d+(?:\.\d+)?)?(?:-[a-zA-Z0-9.]+)?`)
	renovateBareTokenRe = regexp.MustCompile(`^\s*\S+\s*$`)
)

// dependabotUpdates is whether Dependabot version updates update a uses
// whose ref is ref: a commit SHA or a version.
func dependabotUpdates(ref string) bool {
	return dependabotSHARe.MatchString(ref) || dependabotVersionRe.MatchString(ref) || dependabotVPrefixRe.MatchString(ref)
}

// renovateVersionComment is whether Renovate reads the comment c of the
// line of a uses as the version of its SHA.
func renovateVersionComment(c string) bool {
	if strings.TrimSpace(c) == "ratchet:exclude" {
		return false
	}
	return renovatePinTokenRe.MatchString(c) || renovateBareTokenRe.MatchString(c)
}

// dependabotDirectory is the directory of an entry of github-actions that
// reads the file p: / for a workflow right under .github/workflows and the
// action.yml at the root, else the directory of p. Another file at the
// root, which no directory reads, gets / too: such a file is no workflow
// GitHub runs, and comes only as a PATH or by stdin (or as an example).
func dependabotDirectory(p facts.InputPath) string {
	dir := strings.TrimSuffix(path.Dir(p.String()), "/")
	if dir == ".github/workflows" || dir == "." {
		return "/"
	}
	return "/" + dir
}

func (dependabotGitHubActions) Check(_ context.Context, c *lint.RuleContext, v ir.DependabotGitHubActionsReader) error {
	if c.RemoteCalled() {
		// the update tool of the repository updates the files of the
		// repository, not a reusable workflow of another repository
		return nil
	}
	var counted, unversioned []ir.DependabotGitHubActionsOfUses
	for _, u := range v.Uses() {
		if u.Folded() || !dependabotUpdates(u.Ref()) {
			continue
		}
		counted = append(counted, u)
		if renovateSHARe.MatchString(u.Ref()) && !renovateVersionComment(u.LineComment()) {
			unversioned = append(unversioned, u)
		}
	}
	if len(counted) == 0 {
		return nil
	}
	dir := dependabotDirectory(c.Name())
	// no fact names an input whose name has a backslash: its finding has
	// no condition, as no file of facts can say that a tool updates it
	name, named := c.Name().FactArgument()
	dependabot := facts.DependabotVersionUpdates{PackageEcosystem: facts.PackageEcosystemGitHubActions, InputPath: name}
	renovate := facts.RenovateManagerEnabled{Manager: facts.RenovateManagerGitHubActions, InputPath: name}
	// the two kinds may be at one uses (the first is a SHA without a
	// comment): Anchor tells them apart
	report := func(us []ir.DependabotGitHubActionsOfUses, args lint.FindingArgs, renovateHandles bool) {
		var related []lint.Related
		for _, u := range us[1:] {
			related = append(related, lint.Related{Location: c.At(u.RefAt()), Note: "another uses that is not updated"})
		}
		var cond *lint.Condition
		if named {
			all := lint.All(*factCond(dependabot, false), *factCond(renovate, renovateHandles))
			cond = &all
		}
		c.Report(lint.FindingDraft{Location: c.At(us[0].RefAt()), Args: args, Related: related, Condition: cond, Anchor: args.KindID().String()})
	}
	report(counted, DependabotGitHubActionsNoUpdateTool{Uses: counted[0].UsesText(), Directory: dir}, false)
	if len(unversioned) > 0 {
		report(unversioned, DependabotGitHubActionsUnversionedSHA{Uses: unversioned[0].UsesText(), Directory: dir}, true)
	}
	return nil
}

var dependabotGitHubActionsMeta = lint.QualityMeta{
	ID:       DependabotGitHubActionsID,
	Problem:  "no update tool keeps the uses of a workflow or an action metadata file current: no entry of Dependabot version updates reads the file, and Renovate does not update the uses (the rule keeps the name of the rule of sisakulint, and reads the configuration of Renovate too)",
	Expected: "every file whose uses name an action of another repository or a reusable workflow of another repository by a commit SHA or a version is a file that an entry of .github/dependabot.yml with package-ecosystem github-actions makes Dependabot read, or a file whose every such uses Renovate updates",
	Citations: []lint.Citation{
		lint.MustCitation("https://github.com/github/docs/blob/44a609d0382839fdfe455de859774cfebb7f2d83/content/code-security/reference/supply-chain-security/dependabot-options-reference.md"),
		lint.MustCitation("https://github.com/github/docs/blob/44a609d0382839fdfe455de859774cfebb7f2d83/data/reusables/actions/dependabot-version-updates-actions-caveats.md"),
		lint.MustCitation("https://github.com/github/docs/blob/44a609d0382839fdfe455de859774cfebb7f2d83/content/code-security/concepts/supply-chain-security/about-the-dependabot-yml-file.md"),
		lint.MustCitation("https://github.com/github/docs/blob/44a609d0382839fdfe455de859774cfebb7f2d83/data/reusables/dependabot/dependabot-alert-actions-semver.md"),
		lint.MustCitation("https://github.com/dependabot/dependabot-core/blob/fda701f49c7d6ba5807e98a06549fdb935e3bd2e/github_actions/lib/dependabot/github_actions/file_fetcher.rb"),
		lint.MustCitation("https://github.com/dependabot/dependabot-core/blob/fda701f49c7d6ba5807e98a06549fdb935e3bd2e/github_actions/lib/dependabot/github_actions/update_checker.rb"),
		lint.MustCitation("https://github.com/dependabot/dependabot-core/blob/fda701f49c7d6ba5807e98a06549fdb935e3bd2e/common/lib/dependabot/git_commit_checker.rb"),
		lint.MustCitation("https://github.com/renovatebot/renovate/blob/33483f9e6a79721cd22b613505d40cea019d55f6/lib/config/app-strings.ts"),
		lint.MustCitation("https://github.com/renovatebot/renovate/blob/33483f9e6a79721cd22b613505d40cea019d55f6/lib/modules/manager/github-actions/index.ts"),
		lint.MustCitation("https://github.com/renovatebot/renovate/blob/33483f9e6a79721cd22b613505d40cea019d55f6/lib/modules/manager/github-actions/extract.ts"),
		lint.MustCitation("https://github.com/renovatebot/renovate/blob/33483f9e6a79721cd22b613505d40cea019d55f6/lib/modules/manager/github-actions/parse.ts"),
	},
	Targets: []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FindingKinds: []lint.QualityFindingKind{
		{FindingText: textDependabotGitHubActionsNoUpdateTool, FactKinds: []facts.Kind{facts.KindDependabotVersionUpdates, facts.KindRenovateManagerEnabled}},
		{FindingText: textDependabotGitHubActionsUnversionedSHA, FactKinds: []facts.Kind{facts.KindDependabotVersionUpdates, facts.KindRenovateManagerEnabled}},
	},
	UndetectedForms: []lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("other-ref"), Text: "a uses whose ref is a tag that is neither a commit SHA nor a version (v and digits such as v4, digits with dots such as 1.2, or a date such as 20240101), such as stable: the rule does not report the uses, also in a repository with no update tool, since whether Dependabot or Renovate updates such a tag is not known", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("fork"), Text: "a file of a fork: Dependabot version updates do not run on a fork that has .github/dependabot.yml until Dependabot version updates are enabled under Code security and analysis in the settings of the fork, and the rule does not read the settings", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("not-running"), Text: "a repository where the update tool does not run: Dependabot paused for a repository without activity, Dependabot turned off by an administrator or a policy of GitHub Enterprise Server, or a configuration file of Renovate in a repository where Renovate is not installed: the rule does not read whether the update tool runs", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("renovate-line-form"), Text: "a uses that Renovate does not read in the form the uses is written in, such as a uses in a flow mapping or in a scalar of several lines: Renovate reads the line of uses:, and the rule reads the uses as updated", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("folded-uses"), Text: "a uses written as ${{ }} around a string literal, such as ${{ 'actions/setup-node@v4' }} (not a folded scalar of YAML): the rule does not know whether the update tools read such a uses, and does not report the uses, also in a repository with no update tool", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("hex-ref"), Text: "a uses pinned to 8 to 39 hexadecimal digits, such as abcdef12, in a file that Renovate updates: Dependabot reads the ref as a commit SHA, Renovate does not (Renovate reads 40 or 64 digits, or 6 or 7), and whether Renovate updates such a ref is not known: the rule reads the uses as updated by Renovate", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("ignored-dependency"), Text: "a uses of an action that the key ignore: of .github/dependabot.yml or a package rule of Renovate names: the update tool does not update the action, and the rule reads the file as updated", Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustUndetectedFormID("default-branch"), Text: "a run on a branch that is not the default branch, whose .github/dependabot.yml is not on the default branch yet: Dependabot reads .github/dependabot.yml of the default branch, and the rule reads .github/dependabot.yml under --root", Disposition: lint.Todo(lint.NeedFact)},
	},
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("outside-config"), Text: "a repository that Renovate updates by a configuration from outside the repository (a global configuration, an inherited configuration), with no configuration file in the repository: the rule reads the files of the repository only; for such a repository, pass --fact renovate.manager-enabled[manager=github-actions,input_path=<path>]=true once for each workflow and action metadata file that Renovate updates", FindingKinds: []lint.FindingKindID{kindDependabotGitHubActionsNoUpdateTool}, Disposition: lint.Todo(lint.NeedFact)},
	},
}

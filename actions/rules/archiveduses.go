package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// ArchivedUses is the quality rule archived-uses: a uses of an action or a
// reusable workflow of a repository that is archived, which is read-only
// and no longer maintained, though the runner still runs it.
// Whether a repository is archived is the fact repo.archived: upstream's
// embedded list is not kept, since a repository may be archived or
// unarchived at any time.
var ArchivedUses lint.QualityRule = withQualityExamples(lint.WithQualityView[ir.ArchivedUsesReader](archivedUses{}, ir.ArchivedUsesView))

// ArchivedUsesID is the ID of archived-uses.
var ArchivedUsesID = lint.MustRuleID("archived-uses")

type archivedUses struct{}

func (archivedUses) QualityMeta() lint.QualityMeta { return archivedUsesMeta }

func (archivedUses) Check(_ context.Context, c *lint.RuleContext, v ir.ArchivedUsesReader) error {
	for _, u := range v.Uses() {
		if u.Outside() && !u.ReadByOutside() {
			continue // the repository is fetched, but its action does not run: the path goes above its root
		}
		repo, err := facts.ParseRepo(u.Repo())
		if err != nil {
			continue // not a repository GitHub can have: the runner cannot fetch it
		}
		c.Report(lint.FindingDraft{Location: c.At(u.RefAt()), Args: ArchivedUsesArchivedRepository{Uses: u.UsesText(), Repo: repo},
			Condition: factCond(facts.RepoArchived{Repo: repo}, true)})
	}
	// the uses inside the composite actions of other repositories the
	// steps run (action.definition); those of an action.yml of the inputs
	// are the findings of that input
	for _, call := range v.CompositeCalls() {
		for _, s := range call.Steps() {
			if s.Query == nil || s.Repo == "" {
				continue
			}
			repo, err := facts.ParseRepo(s.Repo)
			if err != nil {
				continue
			}
			c.Report(lint.FindingDraft{Location: c.At(call.At()), Anchor: placeAnchor(c, s.Chain, s.At), Args: ArchivedUsesArchivedRepository{Uses: s.UsesText, Repo: repo},
				Evidence:  []lint.Related{{Location: c.At(s.At), Note: "the step of the composite action " + s.Chain[len(s.Chain)-1].Uses + " that uses the action"}},
				Condition: factCond(facts.RepoArchived{Repo: repo}, true)})
		}
	}
	// the reusable workflows of other repositories the jobs call
	// (workflow.definition) are read where the engine runs the rule on them
	// (a remote called workflow), and reported at the uses of the calling job
	return nil
}

var archivedUsesMeta = lint.QualityMeta{
	ID:       ArchivedUsesID,
	Problem:  "a uses names an action or a reusable workflow of a repository that is archived",
	Expected: "every uses that names an action or a reusable workflow of another repository names one of a repository that is not archived",
	Citations: []lint.Citation{
		lint.MustCitation("https://github.com/github/docs/blob/666463860bec200da6c8db9cb9334e7335d9b753/content/repositories/archiving-a-github-repository/archiving-repositories.md"),
		lint.MustCitation("https://github.com/github/docs/blob/666463860bec200da6c8db9cb9334e7335d9b753/content/organizations/managing-organization-settings/archiving-an-organization.md"),
		lint.MustCitation("https://github.com/github/rest-api-description/blob/755ee33b4a81d51f6f07a902cce26cbec3b822f2/descriptions/api.github.com/api.github.com.json"),
	},
	Targets:      []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	FindingKinds: []lint.QualityFindingKind{{FindingText: textArchivedUsesArchivedRepository, FactKinds: []facts.Kind{facts.KindRepoArchived}}},
	// Offline, every uses would be conditional: the rule runs by default
	// only where an answer of repo.archived can come.
	DefaultRun: lint.DefaultRunFacts(facts.KindRepoArchived),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: remoteComposite, Text: "a uses inside the action.yml of a composite action of another repository (a step of that composite action, not the uses that names the composite action) when action.definition has no answer for the composite action (a run without --online and without the answer in --facts, an answer of unknown, or an action deeper than the 4 levels of actions the linter reads): the rule reads the steps of a composite action of another repository only from the answer", Disposition: lint.Todo(lint.NeedFact)},
	}),
}

var (
	remoteComposite = lint.MustUndetectedFormID("remote-composite")
	remoteCalled    = lint.MustUndetectedFormID("remote-called")
)

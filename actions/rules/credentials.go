package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// Credentials is the rule credentials: the password of a registry written
// in the workflow, which whoever reads the workflow reads. Whether
// the repository is public tells who that is, so a password gives a
// finding of each kind, on repo.public true and false.
var Credentials lint.Rule = withExamples(lint.WithView[ir.CredentialsReader](credentials{}, ir.CredentialsView))

// CredentialsID is the ID of credentials.
var CredentialsID = lint.MustRuleID("credentials")

type credentials struct{}

func (credentials) Meta() lint.Meta { return credentialsMeta }

var passwordExpr = lint.MustInconclusiveKindID("password-expr")

func (credentials) Check(_ context.Context, c *lint.RuleContext, v ir.CredentialsReader) error {
	for _, r := range v.RegistryCredentials() {
		switch r.PasswordForm() {
		case ir.PasswordFormLiteral:
			at := c.At(r.PasswordAt())
			c.Report(lint.FindingDraft{Location: at, Anchor: "public", Args: CredentialsPublic{Container: r.Container()}, Condition: isPublic(c)})
			c.Report(lint.FindingDraft{Location: at, Anchor: "private", Args: CredentialsPrivate{Container: r.Container()}, Condition: factCond(facts.RepoPublic{Repo: c.Repo()}, false)})
		case ir.PasswordFormOther:
			c.Inconclusive(lint.InconclusiveDraft{KindID: passwordExpr, Location: c.At(r.PasswordAt()), Note: r.PasswordText() + " reads a context other than secrets; whether its value is written in the repository is not known"})
		}
	}
	return nil
}

// credentialsCVSS is what the password opens: the registry, past the
// workflow's run, which it does not harm as such.
func credentialsCVSS(pr lint.Metric[lint.PrivilegesRequired]) lint.CVSS {
	return lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker reads the workflow file over the network"),
		AC: metric(lint.AttackComplexityLow, "the password is in the file as it is"),
		AT: metric(lint.AttackRequirementsNone, "nothing else is needed: the registry takes the password"),
		PR: pr,
		UI: metric(lint.UserInteractionNone, "nobody does anything"),
		VC: metric(lint.ImpactNone, "the workflow's run is not harmed as such"),
		VI: metric(lint.ImpactNone, "the workflow's run is not harmed as such"),
		VA: metric(lint.ImpactNone, "the workflow's run is not harmed as such"),
		SC: metric(lint.ImpactHigh, "the attacker pulls the private images of the account"),
		SI: metric(lint.ImpactHigh, "an account that may push lets them push images of theirs, which whoever runs them runs"),
		SA: metric(lint.ImpactLow, "they can delete what the account may"),
	}
}

var (
	readableFile         = lint.MustPreconditionID("readable-file")
	historyKeeps         = lint.MustPreconditionID("history-keeps")
	credentialDocs       = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idcontainercredentials")
	collaborators        = lint.MustCitation("https://docs.github.com/en/account-and-profile/reference/permission-levels-for-a-personal-account-repository#access-after-removing-a-collaborator")
	internalReaders      = lint.MustCitation("https://github.com/github/docs/blob/8b39dc44a066dda794bfacdd25653ff86324ef21/content/repositories/creating-and-managing-repositories/about-repositories.md")
	noCredentialIncident = metric(lint.ExploitMaturityUnreported, "no report was found of a password written in the credentials of a workflow's container taken and used")
)

var credentialsMeta = lint.Meta{
	ID:       CredentialsID,
	Problem:  "the password of a registry is written in the workflow, where whoever reads the repository reads it, and its history keeps it",
	Expected: "the password is read from a secret of the repository, ${{ secrets.NAME }}",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessCredentialLeak}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textCredentialsPublic,
			Attackers:       []lint.Attacker{lint.AttackerRepositoryReader},
			Preconditions:   []lint.PreconditionID{readableFile, historyKeeps},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            credentialsCVSS(metric(lint.PrivilegesRequiredNone, "anyone reads the files of a public repository")),
			ExploitMaturity: noCredentialIncident,
		},
		{
			FindingText:     textCredentialsPrivate,
			Attackers:       []lint.Attacker{lint.AttackerRepositoryReader},
			Preconditions:   []lint.PreconditionID{readableFile, historyKeeps},
			FactKinds:       []facts.Kind{facts.KindRepoPublic},
			CVSS:            credentialsCVSS(metric(lint.PrivilegesRequiredLow, "the files of a private or internal repository are read by those with read access to it, every member of the enterprise for an internal one, the apps given its contents, and whoever has their tokens")),
			ExploitMaturity: noCredentialIncident,
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerRepositoryReader,
			Via:      "reads the workflow file, or a clone or a fork of the repository",
			Gains:    []lint.Gain{lint.GainUseRegistryAccount},
		}},
		Preconditions: []lint.Precondition{
			{ID: readableFile, Text: "the workflow file is read by anyone in a public repository (repo.public, assumed true), and by those with read access, the apps given its contents and whoever has their tokens in a private or internal one, where every member of the enterprise has read access to an internal one; the runner gives the password to docker login as written", Cites: []lint.Citation{credentialDocs, internalReaders}},
			{ID: historyKeeps, Text: "the history keeps the password after the file no longer has it, and one who had access keeps a clone, so only revoking it ends the exposure", Cites: []lint.Citation{collaborators}},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("action-input"), Text: "a credential written in the with of a step, such as the password of docker/login-action: which inputs of an action are credentials is not known", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("run-command"), Text: "a password written in a run: docker login -p", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: passwordExpr, Text: "a password read from a context other than secrets: env, vars, inputs, matrix", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("private-repository"), Text: "a private or internal repository, where the password is credentials.private: whoever may read the repository reads it", FindingKinds: []lint.FindingKindID{kindCredentialsPublic}, FactKinds: []facts.Kind{facts.KindRepoPublic}},
	},
}

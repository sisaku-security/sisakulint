package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// SecretsInherit is the rule secrets-inherit: a job that calls a reusable
// workflow with secrets: inherit, which lets the called workflow reference
// every secret the job has; for a reusable workflow of the repository, only
// when a job of the called workflow reads the secrets without naming them,
// or when the linter does not have its contents.
var SecretsInherit lint.Rule = withExamples(lint.WithView[ir.SecretsInheritReader](secretsInherit{}, ir.SecretsInheritView))

// SecretsInheritID is the ID of secrets-inherit.
var SecretsInheritID = lint.MustRuleID("secrets-inherit")

type secretsInherit struct{}

func (secretsInherit) Meta() lint.Meta { return secretsInheritMeta }

func (secretsInherit) Check(_ context.Context, c *lint.RuleContext, v ir.SecretsInheritReader) error {
	for _, j := range v.Jobs() {
		if !j.InheritSecrets() {
			continue
		}
		k := j.CalledKind()
		switch {
		case k == analysis.CalledWorkflowKindNone:
			// GitHub does not run a workflow whose uses the model rejects
		case k == analysis.CalledWorkflowKindLocal || (!c.Repo().IsZero() && j.CalledRepo() == c.Repo()):
			if !j.Secrets().All {
				continue // GitHub passes the runners of the called jobs only what they read by name
			}
			var related []lint.Related
			for _, r := range j.CalledContextReads() {
				related = append(related, lint.Related{Location: c.At(r), Note: "a read of the secrets without a name in the called workflow, which makes GitHub pass every secret to the runner of the job of the read"})
			}
			c.Report(lint.FindingDraft{Location: c.At(j.SecretsAt()), Args: SecretsInheritLocal{Uses: j.UsesText()}, Related: related})
		default:
			c.Report(lint.FindingDraft{Location: c.At(j.SecretsAt()), Args: SecretsInheritRemote{Uses: j.UsesText()}})
		}
	}
	return nil
}

var (
	inheritAll       = lint.MustPreconditionID("inherit-all")
	namelessInCalled = lint.MustPreconditionID("nameless-in-called")
	calledTurns      = lint.MustPreconditionID("called-turns")
	flawInCalled     = lint.MustPreconditionID("flaw-in-called")

	observedInherit = lint.MustDate("2026-10-06")

	inheritDocs = lint.MustCitation("https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idsecretsinherit")
)

var secretsInheritMeta = lint.Meta{
	ID:       SecretsInheritID,
	Problem:  "a job lets the reusable workflow that it calls reference every secret that the job has, of the organization and the repository, not only the secrets that the workflow needs",
	Expected: "the called workflow declares in on.workflow_call.secrets the secrets it reads, and the job passes those one by one under secrets:",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessExcessivePrivilege}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:   textSecretsInheritRemote,
			Attackers:     []lint.Attacker{lint.AttackerMaintainerOfCalled},
			Preconditions: []lint.PreconditionID{inheritAll, calledTurns},
			CVSS: lint.CVSS{
				AV: metric(lint.AttackVectorNetwork, "the attacker pushes to the repository of the called workflow, over the network"),
				AC: metric(lint.AttackComplexityLow, "the called workflow reads any secret by its name"),
				AT: metric(lint.AttackRequirementsPresent, "the attacker must control the repository of the called workflow, of the same organization or enterprise: maintain it, or have taken over an account that does"),
				PR: metric(lint.PrivilegesRequiredNone, "nothing of the calling repository is needed"),
				UI: metric(lint.UserInteractionPassive, "the caller runs on its usual events; nobody does anything unusual"),
				VC: metric(lint.ImpactHigh, "the attacker reads every secret of the caller"),
				VI: metric(lint.ImpactNone, "the secrets do not write to the repository as such"),
				VA: metric(lint.ImpactNone, "the secrets do not act on the repository as such"),
				SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
				SI: metric(lint.ImpactHigh, "they write what the secrets may: deployments, packages"),
				SA: metric(lint.ImpactLow, "they can delete what the secrets may"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of secrets taken through secrets: inherit was found"),
		},
		{
			FindingText:   textSecretsInheritLocal,
			Attackers:     exposureAttackers,
			Preconditions: []lint.PreconditionID{inheritAll, namelessInCalled, flawInCalled},
			CVSS: lint.CVSS{
				AV: metric(lint.AttackVectorNetwork, "the attacker reaches the flaw over the network: an issue, a comment or a pull request"),
				AC: metric(lint.AttackComplexityLow, "once the flaw runs the attacker's code, every secret is in the runner of the job"),
				AT: metric(lint.AttackRequirementsPresent, "a flaw in the called workflow has to run the attacker's code there, on an event of the caller they can trigger"),
				PR: metric(lint.PrivilegesRequiredNone, "on a public repository anyone opens an issue or a pull request from a fork"),
				UI: metric(lint.UserInteractionNone, "the event runs the job with nobody doing anything"),
				VC: metric(lint.ImpactHigh, "the attacker reads every secret of the caller, which GitHub passes to the runner of a job of the called workflow that reads the secrets without naming the secrets, not only the secrets that the called workflow needs"),
				VI: metric(lint.ImpactNone, "the secrets do not write to the repository as such"),
				VA: metric(lint.ImpactNone, "the secrets do not act on the repository as such"),
				SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
				SI: metric(lint.ImpactHigh, "they write what the secrets may: deployments, packages"),
				SA: metric(lint.ImpactLow, "they can delete what the secrets may"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of secrets taken through secrets: inherit was found"),
		},
	},
	Threat: lint.Threat{
		Actors: append([]lint.Actor{{
			Attacker: lint.AttackerMaintainerOfCalled,
			Via:      "pushes to the repository of the called workflow, or takes over an account that maintains it, and has the workflow read the secrets",
			Gains:    []lint.Gain{lint.GainReadSecrets},
		}}, exposureActors...),
		Preconditions: []lint.Precondition{
			{ID: inheritAll, Text: "secrets: inherit lets the called workflow reference every secret of the organization and the repository that the caller has, by name or without a name, even where the on.workflow_call of the called workflow does not declare the secret; which of those secrets GitHub passes to the runner of a job of the called workflow is the precondition nameless-in-called", Cites: []lint.Citation{inheritDocs},
				Observed: []lint.Observation{{Date: observedInherit, Runner: runner, What: "with secrets: inherit, a called workflow that declares no secret, and one that declares only FOO as required, both read the repository's secrets FOO and BAR"}}},
			{ID: namelessInCalled, Text: "a job of the called workflow reads the secrets context without naming a secret (toJSON(secrets), secrets[<an expression>], secrets.* (an object filter)), and GitHub then passes every secret of the caller to the runner of that job; a job that reads the secrets only by name gets only those secrets in its runner. The rule reads the called workflow when the linter has the contents of the called workflow (a workflow that is among the inputs and that the job calls by ./ or $/); for a called workflow whose contents the linter does not have, the rule assumes that a job of the called workflow reads the secrets without naming them", Cites: []lint.Citation{inheritDocs},
				Observed: []lint.Observation{sawCalledReads}},
			{ID: calledTurns, Text: "the called workflow, of another repository of the organization or the enterprise, turns malicious: its maintainers' doing, or that of one who took over an account of theirs", Cites: []lint.Citation{tjActions, reviewdog}},
			{ID: flawInCalled, Text: "a flaw in the called workflow runs an attacker's code there: an injection, a checkout of their code; the other rules report those they see", Cites: []lint.Citation{pwnRequests}},
		},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow},
	InconclusiveKinds: withRemoteCalleeUnknown(nil),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("unneeded-secret"), Text: "a secret that the job passes one by one under secrets: to a reusable workflow of another repository, and that no job of the called workflow reads: GitHub does not pass the secret to the runners of the called workflow, but whoever maintains the repository of the called workflow can add a read of the secret; telling which secrets the called workflow reads takes the contents of the called workflow, from the fact workflow.definition", Disposition: lint.Todo(lint.NeedFact)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("no-attacker-value-caller"), Text: "a workflow that calls a reusable workflow of the same repository with secrets: inherit only on events whose runs read no value that an attacker writes, such as schedule: the rule reports secrets: inherit whatever the events of the calling workflow are", FindingKinds: []lint.FindingKindID{kindSecretsInheritLocal}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("other-owner"), Text: "a call with secrets: inherit, from a workflow of a repository of a user account to a reusable workflow of a repository of an organization: on 2026-10-22 the called workflow got no secret of the repository, only github_token, which a called workflow has without secrets: inherit too", FindingKinds: []lint.FindingKindID{kindSecretsInheritRemote}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("named-reads"), Text: "a reusable workflow of the repository whose contents the linter does not have (a workflow file that is not among the inputs, or the repository's own workflow called by owner/repo/path@ref when the linter is given the name of the repository, --repo; without the name, the linter takes such a call as a call of another repository, reported as .remote), whose jobs read the secrets only by name; also a called workflow whose contents the linter has, when a job of the called workflow calls with secrets: inherit, in turn, such a reusable workflow: GitHub passes the runner of each job of the called workflow only the secrets that the job reads by name, so a flaw in a job of the called workflow gets those secrets, as when the calling job passes those secrets one by one. With secrets: inherit, a job of the called workflow that reads the secrets without naming them (toJSON(secrets), secrets[<an expression>], secrets.*) gets every secret in its runner", FindingKinds: []lint.FindingKindID{kindSecretsInheritLocal}, Disposition: lint.Todo(lint.NeedRepoFile)},
	},
}

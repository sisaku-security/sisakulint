package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// Permissions is the rule permissions: a job whose GITHUB_TOKEN has
// write-all, or the repository's default when neither the job nor the
// workflow writes permissions. Every action, reusable workflow and package
// the job runs holds the token.
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var Permissions lint.Rule = withExamples(lint.WithView[ir.PermissionsReader](permissions{}, ir.PermissionsView))

// PermissionsID is the ID of permissions.
var PermissionsID = lint.MustRuleID("permissions")

type permissions struct{}

func (permissions) Meta() lint.Meta { return permissionsMeta }

func (permissions) Check(_ context.Context, c *lint.RuleContext, v ir.PermissionsReader) error {
	for _, j := range v.Jobs() {
		if j.AlwaysSkipped() {
			continue // GitHub skips its job in every run
		}
		if j.CalledOnly() {
			continue // its token is no more than its caller's, whose job is read
		}
		switch {
		case j.WriteAll() != analysis.WriteAllNo:
			c.Report(lint.FindingDraft{Location: c.At(j.At()), Args: PermissionsWriteAll{WriteAll: j.WriteAll()}})
		case j.TokenWrite() == analysis.TokenWriteUnwritten:
			c.Report(lint.FindingDraft{Location: c.At(j.At()), Args: PermissionsUnwritten{}, Condition: defaultWrites(c)})
		}
	}
	return nil
}

var (
	othersCode    = lint.MustPreconditionID("others-code")
	maliciousCode = lint.MustPreconditionID("malicious-code")

	// othersTokenTaken: the attack, taking a token that may write from code
	// of others in the job, is reported; a write made with it is not.
	othersTokenTaken = metric(lint.ExploitMaturityAttacked, "in 2025-03 tj-actions/changed-files, whose tag the attacker pointed to a malicious commit aimed at Coinbase, gave the attacker a GITHUB_TOKEN that could write to coinbase/agentkit from a job that wrote no permissions; no write made with it was reported, and the token expires when the job ends", unit42)

	// othersToken is the CVSS of a token that code of others in the job holds.
	othersToken = lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker publishes the code the job runs, over the network"),
		AC: metric(lint.AttackComplexityLow, "the code reads github.token from its context, with nothing written in with"),
		AT: metric(lint.AttackRequirementsPresent, "the attacker must control code the job runs: maintain an action, a reusable workflow or a package it installs, or have taken over an account that does"),
		PR: metric(lint.PrivilegesRequiredNone, "nothing of the repository of the job is needed"),
		UI: metric(lint.UserInteractionPassive, "the workflow runs on its usual events; nobody does anything unusual"),
		VC: metric(lint.ImpactHigh, "the token reads what the job may: the code and the issues of a private repository"),
		VI: metric(lint.ImpactHigh, "the token pushes, releases and writes packages"),
		VA: metric(lint.ImpactLow, "the token can cancel runs or delete what it may"),
		SC: metric(lint.ImpactNone, "the GITHUB_TOKEN opens only this repository"),
		SI: metric(lint.ImpactHigh, "what it pushes or releases reaches those who use the repository"),
		SA: metric(lint.ImpactNone, "nothing past the repository is made unavailable by this as such"),
	}
)

var permissionsMeta = lint.Meta{
	ID:       PermissionsID,
	Problem:  "a job's GITHUB_TOKEN may write more than the job needs, write-all or the repository's default when no permissions are written; every action, reusable workflow and package the job runs holds it, and one whose maintainer turns or is taken over writes to the repository with it",
	Expected: "permissions written on the workflow or the job with only the scopes the job needs",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessExcessivePrivilege}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textPermissionsWriteAll,
			Attackers:       []lint.Attacker{lint.AttackerMaintainerOfCalled},
			Preconditions:   []lint.PreconditionID{othersCode, maliciousCode},
			CVSS:            othersToken,
			Incidents:       []lint.IncidentID{agentkit2025},
			ExploitMaturity: othersTokenTaken,
		},
		{
			FindingText:     textPermissionsUnwritten,
			Attackers:       []lint.Attacker{lint.AttackerMaintainerOfCalled},
			Preconditions:   []lint.PreconditionID{othersCode, maliciousCode, tokenWrites},
			FactKinds:       []facts.Kind{facts.KindRepoDefaultTokenWrite},
			CVSS:            othersToken,
			Incidents:       []lint.IncidentID{agentkit2025},
			ExploitMaturity: othersTokenTaken,
		},
	},
	Threat: lint.Threat{
		Actors: []lint.Actor{{
			Attacker: lint.AttackerMaintainerOfCalled,
			Via:      "turns the action, the reusable workflow or the package the job runs, or takes over an account that maintains it, and the code reads github.token",
			Gains:    []lint.Gain{lint.GainWriteWithToken},
		}},
		Preconditions: []lint.Precondition{
			{ID: othersCode, Text: "the job runs code of others: an action or a reusable workflow of another repository, or a package a script installs; an action reads the token from the github context with nothing written in with", Cites: []lint.Citation{secureUse}},
			{ID: maliciousCode, Text: "that code turns malicious: its maintainer's doing, or that of an attacker who took over their account or moved its tag", Cites: []lint.Citation{tjActions, reviewdog}},
			{ID: tokenWrites, Text: "neither the job nor the workflow declares permissions, and the default GITHUB_TOKEN of the repository may write (repo.default-token-write true; without an answer, the finding is conditional. The permissive default is the default of the repositories made before 2023-02-02, and those repositories keep the permissive default until someone changes the setting)", Cites: []lint.Citation{tokenDocs}},
		},
		Incidents: []lint.Incident{
			agentkitIncident,
		},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow},
	InconclusiveKinds: withRemoteCalleeUnknown(nil),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("id-token"), Text: "a job that writes id-token write and no other scope: the rule does not report written scopes, yet code there takes an OIDC token for the clouds that trust the repository", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustUndetectedFormID("written-scopes"), Text: "a job whose written permissions give write on scopes it does not need: what it needs is what the code it runs calls with the token, which the workflow does not say; the rule reports only write-all and permissions not written", Disposition: lint.Limitation(lint.DeciderRunTime)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("job-never-runs"), Text: "a job that GitHub never runs because the if of the job is false in every run, and the if is false because of a value other than github.event_name and github.event.action (for example, if: github.event.pull_request.merged == true in a workflow that runs only on pull_request with types: [opened]). No code runs with the GITHUB_TOKEN of a job that GitHub never runs. In the if of a job, and in the if of each job that the job needs, the rule reads only github.event_name, github.event.action and needs.<job_id>.result.", FindingKinds: []lint.FindingKindID{kindPermissionsUnwritten, kindPermissionsWriteAll}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("no-third-party-code"), Text: "a job that runs no code of others, only commands of the runner: no one else holds the token, which the rule does not tell apart", FindingKinds: []lint.FindingKindID{kindPermissionsWriteAll, kindPermissionsUnwritten}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("called-narrows"), Text: "a job that only calls a reusable workflow of the same repository, which writes permissions that narrow the token before any code of others runs: the called workflow can only downgrade the caller's token, and the rule does not read it", FindingKinds: []lint.FindingKindID{kindPermissionsWriteAll, kindPermissionsUnwritten}, Disposition: lint.Todo(lint.NeedRepoFile)},
		{ID: lint.MustFalsePositiveFormID("default-token-read"), Text: "a job that writes no permissions, in a repository whose default token is read", FindingKinds: []lint.FindingKindID{kindPermissionsUnwritten}, FactKinds: []facts.Kind{facts.KindRepoDefaultTokenWrite}},
	},
}

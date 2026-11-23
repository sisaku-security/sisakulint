package rules

import (
	"context"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// SecretExposure is the rule secret-exposure: a ${{ }} that reads the
// secrets context and names no secret, for which GitHub sends the job
// every secret.
// In a workflow only a caller runs, the secrets are those the caller
// passes: it reports a read there when a caller of the inputs passes them
// with secrets: inherit from a workflow that may have every secret (a
// caller only called in turn counts through its own callers), or when the
// inputs do not have every caller.
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var SecretExposure lint.Rule = withExamples(lint.WithView[ir.SecretExposureReader](secretExposure{}, ir.SecretExposureView))

// SecretExposureID is the ID of secret-exposure.
var SecretExposureID = lint.MustRuleID("secret-exposure")

type secretExposure struct{}

func (secretExposure) Meta() lint.Meta { return secretExposureMeta }

func (secretExposure) Check(_ context.Context, c *lint.RuleContext, v ir.SecretExposureReader) error {
	for _, r := range v.SecretsContextReads() {
		if r.AlwaysSkipped() {
			continue // GitHub skips its job in every run
		}
		var related []lint.Related
		if r.CalledOnly() && r.CallerCoverage() == analysis.CallerCoverageAll {
			if len(r.InheritCallers()) == 0 {
				continue // every caller names what it passes: nothing more reaches the job
			}
			for _, ic := range r.InheritCallers() {
				related = append(related, lint.Related{Location: c.At(ic.At), Note: "the job " + ic.Job + " of " + ic.Caller.String() + " calls it with secrets: inherit"})
			}
		}
		c.Report(lint.FindingDraft{Location: c.At(r.At()), Args: SecretExposureAllSecrets{Reference: r.Text()}, Related: related})
	}
	return nil
}

var (
	namelessReadsAll = lint.MustPreconditionID("nameless-reads-all")
	codeInJob        = lint.MustPreconditionID("code-in-job")

	observedSecretExposure = lint.MustDate("2026-10-14")
	observedOtherKeys      = lint.MustDate("2026-10-23")
	observedEnvironment    = lint.MustDate("2026-10-23")

	secureUseSecrets     = lint.MustCitation("https://github.com/github/docs/blob/ba6f6f9b9b31c4f0a991fbcb1005080526424804/content/actions/reference/security/secure-use.md")
	secretsConcept       = lint.MustCitation("https://github.com/github/docs/blob/ba6f6f9b9b31c4f0a991fbcb1005080526424804/content/actions/concepts/security/secrets.md")
	environmentSecrets   = lint.MustCitation("https://github.com/github/docs/blob/01c4e7416d12324b53d3a4f35ea7ae01d9bbc4e6/content/actions/reference/workflows-and-actions/deployments-and-environments.md")
	contextsAvailability = lint.MustCitation("https://github.com/github/docs/blob/935221fd662811fa04955b1759bf67b96b7ae028/content/actions/reference/workflows-and-actions/contexts.md")
)

var secretExposureMeta = lint.Meta{
	ID:       SecretExposureID,
	Problem:  "a ${{ }} reads the secrets without naming a secret, and GitHub then sends the job every secret of the repository, including the secrets that no expression of the job names, and also every secret of the environment of the job when the job references an environment (the key environment of the job)",
	Expected: "the job names each secret it needs, secrets.NAME",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessExcessivePrivilege}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:   textSecretExposureAllSecrets,
			Attackers:     append([]lint.Attacker{lint.AttackerMaintainerOfCalled}, exposureAttackers...),
			Preconditions: []lint.PreconditionID{namelessReadsAll, codeInJob},
			CVSS: lint.CVSS{
				AV: metric(lint.AttackVectorNetwork, "the attacker pushes to an action the job uses, or reaches a flaw of the job, over the network"),
				AC: metric(lint.AttackComplexityLow, "once their code runs in the job, every secret is in it"),
				AT: metric(lint.AttackRequirementsPresent, "the attacker's code has to run in the job: an action of it turns malicious, or a flaw runs it there"),
				PR: metric(lint.PrivilegesRequiredNone, "on a public repository anyone opens an issue or a pull request from a fork"),
				UI: metric(lint.UserInteractionNone, "the job runs on its events with nobody doing anything"),
				VC: metric(lint.ImpactHigh, "the attacker reads the secrets that the code of the attacker could not read if each job named only the secrets that the job needs, up to every secret of the repository"),
				VI: metric(lint.ImpactNone, "the secrets do not write to the repository as such"),
				VA: metric(lint.ImpactNone, "the secrets do not act on the repository as such"),
				SC: metric(lint.ImpactHigh, "the secrets open what is past the job: clouds, registries, other repositories"),
				SI: metric(lint.ImpactHigh, "they write what the secrets may: deployments, packages"),
				SA: metric(lint.ImpactLow, "they can delete what the secrets may"),
			},
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of secrets taken from a job because it read toJSON(secrets) or secrets[...] (searched 2026-10-14)"),
		},
	},
	Threat: lint.Threat{
		Actors: append([]lint.Actor{{
			Attacker: lint.AttackerMaintainerOfCalled,
			Via:      "pushes to an action the job uses, or takes over an account that maintains it, and has it read the runner's memory or the step's env",
			Gains:    []lint.Gain{lint.GainReadSecrets},
		}}, exposureActors...),
		Preconditions: []lint.Precondition{
			{ID: namelessReadsAll, Text: "GitHub sends a job's runner only the secrets the job names, and every secret of the repository when a ${{ }} of the job reads the secrets without naming one, in a step's env, run, with, name, working-directory, timeout-minutes or continue-on-error, the job's env or outputs, the env or the credentials of the job's container or of a service, or the workflow's env, even in a step whose if is false; a reusable workflow's job gets those its caller passes, all with secrets: inherit, and, when the caller writes toJSON(secrets) as the value of a key under secrets:, every secret of the caller as the value of that one key; when the caller is itself a job of a reusable workflow, secrets: inherit passes only what the caller of that reusable workflow passed, so the rule follows the callers up and does not report a finding on a read when every path of calls up from the read has at least one call that passes named secrets or no secret, in place of secrets: inherit; in a job that references an environment, GitHub sends the secrets of the environment in the same way as the secrets of the repository (observed with the env of a step), and GitHub sends no secret of an environment to a job that references no environment; the observations of this rule did not check whether GitHub sends a job the secrets of the organization, and did not check which secrets GitHub sends a job whose environment has protection rules (such as required reviewers) after a required reviewer approves the job; the rule reports a finding on a job whose environment has protection rules too, as on a job whose environment has no protection rules", Cites: []lint.Citation{secretsConcept, secureUseSecrets, reusingDocs, contextsAvailability, environmentSecrets},
				Observed: []lint.Observation{
					sawCalledReads,
					{Date: observedSecretExposure, Runner: runner, What: "a job that named PROBE_A masked it and printed PROBE_B as it is, and its job message had no PROBE_B; a job with toJSON(secrets), secrets[format(...)] or secrets.*, also in a step whose if is false, masked both and its message had every secret; a called job's toJSON(secrets) masked only what its caller passed, every secret with secrets: inherit; toJSON(secrets) in a step's run, with or name, the job's env or outputs, or the workflow's env masked both; a called job given toJSON(secrets) under secrets: had every secret's name in it"},
					{Date: observedOtherKeys, Runner: runner, What: "toJSON(secrets) in the env of the job's container, the env of a service, the username or the password of the container's credentials, the username of a service's credentials, or a step's working-directory, timeout-minutes or continue-on-error masked both PROBE_A and PROBE_B; with secrets.PROBE_A in the username of the credentials of the job's container and no other secret in the job, a step that echoed the values of PROBE_A and PROBE_B as literals printed the value of PROBE_A as *** and the value of PROBE_B unmasked"},
					{Date: observedEnvironment, Runner: runnerAfter, What: "in jobs that reference the environment e: a job that named PROBE_A masked PROBE_A and not PROBE_ENV, the secret of e; a job that named PROBE_ENV masked PROBE_ENV and not PROBE_A; a job with toJSON(secrets) masked PROBE_A, PROBE_B and PROBE_ENV. A job with toJSON(secrets) that references no environment masked PROBE_A and PROBE_B and printed PROBE_ENV unmasked. Each job of a matrix whose step read secrets[format('PROBE_{0}', matrix.p)] masked PROBE_A and PROBE_B, for the value A of p and for the value B"},
				}},
			{ID: codeInJob, Text: "code that runs in the job reads what its runner holds: an action of the job that turns malicious, as tj-actions/changed-files did, which read the runner's memory, or an attacker's code that a flaw of the job runs; the step whose env has toJSON(secrets) has them in its env", Cites: []lint.Citation{tjActions, pwnRequests}},
		},
	},
	Citations:         []lint.Citation{cvss},
	Targets:           []lint.InputKind{lint.InputKindWorkflow},
	InconclusiveKinds: withRemoteCalleeUnknown(nil),
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("remote-caller"), Text: "a workflow that only a caller runs, whose callers in the repository all pass their secrets by name, directly or through workflows that only callers run and that call the workflow with secrets: inherit, and that a caller in another repository calls with secrets: inherit, directly or through such a workflow: that caller's every secret reaches the job, and the rule sees only the callers in the repository", Disposition: lint.Limitation(lint.DeciderRemoteCaller)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("no-other-secret"), Text: "a job in which each piece of code that runs in the job could still read each secret that GitHub sends the job, if each job of each workflow that can read the secret named only the secrets that the job needs. A piece of code is an action, which can read the secrets of every job, of any workflow, that runs the action, or code that an attacker writes, which can read the secrets of each job whose flaw runs the code of the attacker. In a job that names only the needed secrets, any piece of code that runs in the job can read every secret that the job names. The secrets are the secrets of the repository, of the organization of the repository and of the environment of the job. The observations of this rule did not check whether GitHub sends a job the secrets of the organization, so the form counts the secrets of the organization as if GitHub sends the job the secrets of the organization: counting more secrets keeps more jobs out of the form, and keeps out every job where a secret of the organization could cause the harm. Example: the jobs of a matrix that run the same steps and each pick one secret by the value of the matrix, in a repository whose only secrets are the secrets that the jobs pick. If each job of the matrix named only the secret that the job picks, the action in each job could still read the secret that the job picks, so the action could still read each of the secrets, in the job that picks the secret", FindingKinds: []lint.FindingKindID{kindSecretExposureAllSecrets}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("named-callers"), Text: "a workflow that only a caller runs, whose callers are in other repositories and each passes its secrets by name: the job gets only those, which the rule does not see", FindingKinds: []lint.FindingKindID{kindSecretExposureAllSecrets}, Disposition: lint.Limitation(lint.DeciderRemoteCaller)},
	},
}

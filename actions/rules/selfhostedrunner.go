package rules

import (
	"context"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// SelfHostedRunner is the rule self-hosted-runner: a job that runs on a
// self-hosted runner, which the code of a pull request from a fork
// reaches: of anyone in a public repository, of whoever may read it in a
// private or internal one that runs the workflows of such pull requests. The
// author of a pull request writes the workflow its pull_request run uses, so
// what the runs-on of this workflow says is that the repository has such a
// runner, which their code then reaches.
var SelfHostedRunner lint.Rule = withExamples(lint.WithView[ir.SelfHostedRunnerReader](selfHostedRunner{}, ir.SelfHostedRunnerView))

// SelfHostedRunnerID is the ID of self-hosted-runner.
var SelfHostedRunnerID = lint.MustRuleID("self-hosted-runner")

type selfHostedRunner struct{}

func (selfHostedRunner) Meta() lint.Meta { return selfHostedRunnerMeta }

var runsOnExpr = lint.MustInconclusiveKindID("runs-on-expr")

// isPublic is the condition of a finding: the repository is public.
func isPublic(c *lint.RuleContext) *lint.Condition {
	return factCond(facts.RepoPublic{Repo: c.Repo()}, true)
}

// forkPRRuns is the condition of a finding of a private or internal
// repository: those who may read it fork it, and the workflows of pull
// requests from its forks run.
func forkPRRuns(c *lint.RuleContext) *lint.Condition {
	all := lint.All(*factCond(facts.RepoPublic{Repo: c.Repo()}, false), *factCond(facts.RepoAllowForking{Repo: c.Repo()}, true), *factCond(facts.RepoForkPRRunWorkflows{Repo: c.Repo()}, true))
	return &all
}

func (selfHostedRunner) Check(_ context.Context, c *lint.RuleContext, v ir.SelfHostedRunnerReader) error {
	for _, j := range v.Jobs() {
		for _, r := range j.RunnerLabels() {
			if r.HasSelfHostedLabel {
				c.Report(lint.FindingDraft{Location: c.At(r.At), Args: SelfHostedRunnerPublic{Label: r.Label.String()}, Condition: isPublic(c)})
				c.Report(lint.FindingDraft{Location: c.At(r.At), Anchor: "private", Args: SelfHostedRunnerPrivate{Label: r.Label.String()}, Condition: forkPRRuns(c)})
			}
		}
		for _, g := range j.InconclusiveLabels() {
			if g.Dispatch {
				c.Inconclusive(lint.InconclusiveDraft{KindID: inputDispatch, Location: c.At(g.At), Note: g.Text + " refers to an input of workflow_dispatch, whose value the one who dispatches the workflow chooses; the rule does not determine the runner that the label names"})
				continue
			}
			c.Inconclusive(lint.InconclusiveDraft{KindID: runsOnExpr, Location: c.At(g.At), Note: g.Text + " has a ${{ }} that the rule does not read as values written in the matrix; the rule does not determine the runner that the label names"})
		}
	}
	// the jobs of the reusable workflows of other repositories the jobs
	// call (workflow.definition) are read where the engine runs the rule on
	// them (a remote called workflow), and reported at the uses of the
	// calling job; the engine reports the calls with no answer
	// (lint.RemoteCalleeUnknownKind)
	return nil
}

var selfHostedBase = lint.CVSS{
	AV: metric(lint.AttackVectorNetwork, "the attacker opens a pull request from a fork over the network"),
	AC: metric(lint.AttackComplexityLow, "a pull request whose workflow has a step of their own on the runner is all it takes"),
	AT: metric(lint.AttackRequirementsPresent, "by default the run of a pull request from a first-time contributor waits for approval: the run starts when the attacker has contributed once before, such as a typo fixed and merged, as in the PyTorch report, or when the attacker approves the run of the pull request of the attacker with a credential whose only write access is to the permission Actions; either one is enough", approveForks, stawinski),
	PR: metric(lint.PrivilegesRequiredNone, "anyone with an account forks a public repository"),
	UI: metric(lint.UserInteractionNone, "once the author has contributed, the pull request runs with nobody doing anything"),
	VC: metric(lint.ImpactHigh, "their code reads the secrets and tokens of the jobs that run on the runner after it"),
	VI: metric(lint.ImpactHigh, "it changes what those jobs build and publish"),
	VA: metric(lint.ImpactHigh, "it controls the runner's machine"),
	SC: metric(lint.ImpactHigh, "the runner's network and the jobs of other repositories that share the runner"),
	SI: metric(lint.ImpactHigh, "what those jobs publish reaches those who use it"),
	SA: metric(lint.ImpactLow, "it can take the runner and what it reaches down"),
}

// selfHostedPrivateCVSS is selfHostedBase of a private or internal
// repository: the attacker may read it, and its setting runs the workflows
// of pull requests from its forks.
var selfHostedPrivateCVSS = func() lint.CVSS {
	c := selfHostedBase
	c.AT = metric(lint.AttackRequirementsNone, "the repository runs the workflows of pull requests from its forks, which the finding's condition asks; a run of a collaborator without write access waits for approval when the repository, its organization or its enterprise requires it, which no fact answers, so the worse is taken", forkOptionsDocs, approveForks)
	c.PR = metric(lint.PrivilegesRequiredLow, "forking takes read access, generally: the collaborators of the repository, and for an internal one every member of the enterprise reads it", selfHostedPrivateDocs, internalReaders)
	c.UI = metric(lint.UserInteractionNone, "the pull request runs with nobody doing anything")
	return c
}()

var (
	readerFork     = lint.MustPreconditionID("reader-fork")
	publicRepo     = lint.MustPreconditionID("public-repo")
	prWorkflow     = lint.MustPreconditionID("pr-workflow")
	runnerPersists = lint.MustPreconditionID("runner-persists")
	pytorch2023    = lint.MustIncidentID("pytorch-2023")

	selfHostedDocs = lint.MustCitation("https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners")
	approveForks   = lint.MustCitation("https://docs.github.com/en/actions/how-tos/manage-workflow-runs/approve-runs-from-forks")
	stawinski      = lint.MustCitation("https://johnstawinski.com/2024/01/11/playing-with-fire-how-we-executed-a-critical-supply-chain-attack-on-pytorch/")

	selfHostedPrivateDocs = lint.MustCitation("https://github.com/github/docs/blob/8b39dc44a066dda794bfacdd25653ff86324ef21/content/actions/reference/security/secure-use.md")
	forkSettingsDocs      = lint.MustCitation("https://github.com/github/docs/blob/8b39dc44a066dda794bfacdd25653ff86324ef21/data/reusables/actions/private-repository-forks-overview.md")
	forkOptionsDocs       = lint.MustCitation("https://github.com/github/docs/blob/8b39dc44a066dda794bfacdd25653ff86324ef21/data/reusables/actions/private-repository-forks-options.md")
	internalForkPolicy    = lint.MustCitation("https://github.com/github/docs/blob/8b39dc44a066dda794bfacdd25653ff86324ef21/content/repositories/creating-and-managing-repositories/about-repositories.md#about-internal-repositories")
	personalWriteOnly     = lint.MustCitation("https://github.com/github/docs/blob/8b39dc44a066dda794bfacdd25653ff86324ef21/content/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository.md")
)

var selfHostedRunnerMeta = lint.Meta{
	ID:       SelfHostedRunnerID,
	Problem:  "a repository has a self-hosted runner, which the code of a pull request from a fork reaches, of anyone in a public repository, of whoever may read it in a private or internal one that runs the workflows of such pull requests, and whose state persists for the jobs after it",
	Expected: "the jobs on GitHub-hosted runners, or on self-hosted runners that no pull request from a fork reaches; or a private or internal repository that does not run the workflows of pull requests from its forks. The rule reads the labels of runs-on only: the rule does not distinguish an ephemeral runner from another runner, and does not read the settings of a runner group. An ephemeral runner removes the files and the processes that a job leaves on the machine of the runner before the next job, and the code of a pull request still reaches the network of the runner while the job runs",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessUntrustedCodeExecution}, AttackMeans: []lint.AttackMeans{lint.AttackMeansCode}},
	FindingKinds: []lint.FindingKind{{
		FindingText:     textSelfHostedRunnerPrivate,
		Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor},
		Preconditions:   []lint.PreconditionID{readerFork, prWorkflow, runnerPersists},
		FactKinds:       []facts.Kind{facts.KindRepoPublic, facts.KindRepoAllowForking, facts.KindRepoForkPRRunWorkflows},
		CVSS:            selfHostedPrivateCVSS,
		ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report was found of one who may read a private or internal repository taking its self-hosted runner by a pull request from a fork (searched 2026-10-14)"),
	}, {
		FindingText:     textSelfHostedRunnerPublic,
		Attackers:       []lint.Attacker{lint.AttackerForkPRAuthor},
		Preconditions:   []lint.PreconditionID{publicRepo, prWorkflow, runnerPersists},
		Incidents:       []lint.IncidentID{pytorch2023},
		FactKinds:       []facts.Kind{facts.KindRepoPublic},
		CVSS:            selfHostedBase,
		ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2023 researchers fixed a typo of pytorch/pytorch to become contributors, then ran a pull request's workflow on its self-hosted runners and took secrets and tokens there, as a bug bounty", stawinski),
	}},
	Threat: lint.Threat{
		Actors: []lint.Actor{{Attacker: lint.AttackerForkPRAuthor, Via: "opens a pull request whose workflow, which the pull request writes, runs their code on the self-hosted runner",
			Events: []workflow.EventName{workflow.EventNamePullRequest}, RunStarters: startedBy([]workflow.EventName{workflow.EventNamePullRequest}), Gains: []lint.Gain{lint.GainRunCode, lint.GainPersistOnRunner}}},
		Preconditions: []lint.Precondition{
			{ID: readerFork, Text: "the repository is private or internal, lets those who may read it fork it (repo.allow-forking) and runs the workflows of pull requests from its forks (repo.fork-pr-run-workflows), a setting of private and internal repositories: those who may read it and fork it, generally those with read access, open such a pull request and compromise the runner; every member of the enterprise reads an internal repository, and the policies of the repository, the organization and the enterprise decide who forks it", Cites: []lint.Citation{selfHostedPrivateDocs, internalReaders, forkSettingsDocs, internalForkPolicy}},
			{ID: publicRepo, Text: "the repository is public, so anyone forks it and opens a pull request (repo.public, assumed true); by default, the run of a first-time contributor's pull request waits for approval, a contributor's does not; a credential whose only write access is to the permission Actions can approve the run (the endpoint POST /repos/{owner}/{repo}/actions/runs/{run_id}/approve), and the credential premise keeps the holder of such a credential as a possible attacker", Cites: []lint.Citation{selfHostedDocs, approveForks}},
			{ID: prWorkflow, Text: "a pull request from a fork proposes changes to the repository's workflows, and its pull_request run uses them: its author writes the runs-on", Cites: []lint.Citation{approveForks}},
			{ID: runnerPersists, Text: "a self-hosted runner does not run each job in a clean virtual machine: what a job leaves stays for the jobs after it", Cites: []lint.Citation{selfHostedDocs}},
		},
		Incidents: []lint.Incident{
			{ID: pytorch2023, Date: lint.MustDate("2023-08-09"), Advisory: stawinski,
				Compromised: repos("pytorch/pytorch"),
				Summary:     "researchers became contributors by a typo fix, then a pull request whose workflow they wrote ran on the self-hosted runners of pytorch/pytorch, where they took secrets and tokens; the repository had jobs on runs-on [self-hosted, linux.2xlarge], and the runner they used had labels of its own"},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow},
	UndetectedForms: withRemoteCallee([]lint.UndetectedForm{
		{ID: lint.MustUndetectedFormID("group"), Text: "a runs-on of a runner group: the group may be of self-hosted runners or of GitHub's larger runners, and public repositories cannot use a group's runners by default", Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustUndetectedFormID("custom-label"), Text: "a runs-on of labels of its own without self-hosted, such as linux.2xlarge: a runner may be made without the default labels, and whether a self-hosted runner has them is not known", Disposition: lint.Todo(lint.NeedFact)},
	}),
	InconclusiveKinds: withRemoteCalleeUnknown([]lint.InconclusiveKind{
		{ID: inputDispatch, Text: "a label of runs-on with a ${{ }} that refers to an input of workflow_dispatch (inputs, github.event.inputs), alone or in a string with other text: " + dispatcherChooses, Disposition: lint.Limitation(lint.DeciderDispatcher)},
		{ID: runsOnExpr, Text: "a label of runs-on with a ${{ }} that refers to no input of workflow_dispatch and that the rule does not read as values written in the matrix, such as an input of workflow_call, fromJSON, or a value of the matrix in a string with other text (the rule reads the values of the matrix only for a label that is a ${{ matrix.<name> }} alone)", Disposition: lint.Todo(lint.NeedSameFile)},
	}),
	FalsePositiveForms: []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("group-access"), Text: "a job whose labels only self-hosted runners of the organization have, where all those runners are in runner groups that do not allow public repositories: GitHub does not let a public repository use any runner of such a runner group, and a runner group does not allow public repositories by default", FindingKinds: []lint.FindingKindID{kindSelfHostedRunnerPublic}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("matrix-exclude"), Text: "a self-hosted label of a matrix that its exclude takes out, so no job runs on it", FindingKinds: []lint.FindingKindID{kindSelfHostedRunnerPublic, kindSelfHostedRunnerPrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("matrix-no-label"), Text: "a matrix whose labels are none that can be read, or an empty one, so that no job runs", FindingKinds: []lint.FindingKindID{kindSelfHostedRunnerPublic, kindSelfHostedRunnerPrivate}, Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustFalsePositiveFormID("private-repository"), Text: "a private or internal repository, which not anyone forks: one who may read it and fork it is self-hosted-runner.private", FindingKinds: []lint.FindingKindID{kindSelfHostedRunnerPublic}, FactKinds: []facts.Kind{facts.KindRepoPublic}},
		{ID: lint.MustFalsePositiveFormID("readers-write"), Text: "a private repository whose readers all may write to it, as every collaborator of a repository of a personal account: they reach the runner by pushing a branch, which the rule does not count", FindingKinds: []lint.FindingKindID{kindSelfHostedRunnerPrivate}, Disposition: lint.Todo(lint.NeedFact)},
		{ID: lint.MustFalsePositiveFormID("owner-policy"), Text: "a private or internal repository whose organization or enterprise forbids forking it, or running the workflows of pull requests from forks, where whether the settings of the repository the facts read show the policy was not checked", FindingKinds: []lint.FindingKindID{kindSelfHostedRunnerPrivate}, Disposition: lint.Todo(lint.NeedFact)},
	},
}

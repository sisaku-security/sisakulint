package rules

import (
	"context"
	"strconv"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// SecretsInArtifacts is the rule secrets-in-artifacts: a step leaves a
// credential in a file of the workspace other than .git/config
// (google-github-actions/auth), and an upload of actions/upload-artifact
// after it puts the file in an artifact. actions/setup-dotnet writes its
// nuget.config one directory above the workspace, which an upload takes
// only by a path out of the workspace: upload-input, inconclusive.
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var SecretsInArtifacts lint.Rule = withExamples(lint.WithView[ir.SecretsInArtifactsReader](secretsInArtifacts{}, ir.SecretsInArtifactsView))

type secretsInArtifacts struct{}

func (secretsInArtifacts) Meta() lint.Meta { return secretsInArtifactsMeta }

func (secretsInArtifacts) Check(_ context.Context, c *lint.RuleContext, v ir.SecretsInArtifactsReader) error {
	creds := v.LeftCredentials()
	// the conditions of the steps and their keys, made once each, not once
	// for each pair of a credential and an upload
	credCond := make([]*lint.Condition, len(creds))
	credKey := make([]string, len(creds))
	for i, e := range creds {
		credCond[i] = unlessCond(e.MissingCommits())
		credKey[i] = condKey(credCond[i])
	}
	for _, u := range v.Uploads() {
		if u.AlwaysSkipped() {
			continue // GitHub skips its job in every run: it uploads nothing
		}
		hidden := unlessCond(u.HiddenMissingCommits())
		hiddenKey := condKey(hidden)
		// one finding for each kind: lasting, then job-scoped
		type finding struct {
			or     anyCond
			seen   map[[2]string]bool
			step   int  // the evidence, of creds; -1 for none
			onNone bool // the evidence's step leaves the file on no condition
			steps  int  // the steps counted
		}
		var fs [2]finding
		for k := range fs {
			fs[k].step = -1
		}
		for _, t := range u.TakenCredentials() {
			e := creds[t.Index]
			if e.AlwaysSkipped() || e.File() != analysis.CredentialFileOther {
				continue
			}
			k := 0
			if e.Lifetime() != analysis.CredentialLifetimeLasting {
				if !u.DownloadableDuringRun() {
					continue
				}
				k = 1
			}
			f := &fs[k]
			part, key := (*lint.Condition)(nil), ""
			if t.Hidden {
				part, key = hidden, hiddenKey
			}
			none := credCond[t.Index] == nil && part == nil
			f.steps++
			if f.step < 0 || none && !f.onNone {
				f.step, f.onNone = t.Index, none
			}
			leaf := [2]string{credKey[t.Index], key}
			if f.seen[leaf] {
				continue
			}
			if f.seen == nil {
				f.seen = map[[2]string]bool{}
			}
			f.seen[leaf] = true
			f.or.add(allOf(credCond[t.Index], part), leaf[0]+"&"+leaf[1])
		}
		for k := range fs {
			f := &fs[k]
			cond, some := f.or.cond()
			if !some {
				continue
			}
			e := creds[f.step]
			d := lint.FindingDraft{Location: c.At(u.PathAt()), Condition: cond,
				Evidence: []lint.Related{{Location: c.At(e.At()), Note: stepNote(f.steps - 1)}}}
			if k == 0 {
				d.Args = SecretsInArtifactsLasting{Uses: e.UsesText(), Upload: u.UsesText()}
			} else {
				d.Args = SecretsInArtifactsJobScoped{Uses: e.UsesText(), Upload: u.UsesText()}
			}
			d.Anchor = d.Args.KindID().String()
			c.Report(d)
		}
		artifactGaps(c, u.Inconclusive(), func(g ir.InconclusiveUpload) []lint.Related {
			return artifactGapRelated(c, g, u.PathAt(), analysis.CredentialFileOther)
		}, analysis.CredentialFileOther)
	}
	return nil
}

// stepNote is the note of the step that is the evidence of a finding of
// an upload, with how many other steps before the upload leave a
// credential that the upload takes.
func stepNote(others int) string {
	note := "leaves the credential in a file of the workspace"
	switch {
	case others == 1:
		note += "; 1 more step before the upload leaves a credential that the upload takes"
	case others > 1:
		note += "; " + strconv.Itoa(others) + " more steps before the upload leave a credential that the upload takes"
	}
	return note
}

var (
	secretsLasting = lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker downloads the artifact over the network"),
		AC: metric(lint.AttackComplexityLow, "reading the file in the artifact's zip is all it takes"),
		AT: metric(lint.AttackRequirementsNone, "the credential does not expire with the job: any time while the artifact is kept"),
		PR: metric(lint.PrivilegesRequiredNone, "on a public repository any account downloads the artifacts"),
		UI: metric(lint.UserInteractionNone, "the run uploads the artifact with nobody doing anything"),
		VC: metric(lint.ImpactHigh, "the credential is a secret of the workflow"),
		VI: metric(lint.ImpactNone, "the credential does not write to the repository"),
		VA: metric(lint.ImpactNone, "the credential does not act on the repository"),
		SC: metric(lint.ImpactHigh, "a service account key reads what the account may read in the cloud"),
		SI: metric(lint.ImpactHigh, "it writes what the account may write: deployments, packages"),
		SA: metric(lint.ImpactLow, "it can delete what the account may"),
	}
	secretsJobScoped = lint.CVSS{
		AV: secretsLasting.AV, AC: secretsLasting.AC,
		AT: metric(lint.AttackRequirementsNone, "the file works only while the job runs, a race the attacker has to win; but a workflow that waits for the artifact wins it by itself, as the ArtiPACKED report did for a GITHUB_TOKEN", unit42Artipacked),
		PR: secretsLasting.PR, UI: secretsLasting.UI, VC: secretsLasting.VC, VI: secretsLasting.VI, VA: secretsLasting.VA,
		SC: secretsLasting.SC, SI: secretsLasting.SI, SA: secretsLasting.SA,
	}
)

var leavesFile = lint.MustPreconditionID("leaves-credential-file")

var secretsInArtifactsMeta = lint.Meta{
	ID:       SecretsInArtifactsID,
	Problem:  "a step leaves a credential in a file of the workspace, and actions/upload-artifact after it puts the file in an artifact, which anyone who can read the repository downloads",
	Expected: "the file left out of the artifact's path, or the upload before the step that writes it",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessCredentialLeak}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textSecretsInArtifactsLasting,
			Attackers:       []lint.Attacker{lint.AttackerArtifactReader},
			Preconditions:   []lint.PreconditionID{leavesFile, artifactsTaken},
			CVSS:            secretsLasting,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of such a file taken from an artifact was found"),
		},
		{
			FindingText:     textSecretsInArtifactsJobScoped,
			Attackers:       []lint.Attacker{lint.AttackerArtifactReader},
			Preconditions:   []lint.PreconditionID{leavesFile, artifactsTaken},
			CVSS:            secretsJobScoped,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of such a file taken from an artifact was found"),
		},
	},
	Threat: lint.Threat{
		Actors: artifactReaders([]lint.Gain{lint.GainReadSecrets}),
		Preconditions: []lint.Precondition{
			{ID: leavesFile, Text: "google-github-actions/auth leaves a credential in a file of the workspace: the action writes gha-creds-<16 hex>.json in the workspace unless create_credentials_file is false (a service account key, or with Workload Identity Federation a bearer token that works while the job runs); and the upload takes the file",
				Observed: []lint.Observation{{Date: observedArtifact, Runner: runner, What: "an upload of actions/upload-artifact v4 with path . took gha-creds-0123456789abcdef.json written in the workspace, and a line !gha-creds-*.json left it out"}},
				Cites:    []lint.Citation{lint.MustCitation("https://github.com/google-github-actions/auth/blob/c200f3691d83b41bf9bbd8638997a462592937ed/src/main.ts#L150-L186")}},
			artifactsTakenPre,
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append(append([]lint.UndetectedForm(nil), artifactLimits...),
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("action-code"), Text: "an action whose code puts a file that holds secrets of the job in a place where others read the file: the debug artifact of github/codeql-action, which holds the environment of the job (GHSA-vqf5-2xx6-9wfm), or the cache of GitHub Actions, where gradle/gradle-build-action saves the configuration cache of Gradle, which a run of a pull request from a fork restores (GHSA-h3qr-39j9-4r5v); known-vulnerable-actions reports a step that uses a version in the range of such an advisory", Disposition: lint.Limitation(lint.DeciderRunTime)},
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("git-config"), Text: "a git credential in .git/config", Disposition: lint.OtherRule(ArtipackedID)},
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("before-v4"), Text: "a credential that works while the job runs, in an artifact of actions/upload-artifact v1 to v3, an artifact that the REST API and the web page give only after the run, when the credential has expired", Disposition: lint.NoAddedGain()},
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("same-run-job"), Text: "a credential that works while the job runs, in an artifact of actions/upload-artifact v1 to v3 that another job of the same run downloads with actions/download-artifact v1 to v3 before the job that uploads ends, where the job that downloads runs code of an attacker: whether the download finds the artifact before the job that uploads ends is decided by GitHub Enterprise Server, the only place where v1 to v3 run (v1 to v3 do not run on github.com), and GitHub's documentation does not say", Disposition: lint.Limitation(lint.DeciderRunTime)})),
	InconclusiveKinds:  withRemoteCalleeUnknown(artifactGapKinds("a step of google-github-actions/auth whose with gives the input credentials_json or the input workload_identity_provider and whose input create_credentials_file is a ${{ }}, or whose whole with is a ${{ }}: whether the step writes the file of the credential in the workspace is not analyzed")),
	FalsePositiveForms: artifactFalsePositives([]lint.FindingKindID{kindSecretsInArtifactsLasting, kindSecretsInArtifactsJobScoped}),
}

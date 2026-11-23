package rules

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// Artipacked is the rule artipacked: a step leaves a git credential in
// .git/config, and an upload of actions/upload-artifact after it puts the
// file in an artifact, which anyone who can read the repository takes.
// It reads no summary in a job that GitHub skips in every run
// (AlwaysSkipped): nothing of such a job runs.
var Artipacked lint.Rule = withExamples(lint.WithView[ir.ArtipackedReader](artipacked{}, ir.ArtipackedView))

// ArtipackedID is the ID of artipacked, and PersistCredentialsFalseID the kind of its
// fix.
var (
	ArtipackedID              = lint.MustRuleID("artipacked")
	PersistCredentialsFalseID = lint.MustFixKindID(ir.FixPersistCredentialsFalse.String())
)

type artipacked struct{}

func (artipacked) Meta() lint.Meta { return artipackedMeta }

func (artipacked) Check(_ context.Context, c *lint.RuleContext, v ir.ArtipackedReader) error {
	creds := v.LeftCredentials()
	// the conditions and their keys, made once each, not once for each
	// pair of a credential and an upload
	credCond := make([]*lint.Condition, len(creds))
	credKey := make([]string, len(creds))
	for i, e := range creds {
		credCond[i] = unlessCond(e.MissingCommits())
		credKey[i] = condKey(credCond[i])
	}
	// one finding for each step that leaves the credential: its
	// credentials, a file each, are next to one another in creds
	type finding struct {
		first   int // of creds
		or      anyCond
		seen    map[[2]string]bool        // the leaves of or
		upload  int                       // the evidence, of the uploads; -1 for none
		onNone  bool                      // the evidence takes the file on no condition
		files   []analysis.CredentialFile // what the evidence takes
		uploads int                       // the uploads counted
		last    int                       // the upload counted last
		// unwritten is whether the job's token writes on the condition of
		// the default token (no permissions written): a condition of the
		// job, so of every upload of the step, outside the disjunction
		unwritten bool
	}
	var fs []*finding
	stepOf := make([]*finding, len(creds))
	for i, e := range creds {
		if e.AlwaysSkipped() {
			continue // GitHub skips its job in every run: the step leaves nothing
		}
		if e.File() != analysis.CredentialFileGitConfig && e.File() != analysis.CredentialFileGitCredentialsTemp {
			continue
		}
		if n := len(fs); n > 0 && creds[fs[n-1].first].Key() == e.Key() {
			stepOf[i] = fs[n-1]
			continue
		}
		f := &finding{first: i, upload: -1, last: -1}
		fs = append(fs, f)
		stepOf[i] = f
	}
	ups := v.Uploads()
	for ui, u := range ups {
		if u.AlwaysSkipped() {
			continue // GitHub skips its job in every run: it uploads nothing
		}
		// what the upload adds to the condition, as a hidden file or not,
		// made once for it
		hidden := unlessCond(u.HiddenMissingCommits())
		parts := [2]*lint.Condition{nil, hidden}
		keys := [2]string{"", condKey(hidden)}
		tokenCounts := u.DownloadableDuringRun() && u.TokenWrite() != analysis.TokenWriteNo // before v4 the artifact is there only after the run: the limit before-v4
		for _, t := range u.TakenCredentials() {
			f := stepOf[t.Index]
			if f == nil {
				continue
			}
			e := creds[t.Index]
			h := 0
			if t.Hidden {
				h = 1
			}
			if e.Lifetime() != analysis.CredentialLifetimeLasting {
				if !tokenCounts {
					continue
				}
				f.unwritten = u.TokenWrite() == analysis.TokenWriteUnwritten
			}
			part, key := parts[h], keys[h]
			if f.last != ui {
				f.uploads, f.last = f.uploads+1, ui
			}
			none := credCond[t.Index] == nil && part == nil
			if f.upload < 0 || none && !f.onNone {
				if f.upload != ui {
					f.files = nil
				}
				f.upload, f.onNone = ui, none
			}
			if f.upload == ui && !slices.Contains(f.files, e.File()) {
				f.files = append(f.files, e.File())
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
		artifactGaps(c, u.Inconclusive(), func(g ir.InconclusiveUpload) []lint.Related {
			return artifactGapRelated(c, g, u.PathAt(), analysis.CredentialFileGitConfig, analysis.CredentialFileGitCredentialsTemp)
		}, analysis.CredentialFileGitConfig, analysis.CredentialFileGitCredentialsTemp)
	}
	var writes *lint.Condition
	for _, f := range fs {
		cond, some := f.or.cond()
		if !some {
			continue
		}
		if f.unwritten {
			if writes == nil {
				writes = defaultWrites(c)
			}
			cond = allOf(cond, writes)
		}
		e, u := creds[f.first], ups[f.upload]
		d := lint.FindingDraft{Location: c.At(e.At()), Condition: cond,
			Evidence: []lint.Related{{Location: c.At(u.PathAt()), Note: uploadNote(f.files, f.uploads-1)}}}
		if e.Lifetime() == analysis.CredentialLifetimeLasting {
			d.Args = ArtipackedTokenInput{Uses: e.UsesText(), Upload: u.UsesText()}
		} else {
			d.Args = ArtipackedGitHubToken{Uses: e.UsesText(), Upload: u.UsesText()}
		}
		d.Anchor = d.Args.KindID().String()
		d.Fix, d.NoFix = fixOf(e.PersistCredentialsFalse())
		c.Report(d)
	}
	return nil
}

// uploadNote is the note of the upload that is the evidence of a finding:
// the files of the credential it puts in an artifact, and how many other
// uploads after the step put the credential in artifacts.
func uploadNote(files []analysis.CredentialFile, others int) string {
	var names []string
	for _, f := range files {
		switch f {
		case analysis.CredentialFileGitConfig:
			names = append(names, ".git/config")
		case analysis.CredentialFileGitCredentialsTemp:
			names = append(names, "the file of the credential in RUNNER_TEMP")
		}
	}
	note := "puts " + strings.Join(names, " and ") + " with the credential in an artifact"
	switch {
	case others == 1:
		note += "; 1 more upload after the step that leaves the credential puts the credential in an artifact too"
	case others > 1:
		note += "; " + strconv.Itoa(others) + " more uploads after the step that leaves the credential put the credential in artifacts too"
	}
	return note
}

// the CVSS of the kinds: the attacker reads an artifact and uses the token
var (
	artipackedJobToken = lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker downloads the artifact over the network"),
		AC: metric(lint.AttackComplexityLow, "reading .git/config in the artifact's zip is all it takes"),
		AT: metric(lint.AttackRequirementsNone, "the token works only until the job ends, a race the attacker has to win; but a workflow that waits for the artifact wins it by itself: the ArtiPACKED report took the token of a Nightly CI run of quay/clair whose upload was the job's last step", unit42Artipacked),
		PR: metric(lint.PrivilegesRequiredNone, "on a public repository any account downloads the artifacts; nothing of the repository is needed"),
		UI: metric(lint.UserInteractionNone, "the run uploads the artifact with nobody doing anything"),
		VC: metric(lint.ImpactHigh, "the token reads what the job may read"),
		VI: metric(lint.ImpactHigh, "the token writes what the job may write: pushes, releases"),
		VA: metric(lint.ImpactLow, "the token can cancel runs or delete what the job may"),
		SC: metric(lint.ImpactNone, "the GITHUB_TOKEN opens only this repository"),
		SI: metric(lint.ImpactHigh, "what it pushes or releases reaches those who use the repository"),
		SA: metric(lint.ImpactNone, "nothing past the repository is made unavailable by this as such"),
	}
	artipackedLasting = lint.CVSS{
		AV: metric(lint.AttackVectorNetwork, "the attacker downloads the artifact over the network"),
		AC: metric(lint.AttackComplexityLow, "reading .git/config in the artifact's zip is all it takes"),
		AT: metric(lint.AttackRequirementsNone, "the token does not expire with the job: any time while the artifact is kept"),
		PR: metric(lint.PrivilegesRequiredNone, "on a public repository any account downloads the artifacts; nothing of the repository is needed"),
		UI: metric(lint.UserInteractionNone, "the run uploads the artifact with nobody doing anything"),
		VC: metric(lint.ImpactHigh, "the token reads what its owner may read"),
		VI: metric(lint.ImpactHigh, "the token writes what its owner may write"),
		VA: metric(lint.ImpactLow, "the token can delete what its owner may"),
		SC: metric(lint.ImpactHigh, "a personal access token opens the owner's other repositories"),
		SI: metric(lint.ImpactHigh, "what it pushes reaches those who use those repositories"),
		SA: metric(lint.ImpactNone, "nothing past them is made unavailable by this as such"),
	}
)

var (
	leavesGit   = lint.MustPreconditionID("leaves-git-credential")
	tokenWrites = lint.MustPreconditionID("token-writes")
)

var artipackedMeta = lint.Meta{
	ID:       ArtipackedID,
	Problem:  "a step leaves a git credential in .git/config, or, for actions/checkout v6 and later, in a file of RUNNER_TEMP, and actions/upload-artifact after the step puts the file in an artifact, which anyone who can read the repository downloads",
	Expected: "a checkout whose credential is not left (persist-credentials: false), or an upload of only the files the artifact needs",
	Facets:   lint.Facets{Weakness: []lint.Weakness{lint.WeaknessCredentialLeak}, AttackMeans: []lint.AttackMeans{lint.AttackMeansNone}},
	FindingKinds: []lint.FindingKind{
		{
			FindingText:     textArtipackedGitHubToken,
			Attackers:       []lint.Attacker{lint.AttackerArtifactReader},
			Preconditions:   []lint.PreconditionID{leavesGit, artifactsTaken, tokenWrites},
			Incidents:       []lint.IncidentID{artipacked2024},
			FactKinds:       []facts.Kind{facts.KindRepoDefaultTokenWrite, facts.KindGitCommitContains},
			Fixes:           []lint.FixKindID{PersistCredentialsFalseID},
			CVSS:            artipackedJobToken,
			ExploitMaturity: metric(lint.ExploitMaturityProofOfConcept, "in 2024 a researcher took the GITHUB_TOKEN from artifacts of public projects while their jobs ran, and created a branch of quay/clair with it", unit42Artipacked),
		},
		{
			FindingText:     textArtipackedTokenInput,
			Attackers:       []lint.Attacker{lint.AttackerArtifactReader},
			Preconditions:   []lint.PreconditionID{leavesGit, artifactsTaken},
			FactKinds:       []facts.Kind{facts.KindGitCommitContains},
			Fixes:           []lint.FixKindID{PersistCredentialsFalseID},
			CVSS:            artipackedLasting,
			ExploitMaturity: metric(lint.ExploitMaturityUnreported, "no report of a token given as an input taken from an artifact was found"),
		},
	},
	Threat: lint.Threat{
		Actors: artifactReaders([]lint.Gain{lint.GainReadSecrets, lint.GainWriteWithToken}),
		Preconditions: []lint.Precondition{
			{ID: leavesGit, Text: "a step leaves a git credential in a file: in .git/config of the workspace, actions/checkout v1 to v5 without persist-credentials false, or JamesIves/github-pages-deploy-action without ssh-key; in git-credentials-<uuid>.config of RUNNER_TEMP, actions/checkout v6 and later without persist-credentials false, until its post step at the end of the job removes the file. The upload takes the file: for .git/config, hidden files taken (actions/upload-artifact v4 before v4.4.0, v3 before v3.2.0, or include-hidden-files true), or the path names .git/config; for the file of RUNNER_TEMP, a line of path that starts with ${{ runner.temp }} and includes the file, git-credentials-<uuid>.config, whose name does not start with a dot",
				Observed: []lint.Observation{{Date: observedArtifact, Runner: runner, What: "an upload of actions/upload-artifact v4.3.6 with path ., and of v4 with include-hidden-files true and path ., * or ** after actions/checkout v4, had .git/config; one of v4 with path . alone did not, and one with path .git/config did"}},
				Cites:    []lint.Citation{uploadHidden, checkoutV6}},
			artifactsTakenPre,
			{ID: tokenWrites, Text: "the GITHUB_TOKEN works until the job ends, and the artifact is there before (v4 on): the steps and the post steps after the upload leave the time, even when it is the last step; the token may write: a scope other than id-token written write, or no permissions written and the repository's default writes (repo.default-token-write, assumed true)",
				Observed: []lint.Observation{{Date: observedArtifact, Runner: runner, What: "a token read from .git/config of an artifact downloaded while its job still ran read the private repository then, and was refused after the run"}},
				Cites:    []lint.Citation{tokenDocs}},
		},
		Incidents: []lint.Incident{
			{ID: artipacked2024, Date: lint.MustDate("2024-08-13"), Advisory: unit42Artipacked,
				Compromised: repos("quay/clair"),
				Summary:     "artifacts of public projects had .git/config with the GITHUB_TOKEN of actions/checkout; the researcher took one while the job still ran and created a branch of quay/clair with it; the report does not name the workflow; the one quay/clair fixed after it uploaded the workspace as the job's last step, after actions/cache whose post step saves the cache"},
		},
	},
	Citations: []lint.Citation{cvss},
	Targets:   []lint.InputKind{lint.InputKindWorkflow, lint.InputKindActionMetadata},
	UndetectedForms: withRemoteCallee(append(append([]lint.UndetectedForm(nil), artifactLimits...),
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("checkout-v6"), Text: "actions/checkout v6 and later, which keep the credential in RUNNER_TEMP, out of the workspace, with no upload whose path includes the file git-credentials-<uuid>.config of RUNNER_TEMP (a line of path that starts with ${{ runner.temp }} and includes the file is reported)", Disposition: lint.NoAddedGain()},
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("read-only-token"), Text: "the GITHUB_TOKEN of a job whose permissions have no scope that writes", Disposition: lint.NoAddedGain()},
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("before-v4"), Text: "the GITHUB_TOKEN in an artifact of actions/upload-artifact v1 to v3, an artifact that the REST API and the web page give only after the run, when the token has expired", Disposition: lint.NoAddedGain()},
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("same-run-job"), Text: "the GITHUB_TOKEN in an artifact of actions/upload-artifact v1 to v3 that another job of the same run downloads with actions/download-artifact v1 to v3 before the job that uploads ends, where the job that downloads runs code of an attacker: whether the download finds the artifact before the job that uploads ends is decided by GitHub Enterprise Server, the only place where v1 to v3 run (v1 to v3 do not run on github.com), and GitHub's documentation does not say", Disposition: lint.Limitation(lint.DeciderRunTime)},
		lint.UndetectedForm{ID: lint.MustUndetectedFormID("other-file"), Text: "a credential in a file other than .git/config", Disposition: lint.OtherRule(SecretsInArtifactsID)})),
	InconclusiveKinds: withRemoteCalleeUnknown(artifactGapKinds("a step of actions/checkout at a ref that may leave the git credential in .git/config of the workspace (a release before v6, a branch, or a SHA of no known release), where (a) the input persist-credentials, the input path or the whole with is a ${{ }}, or (b) the input path names a directory out of the workspace: neither whether the step leaves the git credential in a .git/config of the workspace nor the directory of that .git/config is analyzed; and a step of actions/checkout at a ref that may keep the git credential in the file git-credentials-<uuid>.config of RUNNER_TEMP (v6 and later, a branch, or a SHA of no known release), where the input persist-credentials is a ${{ }}, before an upload whose path includes that file: whether the step leaves the git credential in that file is not analyzed")),
	FixKinds: []lint.FixKind{{
		ID:                  PersistCredentialsFalseID,
		Title:               "keep the checkout's credential out of .git/config: persist-credentials: false",
		Safety:              lint.SafetyReview,
		PossibleSideEffects: []ir.SideEffect{ir.SideEffectCredentialNotPersisted},
	}},
	FalsePositiveForms: append(artifactFalsePositives([]lint.FindingKindID{kindArtipackedGitHubToken, kindArtipackedTokenInput}),
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("credential-removed"), Text: "a step before the upload that removes the credential that actions/checkout wrote to .git/config: a second checkout of the same path with persist-credentials false, or git config --unset-all http.https://github.com/.extraheader", FindingKinds: []lint.FindingKindID{kindArtipackedGitHubToken, kindArtipackedTokenInput}, Disposition: lint.Todo(lint.NeedSameFile)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("fork-pull-request"), Text: "pull_request from a fork, whose token is read whatever permissions say, unless a private repository sends a token that writes to the runs of pull requests from forks: the rule reads permissions only", FindingKinds: []lint.FindingKindID{kindArtipackedGitHubToken}, Disposition: lint.Todo(lint.NeedSameFile, lint.NeedFact)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("unknown-version"), Text: "a ref whose version is not known (@main) of actions/checkout or actions/upload-artifact, read in the worst case: the main of actions/checkout now keeps the token out of .git/config", FindingKinds: []lint.FindingKindID{kindArtipackedGitHubToken, kindArtipackedTokenInput}, Disposition: lint.Todo(lint.NeedFact)},
		lint.FalsePositiveForm{ID: lint.MustFalsePositiveFormID("default-token-read"), Text: "a job that writes no permissions, in a repository whose default token is read", FindingKinds: []lint.FindingKindID{kindArtipackedGitHubToken}, FactKinds: []facts.Kind{facts.KindRepoDefaultTokenWrite}},
	),
}

package rules

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// What artipacked and secrets-in-artifacts share: both read the uploads of
// actions/artifact.

// SecretsInArtifactsID is the ID of secrets-in-artifacts, here because the
// limits of artipacked refer to it.
var SecretsInArtifactsID = lint.MustRuleID("secrets-in-artifacts")

// unlessCond is the condition of the pins of an exposure: each commit is
// not in the history of the commit pinned; nil when there is none.
func unlessCond(us []ir.MissingCommit) *lint.Condition {
	var cs []*lint.Condition
	for _, u := range us {
		cs = append(cs, factCond(facts.GitCommitContains{Repo: u.Repo, SHA: u.SHA, Commit: u.Commit}, false))
	}
	return allOf(cs...)
}

// anyCond is the disjunction of the conditions added one at a time: none
// once a condition that always holds (nil) is added, and the same
// condition (by its key, condKey) once. The conditions and their keys are
// made by the caller once for each, not once for each pair of a credential
// and an upload: FactEq and MarshalJSON each encode the query of a leaf.
type anyCond struct {
	conds  []lint.Condition
	keys   map[string]bool
	always bool // a condition that always holds was added
	some   bool // a condition was added
}

// add adds c, whose key is key (not read when c is nil).
func (a *anyCond) add(c *lint.Condition, key string) {
	a.some = true
	if a.always {
		return
	}
	if c == nil {
		a.always, a.conds, a.keys = true, nil, nil
		return
	}
	if a.keys[key] {
		return
	}
	if a.keys == nil {
		a.keys = map[string]bool{}
	}
	a.keys[key] = true
	a.conds = append(a.conds, *c)
}

// cond is the disjunction: nil when it always holds, else the one
// condition or lint.Any of them; some is false when none was added (no
// disjunction: lint.Any of none never holds).
func (a *anyCond) cond() (c *lint.Condition, some bool) {
	switch {
	case !a.some:
		return nil, false
	case a.always:
		return nil, true
	case len(a.conds) == 1:
		one := a.conds[0]
		return &one, true
	}
	or := lint.Any(a.conds...)
	return &or, true
}

// condKey is the key of c for anyCond: its JSON; "" for nil.
func condKey(c *lint.Condition) string {
	if c == nil {
		return ""
	}
	b, err := c.MarshalJSON()
	if err != nil {
		panic(err) // the conditions of the rules are of facts that encode
	}
	return string(b)
}

// defaultWrites is the condition of a job that writes no permissions: the
// repository's default token writes.
func defaultWrites(c *lint.RuleContext) *lint.Condition {
	return factCond(facts.RepoDefaultTokenWrite{Repo: c.Repo()}, true)
}

// artifactGaps reports what the upload and the steps before it have that
// the analysis reaches no conclusion on, of the credentials in files: a gap
// of the other rule's credentials would be no finding of this rule
// whatever its value is. related are the related places of a gap.
func artifactGaps(c *lint.RuleContext, gaps []ir.InconclusiveUpload, related func(ir.InconclusiveUpload) []lint.Related, files ...analysis.CredentialFile) {
	for _, g := range gaps {
		if !slices.ContainsFunc(g.Files, func(f analysis.CredentialFile) bool { return slices.Contains(files, f) }) {
			continue
		}
		c.Inconclusive(lint.InconclusiveDraft{KindID: lint.MustInconclusiveKindID(g.Kind.String()), Location: c.At(g.At), Related: related(g), Note: g.Text + " is a ${{ }} or not a path of the workspace; what the artifact takes is not analyzed"})
	}
}

// artifactGapRelated are the places of the findings that the gap g of the
// upload whose path is at pathAt would give, other than where g is: for a
// gap of a step that leaves a credential, the path of the upload; for a
// gap of the upload, the steps whose credential in a file of files the
// value of the gap decides the taking of (g.Credentials).
func artifactGapRelated(c *lint.RuleContext, g ir.InconclusiveUpload, pathAt ir.Handle, files ...analysis.CredentialFile) []lint.Related {
	if g.Kind == analysis.InconclusiveCredentialInput {
		return []lint.Related{{Location: c.At(pathAt), Note: "the paths that the upload puts in the artifact"}}
	}
	var out []lint.Related
	for _, e := range g.Credentials {
		if slices.Contains(files, e.File) {
			out = append(out, lint.Related{Location: c.At(e.At), Note: leftCredentialNote[e.File]})
		}
	}
	return out
}

// leftCredentialNote is, for each file of a credential, the note of the
// step that leaves the credential in the file.
var leftCredentialNote = map[analysis.CredentialFile]string{
	analysis.CredentialFileGitConfig:          "leaves the credential in .git/config",
	analysis.CredentialFileGitCredentialsTemp: "leaves the credential in a file of RUNNER_TEMP",
	analysis.CredentialFileOther:              "leaves the credential in a file of the workspace",
}

// artifactGapKinds are the inconclusive kinds of artipacked and
// secrets-in-artifacts: what an upload takes, and, as credential says,
// whether a step leaves the credential of the rule.
func artifactGapKinds(credential string) []lint.InconclusiveKind {
	return []lint.InconclusiveKind{
		{ID: lint.MustInconclusiveKindID(analysis.InconclusiveUploadInput.String()), Text: "an upload whose with, a line of path, or include-hidden-files is a ${{ }}, or a path not of the workspace: what it takes is not analyzed", Disposition: lint.Todo(lint.NeedSameFile)},
		{ID: lint.MustInconclusiveKindID(analysis.InconclusiveCredentialInput.String()), Text: credential, Disposition: lint.Todo(lint.NeedSameFile)},
	}
}

var (
	observedArtifact = lint.MustDate("2026-09-30")

	unit42Artipacked = lint.MustCitation("https://unit42.paloaltonetworks.com/github-repo-artifacts-leak-tokens/")
	downloadDocs     = lint.MustCitation("https://docs.github.com/en/actions/how-tos/manage-workflow-runs/download-workflow-artifacts")
	tokenDocs        = lint.MustCitation("https://docs.github.com/en/actions/concepts/security/github_token")
	uploadHidden     = lint.MustCitation("https://github.com/actions/upload-artifact/releases/tag/v4.4.0")
	checkoutV6       = lint.MustCitation("https://github.com/actions/checkout/releases/tag/v6.0.0")

	artifactsTaken = lint.MustPreconditionID("artifact-taken")
	artipacked2024 = lint.MustIncidentID("artipacked-2024")

	artifactsTakenPre = lint.Precondition{
		ID:    artifactsTaken,
		Text:  "anyone signed in with read access to the repository downloads the artifacts of its runs, on a public repository anyone with an account; from actions/upload-artifact v4 an artifact is there as soon as it is uploaded, before the run ends",
		Cites: []lint.Citation{downloadDocs},
	}
)

// artifactReaders are those who take a credential from an artifact.
func artifactReaders(gains []lint.Gain) []lint.Actor {
	return []lint.Actor{{Attacker: lint.AttackerArtifactReader, Via: "downloads the artifact of a run and reads the credential in it",
		Events: []workflow.EventName{}, Gains: gains}}
}

// artifactFalsePositives are the false positive forms artipacked and
// secrets-in-artifacts share, of all the rule's kinds.
func artifactFalsePositives(all []lint.FindingKindID) []lint.FalsePositiveForm {
	return []lint.FalsePositiveForm{
		{ID: lint.MustFalsePositiveFormID("hidden-files-case"), Text: "include-hidden-files written in a case other than true, True and TRUE (tRuE): core.getBooleanInput refuses it, so the step fails and uploads nothing", FindingKinds: all, Disposition: lint.Todo(lint.NeedSameFile)},
	}
}

// artifactLimits are the forms both rules do not report.
var artifactLimits = []lint.UndetectedForm{
	{ID: lint.MustUndetectedFormID("run-command"), Text: "a credential a command of a run writes into the workspace (git clone with a token in the URL, git config), or files a command uploads (gh release upload)", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("other-upload"), Text: "an action other than actions/upload-artifact that makes files of the workspace readable: actions/upload-pages-artifact, a release or a registry", Disposition: lint.Todo(lint.NeedSameFile)},
	{ID: lint.MustUndetectedFormID("unlisted-action"), Text: "an action outside the table that writes a credential into the workspace", Disposition: lint.Todo(lint.NeedFact)},
	{ID: lint.MustUndetectedFormID("other-job"), Text: "a credential left in one job and put in an artifact in another (an artifact downloaded and uploaded again), or left and uploaded inside a composite action the job calls, whose steps are paired only when its action.yml is an input on its own", Disposition: lint.Todo(lint.NeedRepoFile)},
}

package ir

import "github.com/sisaku-security/sisakulint/actions/artifact"

func (x *IR) allUploads() []*Upload {
	x.once(SummaryUpload, func() {
		ups, creds := artifact.Analyze(x.workflow, x.action)
		for _, c := range creds {
			x.leftCredentials = append(x.leftCredentials, x.projectLeftCredential(c))
		}
		for _, u := range ups {
			x.uploads = append(x.uploads, x.projectUpload(u))
		}
	})
	return x.uploads
}

// allLeftCredentials are the credentials the uploads take, each once, in
// the order the indices of TakenCredential name: made with the uploads.
func (x *IR) allLeftCredentials() []*LeftCredential {
	x.once(SummaryLeftCredential, func() { x.allUploads() })
	return x.leftCredentials
}

// projectLeftCredential is the projection of the left credential c: its
// values without their positions and pointers, which the handles keep.
func (x *IR) projectLeftCredential(c artifact.LeftCredential) *LeftCredential {
	o := &LeftCredential{
		key:      keyOf(x.paths, x.input, x.tree, c.Step.Base),
		at:       x.handleOf(c.Step.Base),
		file:     c.File,
		lifetime: c.Lifetime,
		checkout: c.Checkout,
		usesText: c.UsesText,
	}
	for _, n := range c.MissingCommits {
		o.missingCommits = append(o.missingCommits, MissingCommit{Repo: n.Repo, SHA: n.SHA, Commit: n.Commit})
	}
	x.stepOf[o] = c.Step
	return o
}

// projectUpload is the projection of the upload u: its values without
// their positions and pointers, which the handles keep.
func (x *IR) projectUpload(u artifact.Upload) *Upload {
	o := &Upload{
		key:                   keyOf(x.paths, x.input, x.tree, u.Step.Base),
		at:                    x.handleOf(u.Step.Base),
		pathAt:                x.handleOf(u.Step.Base),
		downloadableDuringRun: u.DownloadableDuringRun,
		tokenWrite:            u.TokenWrite,
		usesText:              u.UsesText,
	}
	if u.Path != nil {
		o.pathAt = x.handleOf(u.Path.Base)
	}
	o.takenCredentials = make([]TakenCredential, 0, len(u.TakenCredentials))
	for _, t := range u.TakenCredentials {
		o.takenCredentials = append(o.takenCredentials, TakenCredential{Index: t.Index, Hidden: t.Hidden})
	}
	for _, n := range u.HiddenMissingCommits {
		o.hiddenMissingCommits = append(o.hiddenMissingCommits, MissingCommit{Repo: n.Repo, SHA: n.SHA, Commit: n.Commit})
	}
	for _, g := range u.Inconclusive {
		gap := InconclusiveUpload{Kind: g.Kind, Text: g.Text, Files: g.Files, At: x.handleOf(g.At)}
		for _, c := range g.Credentials {
			gap.Credentials = append(gap.Credentials, GapCredential{File: c.File, At: x.handleOf(c.Step.Base)})
		}
		o.inconclusive = append(o.inconclusive, gap)
	}
	return o
}

// persistCredentialsFalse is the fix that keeps the credential c out of
// .git/config: persist-credentials false on its checkout.
func (c *LeftCredential) persistCredentialsFalse(q *RuleAccess) FixPlan {
	if !c.checkout {
		return FixPlan{NoFix: manual("the step writes the token into the remote URL in .git/config, and no input keeps it out; give it ssh-key, or upload before it")}
	}
	return persistCredentialsFalseFix(&q.ir.editor, *q.ir.stepOf[c])
}

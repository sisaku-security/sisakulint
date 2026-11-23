package prcode

import "github.com/gh-intel/sisakulint/actions/facts"

// MissingCommit is a commit a pinned uses has to lack for a finding to
// hold (git.commit-contains false): a release of the guard of
// actions/checkout, the commit of v6.0.0 of it, a fix of
// actions/download-artifact or of dawidd6/action-download-artifact.
type MissingCommit struct {
	Repo   facts.Repo // of the uses
	SHA    facts.SHA  // the commit it is pinned to
	Commit facts.SHA  // the commit it has to lack
}

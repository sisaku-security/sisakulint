package analysis

import (
	"encoding/json"
	"errors"
)

// CredentialFile is where a step leaves a credential, in the workspace or in
// RUNNER_TEMP.
type CredentialFile uint8

const (
	CredentialFileGitConfig          CredentialFile = iota // .git/config: a git credential, which artipacked reads
	CredentialFileOther                                    // a file of its own: gha-creds-*.json, nuget.config, which secrets-in-artifacts reads
	CredentialFileGitCredentialsTemp                       // git-credentials-<uuid>.config in RUNNER_TEMP, where actions/checkout v6 and later keeps the git credential, which artipacked reads
)

var credentialFileNames = [...]string{"CredentialFileGitConfig", "CredentialFileOther", "CredentialFileGitCredentialsTemp"}

func (p CredentialFile) String() string { return credentialFileNames[p] }

// CredentialLifetime is how long a credential left in a file works.
type CredentialLifetime uint8

const (
	CredentialLifetimeGitHubToken CredentialLifetime = iota // the job's GITHUB_TOKEN: until the job ends
	CredentialLifetimeJob                                   // another that works while the job runs: a Workload Identity Federation file
	CredentialLifetimeLasting                               // one that does not expire with the job: a token given as an input, a key
)

var credentialLifetimeNames = [...]string{"CredentialLifetimeGitHubToken", "CredentialLifetimeJob", "CredentialLifetimeLasting"}

func (l CredentialLifetime) String() string { return credentialLifetimeNames[l] }

// TokenWrite is whether the job's GITHUB_TOKEN may write, by the
// permissions written for the job or else the workflow.
type TokenWrite uint8

const (
	TokenWriteYes       TokenWrite = iota // a scope other than id-token is write, write-all, or a ${{ }}; an action.yml, whose caller is not known
	TokenWriteNo                          // written, with no such scope
	TokenWriteUnwritten                   // not written: the repository's default decides
)

var tokenWriteNames = [...]string{"TokenWriteYes", "TokenWriteNo", "TokenWriteUnwritten"}

func (w TokenWrite) String() string { return tokenWriteNames[w] }

// WriteAll is where write-all is written for a job's GITHUB_TOKEN: the
// job's permissions, else the workflow's when the job writes none.
type WriteAll uint8

const (
	WriteAllNo       WriteAll = iota // the permissions that hold are not write-all, or none is written
	WriteAllJob                      // the job's permissions are write-all
	WriteAllWorkflow                 // the job writes no permissions, and the workflow's are write-all
)

// CalledWorkflowKind is where the reusable workflow a job calls is.
type CalledWorkflowKind uint8

const (
	CalledWorkflowKindNone   CalledWorkflowKind = iota // the job calls none, or its uses is one GitHub rejects
	CalledWorkflowKindLocal                            // ./path or $/path: the workflow's own repository
	CalledWorkflowKindRemote                           // owner/repo/path@ref: another repository, or the same by its name
)

var calledWorkflowKindNames = [...]string{"CalledWorkflowKindNone", "CalledWorkflowKindLocal", "CalledWorkflowKindRemote"}

func (k CalledWorkflowKind) String() string { return calledWorkflowKindNames[k] }

// writeAllNames are the values of $defs/write-all of the schema of
// findings (actions/rules/schema/findings-v0.json), which the args of
// findings hold.
var writeAllNames = [...]string{"WriteAllNo", "job", "workflow"}

func (w WriteAll) String() string { return writeAllNames[w] }

// MarshalJSON writes w as the schema of findings names it
// (findings-v0.json, $defs/write-all); WriteAllNo has no name there.
func (w WriteAll) MarshalJSON() ([]byte, error) {
	if w == WriteAllNo {
		return nil, errors.New("WriteAllNo has no name in the schema of findings")
	}
	return json.Marshal(w.String())
}

// InconclusiveUploadKind is what the analysis of uploads reaches no
// conclusion on. Its String is the ID of the kind in the registry of rules
// (lint.InconclusiveKindID).
type InconclusiveUploadKind uint8

const (
	InconclusiveUploadInput     InconclusiveUploadKind = iota // the with, a line of path, or include-hidden-files of an upload is a ${{ }} or not a path of the workspace
	InconclusiveCredentialInput                               // an input that decides whether or where a step leaves a credential is a ${{ }}
)

var inconclusiveUploadKindNames = [...]string{"upload-input-unknown", "credential-input-unknown"}

func (g InconclusiveUploadKind) String() string { return inconclusiveUploadKindNames[g] }

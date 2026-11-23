package analysis

import (
	"encoding/json"
	"errors"
)

// DownloadInput is the input of a step that downloads an artifact by which
// the analysis takes the artifact for an attacker's run: the
// run-id of actions/download-artifact, the run_id, repo or allow_forks of
// dawidd6/action-download-artifact, or its uses, a search of the runs of a
// workflow, which takes the run of a review of a pull request from a fork
// whatever allow_forks is, and that of the pull request before v4.
type DownloadInput uint8

const (
	DownloadInputRunID      DownloadInput = iota // run-id
	DownloadInputRunIDSnake                      // run_id
	DownloadInputRepo                            // repo
	DownloadInputAllowForks                      // allow_forks
	DownloadInputUses                            // the uses: a search of runs by dawidd6/action-download-artifact
)

var downloadInputNames = [...]string{"run-id", "run_id", "repo", "allow_forks", "uses"}

func (i DownloadInput) String() string { return downloadInputNames[i] }

// MarshalJSON writes i as the schema of findings names it
// (findings-v0.json, $defs/download-input).
func (i DownloadInput) MarshalJSON() ([]byte, error) {
	if int(i) >= len(downloadInputNames) {
		return nil, errors.New("no such DownloadInput")
	}
	return json.Marshal(i.String())
}

// DownloadDestination is where a download puts the files of the artifact,
// as its path reads.
type DownloadDestination uint8

const (
	DownloadDestinationWorkspace    DownloadDestination = iota // the workspace or under it: no path, a relative one, github.workspace, a literal $RUNNER_TEMP, or a release with the zip-slip
	DownloadDestinationRunnerTemp                              // under ${{ runner.temp }}, not leaving it
	DownloadDestinationInconclusive                            // an absolute path, ~, another ${{ }}, a Windows path, or one that leaves by ..
)

var downloadDestinationNames = [...]string{"DownloadDestinationWorkspace", "DownloadDestinationRunnerTemp", "DownloadDestinationInconclusive"}

func (d DownloadDestination) String() string { return downloadDestinationNames[d] }

// ActionsRead is whether the token of a download from another run may read
// its artifacts: the scope actions of the job's permissions, else the
// workflow's, for the GITHUB_TOKEN.
type ActionsRead uint8

const (
	ActionsReadYes       ActionsRead = iota // actions read or write, read-all, write-all, a ${{ }}; an action.yml, whose caller is not known
	ActionsReadNo                           // permissions written without actions: it is none
	ActionsReadUnwritten                    // not written: the repository's default decides (permissive has it, restricted not)
	ActionsReadNotNeeded                    // the token is not the GITHUB_TOKEN
)

var actionsReadNames = [...]string{"ActionsReadYes", "ActionsReadNo", "ActionsReadUnwritten", "ActionsReadNotNeeded"}

func (a ActionsRead) String() string { return actionsReadNames[a] }

// InconclusiveDownloadKind is what the analysis of downloads reaches no
// conclusion on. Its String is the ID of the kind in the registry of rules
// (lint.InconclusiveKindID).
type InconclusiveDownloadKind uint8

const (
	InconclusiveDownloadInput InconclusiveDownloadKind = iota // an input that decides the run is a ${{ }} the tables cannot tell, or the with is one
	InconclusiveDownloadPath                                  // the path is not of the workspace nor under runner.temp, by what is written
)

var inconclusiveDownloadKindNames = [...]string{"download-input-unknown", "download-path-unknown"}

func (g InconclusiveDownloadKind) String() string { return inconclusiveDownloadKindNames[g] }

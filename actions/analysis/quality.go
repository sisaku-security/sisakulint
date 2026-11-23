package analysis

import (
	"encoding/json"
	"errors"
	"strings"
)

// ActionBoolean is a boolean input of an action read by core.getBooleanInput
// of @actions/toolkit: true, True and TRUE are true, false, False and FALSE
// false, and any other value fails the step.
type ActionBoolean uint8

const (
	ActionBooleanUnwritten  ActionBoolean = iota // not written, or empty: the action's default
	ActionBooleanTrue                            // true, True, TRUE
	ActionBooleanFalse                           // false, False, FALSE
	ActionBooleanOther                           // another value, which fails the step
	ActionBooleanExpression                      // a ${{ }}: known when the workflow runs
)

var actionBooleanNames = [...]string{"ActionBooleanUnwritten", "ActionBooleanTrue", "ActionBooleanFalse", "ActionBooleanOther", "ActionBooleanExpression"}

func (b ActionBoolean) String() string { return actionBooleanNames[b] }

// ParseActionBoolean is s, a value written without ${{ }}, as the action
// reads it: trimmed, as core.getInput trims it.
func ParseActionBoolean(s string) ActionBoolean {
	switch strings.TrimSpace(s) {
	case "":
		return ActionBooleanUnwritten
	case "true", "True", "TRUE":
		return ActionBooleanTrue
	case "false", "False", "FALSE":
		return ActionBooleanFalse
	}
	return ActionBooleanOther
}

// PullRequestsWrite is whether a job's GITHUB_TOKEN may write the scope
// pull-requests, by its permissions, else the workflow's.
type PullRequestsWrite uint8

const (
	PullRequestsWriteYes       PullRequestsWrite = iota // pull-requests write, write-all, or a ${{ }}
	PullRequestsWriteNo                                 // permissions written without it: read, none, read-all, or not named
	PullRequestsWriteUnwritten                          // not written: the repository's default decides (repo.default-token-write)
)

var pullRequestsWriteNames = [...]string{"PullRequestsWriteYes", "PullRequestsWriteNo", "PullRequestsWriteUnwritten"}

func (w PullRequestsWrite) String() string { return pullRequestsWriteNames[w] }

// StatusFunction is a function an if may call that reads the status of the
// jobs or the steps before: with one in an if, the runner does not add
// success() && to the if (WorkflowTemplateConverter.ConvertToIfCondition).
type StatusFunction uint8

const (
	StatusFunctionUnset StatusFunction = iota
	StatusFunctionAlways
	StatusFunctionCancelled
	StatusFunctionFailure
	StatusFunctionSuccess
)

var statusFunctionNames = [...]string{"StatusFunctionUnset", "StatusFunctionAlways", "StatusFunctionCancelled", "StatusFunctionFailure", "StatusFunctionSuccess"}

func (f StatusFunction) String() string { return statusFunctionNames[f] }

// statusFunctionArgs are the values of $defs/status-function of the schema
// of findings (actions/rules/schema/findings-v0.json): the names of the
// functions, lowercase.
var statusFunctionArgs = [...]string{"", "always", "cancelled", "failure", "success"}

// ParseStatusFunction is the status function named name, in any case.
func ParseStatusFunction(name string) (StatusFunction, bool) {
	for f := StatusFunctionAlways; f <= StatusFunctionSuccess; f++ {
		if strings.EqualFold(name, statusFunctionArgs[f]) {
			return f, true
		}
	}
	return StatusFunctionUnset, false
}

// MarshalJSON writes f as the schema of findings names it;
// StatusFunctionUnset has no name there.
func (f StatusFunction) MarshalJSON() ([]byte, error) {
	if f == StatusFunctionUnset {
		return nil, errors.New("StatusFunctionUnset is no function")
	}
	return json.Marshal(statusFunctionArgs[f])
}

// AuthoredCommandName is a workflow command that GitHub deprecated
// (set-output, save-state) or disabled (set-env, add-path), whose name the
// text of a run script writes (taint.AuthoredCommand).
type AuthoredCommandName uint8

const (
	AuthoredCommandUnset AuthoredCommandName = iota
	AuthoredSetOutput
	AuthoredSaveState
	AuthoredSetEnv
	AuthoredAddPath
)

var authoredCommandNames = [...]string{"AuthoredCommandUnset", "AuthoredSetOutput", "AuthoredSaveState", "AuthoredSetEnv", "AuthoredAddPath"}

func (n AuthoredCommandName) String() string { return authoredCommandNames[n] }

// authoredCommands are the names of the commands as the runner reads them,
// lowercase, which are the values of $defs/authored-command-name of the
// schema of findings.
var authoredCommands = [...]string{"", "set-output", "save-state", "set-env", "add-path"}

// Command is the name of the command as the runner reads it, lowercase.
func (n AuthoredCommandName) Command() string { return authoredCommands[n] }

// AuthoredCommandNames are the commands, AuthoredSetOutput to
// AuthoredAddPath.
func AuthoredCommandNames() []AuthoredCommandName {
	return []AuthoredCommandName{AuthoredSetOutput, AuthoredSaveState, AuthoredSetEnv, AuthoredAddPath}
}

// MarshalJSON writes n as the schema of findings names it;
// AuthoredCommandUnset has no name there.
func (n AuthoredCommandName) MarshalJSON() ([]byte, error) {
	if n == AuthoredCommandUnset {
		return nil, errors.New("AuthoredCommandUnset is no command")
	}
	return json.Marshal(authoredCommands[n])
}

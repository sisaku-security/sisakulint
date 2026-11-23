package analysis

import (
	"encoding/json"
	"errors"
)

// SecretForm is how a value a run makes carries a secret: the
// runner masks the value of a secret where the value is in the log as it
// is, not one the shell changed.
type SecretForm uint8

const (
	SecretFormUnset       SecretForm = iota
	SecretFormVerbatim               // the secret's value as it is, maybe with more around it: the runner masks it
	SecretFormTransformed            // a value the shell made from the secret's: the runner does not mask it
	SecretFormOpaque                 // what a command not known writes, with the secret among what it reads
)

var secretFormNames = [...]string{"SecretFormUnset", "SecretFormVerbatim", "SecretFormTransformed", "SecretFormOpaque"}

func (f SecretForm) String() string { return secretFormNames[f] }

// ExpansionChange is how a parameter expansion changes the value of its
// variable.
type ExpansionChange uint8

const (
	ExpansionChangeUnset         ExpansionChange = iota
	ExpansionChangeSubstring                     // ${X:offset:length}
	ExpansionChangePrefixRemoval                 // ${X#p}, ${X##p}
	ExpansionChangeSuffixRemoval                 // ${X%p}, ${X%%p}
	ExpansionChangeReplacement                   // ${X/p/r}, ${X//p/r}
	ExpansionChangeCaseChange                    // ${X^}, ${X^^}, ${X,}, ${X,,}, ${X~}, ${X@U}, ${X@L}
	ExpansionChangeOther                         // another operator that gives a value made from X's
)

var expansionChangeNames = [...]string{"", "substring", "prefix-removal", "suffix-removal", "replacement", "case-change", "expansion"}

// Transform is how the shell changed a secret's value: by a parameter
// expansion, or by a command whose output is made from its input (its
// name, the first name of its entry of the commands table).
type Transform struct {
	change  ExpansionChange
	command string
}

// TransformByExpansion is a change of an expansion.
func TransformByExpansion(c ExpansionChange) Transform { return Transform{change: c} }

// TransformByCommand is the change of the command named name.
func TransformByCommand(name string) Transform { return Transform{command: name} }

// String is the change's name, or the command's: "" for none.
func (t Transform) String() string {
	if t.command != "" {
		return t.command
	}
	return expansionChangeNames[t.change]
}

// LogPlace is where a run prints a value to its log, or to what those who
// read its log read.
type LogPlace uint8

const (
	LogPlaceUnset                 LogPlace = iota
	LogPlaceStandardOutputOrError          // what the script writes to the standard output or error it inherits
	LogPlaceJobSummary                     // $GITHUB_STEP_SUMMARY, shown with the run
	LogPlaceXtrace                         // the trace of set -x or of the -x of shell:, on the standard error
	LogPlaceGitHubEnv                      // $GITHUB_ENV: the runner prints its variables in the env of the header of each step after
	LogPlaceStepHeader                     // the header of a step, which prints its run with the ${{ }} evaluated, its env and its with
)

var logPlaceNames = [...]string{"LogPlaceUnset", "LogPlaceStandardOutputOrError", "LogPlaceJobSummary", "LogPlaceXtrace", "LogPlaceGitHubEnv", "LogPlaceStepHeader"}

func (p LogPlace) String() string { return logPlaceNames[p] }

// logPlaceArgs are the values of $defs/log-place of the schema of findings
// (actions/rules/schema/findings-v0.json), which the args of findings hold.
var logPlaceArgs = [...]string{"", "standard-output-or-error", "job-summary", "xtrace", "github-env", "step-header"}

// MarshalJSON writes p as the schema of findings names it; LogPlaceUnset
// has no name there.
func (p LogPlace) MarshalJSON() ([]byte, error) {
	if p == LogPlaceUnset {
		return nil, errors.New("LogPlaceUnset is no place")
	}
	return json.Marshal(logPlaceArgs[p])
}

// FlagPlace is where the ACTIONS_ALLOW_UNSECURE_COMMANDS a step reads is
// set: the env of the workflow, the job or the step, or $GITHUB_ENV of a
// step before.
type FlagPlace uint8

const (
	FlagPlaceUnset FlagPlace = iota
	FlagPlaceWorkflow
	FlagPlaceJob
	FlagPlaceStep
	FlagPlaceGitHubEnv
)

var flagPlaceNames = [...]string{"FlagPlaceUnset", "FlagPlaceWorkflow", "FlagPlaceJob", "FlagPlaceStep", "FlagPlaceGitHubEnv"}

func (p FlagPlace) String() string { return flagPlaceNames[p] }

// flagPlaceArgs are the values of $defs/flag-place of the schema of
// findings, which the args of findings hold.
var flagPlaceArgs = [...]string{"", "workflow", "job", "step", "github-env"}

// MarshalJSON writes p as the schema of findings names it; FlagPlaceUnset
// has no name there.
func (p FlagPlace) MarshalJSON() ([]byte, error) {
	if p == FlagPlaceUnset {
		return nil, errors.New("FlagPlaceUnset is no place")
	}
	return json.Marshal(flagPlaceArgs[p])
}

// UnsecureState is what ACTIONS_ALLOW_UNSECURE_COMMANDS is in the env
// context of a step.
type UnsecureState uint8

const (
	UnsecureOff        UnsecureState = iota // absent, or a value the runner does not read as true
	UnsecureOn                              // a value the runner reads as true (bool.TryParse: true in any case, blanks around it)
	UnsecureExpression                      // a ${{ }}, or an env that is all an expression: not known
)

var unsecureStateNames = [...]string{"UnsecureOff", "UnsecureOn", "UnsecureExpression"}

func (s UnsecureState) String() string { return unsecureStateNames[s] }

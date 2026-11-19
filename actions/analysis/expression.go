package analysis

import (
	"encoding/json"
	"errors"
)

// ExpressionKey is a key whose ${{ }} the quality rule expression reads,
// by what happens when the value of the ${{ }} does not fit the key or an
// error stops its evaluation. Keys of steps
// are of workflows and of composite actions alike.
type ExpressionKey uint8

const (
	ExpressionKeyUnset ExpressionKey = iota
	// GitHub does not start the job, or for a key of the workflow, the run
	ExpressionKeyJobName
	ExpressionKeyRunsOn
	ExpressionKeyJobTimeoutMinutes
	ExpressionKeyJobCancelTimeoutMinutes
	ExpressionKeyJobContinueOnError
	ExpressionKeyEnvironment
	ExpressionKeyStrategyFailFast
	ExpressionKeyStrategyMaxParallel
	ExpressionKeyStrategyMatrix
	ExpressionKeyJobConcurrency
	ExpressionKeyJobIf
	ExpressionKeyCallWith
	ExpressionKeyRunName
	ExpressionKeyWorkflowConcurrency
	// a job that calls the workflow does not start
	ExpressionKeyInputDefault
	// the job fails before its first step or after its last
	ExpressionKeyWorkflowEnv
	ExpressionKeyJobEnv
	ExpressionKeyContainer
	ExpressionKeyServices
	ExpressionKeyDefaultsRun
	ExpressionKeyJobOutputs
	ExpressionKeyEnvironmentURL
	ExpressionKeyCallSecrets
	ExpressionKeyWorkflowCallOutputs
	// the step fails
	ExpressionKeyStepEnv
	ExpressionKeyStepWith
	ExpressionKeyStepRun
	ExpressionKeyStepWorkingDirectory
	ExpressionKeyStepIf
	ExpressionKeyActionOutputs
	// the step runs without the setting
	ExpressionKeyStepTimeoutMinutes
	ExpressionKeyStepContinueOnError
	numExpressionKeys
)

var expressionKeyNames = [numExpressionKeys]string{"ExpressionKeyUnset", "ExpressionKeyJobName", "ExpressionKeyRunsOn", "ExpressionKeyJobTimeoutMinutes", "ExpressionKeyJobCancelTimeoutMinutes", "ExpressionKeyJobContinueOnError", "ExpressionKeyEnvironment", "ExpressionKeyStrategyFailFast", "ExpressionKeyStrategyMaxParallel", "ExpressionKeyStrategyMatrix", "ExpressionKeyJobConcurrency", "ExpressionKeyJobIf", "ExpressionKeyCallWith", "ExpressionKeyRunName", "ExpressionKeyWorkflowConcurrency", "ExpressionKeyInputDefault", "ExpressionKeyWorkflowEnv", "ExpressionKeyJobEnv", "ExpressionKeyContainer", "ExpressionKeyServices", "ExpressionKeyDefaultsRun", "ExpressionKeyJobOutputs", "ExpressionKeyEnvironmentURL", "ExpressionKeyCallSecrets", "ExpressionKeyWorkflowCallOutputs", "ExpressionKeyStepEnv", "ExpressionKeyStepWith", "ExpressionKeyStepRun", "ExpressionKeyStepWorkingDirectory", "ExpressionKeyStepIf", "ExpressionKeyActionOutputs", "ExpressionKeyStepTimeoutMinutes", "ExpressionKeyStepContinueOnError"}

func (k ExpressionKey) String() string { return expressionKeyNames[k] }

// expressionKeyArgs are the values of $defs/expression-key of the schema
// of findings (actions/rules/schema/findings-v0.json).
var expressionKeyArgs = [numExpressionKeys]string{"", "job-name", "runs-on", "job-timeout-minutes", "job-cancel-timeout-minutes", "job-continue-on-error", "environment", "strategy-fail-fast", "strategy-max-parallel", "strategy-matrix", "job-concurrency", "job-if", "call-with", "run-name", "workflow-concurrency", "input-default", "workflow-env", "job-env", "container", "services", "defaults-run", "job-outputs", "environment-url", "call-secrets", "workflow-call-outputs", "step-env", "step-with", "step-run", "step-working-directory", "step-if", "action-outputs", "step-timeout-minutes", "step-continue-on-error"}

// ExpressionKeys are the keys, ExpressionKeyJobName to
// ExpressionKeyStepContinueOnError.
func ExpressionKeys() []ExpressionKey {
	out := make([]ExpressionKey, 0, numExpressionKeys-1)
	for k := ExpressionKeyJobName; k < numExpressionKeys; k++ {
		out = append(out, k)
	}
	return out
}

// MarshalJSON writes k as the schema of findings names it;
// ExpressionKeyUnset has no name there.
func (k ExpressionKey) MarshalJSON() ([]byte, error) {
	if k == ExpressionKeyUnset {
		return nil, errors.New("ExpressionKeyUnset is no key")
	}
	return json.Marshal(expressionKeyArgs[k])
}

// EvaluationError is why a ${{ }} fails when GitHub or the runner
// evaluates it for its key.
type EvaluationError uint8

const (
	EvaluationErrorUnset EvaluationError = iota
	// EvaluationErrorType: the value has a type the key does not take.
	EvaluationErrorType
	// EvaluationErrorFormat: format() has a placeholder whose number is
	// not less than the number of its other arguments.
	EvaluationErrorFormat
	// EvaluationErrorCase: a predicate of case() that is not a boolean.
	EvaluationErrorCase
	// EvaluationErrorFromJSON: fromJSON() of an object or an array.
	EvaluationErrorFromJSON
)

var evaluationErrorNames = [...]string{"EvaluationErrorUnset", "EvaluationErrorType", "EvaluationErrorFormat", "EvaluationErrorCase", "EvaluationErrorFromJSON"}

func (e EvaluationError) String() string { return evaluationErrorNames[e] }

// evaluationErrorArgs are the values of $defs/evaluation-error of the
// schema of findings.
var evaluationErrorArgs = [...]string{"", "value-type", "format-arguments", "case-predicate", "fromjson-argument"}

// MarshalJSON writes e as the schema of findings names it;
// EvaluationErrorUnset has no name there.
func (e EvaluationError) MarshalJSON() ([]byte, error) {
	if e == EvaluationErrorUnset {
		return nil, errors.New("EvaluationErrorUnset is no error")
	}
	return json.Marshal(evaluationErrorArgs[e])
}

// ConfigurationVariableUse is how a ${{ }} uses the value of a reference to
// a configuration variable (vars.<name>), which is the empty string when no
// level defines the name: as the value of the ${{ }}, as the argument of
// fromJSON(), which fails on the empty string, or only as a truth or in a
// comparison, where the empty string reads as false or as a value compared.
type ConfigurationVariableUse uint8

const (
	ConfigurationVariableUseValue    ConfigurationVariableUse = iota // the empty string is what the ${{ }} gives
	ConfigurationVariableUseFromJSON                                 // fromJSON('') fails
	ConfigurationVariableUseCompared                                 // read as a truth, compared, or an argument of contains(), startsWith() or endsWith()
)

var configurationVariableUseNames = [...]string{"ConfigurationVariableUseValue", "ConfigurationVariableUseFromJSON", "ConfigurationVariableUseCompared"}

func (u ConfigurationVariableUse) String() string { return configurationVariableUseNames[u] }

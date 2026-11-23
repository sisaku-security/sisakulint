package taint

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// runnerVariables are the environment variables the runner writes in every
// step, after the env of the workflow, the job and the step, and what it
// writes to each: the keys of the github context it writes as
// GITHUB_<KEY>
// (https://github.com/actions/runner/blob/v2.337.0/src/Runner.Worker/GitHubContext.cs),
// those of the runner context as RUNNER_<KEY> (RunnerContext.cs), which
// ScriptHandler.cs, NodeScriptActionHandler.cs and ContainerActionHandler.cs
// write over the env of the step, and GITHUB_ACTIONS, which
// src/Runner.Sdk/ProcessInvoker.cs sets to true for every process.
// GitHub-hosted runners of Linux, Windows and macOS gave every step the
// runner's value of each, not a value an env wrote.
// GITHUB_ACTION_PATH (only for an action's step) and RUNNER_DEBUG (only in
// a run with debug logging) are not here: an env's value reached the step.
var runnerVariables = map[string]RunnerValue{"GITHUB_ACTIONS": {Fixed: "true"}}

func init() {
	github := []string{"action", "action_ref", "action_repository", "actor", "actor_id", "api_url", "artifacts", "artifacts_list",
		"base_ref", "env", "event_name", "event_path", "graphql_url", "head_ref", "job", "output", "path", "ref", "ref_name", "ref_protected",
		"ref_type", "repository", "repository_id", "repository_owner", "repository_owner_id", "retention_days", "run_attempt", "run_id",
		"run_number", "server_url", "sha", "state", "step_summary", "triggering_actor", "workflow", "workflow_ref", "workflow_sha", "workspace"}
	for _, k := range github {
		runnerVariables["GITHUB_"+strings.ToUpper(k)] = RunnerValue{Context: []expr.PathElem{{Name: "github"}, {Name: k}}}
	}
	for _, k := range []string{"arch", "environment", "name", "os", "temp", "tool_cache", "workspace"} {
		runnerVariables["RUNNER_"+strings.ToUpper(k)] = RunnerValue{Context: []expr.PathElem{{Name: "runner"}, {Name: k}}}
	}
}

// RunnerValue is what the runner writes to a variable of runnerVariables:
// the value of the context Context, or, when Context is nil, the text
// Fixed.
type RunnerValue struct {
	Context []expr.PathElem
	Fixed   string
}

// String is the context as a path (github.sha), or the fixed text.
func (v RunnerValue) String() string {
	if v.Context == nil {
		return v.Fixed
	}
	return expr.PathString(v.Context)
}

// RunnerVariable is what the runner writes to the environment variable
// name in every step (runnerVariables): ok for a name as the runner writes
// it, and, when the runner is Windows (windows), whose variables have no
// case, for the name in another case too.
func RunnerVariable(name string, windows bool) (RunnerValue, bool) {
	v, ok := runnerVariables[name]
	if !ok && windows {
		v, ok = runnerVariables[strings.ToUpper(name)]
	}
	return v, ok
}

// WindowsRunner is whether the runs-on of j picks a Windows runner: no
// label is a ${{ }}, and a label is a GitHub-hosted Windows one (windows-*)
// or windows, the label of the OS of a self-hosted runner, in any case.
// It is false for nil, a step of an action.yml, whose job is the caller's.
func WindowsRunner(j *workflow.Job) bool {
	if j == nil || j.RunsOn.Status != workflow.Present {
		return false
	}
	windows := false
	for _, l := range j.RunsOn.Value.Items {
		if l.HasExpr() {
			return false
		}
		label := strings.ToLower(strings.TrimSpace(l.AsString()))
		if label == "windows" || strings.HasPrefix(label, "windows-") {
			windows = true
		}
	}
	return windows
}

// RunnerVariableOf is the environment variable the runner writes the value
// of the context path to in every step, the reverse of RunnerVariable.
func RunnerVariableOf(path []expr.PathElem) (name string, ok bool) {
	ctx := expr.PathString(path)
	for n, v := range runnerVariables {
		if v.Context != nil && v.String() == ctx {
			return n, true
		}
	}
	return "", false
}

// runnerVariable is RunnerVariable for a variable of the step of c. A name
// in another case than the runner's is one only on Windows and when an env
// of the step writes it (the runner was seen to write over such an env; a
// name in another case that no env writes was not tried).
func (c scope) runnerVariable(name string) (RunnerValue, bool) {
	if v, ok := RunnerVariable(name, false); ok {
		return v, true
	}
	if !WindowsRunner(c.job) {
		return RunnerValue{}, false
	}
	for _, e := range c.envs {
		if e.Status != workflow.Present {
			continue
		}
		if x, ok := e.Value.Lookup(name); ok && x.Key.AsString() == name {
			return RunnerVariable(name, true)
		}
	}
	return RunnerValue{}, false
}

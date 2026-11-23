package ir

import (
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// contextTypes are the types of the contexts where a ${{ }} is read, for
// expr.TypeOfExpr.
// Names are compared by expr.FoldName. A reference the table does not
// type is not answered: it may be any value.
type contextTypes struct {
	inputs    map[string]expr.Type // by folded name; a name both events give other types is not there
	action    bool                 // in an action.yml: inputs.<name> of a declared input is a string
	steps     map[string]bool      // the ids of the steps before, folded
	needs     map[string]bool      // the jobs the job needs, folded
	jobs      map[string]bool      // the jobs of the workflow, folded, for jobs.<id> of workflow_call's outputs
	hasMatrix bool                 // the job has strategy.matrix
	matrix    map[string]expr.Type // the names of the matrix whose types are known
}

// githubTypes are the keys of the github context and their types, by the
// table of github/docs: event is an object, ref_protected a
// boolean, the others strings.
var githubTypes = func() map[string]expr.Type {
	m := map[string]expr.Type{"event": expr.TypeOf(expr.ValueObject), "ref_protected": expr.TypeOf(expr.ValueBoolean)}
	for _, k := range []string{"action", "action_path", "action_ref", "action_repository", "action_status", "actor", "actor_id", "api_url", "artifacts", "artifacts_list", "base_ref", "env", "event_name", "event_path", "graphql_url", "head_ref", "job", "path", "ref", "ref_name", "ref_type", "repository", "repository_id", "repository_owner", "repository_owner_id", "repositoryUrl", "retention_days", "run_id", "run_number", "run_attempt", "secret_source", "server_url", "sha", "token", "triggering_actor", "workflow", "workflow_ref", "workflow_sha", "workspace"} {
		m[expr.FoldName(k)] = expr.TypeOf(expr.ValueString)
	}
	return m
}()

// propertyTypes are the documented keys of the runner, job and strategy
// contexts.
var propertyTypes = map[expr.ContextName]map[string]expr.Type{
	expr.ContextRunner: typesOfKeys(expr.ValueString, "name", "os", "arch", "temp", "tool_cache", "debug", "environment"),
	expr.ContextJob: merge(typesOfKeys(expr.ValueString, "status", "workflow_ref", "workflow_sha", "workflow_repository", "workflow_file_path"),
		typesOfKeys(expr.ValueNumber, "check_run_id"), typesOfKeys(expr.ValueObject, "container", "services")),
	expr.ContextStrategy: merge(typesOfKeys(expr.ValueBoolean, "fail-fast"), typesOfKeys(expr.ValueNumber, "job-index", "job-total", "max-parallel")),
}

// stringKeys are the keys of steps.<id>, needs.<id> and jobs.<id> other
// than outputs, which are strings.
var stringKeys = map[expr.ContextName]map[string]expr.Type{
	expr.ContextSteps: typesOfKeys(expr.ValueString, "outcome", "conclusion"),
	expr.ContextNeeds: typesOfKeys(expr.ValueString, "result"),
	expr.ContextJobs:  typesOfKeys(expr.ValueString, "result"),
}

func typesOfKeys(v expr.ValueType, keys ...string) map[string]expr.Type {
	m := map[string]expr.Type{}
	for _, k := range keys {
		m[expr.FoldName(k)] = expr.TypeOf(v)
	}
	return m
}

func merge(ms ...map[string]expr.Type) map[string]expr.Type {
	out := map[string]expr.Type{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// workflowContextTypes are the types of the contexts in w: in the job j
// (nil for a key of the workflow), at a step after the steps before.
func workflowContextTypes(w *workflow.Workflow, j *workflow.Job, before []workflow.Step) contextTypes {
	c := contextTypes{inputs: map[string]expr.Type{}, jobs: map[string]bool{}}
	conflict := map[string]bool{}
	if w.On.Status == workflow.Present {
		for _, name := range []workflow.EventName{workflow.EventNameWorkflowCall, workflow.EventNameWorkflowDispatch} {
			ev, ok := w.On.Value.Event(name)
			if !ok || ev.Inputs.Status != workflow.Present {
				continue
			}
			for _, e := range ev.Inputs.Value.Entries {
				if e.Key.HasExpr() || e.Value.Status != workflow.Present {
					continue
				}
				k := expr.FoldName(e.Key.AsString())
				t, known := inputType(e.Value.Value)
				if prev, ok := c.inputs[k]; !known || ok && prev != t {
					conflict[k] = true
				}
				c.inputs[k] = t
			}
		}
	}
	for k := range conflict {
		delete(c.inputs, k)
	}
	if w.Jobs.Status == workflow.Present {
		for _, je := range w.Jobs.Value.Entries {
			c.jobs[expr.FoldName(je.Key.AsString())] = true
		}
	}
	if j == nil {
		return c
	}
	c.steps = stepIDs(before)
	c.needs = map[string]bool{}
	if j.Needs.Status == workflow.Present {
		for _, n := range j.Needs.Value.Items {
			c.needs[expr.FoldName(n.AsString())] = true
		}
	}
	c.hasMatrix = j.Matrix.Status == workflow.Present || j.Matrix.Status == workflow.Dynamic
	c.matrix = map[string]expr.Type{}
	for _, v := range j.MatrixVariables {
		if t, ok := matrixType(v); ok {
			c.matrix[expr.FoldName(v.Name)] = t
		}
	}
	return c
}

// actionContextTypes are the types of the contexts in a, at a step after
// the steps before.
func actionContextTypes(a *workflow.ActionMetadata, before []workflow.Step) contextTypes {
	c := contextTypes{inputs: map[string]expr.Type{}, action: true, steps: stepIDs(before)}
	if a.Inputs.Status == workflow.Present {
		for _, e := range a.Inputs.Value.Entries {
			if !e.Key.HasExpr() {
				c.inputs[expr.FoldName(e.Key.AsString())] = expr.TypeOf(expr.ValueString)
			}
		}
	}
	return c
}

// inputType is the type of an input of workflow_call or
// workflow_dispatch by its type; choice and environment, whose type the
// table of github/docs does not tell (choice is named as a type), are not
// known.
func inputType(in workflow.Input) (expr.Type, bool) {
	if in.Type.Status != workflow.Present {
		return expr.AnyType(), false
	}
	switch in.Type.Value.AsString() {
	case "string":
		return expr.TypeOf(expr.ValueString), true
	case "boolean":
		return expr.TypeOf(expr.ValueBoolean), true
	case "number":
		return expr.TypeOf(expr.ValueNumber), true
	}
	return expr.AnyType(), false
}

// matrixType is the union of the types written for v; false when one is a
// ${{ }}, or the matrix may give v other values.
func matrixType(v workflow.MatrixVariable) (expr.Type, bool) {
	if len(v.Types) == 0 {
		return expr.AnyType(), false
	}
	var t expr.Type
	for i, vt := range v.Types {
		if vt == expr.ValueTypeUnset {
			return expr.AnyType(), false
		}
		if i == 0 {
			t = expr.TypeOf(vt)
		} else {
			t = t.Union(expr.TypeOf(vt))
		}
	}
	return t, true
}

func stepIDs(steps []workflow.Step) map[string]bool {
	ids := map[string]bool{}
	for _, s := range steps {
		if s.ID.Status == workflow.Present && !s.ID.Value.HasExpr() {
			ids[expr.FoldName(s.ID.Value.AsString())] = true
		}
	}
	return ids
}

// lookup is the type of the reference path, where the table types it.
func (c contextTypes) lookup(path []expr.PathElem) (expr.Type, bool) {
	name := func(i int) (string, bool) {
		if i >= len(path) || path[i].Name == "" {
			return "", false
		}
		return expr.FoldName(path[i].Name), true
	}
	object, str := expr.TypeOf(expr.ValueObject), expr.TypeOf(expr.ValueString)
	if len(path) == 0 || path[0].Name == "" {
		return expr.AnyType(), false
	}
	root, ok := expr.ParseContextName(path[0].Name)
	if !ok {
		return expr.AnyType(), false
	}
	n := len(path)
	switch root {
	case expr.ContextGithub:
		if n == 1 {
			return object, true
		}
		if k, ok := name(1); ok && n == 2 {
			t, ok := githubTypes[k]
			return t, ok
		}
	case expr.ContextEnv, expr.ContextVars, expr.ContextSecrets:
		// maps of strings: any name, also one given by an index
		if n == 1 {
			return object, true
		}
		if n == 2 {
			return str, true
		}
	case expr.ContextInputs:
		if n == 1 {
			return object, true
		}
		if k, ok := name(1); ok && n == 2 {
			t, ok := c.inputs[k]
			return t, ok
		}
	case expr.ContextSteps, expr.ContextNeeds, expr.ContextJobs:
		ids := map[expr.ContextName]map[string]bool{expr.ContextSteps: c.steps, expr.ContextNeeds: c.needs, expr.ContextJobs: c.jobs}[root]
		if ids == nil {
			return expr.AnyType(), false
		}
		if n == 1 {
			return object, true
		}
		if id, ok := name(1); !ok || !ids[id] {
			return expr.AnyType(), false
		}
		if n == 2 {
			return object, true
		}
		k, ok := name(2)
		switch {
		case !ok:
		case k == "outputs" && n == 3:
			return object, true
		case k == "outputs" && n == 4:
			return str, true
		case n == 3:
			t, ok := stringKeys[root][k]
			return t, ok
		}
	case expr.ContextMatrix:
		if !c.hasMatrix {
			return expr.AnyType(), false
		}
		if n == 1 {
			return object, true
		}
		if k, ok := name(1); ok && n == 2 {
			t, ok := c.matrix[k]
			return t, ok
		}
	case expr.ContextRunner, expr.ContextJob, expr.ContextStrategy:
		if n == 1 {
			return object, true
		}
		if k, ok := name(1); ok && n == 2 {
			t, ok := propertyTypes[root][k]
			return t, ok
		}
	}
	return expr.AnyType(), false
}

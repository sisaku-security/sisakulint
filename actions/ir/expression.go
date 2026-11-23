package ir

import (
	"encoding/json"
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// accepts is what a key takes of the value of a ${{ }} written alone as
// its value: the types
// whose token its definition takes, a boolean or a number also where a
// string is taken (the runner makes a string of them). props are the
// properties of the mapping of a definition with known properties; an
// object takes it only when the object has no other property. null is
// never reported: what the runner does with it was not tried everywhere.
type accepts struct {
	types []expr.ValueType
	props []string
}

var (
	acceptString  = accepts{types: []expr.ValueType{expr.ValueBoolean, expr.ValueNumber, expr.ValueString}}
	acceptNumber  = accepts{types: []expr.ValueType{expr.ValueNumber}}
	acceptBoolean = accepts{types: []expr.ValueType{expr.ValueBoolean}}
	acceptMapping = accepts{types: []expr.ValueType{expr.ValueObject}}
	// the one-of of a string and a mapping of the schema's definitions
	// runs-on-mapping (with a sequence of labels), job-environment-mapping,
	// container-mapping, service-container-mapping and concurrency-mapping
	acceptRunsOn        = accepts{types: []expr.ValueType{expr.ValueBoolean, expr.ValueNumber, expr.ValueString, expr.ValueArray, expr.ValueObject}, props: []string{"group", "labels"}}
	acceptEnvironment   = stringOr("deployment", "name", "url")
	acceptContainer     = stringOr("credentials", "env", "image", "options", "ports", "volumes")
	acceptService       = stringOr("command", "credentials", "entrypoint", "env", "image", "options", "ports", "volumes")
	acceptConcurrency   = stringOr("cancel-in-progress", "group", "queue")
	acceptByInputType   = map[string]accepts{"string": acceptString, "boolean": acceptBoolean, "number": acceptNumber}
	callMistakeEvalErrs = [...]analysis.EvaluationError{expr.MistakeFormatArguments: analysis.EvaluationErrorFormat, expr.MistakeCasePredicate: analysis.EvaluationErrorCase, expr.MistakeFromJSONArgument: analysis.EvaluationErrorFromJSON}
)

func stringOr(props ...string) accepts {
	return accepts{types: []expr.ValueType{expr.ValueBoolean, expr.ValueNumber, expr.ValueString, expr.ValueObject}, props: props}
}

// takes is whether a takes a value of t, where n is the ${{ }} of the value
// and c the types of its contexts: whether any type t may be is taken.
func (a accepts) takes(n expr.Node, t expr.Type, c contextTypes) bool {
	for _, v := range t.ValueTypes() {
		if v == expr.ValueNull {
			return true
		}
		if !slices.Contains(a.types, v) {
			continue
		}
		if v != expr.ValueObject || a.props == nil {
			return true
		}
		props, known := objectProps(n, c)
		if !known || !slices.ContainsFunc(props, func(p string) bool { return !slices.Contains(a.props, p) }) {
			return true
		}
	}
	return false
}

// objectProps are the properties of the object n gives, when they are
// known: of a context whose properties are written down (github, runner,
// job, strategy), of steps.<id> and needs.<id> of the steps and the jobs
// there, and of fromJSON of a literal. The payload of github.event
// depends on the event, and is not known.
func objectProps(n expr.Node, c contextTypes) ([]string, bool) {
	if call, ok := n.(*expr.Call); ok && len(call.Args) == 1 && expr.EqualName(call.Name, "fromJSON") {
		if l, ok := call.Args[0].(*expr.Literal); ok && l.Kind == expr.LitString {
			var m map[string]json.RawMessage
			if json.Unmarshal([]byte(l.Str), &m) != nil {
				return nil, false
			}
			var out []string
			for k := range m {
				out = append(out, k)
			}
			return out, true
		}
		return nil, false
	}
	p, ok := expr.AccessPath(n)
	if !ok || len(p) == 0 || p[0].Name == "" {
		return nil, false
	}
	root, ok := expr.ParseContextName(p[0].Name)
	if !ok {
		return nil, false
	}
	switch {
	case len(p) == 1 && root == expr.ContextGithub:
		return mapKeys(githubTypes), true
	case len(p) == 1 && propertyTypes[root] != nil:
		return mapKeys(propertyTypes[root]), true
	case len(p) == 2 && (root == expr.ContextSteps || root == expr.ContextNeeds) && p[1].Name != "":
		if _, ok := c.lookup(p); !ok {
			return nil, false
		}
		return append(mapKeys(stringKeys[root]), "outputs"), true
	}
	return nil, false
}

func mapKeys(m map[string]expr.Type) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// expressionReader walks the keys of the input of x that may hold a
// ${{ }} and gives each value to visit, with the job and whether a step
// holds it. ExpressionMistake and ConfigurationVariableRef are made by
// two visitors of one walk.
type expressionReader struct {
	x      *IR
	visit  keyVisitor
	inJob  *workflow.Job // the job of the key; nil for a key of the workflow
	inStep bool          // whether a step holds the key
	// untyped is whether visit reads no types: the inputs of the workflows
	// the jobs call are then not read (calledInputs asks workflow.definition)
	untyped bool
}

// keyVisitor is what a walk of the keys does with each value.
type keyVisitor interface {
	// value is the value s of the key k in the contexts c, a the types a
	// ${{ }} written alone may give (nil: not read for its type), and calls
	// whether the calls that fail are read.
	value(r *expressionReader, k analysis.ExpressionKey, s workflow.String, a *accepts, c contextTypes, calls bool)
	// condition is an if of the key k.
	condition(r *expressionReader, k analysis.ExpressionKey, f workflow.Field[workflow.If], c contextTypes)
	// matrixValue is a value of a variable of strategy.matrix written as a
	// mapping, which ExpressionMistake does not read.
	matrixValue(r *expressionReader, s workflow.String)
}

func (r *expressionReader) value(k analysis.ExpressionKey, s workflow.String, a *accepts, c contextTypes, calls bool) {
	r.visit.value(r, k, s, a, c, calls)
}

func (r *expressionReader) condition(k analysis.ExpressionKey, f workflow.Field[workflow.If], c contextTypes) {
	r.visit.condition(r, k, f, c)
}

// mistakeVisitor makes the ExpressionMistakes of x.
type mistakeVisitor struct {
	out []*ExpressionMistake
}

func (*mistakeVisitor) matrixValue(*expressionReader, workflow.String) {}

// value reads the value s of the key k in the contexts c: the calls of
// its ${{ }} that fail (when calls), the type of a ${{ }} written alone
// against a (when a is not nil), and the ${{ }} in a text whose value is
// an object or an array.
func (v *mistakeVisitor) value(r *expressionReader, k analysis.ExpressionKey, s workflow.String, a *accepts, c contextTypes, calls bool) {
	whole := s.IsExpr()
	text := s.Text()
	for _, p := range s.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		src := ""
		if p.Span.Start >= 0 && p.Span.End <= len(text) && p.Span.Start <= p.Span.End {
			src = text[p.Span.Start:p.Span.End]
		}
		add := func(m ExpressionMistake) {
			m.key, m.at, m.expression = keyOf(r.x.paths, r.x.input, r.x.tree, s.Base), r.x.spanOf(s, p.Span), src
			v.out = append(v.out, &m)
		}
		if calls {
			for _, m := range expr.CallMistakes(p.Tree, c.lookup) {
				add(ExpressionMistake{expressionKey: k, error: callMistakeEvalErrs[m.Kind]})
			}
		}
		t := expr.TypeOfExpr(p.Tree, c.lookup)
		if !t.Known() {
			continue
		}
		switch {
		case whole && a != nil:
			if !a.takes(p.Tree, t, c) {
				add(ExpressionMistake{expressionKey: k, error: analysis.EvaluationErrorType, valueTypes: t.ValueTypes()})
			}
		case !whole && t.Only(expr.ValueObject, expr.ValueArray):
			add(ExpressionMistake{valueTypes: t.ValueTypes(), objectText: true})
		}
	}
}

func (r *expressionReader) str(k analysis.ExpressionKey, f workflow.Field[workflow.String], a accepts, c contextTypes) {
	if f.Status == workflow.Present {
		r.value(k, f.Value, &a, c, true)
	}
}

// dynamic reads the ${{ }} of a field written as one where a mapping
// belongs.
func dynamic[T any](r *expressionReader, k analysis.ExpressionKey, f workflow.Field[T], a accepts, c contextTypes) {
	if f.Status == workflow.Dynamic && f.Expr != nil {
		r.value(k, *f.Expr, &a, c, true)
	}
}

// strMap reads a mapping of strings: the mapping, and each value.
func (r *expressionReader) strMap(k analysis.ExpressionKey, f workflow.Field[workflow.Map[workflow.String]], c contextTypes) {
	dynamic(r, k, f, acceptMapping, c)
	if f.Status != workflow.Present {
		return
	}
	for _, e := range f.Value.Entries {
		r.str(k, e.Value, acceptString, c)
	}
}

// condition reads the calls of an if of one ${{ }} or none; an if of text
// and ${{ }} is cond's.
func (v *mistakeVisitor) condition(r *expressionReader, k analysis.ExpressionKey, f workflow.Field[workflow.If], c contextTypes) {
	if f.Status != workflow.Present || f.Value.Expr == nil || f.Value.Expr.Tree == nil || f.Value.Form != workflow.IfExpr && f.Value.Form != workflow.IfBare {
		return
	}
	i := f.Value
	for _, m := range expr.CallMistakes(i.Expr.Tree, c.lookup) {
		v.out = append(v.out, &ExpressionMistake{key: keyOf(r.x.paths, r.x.input, r.x.tree, i.Base), at: r.x.spanOf(i.String, i.Expr.Span), expressionKey: k, error: callMistakeEvalErrs[m.Kind], expression: ifSource(i)})
	}
}

// ifSource is the text of the expression of i: the whole value for a folded
// ${{ 'x' }}, whose Part is the whole value (workflow.If.Folded).
func ifSource(i workflow.If) string {
	text := i.Text()
	if sp := i.Expr.Span; sp.Start >= 0 && sp.End <= len(text) && sp.Start <= sp.End {
		return text[sp.Start:sp.End]
	}
	return text
}

// container reads a container of a job or a service: written as one ${{ }}
// (the one-of of a string and a mapping), or its image, credentials and env.
func (r *expressionReader) container(k analysis.ExpressionKey, f workflow.Field[workflow.Container], whole accepts, c contextTypes) {
	dynamic(r, k, f, whole, c)
	if f.Status != workflow.Present {
		return
	}
	v := f.Value
	if v.Image.Status == workflow.Present && v.Image.Value.Node == v.Node {
		r.str(k, v.Image, whole, c) // container: <string>
		return
	}
	r.str(k, v.Image, acceptString, c)
	r.str(k, v.Username, acceptString, c)
	r.str(k, v.Password, acceptString, c)
	r.strMap(k, v.Env, c)
}

// concurrency reads a concurrency: written as one ${{ }}, or its group and
// cancel-in-progress.
func (r *expressionReader) concurrency(k analysis.ExpressionKey, f workflow.Field[workflow.Concurrency], c contextTypes) {
	dynamic(r, k, f, acceptConcurrency, c)
	if f.Status != workflow.Present {
		return
	}
	v := f.Value
	if v.Group.Status == workflow.Present && v.Group.Value.Node == v.Node {
		r.str(k, v.Group, acceptConcurrency, c) // concurrency: <string>
		return
	}
	r.str(k, v.Group, acceptString, c)
	r.str(k, v.CancelInProgress, acceptBoolean, c)
}

// steps reads the steps, each with the steps before it.
func (r *expressionReader) steps(steps []workflow.Step, ctx func(before []workflow.Step) contextTypes) {
	r.inStep = true
	defer func() { r.inStep = false }()
	for i, s := range steps {
		c := ctx(steps[:i])
		r.value(analysis.ExpressionKeyUnset, s.Name.Value, nil, c, false) // only the text: GitHub warns when the name fails
		r.condition(analysis.ExpressionKeyStepIf, s.If, c)
		r.str(analysis.ExpressionKeyStepRun, s.Run, acceptString, c)
		r.str(analysis.ExpressionKeyStepWorkingDirectory, s.WorkingDirectory, acceptString, c)
		r.strMap(analysis.ExpressionKeyStepWith, s.With, c)
		r.strMap(analysis.ExpressionKeyStepEnv, s.Env, c)
		r.str(analysis.ExpressionKeyStepTimeoutMinutes, s.TimeoutMinutes, acceptNumber, c)
		r.str(analysis.ExpressionKeyStepContinueOnError, s.ContinueOnError, acceptBoolean, c)
	}
}

// allExpressionMistakes are the ${{ }} of the input that do not fit their
// keys or fail when they run (ExpressionMistake).
func (x *IR) allExpressionMistakes() []*ExpressionMistake {
	x.once(SummaryExpressionMistake, func() {
		v := &mistakeVisitor{}
		r := &expressionReader{x: x, visit: v}
		if w := x.workflow; w != nil {
			r.workflow(w)
		}
		if a := x.action; a != nil {
			r.action(a)
		}
		x.expressionMistakes = v.out
	})
	return x.expressionMistakes
}

func (r *expressionReader) workflow(w *workflow.Workflow) {
	c := workflowContextTypes(w, nil, nil)
	r.str(analysis.ExpressionKeyRunName, w.RunName, acceptString, c)
	r.concurrency(analysis.ExpressionKeyWorkflowConcurrency, w.Concurrency, c)
	r.strMap(analysis.ExpressionKeyWorkflowEnv, w.Env, c)
	if w.On.Status == workflow.Present {
		if ev, ok := w.On.Value.Event(workflow.EventNameWorkflowCall); ok {
			if ev.Inputs.Status == workflow.Present {
				for _, e := range ev.Inputs.Value.Entries {
					in := e.Value.Value
					if a, ok := acceptByInputType[in.Type.Value.AsString()]; ok && e.Value.Status == workflow.Present && in.Type.Status == workflow.Present && in.Default.Status == workflow.Present {
						// for its type only: what GitHub does with a call that
						// fails in a default was not tried (the UndetectedForm
						// default-call)
						r.value(analysis.ExpressionKeyInputDefault, in.Default.Value, &a, c, false)
					}
				}
			}
			if ev.Outputs.Status == workflow.Present {
				for _, e := range ev.Outputs.Value.Entries {
					r.str(analysis.ExpressionKeyWorkflowCallOutputs, e.Value.Value.Value, acceptString, c)
				}
			}
		}
	}
	if w.Jobs.Status != workflow.Present {
		return
	}
	var called map[string]map[string]workflow.Input
	if !r.untyped {
		called = r.calledInputs()
	}
	for _, je := range w.Jobs.Value.Entries {
		if je.Value.Status != workflow.Present {
			continue
		}
		j := &je.Value.Value
		r.job(w, j, called[expr.FoldName(je.Key.AsString())])
	}
}

// calledInputs are, by the folded id of a job of the input that calls a
// workflow among the inputs, or a workflow of another repository that
// workflow.definition answers (composite.Reader.ExpandCall), the inputs of
// the workflow_call of the called workflow, by their folded names.
func (r *expressionReader) calledInputs() map[string]map[string]workflow.Input {
	out := map[string]map[string]workflow.Input{}
	if w := r.x.workflow; w != nil && r.x.composites != nil {
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			for _, c := range r.x.composites.ExpandCall(r.x.ctx, &j).Workflows {
				if len(c.Chain) == 1 && c.Workflow != nil {
					if ins, ok := workflowCallInputs(c.Workflow); ok {
						out[expr.FoldName(j.ID.AsString())] = ins
					}
				}
			}
		}
	}
	cs := r.x.callersOf()
	if cs == nil || r.x.name.IsZero() {
		return out
	}
	g := cs.Graph()
	for _, call := range g.CalledBy(r.x.name) {
		if call.Job == nil || call.Step != nil {
			continue
		}
		f, ok := g.File(call.Called)
		if !ok || f.Workflow == nil {
			continue
		}
		if ins, ok := workflowCallInputs(f.Workflow); ok {
			out[expr.FoldName(call.Job.ID.AsString())] = ins
		}
	}
	return out
}

// workflowCallInputs are the inputs of the workflow_call of w, by their
// folded names; false when w declares none.
func workflowCallInputs(w *workflow.Workflow) (map[string]workflow.Input, bool) {
	if w.On.Status != workflow.Present {
		return nil, false
	}
	ev, ok := w.On.Value.Event(workflow.EventNameWorkflowCall)
	if !ok || ev.Inputs.Status != workflow.Present {
		return nil, false
	}
	ins := map[string]workflow.Input{}
	for _, e := range ev.Inputs.Value.Entries {
		if e.Value.Status == workflow.Present && !e.Key.HasExpr() {
			ins[expr.FoldName(e.Key.AsString())] = e.Value.Value
		}
	}
	return ins, true
}

func (r *expressionReader) job(w *workflow.Workflow, j *workflow.Job, called map[string]workflow.Input) {
	r.inJob = j
	defer func() { r.inJob = nil }()
	steps := j.Steps.Value.Items
	c := workflowContextTypes(w, j, nil)
	after := workflowContextTypes(w, j, steps) // outputs and environment.url are read after the steps
	r.str(analysis.ExpressionKeyJobName, j.Name, acceptString, c)
	r.runsOn(j, c)
	r.str(analysis.ExpressionKeyJobTimeoutMinutes, j.TimeoutMinutes, acceptNumber, c)
	r.str(analysis.ExpressionKeyJobCancelTimeoutMinutes, j.CancelTimeoutMinutes, acceptNumber, c)
	r.str(analysis.ExpressionKeyJobContinueOnError, j.ContinueOnError, acceptBoolean, c)
	env := acceptString // the name of environment's mapping
	if j.Environment.Status == workflow.Present && r.keyIs(j.Environment, "environment") {
		env = acceptEnvironment
	}
	r.str(analysis.ExpressionKeyEnvironment, j.Environment, env, c)
	r.str(analysis.ExpressionKeyEnvironmentURL, j.EnvironmentURL, acceptString, after)
	r.str(analysis.ExpressionKeyStrategyFailFast, j.FailFast, acceptBoolean, c)
	r.str(analysis.ExpressionKeyStrategyMaxParallel, j.MaxParallel, acceptNumber, c)
	dynamic(r, analysis.ExpressionKeyStrategyMatrix, j.Matrix, acceptMapping, c)
	for _, mv := range j.MatrixVariables {
		for _, v := range mv.Values {
			r.visit.matrixValue(r, v)
		}
	}
	r.concurrency(analysis.ExpressionKeyJobConcurrency, j.Concurrency, c)
	r.condition(analysis.ExpressionKeyJobIf, j.If, c)
	r.strMap(analysis.ExpressionKeyJobEnv, j.Env, c)
	r.container(analysis.ExpressionKeyContainer, j.Container, acceptContainer, c)
	dynamic(r, analysis.ExpressionKeyServices, j.Services, acceptMapping, c)
	if j.Services.Status == workflow.Present {
		for _, e := range j.Services.Value.Entries {
			r.container(analysis.ExpressionKeyServices, e.Value, acceptService, c)
		}
	}
	r.str(analysis.ExpressionKeyDefaultsRun, j.DefaultShell, acceptString, c)
	r.str(analysis.ExpressionKeyDefaultsRun, j.DefaultWorkingDirectory, acceptString, c)
	r.strMap(analysis.ExpressionKeyJobOutputs, j.Outputs, after)
	r.strMap(analysis.ExpressionKeyCallSecrets, j.Secrets, c)
	dynamic(r, analysis.ExpressionKeyCallWith, j.With, acceptMapping, c)
	if j.With.Status == workflow.Present {
		for _, e := range j.With.Value.Entries {
			a := acceptString
			if in, ok := called[expr.FoldName(e.Key.AsString())]; ok && in.Type.Status == workflow.Present {
				if t, ok := acceptByInputType[in.Type.Value.AsString()]; ok {
					a = t
				}
			}
			r.str(analysis.ExpressionKeyCallWith, e.Value, a, c)
		}
	}
	r.steps(steps, func(before []workflow.Step) contextTypes { return workflowContextTypes(w, j, before) })
}

// runsOn reads runs-on: one ${{ }} (the one-of of a string, a sequence and
// a mapping), or each label.
func (r *expressionReader) runsOn(j *workflow.Job, c contextTypes) {
	dynamic(r, analysis.ExpressionKeyRunsOn, j.RunsOn, acceptRunsOn, c)
	if j.RunsOn.Status != workflow.Present {
		return
	}
	items := j.RunsOn.Value.Items
	if j.RunsOnForm == workflow.RunsOnFormString && len(items) == 1 {
		r.value(analysis.ExpressionKeyRunsOn, items[0], &acceptRunsOn, c, true)
		return
	}
	for _, l := range items {
		r.value(analysis.ExpressionKeyRunsOn, l, &acceptString, c, true)
	}
}

// keyIs is whether the key of f is written as name.
func (r *expressionReader) keyIs(f workflow.Field[workflow.String], name string) bool {
	sp := f.Key.ContentSpan()
	b := r.x.tree.Bytes()
	if sp.Start < 0 || sp.End > len(b) || sp.Start > sp.End {
		return false
	}
	return string(b[sp.Start:sp.End]) == name
}

func (r *expressionReader) action(a *workflow.ActionMetadata) {
	if a.Runs.Status != workflow.Present {
		return
	}
	steps := a.Runs.Value.Steps.Value.Items
	after := actionContextTypes(a, steps)
	if a.Outputs.Status == workflow.Present {
		for _, e := range a.Outputs.Value.Entries {
			r.str(analysis.ExpressionKeyActionOutputs, e.Value.Value.Value, acceptString, after)
		}
	}
	r.steps(steps, func(before []workflow.Step) contextTypes { return actionContextTypes(a, before) })
}

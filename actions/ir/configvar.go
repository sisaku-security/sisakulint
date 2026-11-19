package ir

import (
	"regexp"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// allConfigurationVariableRefs are the references to configuration
// variables by name in the ${{ }} of the workflow of x
// (ConfigurationVariableRef). An action.yml has none: GitHub's parser
// refuses vars there.
func (x *IR) allConfigurationVariableRefs() []*ConfigurationVariableRef {
	x.once(SummaryConfigurationVariableRef, func() {
		w := x.workflow
		if w == nil {
			return
		}
		v := &refVisitor{all: jobEnvironments(w), remoteCallerOnly: x.remoteCallerOnly(), calledOnly: x.origin != nil || job.CalledOnly(w)}
		r := &expressionReader{x: x, visit: v, untyped: true}
		r.workflow(w)
		x.configurationVariableRefs = v.out
	})
	return x.configurationVariableRefs
}

// remoteCallerOnly is whether the workflow of x runs on workflow_call only
// and no job of the inputs calls it: only a caller of another repository
// runs it, and the run reads the configuration variables of the caller's
// repository ("For reusable workflows, the variables from the caller
// workflow's repository are used.", line 104 of
// https://github.com/github/docs/blob/6cbe6413ac7177bb692a78c171a74ae8be50d721/content/actions/reference/workflows-and-actions/variables.md
// ). A remote called workflow is called by a job of the inputs.
func (x *IR) remoteCallerOnly() bool {
	if x.origin != nil || !job.CalledOnly(x.workflow) {
		return false
	}
	cs := x.callersOf()
	if cs == nil || x.name.IsZero() {
		return true
	}
	return !slices.ContainsFunc(cs.Graph().CallsOf(x.name), func(c calls.Call) bool { return c.Job != nil })
}

// environmentOf are the environments a job names: its name when written
// without ${{ }}, and whether it is written with one.
func environmentOf(j *workflow.Job) (names []facts.EnvironmentName, expression bool) {
	env := j.Environment
	if env.Status != workflow.Present {
		return nil, false
	}
	if env.Value.Parts != nil {
		return nil, true
	}
	n, err := facts.ParseEnvironmentName(env.Value.AsString())
	if err != nil {
		return nil, false
	}
	return []facts.EnvironmentName{n}, false
}

// environments are environments of jobs, and whether one is written with
// a ${{ }}.
type environments struct {
	names      []facts.EnvironmentName
	expression bool
}

// jobEnvironments are the environments of every job of w, each once, in
// the order of their names.
func jobEnvironments(w *workflow.Workflow) environments {
	var out environments
	if w.Jobs.Status != workflow.Present {
		return out
	}
	for _, je := range w.Jobs.Value.Entries {
		if je.Value.Status != workflow.Present {
			continue
		}
		ns, e := environmentOf(&je.Value.Value)
		out.names = append(out.names, ns...)
		out.expression = out.expression || e
	}
	slices.SortFunc(out.names, func(a, b facts.EnvironmentName) int { return strings.Compare(a.String(), b.String()) })
	out.names = slices.Compact(out.names)
	return out
}

// refVisitor makes the ConfigurationVariableRefs of a walk of the keys.
type refVisitor struct {
	all              environments // of every job of the workflow
	remoteCallerOnly bool
	// calledOnly is whether the workflow runs only as a called workflow,
	// whose run-name GitHub does not use (the run is named by the
	// workflow of the caller)
	calledOnly bool
	out        []*ConfigurationVariableRef
}

// unseenKeys are the keys where the names of the environment level are
// not seen: in a run on GitHub on 2026-11-03, a name that only the
// environment level of the job's environment defined was the empty string
// in run-name and in the if and the name of the job, and had its value in
// env of the workflow and of the job and in the name, env and run of a
// step.
var unseenKeys = []analysis.ExpressionKey{analysis.ExpressionKeyRunName, analysis.ExpressionKeyJobIf, analysis.ExpressionKeyJobName}

// environmentsAt are the environments whose names the key k at the place
// of r reads.
func (v *refVisitor) environmentsAt(r *expressionReader, k analysis.ExpressionKey) environments {
	if !r.inStep && slices.Contains(unseenKeys, k) {
		return environments{}
	}
	if r.inJob == nil {
		return v.all
	}
	ns, e := environmentOf(r.inJob)
	return environments{names: ns, expression: e}
}

func (v *refVisitor) value(r *expressionReader, k analysis.ExpressionKey, s workflow.String, _ *accepts, _ contextTypes, _ bool) {
	if k == analysis.ExpressionKeyRunName && v.calledOnly {
		return
	}
	text := s.Text()
	for _, p := range s.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		v.refs(r, k, s, p, text, configurationVariableRefsOf(p.Tree, false))
	}
}

func (v *refVisitor) matrixValue(r *expressionReader, s workflow.String) {
	v.value(r, analysis.ExpressionKeyStrategyMatrix, s, nil, contextTypes{}, false)
}

func (v *refVisitor) condition(r *expressionReader, k analysis.ExpressionKey, f workflow.Field[workflow.If], _ contextTypes) {
	if f.Status != workflow.Present || f.Value.Expr == nil || f.Value.Expr.Tree == nil || f.Value.Form != workflow.IfExpr && f.Value.Form != workflow.IfBare {
		return // an if of text and ${{ }} is a text, true whatever the value
	}
	i := f.Value
	v.refs(r, k, i.String, *i.Expr, i.Text(), configurationVariableRefsOf(i.Expr.Tree, true))
}

// refs adds the summaries of the references found in the part p of s.
func (v *refVisitor) refs(r *expressionReader, k analysis.ExpressionKey, s workflow.String, p workflow.Part, text string, found []foundRef) {
	src := text
	if p.Span.Start >= 0 && p.Span.End <= len(text) && p.Span.Start <= p.Span.End {
		src = text[p.Span.Start:p.Span.End]
	}
	env := v.environmentsAt(r, k)
	for _, f := range found {
		v.out = append(v.out, &ConfigurationVariableRef{
			key:                   keyOf(r.x.paths, r.x.input, r.x.tree, s.Base),
			at:                    r.x.spanOf(s, p.InValue(f.node.Span())),
			name:                  f.name,
			expression:            src,
			use:                   f.use,
			environments:          slices.Clone(env.names),
			environmentExpression: env.expression,
			remoteCallerOnly:      v.remoteCallerOnly,
		})
	}
}

// regexpPlaceholders are the placeholders of a format string.
var regexpPlaceholders = regexp.MustCompile(`\{[0-9]+\}`)

// foundRef is a reference to a configuration variable by name in a tree.
type foundRef struct {
	node expr.Node
	name string
	use  analysis.ConfigurationVariableUse
}

// configurationVariableRefsOf are the references by name to the vars
// context in n, with how n uses each: the root is read as a truth for an
// if, and as the value otherwise. The value of a name that no level
// defines is the empty string: the references whose empty string can be
// what the ${{ }} gives are value, the arguments of fromJSON() are
// from-json, and those read only as a truth or compared are compared.
func configurationVariableRefsOf(n expr.Node, truth bool) []foundRef {
	var out []foundRef
	mode := analysis.ConfigurationVariableUseValue
	if truth {
		mode = analysis.ConfigurationVariableUseCompared
	}
	walkConfigurationVariableUse(n, mode, &out)
	return out
}

// walkConfigurationVariableUse adds the references of n, where n is used
// as mode says: ConfigurationVariableUseValue, or
// ConfigurationVariableUseCompared for a truth or a comparison.
func walkConfigurationVariableUse(n expr.Node, mode analysis.ConfigurationVariableUse, out *[]foundRef) {
	if n == nil {
		return
	}
	if name, ok := varsName(n); ok {
		*out = append(*out, foundRef{node: n, name: name, use: mode})
		return
	}
	compared := analysis.ConfigurationVariableUseCompared
	switch x := n.(type) {
	case *expr.Group:
		walkConfigurationVariableUse(x.X, mode, out)
	case *expr.Not:
		walkConfigurationVariableUse(x.X, compared, out)
	case *expr.Compare:
		walkConfigurationVariableUse(x.X, compared, out)
		walkConfigurationVariableUse(x.Y, compared, out)
	case *expr.Logical:
		// an operand after one that reads the same name is guarded: the
		// operand before decides on the empty string whether the runner
		// evaluates it, as vars.X && fromJSON(vars.X) does
		seen := map[string]bool{}
		for i, o := range x.Xs {
			m := compared
			if i == len(x.Xs)-1 {
				m = mode
			}
			var refs []foundRef
			walkConfigurationVariableUse(o, m, &refs)
			for j := range refs {
				if seen[expr.FoldName(refs[j].name)] {
					refs[j].use = compared
				}
			}
			for _, r := range refs {
				seen[expr.FoldName(r.name)] = true
			}
			*out = append(*out, refs...)
		}
	case *expr.Property:
		walkConfigurationVariableUse(x.X, mode, out)
	case *expr.Star:
		walkConfigurationVariableUse(x.X, mode, out)
	case *expr.Index:
		walkConfigurationVariableUse(x.X, mode, out)
		walkConfigurationVariableUse(x.Index, analysis.ConfigurationVariableUseValue, out)
	case *expr.Call:
		walkConfigurationVariableCall(x, mode, out)
	}
}

func walkConfigurationVariableCall(x *expr.Call, mode analysis.ConfigurationVariableUse, out *[]foundRef) {
	compared := analysis.ConfigurationVariableUseCompared
	args := x.Args
	switch strings.ToLower(x.Name) {
	case "contains", "startswith", "endswith":
		for _, a := range args {
			walkConfigurationVariableUse(a, compared, out)
		}
	case "fromjson":
		for _, a := range args {
			walkConfigurationVariableUse(a, analysis.ConfigurationVariableUseFromJSON, out)
		}
	case "case":
		for i, a := range args {
			m := mode
			if i%2 == 0 && i != len(args)-1 {
				m = compared // a predicate
			}
			walkConfigurationVariableUse(a, m, out)
		}
	case "format":
		if len(args) == 0 {
			return
		}
		if l, ok := args[0].(*expr.Literal); ok && l.Kind == expr.LitString && mode == analysis.ConfigurationVariableUseFromJSON && strings.TrimSpace(strings.NewReplacer("{{", "", "}}", "").Replace(regexpPlaceholders.ReplaceAllString(l.Str, ""))) != "" {
			mode = analysis.ConfigurationVariableUseValue // the text around the placeholders is not empty: fromJSON() gets that text
		}
		walkConfigurationVariableUse(args[0], mode, out)
		named := make([]bool, len(args)-1)
		if l, ok := args[0].(*expr.Literal); ok && l.Kind == expr.LitString {
			named, _ = expr.FormatRefs(l.Str, len(args)-1)
		} else {
			for i := range named {
				named[i] = true
			}
		}
		for i, a := range args[1:] {
			if named[i] {
				walkConfigurationVariableUse(a, mode, out)
			}
		}
	case "tojson":
		if mode == analysis.ConfigurationVariableUseFromJSON {
			mode = analysis.ConfigurationVariableUseValue // toJSON('') is "", which fromJSON() reads
		}
		for _, a := range args {
			walkConfigurationVariableUse(a, mode, out)
		}
	default: // join, hashFiles and the functions of the status
		for _, a := range args {
			walkConfigurationVariableUse(a, mode, out)
		}
	}
}

// varsName is the name n reads of the vars context: vars.<name> or
// vars['<name>'], as written.
func varsName(n expr.Node) (string, bool) {
	var x expr.Node
	var name string
	switch r := n.(type) {
	case *expr.Property:
		x, name = r.X, r.Name
	case *expr.Index:
		l, ok := r.Index.(*expr.Literal)
		if !ok || l.Kind != expr.LitString {
			return "", false
		}
		x, name = r.X, l.Str
	default:
		return "", false
	}
	c, ok := x.(*expr.Context)
	return name, ok && expr.EqualName(c.Name, "vars")
}

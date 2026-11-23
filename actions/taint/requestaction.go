package taint

import (
	"regexp"
	"slices"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// requestAction is an action whose input decides where it sends a
// credential, and where it reads the credential from.
type requestAction struct {
	owner, repo string
	inputs      []string // the inputs that decide where the request goes
	env         []string // the variables of env it reads the credential from
	with        []string // the inputs it reads the credential from
}

// requestActions are the actions of the table: the scanner of
// SonarSource's actions sends SONAR_TOKEN to the sonar.host.url args sets;
// octokit/request-action sends its token to a full URL in route, or to
// url.
var requestActions = []requestAction{
	{owner: "SonarSource", repo: "sonarcloud-github-action", inputs: []string{"args"}, env: []string{"SONAR_TOKEN"}},
	{owner: "SonarSource", repo: "sonarqube-scan-action", inputs: []string{"args"}, env: []string{"SONAR_TOKEN"}},
	{owner: "octokit", repo: "request-action", inputs: []string{"route", "url"}, env: []string{"GITHUB_TOKEN"}, with: []string{"github_token", "token"}},
}

// RequestActionSite is an input of a step of an action of the table, with
// the references of its ${{ }}, and the secrets the action sends where the
// input decides.
type RequestActionSite struct {
	Step        workflow.Step
	Job         *workflow.Job // nil in an action.yml
	Action      string        // owner/repo as the table names it
	Input       string
	Value       workflow.String
	ReachableOn []analysis.EventActivity // the attacker's events the step can run on
	// HostRefs are the references of the value that can decide the host
	// the action sends to: all of args, which an attacker's value can
	// split into a -Dsonar.host.url of its own, and those of a route or a
	// URL before its path; PathRefs the others.
	HostRefs []ExprRef
	PathRefs []ExprRef
	Secrets  []SecretRef // by name, the job's token, or the whole context
}

// actionOf is the entry of the table s uses, or nil.
func actionOf(s workflow.Step) *requestAction {
	if s.Uses.Status != workflow.Present {
		return nil
	}
	for _, run := range s.Uses.Value.Actions() {
		for i := range requestActions {
			a := &requestActions[i]
			if run.Is(a.owner, a.repo, workflow.RootActionPath) {
				return a
			}
		}
	}
	return nil
}

// RequestActionSites are the inputs of the steps of w, or of the composite
// steps of a, that decide where an action of the table sends its
// credential, with what AnalyzeIn reads (cl, name).
func RequestActionSites(cl *Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata) []RequestActionSite {
	var out []RequestActionSite
	for _, v := range StepValues(cl, name, w, a, requestInputs) {
		act := actionOf(v.Step)
		input := requestInputsOf(v.Step, act)[v.Index]
		o := RequestActionSite{Step: v.Step, Job: v.Job, Action: act.owner + "/" + act.repo, Input: input, Value: v.Value, ReachableOn: v.ReachableOn}
		o.HostRefs, o.PathRefs = placeRefs(input, v.Value, v.Refs)
		var envs []workflow.Field[workflow.Map[workflow.String]]
		envs = append(envs, v.Step.Env)
		if v.Job != nil {
			envs = append(envs, v.Job.Env)
		}
		if w != nil {
			envs = append(envs, w.Env)
		}
		for _, n := range act.env {
			o.Secrets = append(o.Secrets, envSecretRefs(envs, n, 0)...)
		}
		for _, n := range act.with {
			if val, ok := withValue(v.Step.With, expr.FoldName(n)); ok {
				o.Secrets = append(o.Secrets, secretRefsOf(envs, val, 0)...)
			}
		}
		out = append(out, o)
	}
	return out
}

// requestInputs are the inputs of the table s has, in the order of the
// table.
func requestInputs(s workflow.Step) []Pick {
	act := actionOf(s)
	if act == nil {
		return nil
	}
	var out []Pick
	for _, n := range requestInputsOf(s, act) {
		v, _ := withValue(s.With, expr.FoldName(n))
		out = append(out, Pick{Value: v})
	}
	return out
}

// requestInputsOf are the names of the inputs of act that s writes.
func requestInputsOf(s workflow.Step, act *requestAction) []string {
	var out []string
	for _, n := range act.inputs {
		if _, ok := withValue(s.With, expr.FoldName(n)); ok {
			out = append(out, n)
		}
	}
	return out
}

// placeRefs splits refs, the references of value, the value of the input
// named input: those that can decide the host the action sends to, and the
// others. Every one of args can; a route (its method taken off) or a URL is
// laid out as gh api's endpoint is: a literal head without :// is a path of
// GitHub's API.
func placeRefs(input string, value workflow.String, refs []ExprRef) (host, path []ExprRef) {
	if input == "args" {
		return refs, nil
	}
	text := value.Text()
	var segs []seg
	for i, p := range value.Parts {
		if p.Expr {
			segs = append(segs, seg{kind: segExpr, tree: p.Tree, hole: i})
		} else {
			segs = append(segs, seg{kind: segLiteral, text: text[p.Span.Start:p.Span.End]})
		}
	}
	if input == "route" && len(segs) > 0 && segs[0].kind == segLiteral {
		segs[0].text = routeMethod.ReplaceAllString(segs[0].text, "")
	}
	form := urlFull
	if input == "route" && !urlAtHead(segs) {
		form = urlAPIPath
	}
	l := layoutOf(segs, form)
	for _, r := range refs {
		i := slices.IndexFunc(segs, func(s seg) bool { return s.kind == segExpr && s.hole == r.Part })
		if i < 0 && form != urlAPIPath || i >= 0 && l.decidesHost(i) {
			host = append(host, r)
		} else {
			path = append(path, r)
		}
	}
	return host, path
}

// routeMethod is the method at the head of a route of octokit/request-action
// (GET /repos/{owner}/{repo}).
var routeMethod = regexp.MustCompile(`^\s*[A-Za-z]+\s+`)

// envSecretRefs are the secrets env.name carries, read from the level from
// of envs: in the ${{ }} of its value, and through env.X in them, read from
// the level above.
func envSecretRefs(envs []workflow.Field[workflow.Map[workflow.String]], name string, from int) []SecretRef {
	for lvl := from; lvl < len(envs); lvl++ {
		e := envs[lvl]
		if e.Status != workflow.Present {
			continue
		}
		if x, ok := e.Value.Lookup(name); ok && x.Key.AsString() == name && x.Value.Status == workflow.Present {
			return secretRefsOf(envs, x.Value.Value, lvl+1)
		}
	}
	return nil
}

// secretRefsOf are the secrets the ${{ }} of v read, and those of the
// env.X in them, read from the level from of envs.
func secretRefsOf(envs []workflow.Field[workflow.Map[workflow.String]], v workflow.String, from int) []SecretRef {
	var out []SecretRef
	for _, p := range v.Parts {
		if p.Expr && p.Tree != nil {
			SecretRefs(p.Tree, func(r SecretRef) { out = append(out, r) })
			envRefs(p.Tree, func(n string) { out = append(out, envSecretRefs(envs, n, from)...) })
		}
	}
	return out
}

package ir

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// allJobTimeouts are the jobs of the workflow that run on a runner (not
// those that call a reusable workflow, which take no timeout-minutes), and
// whether each writes timeout-minutes.
func (x *IR) allJobTimeouts() []*JobTimeout {
	x.once(SummaryJobTimeout, func() {
		w := x.workflow
		if w == nil {
			return
		}
		var out []*JobTimeout
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			if j.Uses.Status != workflow.Absent {
				continue
			}
			out = append(out, &JobTimeout{key: keyOf(x.paths, x.input, x.tree, j.Base), at: x.handleOf(j.ID.Base),
				written: j.TimeoutMinutes.Status != workflow.Absent, job: j.ID.AsString()})
		}
		x.jobTimeouts = out
	})
	return x.jobTimeouts
}

// stepInput is the value of the input name of the with of s, or its ${{ }}
// when the with or the value is one; ok is false when it is not written.
func stepInput(s workflow.Step, name string) (v workflow.String, ok bool) {
	if s.With.Status != workflow.Present {
		return workflow.String{}, false
	}
	e, found := s.With.Value.Lookup(name)
	switch {
	case !found:
		return workflow.String{}, false
	case e.Value.Status == workflow.Present:
		return e.Value.Value, true
	case e.Value.Status == workflow.Dynamic && e.Value.Expr != nil:
		return *e.Value.Expr, true
	}
	return workflow.String{}, false
}

// remoteAction is whether u is the action owner/repo, at path (empty for
// the root), in any case of the owner and the name.
func remoteAction(u workflow.Uses, owner, repo, path string) bool {
	return slices.ContainsFunc(u.Actions(), func(a workflow.UsesAction) bool {
		return strings.EqualFold(a.Owner, owner) && strings.EqualFold(a.Repo, repo) && strings.EqualFold(a.Path.String(), path)
	})
}

// hasText is whether v has a character other than white space outside its
// ${{ }}: a value of expressions alone may be empty when the workflow
// runs, which the rule does not know (UndetectedForm expression-restore-keys).
func hasText(v workflow.String) bool {
	if !v.HasExpr() {
		return strings.TrimSpace(v.AsString()) != ""
	}
	for _, p := range v.Parts {
		if !p.Expr && strings.TrimSpace(v.Text()[p.Span.Start:p.Span.End]) != "" {
			return true
		}
	}
	return false
}

// pathsMeet is whether the steps r and s write a line of path alike, as
// text: a path both name the same way. Lines that name one directory
// differently (~/.npm and /home/runner/.npm) do not meet
// (UndetectedForm path-spelling).
func pathsMeet(r, s workflow.Step) bool {
	a, ok := stepInput(r, "path")
	b, ok2 := stepInput(s, "path")
	if !ok || !ok2 {
		return false
	}
	lines := func(v workflow.String) []string {
		var out []string
		for _, l := range strings.Split(v.Text(), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				out = append(out, l)
			}
		}
		return out
	}
	bs := lines(b)
	return slices.ContainsFunc(lines(a), func(l string) bool { return slices.Contains(bs, l) })
}

// lastIndexFunc is the index of the last element of s that f is true of;
// -1 when f is true of none.
func lastIndexFunc[T any](s []T, f func(T) bool) int {
	for i := len(s) - 1; i >= 0; i-- {
		if f(s[i]) {
			return i
		}
	}
	return -1
}

// partialRestore is whether the step s may restore a cache of another key
// than its own:
// actions/cache or actions/cache/restore with restore-keys written, and
// lookup-only not true.
func partialRestore(s workflow.Step) bool {
	if s.Uses.Status != workflow.Present {
		return false
	}
	u := s.Uses.Value
	if !remoteAction(u, "actions", "cache", "restore") && prcode.CacheActionOf(u) != analysis.CacheActionCache {
		return false
	}
	keys, ok := stepInput(s, "restore-keys")
	if !ok || !hasText(keys) {
		return false
	}
	if l, ok := stepInput(s, "lookup-only"); ok && !l.HasExpr() && analysis.ParseActionBoolean(l.AsString()) == analysis.ActionBooleanTrue {
		return false
	}
	return true
}

// allCacheRestoreSaves are the steps that may save a cache after a step of
// their job, or themselves, restored one of another key:
// actions/cache with restore-keys, which saves at the end of the job on a
// miss, and actions/cache/save or actions/cache after an
// actions/cache/restore with restore-keys of a path they save (pathsMeet),
// the last such one. savesOn are the events of the workflow on which the job's
// if, both steps' and the cache-mode let the save happen.
func (x *IR) allCacheRestoreSaves() []*CacheRestoreSave {
	x.once(SummaryCacheRestoreSave, func() {
		w := x.workflow
		if w == nil {
			return
		}
		events := job.EventNamesOf(w)
		var out []*CacheRestoreSave
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			jobIfs := attacker.JobIfs(w, &j)
			// stepIf is the if of a step of j
			stepIf := func(s workflow.Step) attacker.PlacedIf { return attacker.StepIf(w, &j, s.If) }
			on := func(ifs ...attacker.PlacedIf) []workflow.EventName {
				var evs []workflow.EventName
				for _, e := range events {
					if slices.ContainsFunc(jobIfs, func(p attacker.PlacedIf) bool { return !ifAllows(p, e) }) || !job.CacheSavesOn(j.CacheMode, w.CacheMode, e) {
						continue
					}
					if slices.ContainsFunc(ifs, func(p attacker.PlacedIf) bool { return !ifAllows(p, e) }) {
						continue
					}
					evs = append(evs, e)
				}
				return evs
			}
			// onIfs is on for the step outer of j and the step inner of a
			// composite action that outer runs, past the ifs between too
			// (composite.Step.Ifs); the steps of a composite action do not
			// read the needs context of j
			onIfs := func(outer workflow.Step, between []workflow.Field[workflow.If], inner workflow.Step) []workflow.EventName {
				var kept []workflow.EventName
				for _, e := range on(stepIf(outer), attacker.StepIf(nil, nil, inner.If)) {
					if !slices.ContainsFunc(stepIfs(between), func(p attacker.PlacedIf) bool { return !ifAllows(p, e) }) {
						kept = append(kept, e)
					}
				}
				return kept
			}
			steps := j.Steps.Value.Items
			for i, s := range steps {
				if s.Uses.Status != workflow.Present {
					continue
				}
				action := prcode.CacheActionOf(s.Uses.Value)
				if action != analysis.CacheActionCache && action != analysis.CacheActionSave {
					continue
				}
				if action == analysis.CacheActionCache && partialRestore(s) {
					out = append(out, &CacheRestoreSave{key: keyOf(x.paths, x.input, x.tree, s.Base), saveAt: x.handleOf(s.Base), restoreAt: x.handleOf(s.Base),
						action: action, savesOn: on(stepIf(s)), saveText: s.Uses.Value.Text()})
					continue
				}
				// the last actions/cache/restore before s of a path s saves;
				// an actions/cache before s has its own summary, as it saves too
				r := lastIndexFunc(steps[:i], func(r workflow.Step) bool {
					return partialRestore(r) && prcode.CacheActionOf(r.Uses.Value) != analysis.CacheActionCache && pathsMeet(r, s)
				})
				if r < 0 {
					continue
				}
				out = append(out, &CacheRestoreSave{key: keyOf(x.paths, x.input, x.tree, s.Base), saveAt: x.handleOf(s.Base), restoreAt: x.handleOf(steps[r].Base),
					action: action, separate: true, savesOn: on(stepIf(steps[r]), stepIf(s)), saveText: s.Uses.Value.Text()})
			}
			// actions/cache with restore-keys in a composite action of
			// another repository a step runs: at the uses of that step
			for i := range steps {
				s := &steps[i]
				if x.composites == nil || s.Uses.Status != workflow.Present {
					continue
				}
				for _, in := range x.composites.Expand(x.ctx, s, false).Steps {
					if in.Origin.Query == nil || prcode.CacheActionOf(in.Step.Uses.Value) != analysis.CacheActionCache || !partialRestore(*in.Step) {
						continue
					}
					out = append(out, &CacheRestoreSave{key: keyOf(x.paths, x.input, x.tree, s.Base), saveAt: x.handleOf(s.Uses.Value.Base), restoreAt: originHandle(in.Origin, in.Step.Base),
						action: analysis.CacheActionCache, savesOn: onIfs(*s, in.Ifs, *in.Step), saveText: in.Step.Uses.Value.Text(), chain: in.Chain})
				}
			}
		}
		x.cacheRestoreSaves = out
	})
	return x.cacheRestoreSaves
}

// allDependencyReviewSteps are the steps of actions/dependency-review-action
// and what of their with turns off what it checks or asks for a comment
// with whether their job's GITHUB_TOKEN may write
// pull-requests.
func (x *IR) allDependencyReviewSteps() []*DependencyReviewStep {
	x.once(SummaryDependencyReviewStep, func() {
		w := x.workflow
		if w == nil {
			return
		}
		var out []*DependencyReviewStep
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			for _, s := range j.Steps.Value.Items {
				if s.Uses.Status != workflow.Present || !remoteAction(s.Uses.Value, "actions", "dependency-review-action", "") {
					continue
				}
				at := x.handleOf(s.Base)
				d := &DependencyReviewStep{key: keyOf(x.paths, x.input, x.tree, s.Base), at: at, warnOnlyAt: at, vulnerabilityCheckAt: at, licenseCheckAt: at, commentAt: at,
					pullRequestsWrite: job.PullRequestsWriteOf(j.Permissions, w.Permissions), usesText: s.Uses.Value.Text()}
				boolean := func(name string, h *Handle) analysis.ActionBoolean {
					v, ok := stepInput(s, name)
					if !ok {
						return analysis.ActionBooleanUnwritten
					}
					*h = x.handleOf(v.Base)
					if v.HasExpr() {
						return analysis.ActionBooleanExpression
					}
					return analysis.ParseActionBoolean(v.AsString())
				}
				d.warnOnly = boolean("warn-only", &d.warnOnlyAt)
				d.vulnerabilityCheck = boolean("vulnerability-check", &d.vulnerabilityCheckAt)
				d.licenseCheck = boolean("license-check", &d.licenseCheckAt)
				for _, name := range []string{"allow-licenses", "deny-licenses"} {
					if v, ok := stepInput(s, name); ok && (v.HasExpr() || strings.TrimSpace(v.AsString()) != "") {
						d.licensePolicy = true
					}
				}
				// the schema of the action takes the string true for always
				// True is not one of its values
				if v, ok := stepInput(s, "comment-summary-in-pr"); ok && !v.HasExpr() {
					switch strings.TrimSpace(v.AsString()) {
					case "always", "on-failure", "true":
						d.commentRequested = true
						d.commentAt = x.handleOf(v.Base)
					}
				}
				out = append(out, d)
			}
		}
		x.dependencyReviewSteps = out
	})
	return x.dependencyReviewSteps
}

// allRunsUsingSites is the runs.using of the input, when it is an action.yml
// that writes one.
func (x *IR) allRunsUsingSites() []*RunsUsingSite {
	x.once(SummaryRunsUsingSite, func() {
		a := x.action
		if a == nil || a.Runs.Status != workflow.Present || a.Runs.Value.Using.Status != workflow.Present {
			return
		}
		u := a.Runs.Value.Using.Value
		x.runsUsingSites = []*RunsUsingSite{{key: keyOf(x.paths, x.input, x.tree, u.Base), at: x.handleOf(u.Base), using: u.AsString()}}
	})
	return x.runsUsingSites
}

// nodeRuntimeSettingNames are the settings of the Node.js runtime of
// actions that a key of env may name.
var nodeRuntimeSettingNames = []string{"ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION", "FORCE_JAVASCRIPT_ACTIONS_TO_NODE20"}

// allNodeRuntimeSettings are the keys of env, of the workflow, its jobs and
// their steps, or of the steps of a composite action, that name a setting
// of the Node.js runtime, compared without case.
func (x *IR) allNodeRuntimeSettings() []*NodeRuntimeSetting {
	x.once(SummaryNodeRuntimeSetting, func() {
		var out []*NodeRuntimeSetting
		each := func(env workflow.Field[workflow.Map[workflow.String]]) {
			if env.Status != workflow.Present {
				return
			}
			for _, e := range env.Value.Entries {
				name := e.Key.AsString()
				if slices.ContainsFunc(nodeRuntimeSettingNames, func(n string) bool { return strings.EqualFold(n, name) }) {
					out = append(out, &NodeRuntimeSetting{key: keyOf(x.paths, x.input, x.tree, e.Key.Base), at: x.handleOf(e.Key.Base), name: name})
				}
			}
		}
		if w := x.workflow; w != nil {
			each(w.Env)
			for _, je := range w.Jobs.Value.Entries {
				j := je.Value.Value
				each(j.Env)
				for _, s := range j.Steps.Value.Items {
					each(s.Env)
				}
			}
		}
		if a := x.action; a != nil {
			for _, s := range a.Runs.Value.Steps.Value.Items {
				each(s.Env)
			}
		}
		x.nodeRuntimeSettings = out
	})
	return x.nodeRuntimeSettings
}

// allSetupNodeVersions are the node-version of the steps of
// actions/setup-node that have no ${{ }}.
func (x *IR) allSetupNodeVersions() []*SetupNodeVersion {
	x.once(SummarySetupNodeVersion, func() {
		var out []*SetupNodeVersion
		each := func(s workflow.Step) {
			if s.Uses.Status != workflow.Present || !remoteAction(s.Uses.Value, "actions", "setup-node", "") {
				return
			}
			v, ok := stepInput(s, "node-version")
			if !ok || v.HasExpr() {
				return
			}
			out = append(out, &SetupNodeVersion{key: keyOf(x.paths, x.input, x.tree, v.Base), at: x.handleOf(v.Base), nodeVersion: v.AsString()})
		}
		if w := x.workflow; w != nil {
			for _, je := range w.Jobs.Value.Entries {
				for _, s := range je.Value.Value.Steps.Value.Items {
					each(s)
				}
			}
		}
		if a := x.action; a != nil {
			for _, s := range a.Runs.Value.Steps.Value.Items {
				each(s)
			}
		}
		x.setupNodeVersions = out
	})
	return x.setupNodeVersions
}

// allMixedIfs are the ifs of the jobs and steps of the workflow, and of the
// steps of a composite action, that GitHub reads as a string
// (workflow.IfMixed): true whatever their expressions give.
func (x *IR) allMixedIfs() []*MixedIf {
	x.once(SummaryMixedIf, func() {
		var out []*MixedIf
		each := func(f workflow.Field[workflow.If]) {
			if f.Status != workflow.Present || f.Value.Form != workflow.IfMixed {
				return
			}
			c := f.Value
			var status []analysis.StatusFunction
			for _, p := range c.Parts {
				if p.Expr && p.Tree != nil {
					status = attacker.StatusFunctions(p.Tree, status)
				}
			}
			out = append(out, &MixedIf{key: keyOf(x.paths, x.input, x.tree, c.Base), at: x.handleOf(c.Base), condition: c.Text(), statusFunctions: status})
		}
		if w := x.workflow; w != nil {
			for _, je := range w.Jobs.Value.Entries {
				j := je.Value.Value
				each(j.If)
				for _, s := range j.Steps.Value.Items {
					each(s.If)
				}
			}
		}
		if a := x.action; a != nil {
			for _, s := range a.Runs.Value.Steps.Value.Items {
				each(s.If)
			}
		}
		x.mixedIfs = out
	})
	return x.mixedIfs
}

// allEnvKeys are the keys of env that do not set the variable they name:
// of the workflow, its jobs and their steps, a job's container, and of
// runs.env and the steps of an action.yml, a key with = or one the runner
// writes over; of a service, a key with = (the runner does not write its
// variables in a service).
func (x *IR) allEnvKeys() []*EnvKey {
	x.once(SummaryEnvKey, func() {
		var out []*EnvKey
		each := func(env workflow.Field[workflow.Map[workflow.String]], runner bool, windows bool) {
			if env.Status != workflow.Present {
				return
			}
			for _, e := range env.Value.Entries {
				if e.Key.HasExpr() || strings.Contains(e.Key.Text(), "${{") {
					continue // the name is known when the workflow runs
				}
				name := e.Key.AsString()
				k := &EnvKey{key: keyOf(x.paths, x.input, x.tree, e.Key.Base), at: x.handleOf(e.Key.Base), name: name}
				if before, _, ok := strings.Cut(name, "="); ok {
					k.variable = before
				}
				if v, ok := taint.RunnerVariable(name, windows); ok && runner && !sameRunnerValue(e.Value, v) {
					k.runnerValue = v.String()
					if v.Context != nil {
						k.runnerValue = "${{ " + k.runnerValue + " }}"
					}
				}
				if k.variable != "" || k.runnerValue != "" {
					out = append(out, k)
				}
			}
		}
		if w := x.workflow; w != nil {
			// the workflow's env reaches every job: a name in another
			// case is written over in a job on Windows
			anyWindows := false
			for _, je := range w.Jobs.Value.Entries {
				j := je.Value.Value
				anyWindows = anyWindows || taint.WindowsRunner(&j)
			}
			each(w.Env, true, anyWindows)
			for _, je := range w.Jobs.Value.Entries {
				j := je.Value.Value
				windows := taint.WindowsRunner(&j)
				each(j.Env, true, windows)
				if j.Container.Status == workflow.Present {
					each(j.Container.Value.Env, true, false)
				}
				if j.Services.Status == workflow.Present {
					for _, se := range j.Services.Value.Entries {
						each(se.Value.Value.Env, false, false)
					}
				}
				for _, s := range j.Steps.Value.Items {
					each(s.Env, true, windows)
				}
			}
		}
		if a := x.action; a != nil {
			each(a.Runs.Value.Env, true, false)
			for _, s := range a.Runs.Value.Steps.Value.Items {
				each(s.Env, true, false)
			}
		}
		x.envKeys = out
	})
	return x.envKeys
}

// sameRunnerValue is whether the value f of an env key is what the runner
// writes over it, v: exactly ${{ <the context of v> }}, in any case of its
// names, or the text of v when v is no context's. The step then gets the
// value written.
func sameRunnerValue(f workflow.Field[workflow.String], v taint.RunnerValue) bool {
	if f.Status != workflow.Present {
		return false
	}
	s := f.Value
	if v.Context == nil {
		return !s.HasExpr() && strings.TrimSpace(s.AsString()) == v.Fixed
	}
	if !s.IsExpr() {
		return false
	}
	for _, p := range s.Parts {
		if !p.Expr {
			continue
		}
		path, ok := expr.AccessPath(p.Tree)
		return ok && slices.EqualFunc(path, v.Context, func(a, b expr.PathElem) bool { return expr.EqualName(a.Name, b.Name) && !a.Star && a.Dynamic == nil })
	}
	return false
}

// allUsesPathSites are the uses of the steps of the input's jobs, or of the
// composite action, that GitHub does not read as written: a uses of another
// repository, ./ or $/ whose path goes above its root, or whose
// normalized form is not what is written. A uses folded from a literal is
// not one (UndetectedForm folded-uses of uses-path).
func (x *IR) allUsesPathSites() []*UsesPathSite {
	x.once(SummaryUsesPathSite, func() {
		var out []*UsesPathSite
		each := func(steps workflow.Field[workflow.List[workflow.Step]]) {
			for _, s := range steps.Value.Items {
				if s.Uses.Status != workflow.Present {
					continue
				}
				u := s.Uses.Value
				switch u.Kind {
				case workflow.UsesRemote, workflow.UsesLocal, workflow.UsesSelf:
				default:
					continue
				}
				n, read := u.Normalized()
				if read && n == u.AsString() {
					continue
				}
				form := UsesFormUnnormalized
				switch u.Outside {
				case workflow.OutsideRepository:
					form = UsesFormOutsideRepository
				case workflow.OutsideWorkspace:
					form = UsesFormOutsideWorkspace
				}
				out = append(out, &UsesPathSite{key: keyOf(x.paths, x.input, x.tree, u.Base), at: x.handleOf(u.Base), usesText: u.AsString(), normalized: n, form: form})
			}
		}
		if w := x.workflow; w != nil {
			for _, j := range w.Jobs.Value.Entries {
				each(j.Value.Value.Steps)
			}
		}
		if a := x.action; a != nil {
			each(a.Runs.Value.Steps)
		}
		x.usesPathSites = out
	})
	return x.usesPathSites
}

// ifAllows is whether p may be true on a run of the event e, read with
// github.event_name alone (attacker.EventNameOnly): false only when p is
// false whatever the other contexts are.
func ifAllows(p attacker.PlacedIf, e workflow.EventName) bool {
	return attacker.EventNameOnly(p, e) != expr.TruthFalse
}

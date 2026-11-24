package ir

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// cacheWrite is what lets the job j of the workflow save to the cache of
// the default branch's scope:
// on, the attacker's privileged events it may save on, and mode, the
// cache-mode that lets it, the job's or the workflow's. A job saves on an
// event of an attacker only by a cache-mode that writes. It saves on the
// events of its own on, and, when its workflow is
// called, on those of its callers that write none: a caller that writes
// one limits it, and is reported itself when it writes.
func (x *IR) cacheWrite(j *workflow.Job) (on []analysis.EventActivity, mode workflow.Field[workflow.String]) {
	w := x.workflow
	if w == nil || job.CacheWriteOf(j.CacheMode, w.CacheMode) != analysis.CacheWriteYes {
		return nil, workflow.Field[workflow.String]{}
	}
	mode = j.CacheMode
	if mode.Status == workflow.Absent {
		mode = w.CacheMode
	}
	if modes, ok := x.calledCacheWrites(j); ok && !slices.Contains(modes, analysis.CacheWriteYes) && !slices.Contains(modes, analysis.CacheWriteUnwritten) {
		// every job it calls asks for less than the limit: none saves
		return nil, workflow.Field[workflow.String]{}
	}
	add := func(evs []analysis.EventActivity) {
		for _, e := range evs {
			if !slices.Contains(on, e) {
				on = append(on, e)
			}
		}
	}
	add(taint.Filter(x.table(), x.ownEventsOn(cacheEvents()), attacker.JobIfs(x.workflow, j)...))
	cl := x.callersOf()
	g := cl.Graph()
	if g == nil {
		return on, mode
	}
	for _, c := range g.CallsOf(x.name) {
		if c.Job == nil {
			continue
		}
		f, ok := g.File(c.Caller)
		if !ok || f.Workflow == nil || job.CacheWriteOf(c.Job.CacheMode, f.Workflow.CacheMode) != analysis.CacheWriteUnwritten {
			continue
		}
		evs, _ := cl.Events(c.Caller, cacheEvents(), false)
		add(taint.Filter(x.table(), evs, append(attacker.JobIfs(f.Workflow, c.Job), attacker.JobIfs(x.workflow, j)...)...))
	}
	return on, mode
}

// calledCacheWrites are, of each job of the local workflow the job j calls
// (uses: ./…), whether its cache-mode, else its workflow's, saves; ok is
// false when j calls none among the inputs.
func (x *IR) calledCacheWrites(j *workflow.Job) (modes []analysis.CacheWrite, ok bool) {
	if j.Uses.Status != workflow.Present {
		return nil, false
	}
	// a reusable workflow of another repository (workflow.definition): its
	// jobs as answered, and one that may save when it has no answer
	if x.composites != nil {
		e := x.composites.ExpandCall(x.ctx, j)
		for _, c := range e.Workflows {
			if len(c.Chain) != 1 || c.Workflow == nil {
				continue
			}
			ok = true
			for _, je := range c.Workflow.Jobs.Value.Entries {
				if je.Value.Status == workflow.Present {
					modes = append(modes, job.CacheWriteOf(je.Value.Value.CacheMode, c.Workflow.CacheMode))
				}
			}
		}
		for _, n := range e.Unanswered {
			if len(n.Chain) == 1 {
				ok = true
				modes = append(modes, analysis.CacheWriteUnwritten)
			}
		}
	}
	g := x.callersOf().Graph()
	if g == nil {
		return modes, ok
	}
	for _, d := range g.Dependents(x.name) {
		if !slices.ContainsFunc(g.CallsOf(d), func(c calls.Call) bool {
			return c.Caller == x.name && c.Job != nil && c.Job.ID.AsString() == j.ID.AsString()
		}) {
			continue
		}
		f, found := g.File(d)
		if !found || f.Workflow == nil {
			continue
		}
		ok = true
		for _, je := range f.Workflow.Jobs.Value.Entries {
			if je.Value.Status == workflow.Present {
				modes = append(modes, job.CacheWriteOf(je.Value.Value.CacheMode, f.Workflow.CacheMode))
			}
		}
	}
	return modes, ok
}

// cacheSaveOn are the attacker's privileged events on which the steps of
// the job j may save to the cache of the default branch's scope: those of
// cacheWrite, and, when j writes no cache-mode that saves nothing, those of
// its callers that write one that saves, which run it with that
// (writable-job is the caller's there). It is what the kinds of
// the steps read.
func (x *IR) cacheSaveOn(j *workflow.Job) []analysis.EventActivity {
	on, _ := x.cacheWrite(j)
	w := x.workflow
	if w == nil || job.CacheWriteOf(j.CacheMode, w.CacheMode) == analysis.CacheWriteNo {
		return on
	}
	cl := x.callersOf()
	g := cl.Graph()
	if g == nil {
		return on
	}
	for _, c := range g.CallsOf(x.name) {
		if c.Job == nil {
			continue
		}
		f, ok := g.File(c.Caller)
		if !ok || f.Workflow == nil || job.CacheWriteOf(c.Job.CacheMode, f.Workflow.CacheMode) != analysis.CacheWriteYes {
			continue
		}
		evs, _ := cl.Events(c.Caller, cacheEvents(), false)
		for _, e := range taint.Filter(x.table(), evs, append(attacker.JobIfs(f.Workflow, c.Job), attacker.JobIfs(x.workflow, j)...)...) {
			if !slices.Contains(on, e) {
				on = append(on, e)
			}
		}
	}
	return on
}

// dispatchSaveOn are the runs of workflow_dispatch of the workflow's own on
// that the if of the job j lets through, on which j may save to the cache of
// the scope of the ref that the one who dispatches the workflow chooses: a
// run of workflow_dispatch saves with no cache-mode, and with one that
// saves. The callers of a called workflow are not read.
func (x *IR) dispatchSaveOn(j *workflow.Job) []analysis.EventActivity {
	w := x.workflow
	if w == nil {
		return nil
	}
	switch job.CacheWriteOf(j.CacheMode, w.CacheMode) {
	case analysis.CacheWriteYes, analysis.CacheWriteUnwritten:
		return taint.Filter(x.table(), x.ownEventsOn([]workflow.EventName{workflow.EventNameWorkflowDispatch}), attacker.JobIfs(w, j)...)
	}
	return nil
}

func (x *IR) allCacheSaves() []*CacheSave {
	x.once(SummaryCacheSave, func() {
		w := x.workflow
		if w == nil {
			return
		}
		saveOn, dispatchOn := map[string][]analysis.EventActivity{}, map[string][]analysis.EventActivity{}
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status == workflow.Present {
				j := je.Value.Value
				if on := x.cacheSaveOn(&j); len(on) > 0 {
					saveOn[j.ID.AsString()] = on
				}
				if on := x.dispatchSaveOn(&j); len(on) > 0 {
					dispatchOn[j.ID.AsString()] = on
				}
			}
		}
		if len(saveOn) == 0 && len(dispatchOn) == 0 {
			return // no job saves: no value to read
		}
		refs := map[stepAt][]taint.StepValue{}
		for _, v := range taint.StepValues(x.callersOf(), x.name, w, nil, cacheValues) {
			if v.Job != nil {
				at := stepAt{v.Job.ID.AsString(), v.StepIndex}
				refs[at] = append(refs[at], v)
			}
		}
		values := map[*workflow.ActionMetadata][]taint.StepValue{}
		var out []*CacheSave
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			on, don := saveOn[j.ID.AsString()], dispatchOn[j.ID.AsString()]
			if len(on) == 0 && len(don) == 0 {
				continue
			}
			approval, _ := job.ApprovalOf(on, &j)
			_, env := job.ApprovalOf(nil, &j)
			for i, s := range j.Steps.Value.Items {
				if s.Uses.Status != workflow.Present {
					continue
				}
				a := prcode.CacheActionOf(s.Uses.Value)
				if a == analysis.CacheActionNone {
					out = append(out, x.compositeCacheSaves(&j, s, on, don, approval, env, values)...)
					continue
				}
				o := &CacheSave{key: keyOf(x.paths, x.input, x.tree, s.Base), at: x.handleOf(s.Base), action: a,
					cacheWriteOn: taint.Filter(x.table(), on, attacker.StepIf(w, &j, s.If)), dispatchOn: taint.Filter(x.table(), don, attacker.StepIf(w, &j, s.If)), cacheApproval: approval, environment: env, usesText: s.Uses.Value.Text()}
				o.automaticApproval = x.automaticApprovalOf(o.cacheWriteOn, &j, attacker.StepIf(w, &j, s.If))
				for _, v := range refs[stepAt{j.ID.AsString(), i}] {
					text := v.Value.Text()
					for _, r := range v.Refs {
						e := x.exprRefOf(r, text[r.Span.Start:r.Span.End], x.spanOf(v.Value, r.Span))
						if v.Index == 0 {
							o.keyRefs = append(o.keyRefs, e)
						} else {
							o.pathRefs = append(o.pathRefs, e)
						}
					}
				}
				out = append(out, o)
			}
		}
		x.cacheSaves = out
	})
	return x.cacheSaves
}

// compositeCacheSaves are the steps of actions/cache or actions/cache/save
// of the composite actions of the inputs that the step s of the job j runs
// (actions/composite), whose job saves on on and don with approval and env:
// at the step in the file of the action, with the references of its key and
// its path read with the callers of the action (taint.Callers), so that an
// input the with of s gives is read from it. The ifs of s and of the steps
// of the composite actions on the way keep the events. values holds the
// values read of each action, once. An action of another repository is
// read by saved-checkout alone: its values have no callers.
func (x *IR) compositeCacheSaves(j *workflow.Job, s workflow.Step, on, don []analysis.EventActivity, approval analysis.Approval, env facts.EnvironmentName, values map[*workflow.ActionMetadata][]taint.StepValue) []*CacheSave {
	if x.composites == nil || s.Uses.Status != workflow.Present {
		return nil
	}
	var out []*CacheSave
	for _, in := range x.composites.Expand(x.ctx, &s, false).Steps {
		if in.Origin.Query != nil || in.Origin.Input.IsZero() || in.Action == nil || in.Step.Uses.Status != workflow.Present {
			continue
		}
		a := prcode.CacheActionOf(in.Step.Uses.Value)
		if a == analysis.CacheActionNone {
			continue
		}
		steps := in.Action.Runs.Value.Steps.Value.Items
		idx := -1
		for i := range steps {
			if &steps[i] == in.Step {
				idx = i
			}
		}
		vals, ok := values[in.Action]
		if !ok {
			vals = taint.StepValues(x.callersOf(), calls.InputNode(in.Origin.Input), nil, in.Action, cacheValues)
			values[in.Action] = vals
		}
		ifs := append(append([]attacker.PlacedIf{attacker.StepIf(x.workflow, j, s.If)}, stepIfs(in.Ifs)...), attacker.StepIf(nil, nil, in.Step.If))
		origin := in.Origin
		pl := place{x: x, origin: &origin}
		caller := keyOf(x.paths, x.input, x.tree, s.Base)
		o := &CacheSave{key: Key{input: x.input, path: caller.path + " > " + hopsPath(in.Chain) + " " + x.paths.Of(in.Origin.Tree, in.Step.Base.Node, in.Step.Base.Via)},
			at: pl.handle(in.Step.Base), action: a,
			cacheWriteOn: taint.Filter(x.table(), on, ifs...), dispatchOn: taint.Filter(x.table(), don, ifs...), cacheApproval: approval, environment: env, usesText: in.Step.Uses.Value.Text(),
			chain: in.Chain, callerAt: x.handleOf(s.Uses.Value.Base)}
		o.automaticApproval = x.automaticApprovalOf(o.cacheWriteOn, j, ifs...)
		for _, v := range vals {
			if v.StepIndex != idx {
				continue
			}
			text := v.Value.Text()
			for _, r := range v.Refs {
				e := pl.exprRef(r, text[r.Span.Start:r.Span.End], pl.span(v.Value, r.Span))
				if v.Index == 0 {
					o.keyRefs = append(o.keyRefs, e)
				} else {
					o.pathRefs = append(o.pathRefs, e)
				}
			}
		}
		out = append(out, o)
	}
	return out
}

// hopsPath is the uses of hops, as written, joined by " > ".
func hopsPath(hops []composite.Hop) string {
	var parts []string
	for _, h := range hops {
		parts = append(parts, h.Uses)
	}
	return strings.Join(parts, " > ")
}

// cacheValues are the key and the path of a step of actions/cache or
// actions/cache/save, in that order: Pick.Index 0 is the key, 1 the path.
func cacheValues(s workflow.Step) []taint.Pick {
	if s.Uses.Status != workflow.Present || prcode.CacheActionOf(s.Uses.Value) == analysis.CacheActionNone || s.With.Status != workflow.Present {
		return nil
	}
	var out []taint.Pick
	for _, name := range []string{"key", "path"} {
		v := workflow.String{}
		if e, ok := s.With.Value.Lookup(name); ok {
			switch {
			case e.Value.Status == workflow.Present:
				v = e.Value.Value
			case e.Value.Status == workflow.Dynamic && e.Value.Expr != nil:
				v = *e.Value.Expr
			}
		}
		out = append(out, taint.Pick{Value: v})
	}
	return out
}

// cacheSaveSteps is the projection of the steps that save what a site
// brings, steps of the job j (nil for a site of an action) or of the
// composite actions they run, whose job may save on on: each saves on those
// of on its if lets through (the post step of actions/cache runs only after
// its step did).
func (x *IR) cacheSaveSteps(steps []prcode.CacheSaveStep, j *workflow.Job, on []analysis.EventActivity) []CacheSaveStep {
	var out []CacheSaveStep
	for _, e := range steps {
		if e.Via != nil {
			// a step of a composite action: at the step of the job that runs
			// it, which the if of both let through; the steps of the composite
			// action do not read the needs context of the job
			out = append(out, CacheSaveStep{Name: e.Name, Step: keyOf(x.paths, x.input, x.tree, e.Via.Base), Action: e.Action, Line: e.Line, Known: e.Known,
				SaveOn: taint.Filter(x.table(), on, append(append([]attacker.PlacedIf{attacker.StepIf(x.workflow, j, e.Via.If)}, stepIfs(e.Ifs)...), attacker.StepIf(nil, nil, e.Step.If))...), Via: e.Chain, Substituted: e.Substituted,
				At: x.handleOf(e.Via.Uses.Value.Base), PathAt: originHandle(e.Origin, e.Path.Base)})
			continue
		}
		out = append(out, CacheSaveStep{Name: e.Name, Step: keyOf(x.paths, x.input, x.tree, e.Step.Base), Action: e.Action, Line: e.Line, Known: e.Known,
			SaveOn: taint.Filter(x.table(), on, attacker.StepIf(x.workflow, j, e.Step.If)), At: x.handleOf(e.Path.Base)})
	}
	return out
}

// cacheModeNoWrite is the fix that makes the cache-mode that lets j save
// one that does not: write becomes read, which still restores, and
// write-only none.
func (j *Job) cacheModeNoWrite(q *RuleAccess) FixPlan {
	if len(j.calledCacheModes) > 0 {
		return FixPlan{NoFix: manual("the reusable workflow of another repository that this job calls asks for a cache-mode that saves; cache-mode read or none in this job would stop the called workflow from starting; ask the maintainers of the called workflow for a cache-mode that saves nothing on the attacker's events, or call another workflow")}
	}
	m, caller := q.ir.cacheModeOf[j], q.ir.cacheModeJob[j]
	if caller != nil && caller.Uses.Status != workflow.Absent {
		// the calls GitHub refuses past the limit: read here would stop a
		// called workflow that asks for write from starting
		modes, local := q.ir.calledCacheWrites(caller)
		if !local {
			return FixPlan{NoFix: manual("the called workflow is not among the inputs, and may ask for a cache-mode that saves, which read here would stop from starting; write read or none here and in it")}
		}
		if slices.Contains(modes, analysis.CacheWriteYes) {
			return FixPlan{NoFix: manual("the called workflow asks for a cache-mode that saves, which read here would stop from starting; write read or none here and in it")}
		}
	}
	if m.Status != workflow.Present || m.Value.HasExpr() {
		return FixPlan{NoFix: manual("the cache-mode is a ${{ }} that reads a context, which GitHub refuses; write read or none")}
	}
	if len(m.Value.Via) > 0 || hasAnchor(m.Value.Node) {
		return FixPlan{NoFix: form("the cache-mode is reached through an alias or has an anchor; write read or none where it is needed")}
	}
	to := analysis.CacheModeRead
	if mode, _ := analysis.ParseCacheMode(m.Value.AsString()); mode == analysis.CacheModeWriteOnly {
		to = analysis.CacheModeNone
	}
	ed, err := q.ir.editor.SetValue(m.Value.Node, edit.Str(to.String()))
	if err != nil {
		return FixPlan{NoFix: form("the cache-mode cannot be written here (" + err.Error() + "); write " + to.String() + " by hand")}
	}
	return FixPlan{Fix: &Fix{Kind: FixCacheModeNoWrite, Title: "save nothing to the cache on the attacker's events: cache-mode: " + to.String(), Edits: []edit.Edit{ed}, SideEffects: []SideEffect{SideEffectCacheNotSaved}}}
}

// cacheEvents are the privileged events whose run saves a cache to the
// scope of the default branch: not pull_request_review and
// pull_request_review_comment, whose run saves a cache to the merge ref of
// its pull request, as a run on a pull request does.
func cacheEvents() []workflow.EventName {
	return slices.DeleteFunc(job.Privileged(), func(e workflow.EventName) bool {
		return e == workflow.EventNamePullRequestReview || e == workflow.EventNamePullRequestReviewComment
	})
}

package prcode

import (
	"path"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// CacheSaveStep is a step that saves to the cache what a checkout brings:
// actions/cache at the end of the job, or actions/cache/save at the step.
type CacheSaveStep struct {
	Step   workflow.Step
	Name   string
	Action analysis.CacheAction
	// Path is the path of its with, else the with when it is a whole
	// ${{ }}; Line is the line of it that has the tree, as written. Known
	// is false when a ${{ }} that is not the workspace's decides it.
	Path  workflow.String
	Line  string
	Known bool
	// Via is, for a step of a composite action that a step of the steps
	// runs (Inner), that step; nil for a step of the steps. Origin is the
	// file the step is written in, Chain the uses from Via to the action
	// the step is of, and Substituted whether that action is
	// (composite.Action.Substituted).
	Via         *workflow.Step
	Origin      composite.Origin
	Chain       []composite.Hop
	Substituted bool
	// Ifs are the ifs of the steps of the composite actions between Via and
	// the step (composite.Step.Ifs): it runs only past them too.
	Ifs []workflow.Field[workflow.If]
}

// Inner reads what a step runs (actions/composite.Reader): the steps of
// the composite actions and the uses with no answer. A nil Inner reads
// none.
type Inner func(s *workflow.Step) composite.Expansion

// UnansweredCall is a uses with no answer that someone asked could not
// give (composite.Unanswered.Asked), on the way from Via, a step of the
// steps: what it runs may save the tree to the cache.
type UnansweredCall struct {
	Via        *workflow.Step
	Unanswered composite.Unanswered
}

// cacheRef is a step that uses a cache action: the step k of the steps,
// or, when in is not nil, a step of a composite action the step k runs.
type cacheRef struct {
	k  int
	in *composite.Step
}

// jobCaches are the cache steps of the steps of a job or of an action, and
// what each step that runs an action runs (Inner).
type jobCaches struct {
	refs []cacheRef
	exps map[int]composite.Expansion
}

// CacheActionOf is the action u is of the actions that save to the cache:
// actions/cache or actions/cache/save, at any ref.
func CacheActionOf(u workflow.Uses) analysis.CacheAction {
	for _, a := range u.Actions() {
		if !strings.EqualFold(a.Owner, "actions") || !strings.EqualFold(a.Repo, "cache") {
			continue
		}
		switch strings.ToLower(a.Path.String()) {
		case "":
			return analysis.CacheActionCache
		case "save":
			return analysis.CacheActionSave
		}
	}
	return analysis.CacheActionNone
}

// cacheSteps are the steps of steps that use a cache action, and the steps
// of the composite actions they run that do (inner), which cacheSaves reads
// for each checkout of the steps.
func cacheSteps(steps []workflow.Step, inner Inner) jobCaches {
	out := jobCaches{exps: map[int]composite.Expansion{}}
	if !slices.ContainsFunc(steps, func(x workflow.Step) bool { return x.Uses.Status == workflow.Present && calls.IsCheckout(x.Uses.Value) }) {
		inner = nil // no checkout: nothing to save, and no fact to ask
	}
	for k := range steps {
		x := &steps[k]
		if x.Uses.Status != workflow.Present {
			continue
		}
		if CacheActionOf(x.Uses.Value) != analysis.CacheActionNone {
			out.refs = append(out.refs, cacheRef{k: k})
			continue
		}
		if inner == nil {
			continue
		}
		e := inner(x)
		out.exps[k] = e
		for i := range e.Steps {
			if st := e.Steps[i]; st.Step.Uses.Status == workflow.Present && CacheActionOf(st.Step.Uses.Value) != analysis.CacheActionNone {
				out.refs = append(out.refs, cacheRef{k: k, in: &e.Steps[i]})
			}
		}
	}
	return out
}

// cacheSaves are the steps of caches (cacheSteps of steps) that save the
// tree a checkout puts in the directory dir of the workspace, the checkout being the
// step at after: actions/cache/save that may run after it, and
// actions/cache anywhere in the job, whose post step saves at the end of
// it. A checkout of dir or of a directory above it that is done after the
// checkout takes the tree away (it cleans by default): a save after it is
// not of the tree. The steps after the checkout are read up to the first
// that such a clean is done before, as codeRuns reads them.
func cacheSaves(j *workflow.Job, steps []workflow.Step, order workflow.StepOrder, caches jobCaches, after int, dir relDir) ([]CacheSaveStep, []UnansweredCall) {
	if len(caches.refs)+len(caches.exps) == 0 {
		return nil, nil
	}
	var cleans []int
	runs := map[int]bool{} // the steps that may run after the checkout, before a clean
	read := func(k int) {
		x := steps[k]
		if k == after || x.Uses.Status != workflow.Present {
			return
		}
		if calls.IsCheckout(x.Uses.Value) {
			if checkoutCleans(j, steps, order, k, dir) && order.DoneBefore(after, k) {
				cleans = append(cleans, k)
			}
			return
		}
		if order.MayRunAfter(after, k) && !containsDoneBefore(order, cleans, k) {
			runs[k] = true
		}
	}
	for _, k := range order.RunningAt(after) {
		read(k)
	}
	for k := after + 1; k < len(steps); k++ {
		if containsDoneBefore(order, cleans, k) {
			break // a clean is done, and so is every step after it
		}
		read(k)
	}
	var out []CacheSaveStep
	for _, c := range caches.refs {
		x := steps[c.k]
		if c.in != nil {
			x = *c.in.Step
		}
		a := CacheActionOf(x.Uses.Value)
		switch {
		case c.k == after:
			continue
		case a == analysis.CacheActionCache && len(cleans) > 0:
			continue // the end of the job is after the clean
		case a == analysis.CacheActionSave && !runs[c.k]:
			continue
		}
		v, line, known, ok := savedLine(x, dir)
		if !ok {
			continue
		}
		s := CacheSaveStep{Step: x, Name: StepName(x), Action: a, Path: v, Line: line, Known: known}
		if c.in != nil {
			s.Via, s.Origin, s.Chain, s.Substituted, s.Ifs = &steps[c.k], c.in.Origin, c.in.Chain, c.in.Substituted, c.in.Ifs
		}
		out = append(out, s)
	}
	// what a uses with no answer runs may save the tree as those steps do:
	// actions/cache anywhere, before a clean; actions/cache/save after the
	// checkout
	var gaps []UnansweredCall
	for k := range steps {
		e, ok := caches.exps[k]
		if !ok || k == after || len(cleans) > 0 && !runs[k] {
			continue
		}
		for _, u := range e.Unanswered {
			if u.Asked {
				gaps = append(gaps, UnansweredCall{Via: &steps[k], Unanswered: u})
			}
		}
	}
	return out, gaps
}

// containsDoneBefore is whether a checkout of cleans is done before the
// step k.
func containsDoneBefore(order workflow.StepOrder, cleans []int, k int) bool {
	for _, c := range cleans {
		if order.DoneBefore(c, k) {
			return true
		}
	}
	return false
}

// savedLine is the first line of the path of the cache step x that has
// the tree in dir, and whether it is known; ok is false when no line can
// have it. A line that starts with ! takes files out and is not read.
func savedLine(x workflow.Step, dir relDir) (v workflow.String, line string, known, ok bool) {
	switch x.With.Status {
	case workflow.Present:
	case workflow.Dynamic:
		if x.With.Expr != nil {
			return *x.With.Expr, x.With.Expr.Text(), false, true
		}
		return workflow.String{}, "", false, false
	default:
		return workflow.String{}, "", false, false
	}
	e, found := x.With.Value.Lookup("path")
	if !found {
		return workflow.String{}, "", false, false
	}
	switch e.Value.Status {
	case workflow.Present:
		v = e.Value.Value
	case workflow.Dynamic:
		if e.Value.Expr == nil {
			return workflow.String{}, "", false, false
		}
		v = *e.Value.Expr
	default:
		return workflow.String{}, "", false, false
	}
	unknown := ""
	for _, pl := range PathLines(v) {
		l, raw := strings.TrimSpace(pl.Text), strings.TrimSpace(pl.Raw)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		p, inWorkspace, k := cachePath(l)
		switch {
		case !k:
			if unknown == "" {
				unknown = raw
			}
		case !inWorkspace:
		case dir.holds(p) || under(dir.path, p):
			return v, raw, true, true
		}
	}
	if unknown != "" {
		return v, unknown, false, true
	}
	return workflow.String{}, "", false, false
}

// cachePath is the line l of a cache path (the Text of a PathLine) as a
// path relative to the workspace, cleaned and cut before its first glob
// character, and whether it is in the workspace; known is false when a
// ${{ }} other than the workspace's decides it. ~ (alone or before a
// slash), an absolute path, runner.temp, and a path with a .. segment or a
// . segment after the first (refused) are out of it. actions/cache reads
// the lines as patterns of @actions/glob, which expands a leading ~ and no
// environment variable (actions/toolkit fa980c4100e53128102670562e9e293518900112,
// https://github.com/actions/toolkit/blob/fa980c4100e53128102670562e9e293518900112/packages/glob/src/internal-pattern.ts),
// so $GITHUB_WORKSPACE is a directory of the workspace by that name. The
// pattern refuses a . segment after the first and a .. segment.
func cachePath(l string) (p string, inWorkspace, known bool) {
	if strings.HasPrefix(l, RunnerTempMark) {
		return "", false, true
	}
	if strings.Contains(l, ExprMark) {
		return "", false, false
	}
	if l == "~" || strings.HasPrefix(l, "~/") || strings.HasPrefix(l, "/") {
		return "", false, true
	}
	if i := strings.IndexAny(l, "*?[{"); i >= 0 {
		l = l[:i]
		if j := strings.LastIndex(l, "/"); j >= 0 {
			l = l[:j]
		} else {
			l = "."
		}
	}
	if segs := strings.Split(l, "/"); slices.Contains(segs, "..") || slices.Contains(segs[1:], ".") {
		return "", false, true // glob refuses it: nothing is saved
	}
	return path.Clean(l), true, true
}

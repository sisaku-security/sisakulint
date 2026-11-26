package prcode

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// SameRunUpload is an upload of actions/upload-artifact in a job of the
// same workflow that checks out the code of a pull request before the
// upload, with no approval: a download of the current run that takes its
// artifact takes what the author of the pull request made, as a download
// of the run of a fork does.
type SameRunUpload struct {
	Text     string        // jobs.<id>, which the finding names
	Checkout workflow.Base // the step that checks out the code of the pull request
	Upload   workflow.Base // the step that uploads
	// Unless are the commits of the guard of actions/checkout, for a
	// checkout pinned to a commit in no table on the events the guard
	// covers: the upload holds the code of the pull request unless the
	// commit has one of them (the guard refuses the code and the step fails)
	Unless []MissingCommit

	job     string                   // the ID of the job that uploads, in lower case (GitHub reads the IDs of jobs without case)
	name    string                   // the input name, defaultArtifactName when the upload has none
	anyName bool                     // the name is a ${{ }}, which may be any name
	before4 bool                     // the release is v1 to v3, whose artifact only actions/download-artifact v1 to v3 takes during the run
	events  []analysis.EventActivity // the events on which the checkout brings the code of the pull request and the upload runs
	// unread is whether the rule does not read what the upload holds,
	// which may be the code of a pull request: the upload is of cause, a
	// ./ workflow or action that the inputs do not have, or a merge whose
	// pattern is not known or that the rule stops reading (mergeReadMax),
	// or a merge of such an upload
	unread bool
	cause  workflow.String
}

// defaultArtifactName is the name of an artifact whose upload has no
// input name (action.yml of actions/upload-artifact v3 and v4).
const defaultArtifactName = "artifact"

var uploadArtifactRepo = struct{ owner, name string }{"actions", "upload-artifact"}

// isUpload is whether u is actions/upload-artifact itself, at any ref.
func isUpload(u workflow.Uses) bool {
	for _, a := range u.Actions() {
		if a.Is(uploadArtifactRepo.owner, uploadArtifactRepo.name, workflow.RootActionPath) {
			return true
		}
	}
	return false
}

// sameRunUploads are the uploads, in the jobs of the checkouts, that may
// run after a checkout of the code of a pull request that no approval
// admits, on the events on which the checkout brings that code (the guard
// of actions/checkout, as untrusted-checkout reads it) and the if of the
// upload lets the upload run; t is the table of the callers (nil for none),
// and w the workflow of the checkouts.
func sameRunUploads(t *taint.Callers, w *workflow.Workflow, checkouts []CheckoutSite) []SameRunUpload {
	var out []SameRunUpload
	for _, c := range checkouts {
		if c.Job == nil || !c.Placed || c.CheckoutCode != analysis.CodePR || len(c.PRCodeOn) == 0 || c.Approval != analysis.ApprovalNone {
			continue
		}
		events, unless := c.unguarded()
		if len(events) == 0 {
			continue
		}
		steps := c.Job.Steps.Value.Items
		order := workflow.OrderOf(steps)
		id := c.Job.ID.AsString()
		for _, s := range steps {
			if s.Uses.Status != workflow.Present || !isUpload(s.Uses.Value) || !order.MayRunAfter(c.Step.Order, s.Order) {
				continue
			}
			evs := taint.FilterCode(t.Table(), events, attacker.StepIf(w, c.Job, s.If))
			if len(evs) == 0 {
				continue
			}
			if len(c.CodeRunSteps) == 0 && !uploadCovers(s, c.Placement.dir) {
				continue // the artifact holds neither the checked out code nor what the code made
			}
			u := SameRunUpload{job: strings.ToLower(id), Text: "jobs." + id, Checkout: c.Step.Base, Upload: s.Base, Unless: unless, before4: uploadBefore4(s.Uses.Value), events: evs}
			u.name, u.anyName = inputName(s.With, defaultArtifactName)
			out = append(out, u)
		}
	}
	return out
}

// inputName is the input name of with, or def when it has none, and
// whether it may be any name (a ${{ }}).
func inputName(with workflow.Field[workflow.Map[workflow.String]], def string) (string, bool) {
	switch {
	case with.Status == workflow.Dynamic:
		return def, true
	case with.Status == workflow.Present:
		if e, ok := with.Value.Lookup("name"); ok {
			if e.Value.Status != workflow.Present || e.Value.Value.Parts != nil {
				return def, true
			}
			return jsTrim(e.Value.Value.AsString()), false
		}
	}
	return def, false
}

// maxCallDepth bounds the reusable workflows read through each other:
// GitHub runs at most ten levels of them, and refuses a cycle.
const maxCallDepth = 10

// sameRunUploadsIn are sameRunUploads of w, the input name, with the
// uploads that the upload-artifact steps do not show (the undetected form
// same-run-pr-code): those inside a composite action that a step of the
// job of a checkout uses after the checkout, those of a reusable workflow
// of the inputs that a job of w calls, read as uploads of that job on the
// events on which that call runs, and those that
// actions/upload-artifact/merge uploads again under its name. A ./
// workflow or action that the inputs do not have gives an unread upload.
func sameRunUploadsIn(c *taint.Callers, name calls.Node, w *workflow.Workflow, m *shell.Memo, depth int) []SameRunUpload {
	g := c.Graph()
	var called []calls.CalledCall
	if g != nil {
		called = g.CalledBy(name)
	}
	checkouts := AnalyzeIn(c, name, w, nil, m)
	out := sameRunUploads(c, w, checkouts)
	out = append(out, compositeUploads(c, w, checkouts, g, called)...)
	if depth < maxCallDepth && w.Jobs.Status == workflow.Present {
		evs := c.EventsOr(name, prCodeEvents, true, func() []analysis.EventActivity { return taint.EventsOf(w, prCodeEvents) })
		for _, je := range w.Jobs.Value.Entries {
			j := je.Value.Value
			if je.Value.Status != workflow.Present || j.Kind != workflow.JobCall || j.Uses.Status != workflow.Present {
				continue
			}
			if k := j.Uses.Value.Kind; k != workflow.UsesLocal && k != workflow.UsesSelf {
				continue // a workflow of another repository is not among the inputs
			}
			// the events on which this call runs the workflow: the events
			// of the workflow it calls are those of all its callers
			callEvs := taint.FilterCode(c.Table(), evs, attacker.JobIfs(w, &j)...)
			if len(callEvs) == 0 {
				continue
			}
			id := j.ID.AsString()
			i := slices.IndexFunc(called, func(cc calls.CalledCall) bool {
				return cc.StepIndex < 0 && cc.Job != nil && cc.Job.ID.AsString() == id
			})
			var f calls.File
			if i >= 0 {
				f, _ = g.File(called[i].Called)
			}
			if f.Workflow == nil {
				out = append(out, SameRunUpload{job: strings.ToLower(id), Text: "jobs." + id, Checkout: j.Uses.Value.Base, Upload: j.Uses.Value.Base, anyName: true, events: callEvs, unread: true, cause: j.Uses.Value.String})
				continue
			}
			for _, u := range sameRunUploadsIn(c, called[i].Called, f.Workflow, m, depth+1) {
				u.events = slices.DeleteFunc(u.events, func(e analysis.EventActivity) bool { return !slices.Contains(callEvs, e) })
				if len(u.events) == 0 {
					continue
				}
				u.job, u.Text = strings.ToLower(id), "jobs."+id+" ("+j.Uses.Value.Text()+" "+u.Text+")"
				u.Checkout, u.Upload = j.Uses.Value.Base, j.Uses.Value.Base
				out = append(out, u)
			}
		}
	}
	return append(out, mergeUploads(c, w, out)...)
}

// compositeUploads are the uploads of actions/upload-artifact among the
// steps of the composite actions of the inputs that a step of the job of a
// checkout of checkouts uses after the checkout (one level: an action that
// such an action uses is not read). called are the calls of w (CalledBy);
// a ./ action that the inputs do not have gives an unread upload.
func compositeUploads(c *taint.Callers, w *workflow.Workflow, checkouts []CheckoutSite, g *calls.Graph, called []calls.CalledCall) []SameRunUpload {
	var out []SameRunUpload
	for _, co := range checkouts {
		if co.Job == nil || !co.Placed || co.CheckoutCode != analysis.CodePR || len(co.PRCodeOn) == 0 || co.Approval != analysis.ApprovalNone {
			continue
		}
		events, unless := co.unguarded()
		if len(events) == 0 {
			continue
		}
		steps := co.Job.Steps.Value.Items
		order := workflow.OrderOf(steps)
		id := co.Job.ID.AsString()
		for k, s := range steps {
			if s.Uses.Status != workflow.Present || s.Uses.Value.Kind != workflow.UsesLocal || !order.MayRunAfter(co.Step.Order, s.Order) {
				continue
			}
			evs := taint.FilterCode(c.Table(), events, attacker.StepIf(w, co.Job, s.If))
			if len(evs) == 0 {
				continue
			}
			i := slices.IndexFunc(called, func(cc calls.CalledCall) bool {
				return cc.StepIndex == k && cc.Job != nil && cc.Job.ID.AsString() == id
			})
			var f calls.File
			if i >= 0 {
				f, _ = g.File(called[i].Called)
			}
			if f.Action == nil {
				out = append(out, SameRunUpload{job: strings.ToLower(id), Text: "jobs." + id + " (" + s.Uses.Value.Text() + ")", Checkout: co.Step.Base, Upload: s.Base, Unless: unless, anyName: true, events: evs, unread: true, cause: s.Uses.Value.String})
				continue
			}
			a := f.Action
			if a.Runs.Status != workflow.Present || a.Runs.Value.Kind != workflow.RunsComposite {
				continue
			}
			for _, x := range a.Runs.Value.Steps.Value.Items {
				if x.Uses.Status != workflow.Present || !isUpload(x.Uses.Value) {
					continue
				}
				if len(co.CodeRunSteps) == 0 && !uploadCovers(x, co.Placement.dir) {
					continue
				}
				xevs := taint.FilterCode(c.Table(), evs, attacker.StepIf(nil, nil, x.If))
				if len(xevs) == 0 {
					continue
				}
				u := SameRunUpload{job: strings.ToLower(id), Text: "jobs." + id + " (" + s.Uses.Value.Text() + ")", Checkout: co.Step.Base, Upload: s.Base, Unless: unless, before4: uploadBefore4(x.Uses.Value), events: xevs}
				u.name, u.anyName = inputName(x.With, defaultArtifactName)
				out = append(out, u)
			}
		}
	}
	return out
}

// mergedArtifactName is the name of the artifact of
// actions/upload-artifact/merge with no input name (merge/action.yml).
const mergedArtifactName = "merged-artifacts"

// isMerge is whether u is actions/upload-artifact/merge, at any ref.
func isMerge(u workflow.Uses) bool {
	for _, a := range u.Actions() {
		if strings.EqualFold(a.Owner, uploadArtifactRepo.owner) && strings.EqualFold(a.Repo, uploadArtifactRepo.name) && a.Path.String() == "merge" {
			return true
		}
	}
	return false
}

// mergeReadMax bounds the reads of mergeUploads, each of an upload by a
// merge step that may take it: past it, the rule stops reading the merges.
const mergeReadMax = 100000

// mergeStep is a step of actions/upload-artifact/merge in a job of a
// workflow, as mergeUploads reads it.
type mergeStep struct {
	job     string // the ID of the job, in lower case
	jobText string // the ID of the job, as written
	step    workflow.Step
	steps   []workflow.Step // the steps of the job
	order   workflow.StepOrder
	keeps   []analysis.EventActivity // the events of the uploads that the ifs of the job and of the step let through
	name    string                   // the input name, mergedArtifactName when it has none
	anyName bool                     // the name is a ${{ }}
	takes   map[string][2]bool       // mergeTakes of the step, by the name of an artifact
}

// mergeUploads are the uploads of actions/upload-artifact/merge in the
// jobs of w that take an upload of ups, or of another merge, from a job
// they need, directly or through other jobs, or from an earlier step of
// their own job: the merge downloads the artifacts its pattern names and
// uploads their files again under its name. A merge takes every upload its
// pattern matches, each on its own events; a merge whose pattern is not
// known gives an unread upload.
//
// The merges read each upload of ups once for each merge step it passes
// through, on the union of the events of the ways to that step: what a
// merge step uploads from an upload of ups is the same artifact whichever
// merges came before. Past mergeReadMax reads, each merge step of w gives
// an unread upload (unreadMerges).
func mergeUploads(c *taint.Callers, w *workflow.Workflow, ups []SameRunUpload) []SameRunUpload {
	if len(ups) == 0 || w.Jobs.Status != workflow.Present {
		return nil
	}
	// the ifs keep each event on its own (taint.FilterCode), so each merge
	// step filters the events of all the uploads once
	var evs []analysis.EventActivity
	for _, u := range ups {
		evs = unionEvents(evs, u.events)
	}
	var merges []*mergeStep
	takers := map[string][]int{} // by the job of an upload, the merges that may take it: those of its job and of the jobs that need it
	for _, je := range w.Jobs.Value.Entries {
		if je.Value.Status != workflow.Present {
			continue
		}
		j := je.Value.Value
		id := j.ID.AsString()
		steps := j.Steps.Value.Items
		order := workflow.OrderOf(steps)
		jobIfs := attacker.JobIfs(w, &j)
		for _, s := range steps {
			if s.Uses.Status != workflow.Present || !isMerge(s.Uses.Value) {
				continue
			}
			m := &mergeStep{job: strings.ToLower(id), jobText: id, step: s, steps: steps, order: order, keeps: taint.FilterCode(c.Table(), evs, append(slices.Clone(jobIfs), attacker.StepIf(w, &j, s.If))...), takes: map[string][2]bool{}}
			m.name, m.anyName = inputName(s.With, mergedArtifactName)
			takers[m.job] = append(takers[m.job], len(merges))
			for k := range neededJobs(w, id) {
				takers[k] = append(takers[k], len(merges))
			}
			merges = append(merges, m)
		}
	}
	// a state is what a merge step uploads from an upload of ups (its
	// origin), unread for a cause or not
	type state struct {
		merge, origin int
		cause         cst.Node
	}
	all := slices.Clone(ups)
	origin := make([]int, len(ups))
	queue := make([]int, len(ups))
	for i := range ups {
		origin[i], queue[i] = i, i
	}
	index := map[state]int{}
	reads := 0
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		u := all[i]
		if u.before4 {
			continue // a merge takes only artifacts of v4 on
		}
		for _, mi := range takers[u.job] {
			m := merges[mi]
			if u.job == m.job && !uploadedBefore(m.steps, m.order, u, m.step) {
				continue
			}
			if reads++; reads > mergeReadMax {
				return append(all[len(ups):], unreadMerges(merges)...)
			}
			tk, ok := m.takes[u.name]
			if !ok {
				t, k := mergeTakes(m.step.With, u.name)
				tk = [2]bool{t, k}
				m.takes[u.name] = tk
			}
			takes, known := tk[0], tk[1]
			if known && !takes && !u.anyName {
				continue
			}
			evs := slices.DeleteFunc(slices.Clone(u.events), func(e analysis.EventActivity) bool { return !slices.Contains(m.keeps, e) })
			if len(evs) == 0 {
				continue
			}
			n := SameRunUpload{job: m.job, Text: "jobs." + m.jobText + " (" + m.step.Uses.Value.Text() + " of " + u.Text + ")", Checkout: u.Checkout, Upload: m.step.Base, Unless: u.Unless, events: evs, unread: u.unread, cause: u.cause}
			n.name, n.anyName = m.name, m.anyName
			if !known && !n.unread {
				n.unread, n.cause = true, m.step.Uses.Value.String
			}
			k := state{mi, origin[i], n.cause.Node}
			if x, ok := index[k]; ok {
				if grown := unionEvents(all[x].events, evs); len(grown) > len(all[x].events) {
					all[x].events = grown
					queue = append(queue, x)
				}
				continue
			}
			index[k] = len(all)
			all, origin, queue = append(all, n), append(origin, origin[i]), append(queue, len(all))
		}
	}
	return all[len(ups):]
}

// unreadMerges are, when the rule stops reading the merges (mergeReadMax),
// an unread upload of each merge step of merges, on the events of the
// uploads that its job and its step let through.
func unreadMerges(merges []*mergeStep) []SameRunUpload {
	var out []SameRunUpload
	for _, m := range merges {
		if len(m.keeps) == 0 {
			continue
		}
		u := SameRunUpload{job: m.job, Text: "jobs." + m.jobText + " (" + m.step.Uses.Value.Text() + ")", Checkout: m.step.Base, Upload: m.step.Base, events: m.keeps, unread: true, cause: m.step.Uses.Value.String}
		u.name, u.anyName = m.name, m.anyName
		out = append(out, u)
	}
	return out
}

// unionEvents is evs with the events of more that it does not have.
func unionEvents(evs, more []analysis.EventActivity) []analysis.EventActivity {
	out := slices.Clone(evs)
	for _, e := range more {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

// uploadedBefore is whether the step of steps that uploads u may run
// before s, a merge in the same job.
func uploadedBefore(steps []workflow.Step, order workflow.StepOrder, u SameRunUpload, s workflow.Step) bool {
	for _, x := range steps {
		if x.Base.Node == u.Upload.Node {
			return order.MayRunAfter(x.Order, s.Order)
		}
	}
	return false
}

// jsTrim is s as core.getInput of @actions/core gives an input:
// String.prototype.trim of JavaScript, which removes the characters of \s
// (U+FEFF among them, and not U+0085, which strings.TrimSpace removes).
func jsTrim(s string) string { return strings.TrimFunc(s, isJSSpace) }

// mergeTakes is whether a merge step with with takes the artifact name,
// as the merge filters the names with minimatch: its pattern, when it has
// one, else * (merge/action.yml), which takes every name that does not
// start with a dot. known is false when the pattern is a ${{ }}, or the
// with is one, or the rule does not read the pattern (matchArtifactName):
// which names the merge takes is not known.
func mergeTakes(with workflow.Field[workflow.Map[workflow.String]], name string) (takes, known bool) {
	switch with.Status {
	case workflow.Dynamic:
		return false, false
	case workflow.Present:
	default:
		return matchArtifactName("*", name)
	}
	e, ok := with.Value.Lookup("pattern")
	if !ok {
		return matchArtifactName("*", name)
	}
	if e.Value.Status != workflow.Present || e.Value.Value.Parts != nil {
		return false, false
	}
	return matchArtifactName(jsTrim(e.Value.Value.AsString()), name)
}

// unguarded are the events on which the checkout c brings the code of the
// pull request, as untrusted-checkout reads the guard of actions/checkout
// every event without the guard; none of the events the
// guard covers with it; for a commit in no table, the events the guard
// does not cover, or else the events it covers unless the commit has one
// of the commits of the guard.
func (c CheckoutSite) unguarded() ([]analysis.EventActivity, []MissingCommit) {
	guarded, open := c.Split()
	switch c.Guard {
	case analysis.GuardNone:
		return c.PRCodeOn, nil
	case analysis.GuardStatic:
		return open, nil
	}
	if len(open) > 0 || len(guarded) == 0 {
		return open, nil
	}
	var unless []MissingCommit
	for _, commit := range GuardCommits() {
		unless = append(unless, MissingCommit{Repo: CheckoutRepo, SHA: c.SHA, Commit: commit})
	}
	return guarded, unless
}

// uploadCovers is whether a line of the path of the upload step s may take
// a file in the directory dir of the checkout, or the directory takes a
// root of a line: the root of a line is its part before the first part
// with a glob character. The lines are read by their syntax (PathLines):
// a ${{ }} other than github.workspace at the start, a with that is a
// whole ${{ }}, a dir not known, and runner.temp followed by .. (which can
// come back to the workspace, as for a checkout) may take it; a line out
// of the workspace (/, ~, runner.temp) does not.
func uploadCovers(s workflow.Step, dir relDir) bool {
	if !dir.known || s.With.Status == workflow.Dynamic {
		return true
	}
	if s.With.Status != workflow.Present {
		return false // no path: the upload fails
	}
	e, ok := s.With.Value.Lookup("path")
	switch {
	case !ok:
		return false // no path: the upload fails
	case e.Value.Status != workflow.Present:
		return true // a path that is not a scalar may take anything
	}
	for _, pl := range PathLines(e.Value.Value) {
		l := strings.TrimSpace(pl.Text)
		if l == "" || strings.HasPrefix(l, "!") {
			continue
		}
		if rest, ok := strings.CutPrefix(l, RunnerTempMark); ok {
			if c := path.Clean("./" + strings.TrimLeft(rest, "/")); c == ".." || strings.HasPrefix(c, "../") {
				return true
			}
			continue
		}
		if strings.Contains(l, ExprMark) {
			return true
		}
		if strings.HasPrefix(l, "/") || strings.HasPrefix(l, "~") {
			continue
		}
		var root []string
		for _, seg := range strings.Split(path.Clean(l), "/") {
			if strings.ContainsAny(seg, "*?[") {
				break
			}
			root = append(root, seg)
		}
		r := path.Clean(strings.Join(root, "/"))
		if r == "." || dir.path == "." || r == dir.path || strings.HasPrefix(r, dir.path+"/") || strings.HasPrefix(dir.path, r+"/") {
			return true
		}
	}
	return false
}

// uploadBefore4 is whether u is actions/upload-artifact at a version tag
// before v4; a commit or a branch is not known, and read as v4 on.
func uploadBefore4(u workflow.Uses) bool {
	for _, a := range u.Actions() {
		if !a.Is(uploadArtifactRepo.owner, uploadArtifactRepo.name, workflow.RootActionPath) {
			continue
		}
		if m := versionRef.FindStringSubmatch(a.Ref); m != nil {
			major, _ := strconv.Atoi(m[1])
			return major < 4
		}
	}
	return false
}

// sameRun adds to s, a download of the current run, the uploads of ups in
// the jobs that the job of s needs, directly or through other jobs, whose
// artifact s takes by its name, and narrows PRCodeOn to the events on
// which both the checkout and s run. A job that does not need the job that
// uploads may run before the upload: the undetected form same-run-pr-code.
//
// When no upload is found, the causes of the unread uploads of ups that s
// may take are added to SameRunUnknown; so is the pattern of s, when the
// rule does not read it (matchArtifactName) and an upload of ups may be one
// it takes.
func (s *DownloadSite) sameRun(w *workflow.Workflow, ups []SameRunUpload) {
	if !s.currentRun || s.Job == nil || len(ups) == 0 {
		return
	}
	needed := neededJobs(w, s.Job.ID.AsString())
	var unknown []workflow.String
	addUnknown := func(v workflow.String) {
		if !slices.ContainsFunc(unknown, func(x workflow.String) bool { return x.Node == v.Node }) {
			unknown = append(unknown, v)
		}
	}
	var on []analysis.EventActivity
	for _, u := range ups {
		takes, known := true, true
		if !u.anyName {
			takes, known = s.takesName(u.name)
		}
		if !needed[u.job] || !takes && known {
			continue
		}
		if u.before4 && !(s.action == downloaderArtifact && s.release() == releaseBefore) {
			continue // during the run, only download-artifact v1 to v3 takes an artifact of v1 to v3
		}
		both := slices.DeleteFunc(slices.Clone(s.PRCodeOn), func(e analysis.EventActivity) bool { return !slices.Contains(u.events, e) })
		switch {
		case len(both) == 0:
			continue
		case u.unread:
			addUnknown(u.cause)
			continue
		case !known:
			p, _ := s.input("pattern")
			addUnknown(p.Value)
			continue
		}
		s.SameRunUploads = append(s.SameRunUploads, u)
		on = unionEvents(on, both)
	}
	if len(s.SameRunUploads) > 0 {
		s.PRCodeOn = on
		return
	}
	s.SameRunUnknown = append(s.SameRunUnknown, unknown...)
}

// neededJobs is the set of the IDs of the jobs that the job id needs,
// directly or through other jobs, in lower case: GitHub reads the IDs of
// jobs without case.
func neededJobs(w *workflow.Workflow, id string) map[string]bool {
	needs := map[string][]string{}
	for _, je := range w.Jobs.Value.Entries {
		j := je.Value.Value
		if j.Needs.Status != workflow.Present {
			continue
		}
		k := strings.ToLower(j.ID.AsString())
		for _, n := range j.Needs.Value.Items {
			needs[k] = append(needs[k], strings.ToLower(n.AsString()))
		}
	}
	seen := map[string]bool{}
	stack := slices.Clone(needs[strings.ToLower(id)])
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			continue
		}
		seen[n] = true
		stack = append(stack, needs[n]...)
	}
	return seen
}

// takesName is whether the download s takes an artifact uploaded with the
// name upload: a download with neither name nor pattern, or with an empty
// pattern, takes every artifact; a pattern takes the names minimatch
// matches to it (matchArtifactName), and known is false for a pattern the
// rule does not read; a ${{ }} and a name of
// dawidd6/action-download-artifact read as a regular expression may name
// any artifact.
func (s DownloadSite) takesName(upload string) (takes, known bool) {
	if re, ok := s.input("name_is_regexp"); ok && s.action == downloaderDawidd6 && (re.Status != workflow.Present || re.Value.Parts != nil || strings.EqualFold(strings.TrimSpace(re.Value.AsString()), "true")) {
		return true, true
	}
	name, nameOK := s.input("name")
	pattern, patternOK := s.input("pattern")
	switch {
	case nameOK && (name.Status != workflow.Present || name.Value.Parts != nil):
		return true, true
	case nameOK:
		return strings.EqualFold(jsTrim(name.Value.AsString()), upload), true
	case patternOK && (pattern.Status != workflow.Present || pattern.Value.Parts != nil):
		return true, true
	case patternOK:
		p := jsTrim(pattern.Value.AsString())
		if p == "" {
			return true, true // download-artifact filters by a pattern only when it is not empty
		}
		return matchArtifactName(p, upload)
	}
	return true, true
}

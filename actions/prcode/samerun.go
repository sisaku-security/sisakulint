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
			return strings.TrimSpace(e.Value.Value.AsString()), false
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
// of the inputs that a job of w calls, read as uploads of that job, and
// those that actions/upload-artifact/merge uploads again under its name.
// unknown are, by the job, in lower case, the uses of ./ that the inputs
// do not have, whose uploads are not known.
func sameRunUploadsIn(c *taint.Callers, name calls.Node, w *workflow.Workflow, m *shell.Memo, depth int) (out []SameRunUpload, unknown map[string][]workflow.String) {
	unknown = map[string][]workflow.String{}
	g := c.Graph()
	var called []calls.CalledCall
	if g != nil {
		called = g.CalledBy(name)
	}
	checkouts := AnalyzeIn(c, name, w, nil, m)
	out = sameRunUploads(c, w, checkouts)
	out = append(out, compositeUploads(c, w, checkouts, g, called, unknown)...)
	if depth < maxCallDepth && w.Jobs.Status == workflow.Present {
		for _, je := range w.Jobs.Value.Entries {
			j := je.Value.Value
			if je.Value.Status != workflow.Present || j.Kind != workflow.JobCall || j.Uses.Status != workflow.Present {
				continue
			}
			if k := j.Uses.Value.Kind; k != workflow.UsesLocal && k != workflow.UsesSelf {
				continue // a workflow of another repository is not among the inputs
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
				unknown[strings.ToLower(id)] = append(unknown[strings.ToLower(id)], j.Uses.Value.String)
				continue
			}
			inner, innerUnknown := sameRunUploadsIn(c, called[i].Called, f.Workflow, m, depth+1)
			for _, u := range inner {
				u.job, u.Text = strings.ToLower(id), "jobs."+id+" ("+j.Uses.Value.Text()+" "+u.Text+")"
				u.Checkout, u.Upload = j.Uses.Value.Base, j.Uses.Value.Base
				out = append(out, u)
			}
			for _, vs := range innerUnknown {
				unknown[strings.ToLower(id)] = append(unknown[strings.ToLower(id)], vs...)
			}
		}
	}
	return append(out, mergeUploads(c, w, out)...), unknown
}

// compositeUploads are the uploads of actions/upload-artifact among the
// steps of the composite actions of the inputs that a step of the job of a
// checkout of checkouts uses after the checkout (one level: an action that
// such an action uses is not read). called are the calls of w (CalledBy);
// a ./ action that the inputs do not have is added to unknown.
func compositeUploads(c *taint.Callers, w *workflow.Workflow, checkouts []CheckoutSite, g *calls.Graph, called []calls.CalledCall, unknown map[string][]workflow.String) []SameRunUpload {
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
				unknown[strings.ToLower(id)] = append(unknown[strings.ToLower(id)], s.Uses.Value.String)
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
				u := SameRunUpload{job: strings.ToLower(id), Text: "jobs." + id + " (" + s.Uses.Value.Text() + ")", Checkout: co.Step.Base, Upload: s.Base, Unless: unless, before4: uploadBefore4(x.Uses.Value), events: evs}
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

// mergeUploads are the uploads of actions/upload-artifact/merge in the
// jobs of w that take an artifact of ups, or of another merge, from a job
// they need, directly or through other jobs: the merge downloads the
// artifacts its pattern names and uploads their files again under its
// name.
func mergeUploads(c *taint.Callers, w *workflow.Workflow, ups []SameRunUpload) []SameRunUpload {
	if len(ups) == 0 || w.Jobs.Status != workflow.Present {
		return nil
	}
	var out []SameRunUpload
	seen := map[string]bool{} // jobs.<id>.steps[<order>]
	for changed := true; changed; {
		changed = false
		all := append(slices.Clone(ups), out...)
		for _, je := range w.Jobs.Value.Entries {
			j := je.Value.Value
			if je.Value.Status != workflow.Present {
				continue
			}
			id := j.ID.AsString()
			needed := neededJobs(w, id)
			for _, s := range j.Steps.Value.Items {
				if key := strings.ToLower(id) + "/" + strconv.Itoa(s.Order); seen[key] || s.Uses.Status != workflow.Present || !isMerge(s.Uses.Value) {
					continue
				}
				for _, u := range all {
					if !needed[u.job] || u.before4 || !u.anyName && !mergeTakes(s.With, u.name) {
						continue
					}
					evs := taint.FilterCode(c.Table(), u.events, append(attacker.JobIfs(w, &j), attacker.StepIf(w, &j, s.If))...)
					if len(evs) == 0 {
						continue
					}
					m := SameRunUpload{job: strings.ToLower(id), Text: "jobs." + id + " (" + s.Uses.Value.Text() + " of " + u.Text + ")", Checkout: u.Checkout, Upload: s.Base, Unless: u.Unless, events: evs}
					m.name, m.anyName = inputName(s.With, mergedArtifactName)
					out = append(out, m)
					seen[strings.ToLower(id)+"/"+strconv.Itoa(s.Order)], changed = true, true
					break
				}
			}
		}
	}
	return out
}

// mergeTakes is whether a merge step with with takes the artifact name:
// its pattern, when it has one, else every artifact of the run.
func mergeTakes(with workflow.Field[workflow.Map[workflow.String]], name string) bool {
	if with.Status != workflow.Present {
		return true
	}
	e, ok := with.Value.Lookup("pattern")
	if !ok {
		return true
	}
	if e.Value.Status != workflow.Present || e.Value.Value.Parts != nil {
		return true
	}
	p := strings.TrimSpace(e.Value.Value.AsString())
	if strings.ContainsAny(p, "{}") {
		return true
	}
	ok, err := path.Match(p, name)
	return ok || err != nil
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
// A ./ uses in a job that s needs whose uploads are not known (unknown, by
// the job) is added to InconclusiveValues when no upload is found.
func (s *DownloadSite) sameRun(w *workflow.Workflow, ups []SameRunUpload, unknown map[string][]workflow.String) {
	if !s.currentRun || s.Job == nil || len(ups) == 0 && len(unknown) == 0 {
		return
	}
	needed := neededJobs(w, s.Job.ID.AsString())
	defer func() {
		if len(s.SameRunUploads) > 0 || len(s.PRCodeOn) == 0 {
			return
		}
		for _, je := range w.Jobs.Value.Entries {
			if k := strings.ToLower(je.Value.Value.ID.AsString()); needed[k] {
				s.InconclusiveValues = append(s.InconclusiveValues, unknown[k]...)
			}
		}
	}()
	var on []analysis.EventActivity
	for _, u := range ups {
		if !needed[u.job] || !u.anyName && !s.takesName(u.name) {
			continue
		}
		if u.before4 && !(s.action == downloaderArtifact && s.release() == releaseBefore) {
			continue // during the run, only download-artifact v1 to v3 takes an artifact of v1 to v3
		}
		both := slices.DeleteFunc(slices.Clone(s.PRCodeOn), func(e analysis.EventActivity) bool { return !slices.Contains(u.events, e) })
		if len(both) == 0 {
			continue
		}
		s.SameRunUploads = append(s.SameRunUploads, u)
		for _, e := range both {
			if !slices.Contains(on, e) {
				on = append(on, e)
			}
		}
	}
	if len(s.SameRunUploads) > 0 {
		s.PRCodeOn = on
	}
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
// name upload: a download with neither name nor pattern takes every
// artifact; a ${{ }}, a pattern with braces (minimatch, which path.Match
// does not read) and a name of dawidd6/action-download-artifact read as a
// regular expression may name any artifact.
func (s DownloadSite) takesName(upload string) bool {
	if re, ok := s.input("name_is_regexp"); ok && s.action == downloaderDawidd6 && (re.Status != workflow.Present || re.Value.Parts != nil || strings.EqualFold(strings.TrimSpace(re.Value.AsString()), "true")) {
		return true
	}
	name, nameOK := s.input("name")
	pattern, patternOK := s.input("pattern")
	switch {
	case nameOK && (name.Status != workflow.Present || name.Value.Parts != nil):
		return true
	case nameOK:
		return strings.EqualFold(strings.TrimSpace(name.Value.AsString()), upload)
	case patternOK && (pattern.Status != workflow.Present || pattern.Value.Parts != nil):
		return true
	case patternOK:
		p := strings.TrimSpace(pattern.Value.AsString())
		if strings.ContainsAny(p, "{}") {
			return true
		}
		ok, err := path.Match(p, upload)
		return ok || err != nil
	}
	return true
}

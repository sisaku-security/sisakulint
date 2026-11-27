package prcode

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// SameRunUpload is an upload of actions/upload-artifact in a job of the
// same workflow that checks out the code of a pull request before the
// upload, with no approval or a label: a label approves the whole labeled
// run, so the download of the same run decides it (artifact-poisoning reads
// whether a labeler adds the label for the attacker); a download of the current run that takes its
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
// run after a checkout of the code of a pull request that no environment
// approves (a label approves the run of the download too), on the events on which the checkout brings that code (the guard
// of actions/checkout, as untrusted-checkout reads it) and the if of the
// upload lets the upload run; t is the table of the callers (nil for none),
// and w the workflow of the checkouts.
func sameRunUploads(t *taint.Callers, w *workflow.Workflow, checkouts []CheckoutSite) []SameRunUpload {
	var out []SameRunUpload
	for _, c := range checkouts {
		if c.Job == nil || !c.Placed || c.CheckoutCode != analysis.CodePR || len(c.PRCodeOn) == 0 || c.Approval == analysis.ApprovalEnvironment {
			continue
		}
		if a, _ := job.ApprovalOf(nil, c.Job); a == analysis.ApprovalEnvironment {
			continue // a label approves the run, and the environment of the job also the upload
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
			u := SameRunUpload{job: strings.ToLower(id), Text: "jobs." + id, Checkout: c.Step.Base, Upload: s.Base, Unless: unless, name: defaultArtifactName, before4: uploadBefore4(s.Uses.Value), events: evs}
			switch {
			case s.With.Status == workflow.Dynamic:
				u.anyName = true
			case s.With.Status == workflow.Present:
				if e, ok := s.With.Value.Lookup("name"); ok {
					switch {
					case e.Value.Status != workflow.Present || e.Value.Value.Parts != nil:
						u.anyName = true
					default:
						u.name = strings.TrimSpace(e.Value.Value.AsString())
					}
				}
			}
			out = append(out, u)
		}
	}
	return out
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
func (s *DownloadSite) sameRun(w *workflow.Workflow, ups []SameRunUpload) {
	if !s.currentRun || s.Job == nil || len(ups) == 0 {
		return
	}
	needed := neededJobs(w, s.Job.ID.AsString())
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

package prcode

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// downloader is an action of the table whose downloads are read.
type downloader uint8

const (
	downloaderNone     downloader = iota
	downloaderArtifact            // actions/download-artifact
	downloaderDawidd6             // dawidd6/action-download-artifact
)

// PRRunRef is what makes a download take the artifact of a run an attacker
// drives: a context in an input, or the uses of dawidd6/action-download-artifact
// with no input run_id or one that is empty on the event of the job, whose
// search of the runs of a workflow takes the run
// of a review of a pull request from a fork whatever allow_forks is.
type PRRunRef struct {
	Text  string    // as written: the context, or the uses
	Span  expr.Span // in the value of Input; zero for DownloadInputUses and DownloadInputAllowForks, which are the whole value
	Input analysis.DownloadInput

	events []workflow.EventName // the events whose payload has it; none for every one
	// except are the events on which a search does not happen: those whose
	// payload has the value of run_id, which is then not empty
	except []workflow.EventName
}

// DownloadSite is a step that uses one of the two actions of the table, and
// what the rule of artifact poisoning reads of it.
type DownloadSite struct {
	Step workflow.Step
	Job  *workflow.Job // nil in an action.yml
	Path facts.StepPath
	Uses workflow.Uses
	// ref is the ref of the action that runs, which is not the ref written
	// after @ when the path of Uses goes above the root of its repository
	ref string

	PRRunRefs          []PRRunRef        // what makes it take an attacker's run
	SameRunUploads     []SameRunUpload   // the uploads of the current run that check out the code of a pull request, when it takes the current run
	InconclusiveValues []workflow.String // the inputs the tables cannot tell
	Dynamic            bool              // whether with is a whole ${{ }}

	PRCodeOn    []analysis.EventActivity // the privileged events it can run on, narrowed to those of PRRunRefs
	Approval    analysis.Approval
	Environment facts.EnvironmentName // when ApprovalEnvironment
	ActionsRead analysis.ActionsRead
	// DispatchOn, DispatchInput and CallFromPR are those of CheckoutSite,
	// for the run, the repository, the token and allow_forks.
	DispatchOn    []analysis.EventActivity
	DispatchInput bool
	CallFromPR    bool

	Destination      analysis.DownloadDestination
	DestinationRoot  Placement        // where it puts the files
	DestinationValue *workflow.String // the path, when Destination is inconclusive
	MissingCommits   []MissingCommit  // for a pinned commit in no table
	CodeRunSteps     []CodeRunStep    // the steps after it that run what it puts at DestinationRoot

	action       downloader
	anyEvents    []analysis.EventActivity // every event it can run on: a search of forks' runs holds on any
	called       bool                     // whether callers in the repository decide the events and give the inputs: a workflow on workflow_call, or an action
	dispatchRead bool                     // whether read read an input that refers to an input of workflow_dispatch
	searches     bool                     // whether an inconclusive input decides a search of forks' runs
	currentRun   bool                     // whether it takes the artifacts of the current run
}

// IsDownload is whether u is one of the two actions, at any ref.
func IsDownload(u workflow.Uses) bool {
	d, _ := downloaderOf(u)
	return d != downloaderNone
}

// downloaderOf is the downloader u runs, and the ref of it that runs.
func downloaderOf(u workflow.Uses) (downloader, string) {
	for _, a := range u.Actions() {
		switch {
		case a.Is("actions", "download-artifact", workflow.RootActionPath):
			return downloaderArtifact, a.Ref
		case a.Is("dawidd6", "action-download-artifact", workflow.RootActionPath):
			return downloaderDawidd6, a.Ref
		}
	}
	return downloaderNone, ""
}

// Value is the value of the input in of s's with, or the zero String.
func (s DownloadSite) Value(in string) workflow.String {
	if s.Step.With.Status != workflow.Present {
		return workflow.String{}
	}
	e, ok := s.Step.With.Value.Lookup(in)
	if !ok || e.Value.Status != workflow.Present {
		return workflow.String{}
	}
	return e.Value.Value
}

// AnalyzeDownloads is the downloads of w, or of the composite steps of a,
// each with the privileged events it can run on and the run it takes.
func AnalyzeDownloads(w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo) []DownloadSite {
	return AnalyzeDownloadsIn(nil, calls.Node{}, w, a, m)
}

// AnalyzeDownloadsIn is AnalyzeDownloads, with the events of the input
// name, when it is called, read from its callers c (a nil c reads none).
// When the callers decide them, the events a search of forks' runs holds
// on are every event they run it on; else those of w's on, as without
// callers.
func AnalyzeDownloadsIn(c *taint.Callers, name calls.Node, w *workflow.Workflow, a *workflow.ActionMetadata, m *shell.Memo) []DownloadSite {
	var out []DownloadSite
	if w != nil {
		evs := c.EventsOr(name, prCodeEvents, true, func() []analysis.EventActivity { return taint.EventsOf(w, prCodeEvents) })
		all := taint.EventsOf(w, onNames(w))
		ups, unknown := sameRunUploadsIn(c, name, w, m, 0)
		if c.Coverage(name) == analysis.CallerCoverageAll {
			all, _ = c.Events(name, workflow.EventNames(), true)
		}
		for _, je := range w.Jobs.Value.Entries {
			j := je.Value.Value
			jobIfs := attacker.JobIfs(w, &j)
			jobEvs := taint.FilterCode(c.Table(), evs, jobIfs...)
			jobAll := taint.FilterCode(c.Table(), all, jobIfs...)
			steps := j.Steps.Value.Items
			order := workflow.OrderOf(steps)
			for _, s := range steps {
				if s.Uses.Status != workflow.Present || !IsDownload(s.Uses.Value) {
					continue
				}
				p, err := stepPath(&j, s)
				if err != nil {
					continue // a job id the model reports as invalid
				}
				site := DownloadSite{Step: s, Job: &j, Path: p, Uses: s.Uses.Value, PRCodeOn: taint.FilterCode(c.Table(), jobEvs, attacker.StepIf(w, &j, s.If)), anyEvents: taint.FilterCode(c.Table(), jobAll, attacker.StepIf(w, &j, s.If)), called: onCall(w) && c.Coverage(name) == analysis.CallerCoverageAll}
				site.action, site.ref = downloaderOf(s.Uses.Value)
				site.DispatchOn, site.DispatchInput = dispatchOn(c.Table(), name, w, append(slices.Clone(jobIfs), attacker.StepIf(w, &j, s.If))...), anyDispatchInput(w, s.With)
				if _, remote := name.Remote(); remote {
					site.DispatchInput = false // its own workflow_dispatch starts runs in its repository
				}
				site.CallFromPR = callFromPR(w, site.DispatchInput, site.PRCodeOn)
				site.read(job.ActionsReadOf(j.Permissions, w.Permissions))
				site.sameRun(w, ups, unknown)
				site.DispatchInput = site.dispatchRead // the inputs the release reads, of the run it takes
				site.CallFromPR = site.CallFromPR && site.DispatchInput
				site.Approval, site.Environment = job.ApprovalOf(site.PRCodeOn, site.Job)
				site.CodeRunSteps = codeRuns(w, site.Job, steps, order, s.Order, site.DestinationRoot, m)
				out = append(out, site)
			}
		}
	}
	if a != nil && a.Runs.Status == workflow.Present && a.Runs.Value.Kind == workflow.RunsComposite {
		evs := c.EventsOr(name, prCodeEvents, true, func() []analysis.EventActivity { return taint.EventsAll(prCodeEvents) })
		all := evs // an action without callers is read in the worst case
		if c.Coverage(name) == analysis.CallerCoverageAll {
			all, _ = c.Events(name, workflow.EventNames(), true)
		}
		steps := a.Runs.Value.Steps.Value.Items
		order := workflow.OrderOf(steps)
		for _, s := range steps {
			if s.Uses.Status != workflow.Present || !IsDownload(s.Uses.Value) {
				continue
			}
			p, _ := stepPath(nil, s)
			site := DownloadSite{Step: s, Path: p, Uses: s.Uses.Value, PRCodeOn: taint.FilterCode(c.Table(), evs, attacker.StepIf(nil, nil, s.If)), anyEvents: taint.FilterCode(c.Table(), all, attacker.StepIf(nil, nil, s.If)), called: c.Coverage(name) == analysis.CallerCoverageAll}
			site.action, site.ref = downloaderOf(s.Uses.Value)
			site.read(analysis.ActionsReadYes)
			site.Approval, site.Environment = job.ApprovalOf(site.PRCodeOn, nil)
			site.CodeRunSteps = codeRuns(nil, nil, steps, order, s.Order, site.DestinationRoot, m)
			out = append(out, site)
		}
	}
	return out
}

// read reads the with of s and its release: the run it takes, the token's
// scope (actions, the scope of the job's permissions), and where it puts
// the files.
func (s *DownloadSite) read(actions analysis.ActionsRead) {
	w := s.Step.With
	if w.Status == workflow.Dynamic {
		s.Dynamic = true
		if w.Expr != nil {
			s.InconclusiveValues = append(s.InconclusiveValues, *w.Expr)
		}
		s.Destination = analysis.DownloadDestinationInconclusive
		s.searches = s.action == downloaderDawidd6 // its inputs may search forks
		s.narrow()
		return
	}
	switch s.action {
	case downloaderArtifact:
		s.readArtifact(actions)
	case downloaderDawidd6:
		s.readDawidd6(actions)
	}
	s.narrow()
	s.readDestination()
}

// readArtifact: actions/download-artifact takes another run only with a
// token (if (inputs.token) in src/download-artifact.ts, v4.0.0 to v8.0.1),
// from v4 on; without run-id, or with github.run_id, it is the current
// run whatever the token.
func (s *DownloadSite) readArtifact(actions analysis.ActionsRead) {
	if s.release() == releaseBefore {
		s.currentRun = true
		return
	}
	id, ok := s.input("run-id")
	if !ok || id.Status == workflow.Present && isCurrentRun(id.Value) {
		s.currentRun = true
		return
	}
	tok, ok := s.input("github-token")
	if !ok || tok.Status == workflow.Present && strings.TrimSpace(tok.Value.Text()) == "" {
		s.currentRun = true // without a token, run-id is not read
		return
	}
	if id.Status == workflow.Present && id.Value.Parts == nil {
		return // a run written out
	}
	if tok.Status == workflow.Dynamic || inconclusiveToken(tok.Value) {
		s.inconclusive(tok)
		return
	}
	s.ActionsRead = tokenScope(tok.Value, actions)
	if repo, ok := s.input("repository"); ok && !baseRepo(repo) {
		s.inconclusive(repo)
		return
	}
	s.refs(id, analysis.DownloadInputRunID, runIDRefs)
}

// isCurrentRun is whether v is ${{ github.run_id }} alone.
func isCurrentRun(v workflow.String) bool {
	if len(v.Parts) != 1 || !v.Parts[0].Expr || v.Parts[0].Tree == nil {
		return false
	}
	pth, ok := expr.AccessPath(v.Parts[0].Tree)
	return ok && match(pth, []string{"github", "run_id"})
}

// readDawidd6: dawidd6/action-download-artifact takes run_id as it is,
// and with none (or an empty one, as a ${{ }} is on an event whose
// payload lacks it) searches the runs of repo (default the base), keeping
// those of forks out unless allow_forks, which before v4 is true by
// default and before v2.28.0 is not read (main.js of v27, 115-175; #290;
// #250). A run of a fork is one whose head repository is not repo: the run
// of a review of a pull request from a fork is not one, so every search
// may take the attacker's run.
func (s *DownloadSite) readDawidd6(actions analysis.ActionsRead) {
	tok, _ := s.input("github_token")
	switch {
	case tok.Status == workflow.Dynamic || tok.Status == workflow.Present && inconclusiveToken(tok.Value):
		// not known: the worst case, a token that reads; it decides no run
		s.ActionsRead = analysis.ActionsReadNotNeeded
	case tok.Status == workflow.Present:
		s.ActionsRead = tokenScope(tok.Value, actions)
	default:
		s.ActionsRead = actions // github.token by default
	}
	var except []workflow.EventName
	if id, ok := s.input("run_id"); ok && !(id.Status == workflow.Present && strings.TrimSpace(id.Value.Text()) == "") {
		s.refs(id, analysis.DownloadInputRunIDSnake, runIDRefs)
		if id.Status == workflow.Present && id.Value.Parts == nil {
			return // a run written out
		}
		if id.Status == workflow.Present && isCurrentRun(id.Value) {
			s.currentRun = true
			return
		}
		var never bool
		if except, never = runIDPresentOn(id, s.called); never {
			return // never empty: the run itself, or a value with text written out
		}
		// a ${{ }} may be empty on the other events (or as a step made it): then it searches
	}
	if repo, ok := s.input("repo"); ok && !baseRepo(repo) {
		s.searches = true
		s.refs(repo, analysis.DownloadInputRepo, forkRepoRefs)
		return
	}
	forks, ok := s.input("allow_forks")
	if s.noAllowForks() {
		ok = false // not read: forks are searched
	}
	if ok && forks.Status == workflow.Present && forks.Value.Parts == nil && strings.EqualFold(strings.TrimSpace(forks.Value.AsString()), "true") {
		s.PRRunRefs = append(s.PRRunRefs, PRRunRef{Text: forks.Value.Text(), Input: analysis.DownloadInputAllowForks, except: except})
		return
	}
	// whatever allow_forks is, the search takes the run of a review of a
	// pull request from a fork: that run takes the workflow of the pull
	// request's merge commit, and its head repository is the base
	// (seen on GitHub on 2026-11-05), which allow_forks false does not skip
	s.PRRunRefs = append(s.PRRunRefs, PRRunRef{Text: s.Uses.Text(), Input: analysis.DownloadInputUses, except: except})
}

// onCall is whether w's on has workflow_call: a caller gives its inputs.
func onCall(w *workflow.Workflow) bool {
	if w.On.Status != workflow.Present {
		return false
	}
	_, ok := w.On.Value.Event(workflow.EventNameWorkflowCall)
	return ok
}

// runIDPresentOn is, of a run_id with a ${{ }}, the events on which its
// value is not empty, so that the release does not search: an event whose
// payload has a context of the value (github.event.workflow_run.id on
// workflow_run; an input on workflow_dispatch and workflow_call; the
// client_payload on repository_dispatch, whose sender chooses it; an input
// of a workflow on workflow_call or of an action on every event, when its
// callers in the repository decide the events and give it, which the rule
// declares as caller-omitted-input when a caller does not). never is
// whether the value is not empty on any event: github.run_id, the run
// itself, or text written out beside the ${{ }}. A value of a step, an env
// or another context may be empty on every event.
func runIDPresentOn(f workflow.Field[workflow.String], called bool) (events []workflow.EventName, never bool) {
	if f.Status != workflow.Present {
		return nil, false
	}
	add := func(es ...workflow.EventName) {
		for _, e := range es {
			if !slices.Contains(events, e) {
				events = append(events, e)
			}
		}
	}
	for _, p := range f.Value.Parts {
		if !p.Expr {
			if strings.TrimSpace(f.Value.Text()[p.Span.Start:p.Span.End]) != "" {
				return nil, true
			}
			continue
		}
		if p.Tree == nil {
			continue
		}
		taint.WrittenRefs(p.Tree, func(n expr.Node) {
			pth, _ := expr.AccessPath(n)
			for _, r := range runIDRefs {
				if match(pth, r.path) {
					add(r.events...)
				}
			}
			switch {
			case match(pth, []string{"github", "run_id"}):
				never = true
			case len(pth) > 0 && strings.EqualFold(pth[0].Name, "inputs") && called:
				never = true // the caller gives it on every event the workflow or action runs on
			case len(pth) > 0 && strings.EqualFold(pth[0].Name, "inputs"):
				add(workflow.EventNameWorkflowDispatch, workflow.EventNameWorkflowCall)
			case len(pth) > 2 && match(pth[:2], []string{"github", "event"}) && strings.EqualFold(pth[2].Name, "inputs"):
				add(workflow.EventNameWorkflowDispatch)
			case len(pth) > 2 && match(pth[:2], []string{"github", "event"}) && strings.EqualFold(pth[2].Name, "client_payload"):
				add(workflow.EventNameRepositoryDispatch)
			}
		})
	}
	return events, never
}

// noAllowForks is whether s's release of dawidd6/action-download-artifact
// is before v2.28.0, which has no allow_forks.
func (s DownloadSite) noAllowForks() bool {
	ref := s.ref
	if fullSHA.MatchString(ref) {
		return dawidd6NoAllowForks[strings.ToLower(ref)]
	}
	m := versionRef.FindStringSubmatch(ref)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	return major < 2 || major == 2 && m[2] != "" && minor < 28
}

// PathFixHolds is whether a path under runner.temp keeps the files of s
// out of the workspace: not for a release of actions/download-artifact
// with the zip-slip, nor for a commit in no table, which may be one.
func (s DownloadSite) PathFixHolds() bool {
	if s.action != downloaderArtifact {
		return true
	}
	r := s.release()
	return r != releaseZipSlip && r != releaseUnknownCommit
}

// release is what the tables say of the ref of s's uses.
type release uint8

const (
	releaseOn            release = iota // v4 on: download-artifact takes another run (dawidd6: the default of allow_forks is false, which no longer decides a finding)
	releaseBefore                       // before v4
	releaseZipSlip                      // download-artifact 4.0.0 to 4.1.2
	releaseUnknownCommit                // a commit in no table: the worst case, asked by git.commit-contains
)

var versionRef = regexp.MustCompile(`^v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?(?:-.*)?$`)

func (s DownloadSite) release() release {
	ref := s.ref
	if fullSHA.MatchString(ref) {
		c := strings.ToLower(ref)
		switch {
		case s.action == downloaderArtifact && downloadBefore4[c], s.action == downloaderDawidd6 && dawidd6Forks[c]:
			return releaseBefore
		case s.action == downloaderArtifact && downloadZipSlip[c]:
			return releaseZipSlip
		case s.action == downloaderArtifact && downloadFixedOn[c], s.action == downloaderDawidd6 && dawidd6NoForksOn[c]:
			return releaseOn
		}
		return releaseUnknownCommit
	}
	m := versionRef.FindStringSubmatch(ref)
	if m == nil {
		// a branch or another ref: the worst case, which for dawidd6 is
		// before v4 (it searches forks)
		if s.action == downloaderDawidd6 {
			return releaseBefore
		}
		return releaseOn
	}
	major, _ := strconv.Atoi(m[1])
	minor, patch := -1, -1
	if m[2] != "" {
		minor, _ = strconv.Atoi(m[2])
	}
	if m[3] != "" {
		patch, _ = strconv.Atoi(m[3])
	}
	switch {
	case major < 4:
		return releaseBefore
	case s.action == downloaderArtifact && major == 4 && (minor == 0 || minor == 1 && patch >= 0 && patch <= 2):
		return releaseZipSlip
	}
	return releaseOn
}

// refs adds the references of the value v of the input in that rows says
// name an attacker's run; it is false when v has none. A context the
// tables cannot tell makes v inconclusive.
func (s *DownloadSite) refs(f workflow.Field[workflow.String], in analysis.DownloadInput, rows []runRef) bool {
	s.markDispatch(f)
	if f.Status == workflow.Dynamic {
		s.inconclusive(f)
		return false
	}
	v, found, unknown := f.Value, false, false
	for _, p := range v.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		taint.WrittenRefs(p.Tree, func(n expr.Node) {
			pth, _ := expr.AccessPath(n)
			sp := p.InValue(n.Span())
			for _, r := range rows {
				if match(pth, r.path) {
					s.PRRunRefs = append(s.PRRunRefs, PRRunRef{Text: v.Text()[sp.Start:sp.End], Span: sp, Input: in, events: r.events})
					found = true
					return
				}
			}
			if len(pth) > 0 && (slicesContainsFold(unknownRoots, pth[0].Name) || !match(pth, []string{"github", "run_id"}) && !isBaseRepoPath(pth)) {
				unknown = true
			}
		})
	}
	if unknown && !found {
		s.inconclusive(f)
	}
	return found
}

// runRef is a context whose value is an attacker's run or repository, and
// the events whose payload has it.
type runRef struct {
	path   []string
	events []workflow.EventName
}

var (
	runIDRefs    = []runRef{{[]string{"github", "event", "workflow_run", "id"}, onRun}}
	forkRepoRefs = []runRef{
		{[]string{"github", "event", "workflow_run", "head_repository", "full_name"}, onRun},
		{[]string{"github", "event", "pull_request", "head", "repo", "full_name"}, onPRTarget},
	}
)

// baseRepo is whether the input names the base repository: github.repository
// (and the other forms of baseRepos), or a literal owner/name.
func baseRepo(f workflow.Field[workflow.String]) bool {
	if f.Status != workflow.Present {
		return false
	}
	v := f.Value
	if v.Parts == nil {
		return true // a literal: a repository the author wrote
	}
	if len(v.Parts) != 1 || !v.Parts[0].Expr || v.Parts[0].Tree == nil {
		return false
	}
	pth, ok := expr.AccessPath(v.Parts[0].Tree)
	return ok && isBaseRepoPath(pth)
}

func isBaseRepoPath(pth []expr.PathElem) bool {
	for _, b := range baseRepos {
		if match(pth, b) {
			return true
		}
	}
	return false
}

// inconclusiveToken is whether a token's value has a context the tables
// cannot tell: one of a step, a job, an input, an env, a matrix, a variable.
func inconclusiveToken(v workflow.String) bool {
	bad := false
	for _, p := range v.Parts {
		if !p.Expr || p.Tree == nil {
			continue
		}
		taint.WrittenRefs(p.Tree, func(n expr.Node) {
			if pth, _ := expr.AccessPath(n); len(pth) > 0 && slicesContainsFold(unknownRoots, pth[0].Name) {
				bad = true
			}
		})
	}
	return bad
}

// tokenScope is the ActionsRead of a token: the job's for the GITHUB_TOKEN
// (github.token, secrets.GITHUB_TOKEN), and none needed for another.
func tokenScope(v workflow.String, actions analysis.ActionsRead) analysis.ActionsRead {
	if len(v.Parts) == 1 && v.Parts[0].Expr && v.Parts[0].Tree != nil {
		if pth, ok := expr.AccessPath(v.Parts[0].Tree); ok && (match(pth, []string{"github", "token"}) || match(pth, []string{"secrets", "GITHUB_TOKEN"})) {
			return actions
		}
	}
	return analysis.ActionsReadNotNeeded
}

// input is the entry in of s's with, and whether it is written.
func (s DownloadSite) input(in string) (workflow.Field[workflow.String], bool) {
	if s.Step.With.Status != workflow.Present {
		return workflow.Field[workflow.String]{}, false
	}
	e, ok := s.Step.With.Value.Lookup(in)
	if !ok {
		return workflow.Field[workflow.String]{}, false
	}
	return e.Value, true
}

func (s *DownloadSite) inconclusive(f workflow.Field[workflow.String]) {
	s.markDispatch(f)
	if s.dispatcherChooses(f) {
		return // the dispatcher's: input-dispatch reports it
	}
	switch {
	case f.Status == workflow.Dynamic && f.Expr != nil:
		s.InconclusiveValues = append(s.InconclusiveValues, *f.Expr)
	case f.Status == workflow.Present:
		s.InconclusiveValues = append(s.InconclusiveValues, f.Value)
	}
}

// narrow keeps the references of PRRunRefs that have a value on an event
// of s, and makes PRCodeOn those events: a context's events of PRCodeOn
// whose payload has it, and for a search of forks' runs (no events), every
// event s can run on, as the attacker need not trigger the run.
func (s *DownloadSite) narrow() {
	if len(s.PRRunRefs) == 0 {
		if s.searches && len(s.InconclusiveValues) > 0 {
			s.PRCodeOn = s.anyEvents // a search of forks' runs may take the attacker's on any
		}
		return
	}
	var evs []analysis.EventActivity
	add := func(e analysis.EventActivity) {
		if !slices.Contains(evs, e) {
			evs = append(evs, e)
		}
	}
	var refs []PRRunRef
	for _, r := range s.PRRunRefs {
		on := s.anyEvents
		if len(r.except) > 0 {
			on = slices.DeleteFunc(slices.Clone(on), func(e analysis.EventActivity) bool { return slices.Contains(r.except, e.Name()) })
		}
		if len(r.events) > 0 {
			on = nil
			for _, e := range s.PRCodeOn {
				if slicesContainsName(r.events, e.Name()) {
					on = append(on, e)
				}
			}
		}
		if len(on) == 0 {
			continue
		}
		refs = append(refs, r)
		for _, e := range on {
			add(e)
		}
	}
	slices.SortFunc(evs, func(a, b analysis.EventActivity) int {
		if c := strings.Compare(a.Name().String(), b.Name().String()); c != 0 {
			return c
		}
		return strings.Compare(a.ActivityType().String(), b.ActivityType().String())
	})
	s.PRCodeOn, s.PRRunRefs = evs, refs
}

// onNames are the names of the events of w's on.
func onNames(w *workflow.Workflow) []workflow.EventName {
	if w.On.Status != workflow.Present {
		return nil
	}
	var out []workflow.EventName
	for _, ev := range w.On.Value.Events {
		if n, err := workflow.ParseEventName(ev.Name.AsString()); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func slicesContainsName(ns []workflow.EventName, n workflow.EventName) bool {
	for _, x := range ns {
		if x == n {
			return true
		}
	}
	return false
}

var windowsPath = regexp.MustCompile(`^[A-Za-z]:`)

// readDestination reads the path of s, where the download puts the files.
func (s *DownloadSite) readDestination() {
	s.Destination, s.DestinationRoot = analysis.DownloadDestinationWorkspace, workspacePlacement(relDirOf("."))
	f, ok := s.input("path")
	switch {
	case !ok:
	case f.Status == workflow.Dynamic:
		s.destinationInconclusive(f)
	case f.Status == workflow.Present && f.Value.Parts != nil:
		s.destinationExpr(f)
	case f.Status == workflow.Present:
		p := strings.TrimSpace(f.Value.AsString())
		switch {
		case p == "":
		case strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || windowsPath.MatchString(p) || strings.Contains(p, `\`):
			s.destinationInconclusive(f)
		default:
			c := path.Clean(p)
			if c == ".." || strings.HasPrefix(c, "../") {
				s.destinationInconclusive(f)
				return
			}
			s.DestinationRoot = workspacePlacement(relDirOf(c))
		}
	}
	if s.action != downloaderArtifact || s.Destination == analysis.DownloadDestinationInconclusive {
		return
	}
	switch s.release() {
	case releaseZipSlip:
		// the paths of the zip write anywhere, .. too (GHSA-cxww-7g56-2vh6)
		s.Destination, s.DestinationRoot = analysis.DownloadDestinationWorkspace, workspacePlacement(relDirOf("."))
	case releaseUnknownCommit:
		if s.Destination == analysis.DownloadDestinationRunnerTemp {
			sha, _ := facts.ParseSHA(s.ref)
			s.MissingCommits = append(s.MissingCommits, MissingCommit{Repo: DownloadArtifactRepo, SHA: sha, Commit: mustSHA(downloadFixed)})
			s.Destination, s.DestinationRoot = analysis.DownloadDestinationWorkspace, workspacePlacement(relDirOf("."))
		}
	}
}

// destinationExpr reads a path with a ${{ }}: runner.temp or
// github.workspace as its first part, the rest a literal that stays under
// it.
func (s *DownloadSite) destinationExpr(f workflow.Field[workflow.String]) {
	v := f.Value
	first := v.Parts[0]
	if !first.Expr || first.Tree == nil {
		s.destinationInconclusive(f)
		return
	}
	rest := ""
	for _, p := range v.Parts[1:] {
		if p.Expr {
			s.destinationInconclusive(f)
			return
		}
	}
	rest = v.Text()[first.Span.End:]
	if rest != "" && !strings.HasPrefix(rest, "/") {
		s.destinationInconclusive(f) // ${{ runner.temp }}x
		return
	}
	c := path.Clean("./" + strings.TrimSpace(rest))
	if c == ".." || strings.HasPrefix(c, "../") {
		s.destinationInconclusive(f)
		return
	}
	pth, _ := expr.AccessPath(first.Tree)
	switch {
	case match(pth, []string{"runner", "temp"}):
		s.Destination, s.DestinationRoot = analysis.DownloadDestinationRunnerTemp, runnerTempPlacement(relDirOf(c))
	case match(pth, []string{"github", "workspace"}):
		s.DestinationRoot = workspacePlacement(relDirOf(c))
	default:
		s.destinationInconclusive(f)
	}
}

func (s *DownloadSite) destinationInconclusive(f workflow.Field[workflow.String]) {
	s.Destination, s.DestinationRoot = analysis.DownloadDestinationInconclusive, workspacePlacement(anyDir())
	switch {
	case f.Status == workflow.Dynamic && f.Expr != nil:
		s.DestinationValue = f.Expr
	case f.Status == workflow.Present:
		v := f.Value
		s.DestinationValue = &v
	}
}

func mustSHA(s string) facts.SHA {
	sha, err := facts.ParseSHA(s)
	if err != nil {
		panic(err)
	}
	return sha
}

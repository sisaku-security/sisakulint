package labeler

import (
	"errors"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/attacker"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// TokenSource is where the token of a step that adds labels comes from,
// which decides the actor of the run that the label starts.
type TokenSource uint8

const (
	// TokenSourceAccount is a secret or a literal, read as the token of an
	// account. A token put in a secret serves the runs of a long time after
	// the token was put there, and an installation access token of a GitHub
	// App expires one hour after the installation access token is made
	// ("Installation access tokens expire after one hour, expiring user
	// access tokens expire after eight hours, and refresh tokens expire after
	// six months.", line 112 of
	// https://github.com/github/docs/blob/205d63d65aa98df27c915faebb26710be6a9c787/content/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app.md),
	// so a token in a secret is read as one of an account. A workflow that
	// keeps writing a new installation access token to the secret is an
	// exception, which ai-action-unrestricted-trigger declares as a false
	// positive form.
	TokenSourceAccount TokenSource = iota
	TokenSourceApp                 // the output of actions/create-github-app-token: the bot of the app
	TokenSourceUnknown             // another expression
)

var tokenSourceNames = [...]string{"account", "app", "unknown"}

func (s TokenSource) String() string { return tokenSourceNames[s] }

// Step is a step that runs actions/labeler on the pull request of an
// attacker with a token other than the GITHUB_TOKEN. Labels are the labels
// of its configuration and whether the attacker gets each; AnyLabel is
// that the attacker writes the configuration, so gets any label; Unknown
// is that the labels are not known (the release, the configuration, the
// pull request). MayNotRun is that the step runs only after a step of the
// job fails, after a job that the job depends on through needs does not
// succeed, or in a cancelled run, and the rule does not know whether the
// attacker can cause that; Labels and AnyLabel are then the labels that
// the step adds when the step runs.
type Step struct {
	Input     facts.InputPath
	Tree      *cst.Tree // of the workflow of Input
	Step      workflow.Step
	Token     TokenSource
	Labels    map[string]Reach
	AnyLabel  bool
	Unknown   bool
	MayNotRun bool
}

// maxConfig is the size above which a configuration is not read, as
// actions/repofile reads a file of settings.
const maxConfig = 1 << 20

var attackerEvents = []workflow.EventName{workflow.EventNamePullRequestTarget}

// stepsOf are the steps of w, the input name, that run actions/labeler on
// the pull request of an attacker with a token other than the
// GITHUB_TOKEN; root is the repository the configurations are read from,
// and a path excluded is not read.
func stepsOf(at attacker.Table, name facts.InputPath, w *workflow.Workflow, root fs.FS, excluded func(facts.InputPath) bool) []Step {
	if w == nil {
		return nil
	}
	return workflowSteps(at, name, w, own(w), root, excluded)
}

// workflowSteps is stepsOf on the chain c: the events of the workflow at
// its top, past the ifs of its calls, with the token that its calls give.
func workflowSteps(at attacker.Table, name facts.InputPath, w *workflow.Workflow, c chain, root fs.FS, excluded func(facts.InputPath) bool) []Step {
	evs := c.evs
	if w == nil || w.Jobs.Status != workflow.Present || len(evs) == 0 {
		return nil
	}
	// the checkouts, with their ifs read in at as the steps of actions/labeler
	// are (no callers: the events of the workflow, as prcode.Analyze reads them)
	sites := prcode.AnalyzeIn(taint.NewCallersIn(calls.New(nil, false, false, facts.Repo{}), at), calls.Node{}, w, nil, nil)
	var out []Step
	for _, je := range w.Jobs.Value.Entries {
		j := je.Value.Value
		steps := j.Steps.Value.Items
		jobIfs := attacker.JobIfs(w, &j)
		for i, s := range steps {
			ref, ok := labelerRef(s)
			if !ok {
				continue
			}
			ifs := append(append(slices.Clone(jobIfs), attacker.StepIf(w, &j, s.If)), c.ifs...)
			on := slices.DeleteFunc(slices.Clone(evs), func(e analysis.EventActivity) bool { return !attackerRuns(at, e, ifs...) })
			if len(on) == 0 {
				continue
			}
			run := func(e analysis.EventActivity) jobRun { return jobRunOn(at, e, w, &j, sites) }
			for _, st := range readSteps(s, ref, steps[:i], sites, at, on, run, c.resolve, root, excluded, w, &j) {
				if j.Environment.Status != workflow.Absent || c.environment() {
					st.Unknown = true // required reviewers of the environment may approve the run before the label
				}
				st.Input = name
				out = append(out, st)
			}
		}
	}
	return out
}

// actionSteps are the steps of the composite action a, the input name,
// that run actions/labeler on the pull request of an attacker with a
// token other than the GITHUB_TOKEN, on the events evs its callers run it
// on through the chain c. The jobs of the callers are read for their ifs
// and environments alone: the step is read as one of a job that runs,
// with the steps of a before it.
func actionSteps(at attacker.Table, name facts.InputPath, a *workflow.ActionMetadata, c chain, root fs.FS, excluded func(facts.InputPath) bool) []Step {
	evs := c.evs
	if a == nil || len(evs) == 0 || a.Runs.Status != workflow.Present || a.Runs.Value.Steps.Status != workflow.Present {
		return nil
	}
	sites := prcode.AnalyzeIn(taint.NewCallersIn(calls.New(nil, false, false, facts.Repo{}), at), calls.Node{}, nil, a, nil)
	steps := a.Runs.Value.Steps.Value.Items
	var out []Step
	for i, s := range steps {
		ref, ok := labelerRef(s)
		if !ok {
			continue
		}
		on := slices.DeleteFunc(slices.Clone(evs), func(e analysis.EventActivity) bool {
			return !attackerRuns(at, e, append([]attacker.PlacedIf{attacker.StepIf(nil, nil, s.If)}, c.ifs...)...)
		})
		if len(on) == 0 {
			continue
		}
		run := func(analysis.EventActivity) jobRun { return jobRunSure }
		for _, st := range readSteps(s, ref, steps[:i], sites, at, on, run, c.resolve, root, excluded, nil, nil) {
			if c.environment() {
				st.Unknown = true // required reviewers of the environment of a calling job may approve the run before the label
			}
			st.Input = name
			out = append(out, st)
		}
	}
	return out
}

// attackerRuns is whether the attacker starts a run of e, as its actor, on
// their pull request from a fork, that passes every if of ifs, read in the
// attacker run table at.
func attackerRuns(at attacker.Table, e analysis.EventActivity, ifs ...attacker.PlacedIf) bool {
	return !slices.ContainsFunc(ifs, func(p attacker.PlacedIf) bool {
		return !at.KeptActor(p, e) || !at.KeptCode(p, e)
	})
}

// jobRun is whether the job of a step of actions/labeler runs on an event,
// as the ifs of the job and of the jobs it depends on through needs tell.
type jobRun uint8

const (
	jobRunSure  jobRun = iota // the job runs in the attacker runs of the event that pass its ifs
	jobRunMay                 // the job runs only after a job it depends on does not succeed, or in a cancelled run, which the attacker may not cause
	jobRunNever               // the job does not run: an if with no status function is false when every job it depends on succeeded
)

// jobRunOn is whether the job j of w runs on the event e. Each if of j and
// of the jobs whose ifs a run of j goes through (attacker.NeedJobs) is read
// on its own, with the
// needs.<id>.result and needs.*.result of the jobs that its job depends on
// directly
// (attacker.Table.JobCodeTruth): an if that passes the attacker runs of e
// when every job that its job depends on succeeded and the run is not
// cancelled (attacker.JobStateSucceeded) lets j run. An if that is true
// only when success() is true (attacker.TrueOnlyOnSuccess: one that calls no
// status function, or success() && X) and does not pass then stops j:
// GitHub reads an if that calls no status function only when every job that
// its job depends on succeeded, and skips the job otherwise, and success()
// is false otherwise
// (https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/content/actions/reference/workflows-and-actions/expressions.md,
// status check functions, and
// https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/data/reusables/actions/jobs/section-using-jobs-in-a-workflow-needs.md).
// The if of j itself also lets j run when the if is true when a job that j
// depends on failed (attacker.JobStateFailed, with needs.<id>.result of a
// job that fails as failure) and such a job fails on the pull request of
// the attacker, or the attacker can make that job fail (jobFails). An if of
// another job does not: that job is one that j needs while the if of j
// calls no status function, and the failure of a job that j depends on
// skips j.
func jobRunOn(at attacker.Table, e analysis.EventActivity, w *workflow.Workflow, j *workflow.Job, sites []prcode.CheckoutSite) jobRun {
	runs := surelyRuns{at: at, e: e, byName: job.ByName(w), memo: map[string]bool{}}
	fails := func(a workflow.Job) bool { return jobFails(at, e, w, &a, sites, runs) }
	for _, n := range attacker.NeedJobs(w, j) {
		if passesJobIf(at, e, n.If, needsOf(n, runs, nil), attacker.JobStateSucceeded) {
			continue
		}
		if attacker.TrueOnlyOnSuccess(n.If) {
			return jobRunNever
		}
		if n.ID.AsString() == j.ID.AsString() && trueJobIf(at, e, n.If, needsOf(n, runs, fails), attacker.JobStateFailed) {
			if slices.ContainsFunc(job.Ancestors(w, &n), fails) {
				continue
			}
		}
		return jobRunMay
	}
	return jobRunSure
}

// needsOf are the jobs that the job a depends on directly through needs,
// each with whether it surely runs (runs) and whether it fails (fails; none
// fails when fails is nil). An if of a that calls no status function reads
// the result of each as success; an if that calls one reads the result of
// a job that may be skipped as not known, as that if may be read after the
// job is skipped, which no JobState tells (attacker.Table.JobCodeTruth). A
// need that names no job of the workflow is left out: GitHub does not
// accept the workflow.
func needsOf(a workflow.Job, runs surelyRuns, fails func(workflow.Job) bool) []attacker.Need {
	if a.Needs.Status != workflow.Present {
		return nil
	}
	var out []attacker.Need
	for _, n := range a.Needs.Value.Items {
		x, found := runs.byName[expr.FoldName(n.AsString())]
		if !found {
			continue
		}
		sure := runs.of(x)
		out = append(out, attacker.Need{Job: x, SurelyRuns: sure, Fails: sure && fails != nil && fails(x)})
	}
	return out
}

// surelyRuns reads, on the event e, whether a job of w surely runs: the if
// of the job and of every job it depends on through needs is true in the
// attacker runs of e when every job that its job depends on succeeded, so
// no job before it is skipped but by a failure, and none of the jobs has
// an environment, whose required reviewers may hold the job. Each job is
// read once by its ID (memo); a job in a cycle of needs does not surely
// run.
type surelyRuns struct {
	at     attacker.Table
	e      analysis.EventActivity
	byName map[string]workflow.Job // job.ByName
	memo   map[string]bool
}

func (r surelyRuns) of(a workflow.Job) bool {
	id := a.ID.AsString()
	if v, ok := r.memo[id]; ok {
		return v
	}
	r.memo[id] = false
	// a job in an environment may wait for the approval of a reviewer
	ok := a.Environment.Status == workflow.Absent && trueJobIf(r.at, r.e, a.If, needsOf(a, r, nil), attacker.JobStateSucceeded)
	if ok && a.Needs.Status == workflow.Present {
		for _, n := range a.Needs.Value.Items {
			x, found := r.byName[expr.FoldName(n.AsString())]
			if !found || !r.of(x) {
				ok = false
				break
			}
		}
	}
	r.memo[id] = ok
	return ok
}

// jobFails is whether the job a, on the event e, fails on the pull
// request of the attacker, or the attacker can make a fail: a surely runs
// (runs; a job before a that is skipped by a failure leaves that failure,
// which the job of actions/labeler sees too), the continue-on-error of a
// is absent or written with no ${{ }} and not true, and a step of a fails
// (configWalk.stepFails).
func jobFails(at attacker.Table, e analysis.EventActivity, w *workflow.Workflow, a *workflow.Job, sites []prcode.CheckoutSite, runs surelyRuns) bool {
	if !stopsOnFailure(a.ContinueOnError) || a.Steps.Status != workflow.Present || !runs.of(*a) {
		return false
	}
	return configWalk{at: at, e: e, sites: sites, wf: w, job: a}.stepFails(a.Steps.Value.Items)
}

// trueJobIf is whether the if c of a job, whose direct needs are needs, is
// true in every attacker run of e in the state st, for the attacker's code
// and as its actor.
func trueJobIf(at attacker.Table, e analysis.EventActivity, c workflow.Field[workflow.If], needs []attacker.Need, st attacker.JobState) bool {
	return at.JobCodeTruth(c, needs, e, st) == expr.TruthTrue && at.JobActorTruth(c, needs, e, st) == expr.TruthTrue
}

// passesJobIf is whether an attacker run of e passes the if c of a job,
// whose direct needs are needs, in the state st, for the attacker's code
// and as its actor.
func passesJobIf(at attacker.Table, e analysis.EventActivity, c workflow.Field[workflow.If], needs []attacker.Need, st attacker.JobState) bool {
	return at.JobCodeTruth(c, needs, e, st) != expr.TruthFalse && at.JobActorTruth(c, needs, e, st) != expr.TruthFalse
}

// labelerRef is the ref of actions/labeler that s runs.
func labelerRef(s workflow.Step) (string, bool) {
	if s.Uses.Status != workflow.Present {
		return "", false
	}
	for _, a := range s.Uses.Value.Actions() {
		if a.Is("actions", "labeler", workflow.RootActionPath) {
			return a.Ref, true
		}
	}
	return "", false
}

// readSteps reads the labeler step s at ref, after the steps before of its
// job, on the events evs whose attacker runs pass its ifs, read in the
// table at, with its repo-token as resolve gives it through the calls
// that run the step (chain.resolve): one Step for each reading of the
// configuration that
// attackerConfig gives, so one step of actions/labeler may give a Step
// that surely runs and a Step that may not run (MayNotRun). None for a
// step that adds no label that starts a run: the GITHUB_TOKEN, no
// configuration, a checkout before it that stops the job.
func readSteps(s workflow.Step, ref string, before []workflow.Step, sites []prcode.CheckoutSite, at attacker.Table, evs []analysis.EventActivity, jobRun func(analysis.EventActivity) jobRun, resolve func(workflow.String, []workflow.Step) (workflow.String, []workflow.Step, bool), root fs.FS, excluded func(facts.InputPath) bool, wf *workflow.Workflow, job *workflow.Job) []Step {
	st := Step{Step: s}
	if s.With.Status == workflow.Dynamic {
		st.Token, st.Unknown = TokenSourceUnknown, true
		return []Step{st}
	}
	token, present := input(s, "repo-token")
	own := before
	resolved := true
	if present {
		token, before, resolved = resolve(token, before)
	}
	if !present || resolved && githubToken(token) {
		return nil // the default github.token, or none (the labeler fails)
	}
	st.Token = tokenSource(token, before)
	before = own
	if !resolved {
		st.Token, st.Unknown = TokenSourceUnknown, true
	}
	if mayBeJobToken(token) {
		st.Unknown = true // the token may be the GITHUB_TOKEN, whose label starts no run
	}
	releases, _ := ReleaseOf(ref)
	if n, present := input(s, "pr-number"); present && !runNumber(n) && slices.ContainsFunc(releases, func(r Release) bool { return r.PRNumber }) {
		st.Unknown = true
	}
	p, ok := configPath(s)
	if !ok || excluded(p) {
		st.Unknown = true
		return []Step{st}
	}
	readings := attackerConfig(p, s, before, sites, at, evs, jobRun, wf, job)
	if slices.Contains(readings, readingUnknown) {
		st.Unknown = true
		return []Step{st}
	}
	var out []Step
	for _, r := range readings {
		x := st
		x.MayNotRun = r == readingWrittenMay || r == readingBaseMay
		x, ok := withConfig(x, root, p, releases, r == readingWritten || r == readingWrittenMay)
		if !ok || x.MayNotRun && slices.ContainsFunc(out, x.sameLabels) {
			continue // a Step that may not run adds nothing to a Step that surely runs with the same labels
		}
		out = append(out, x)
	}
	return out
}

// sameLabels is whether st and o add the same labels when they run.
func (st Step) sameLabels(o Step) bool {
	return st.AnyLabel == o.AnyLabel && st.Unknown == o.Unknown && maps.Equal(st.Labels, o.Labels)
}

// withConfig is st with the labels of the configuration p of root, as
// each release of releases reads it; written is that a checkout before
// the step brings the tree of the attacker that has p. ok is false when
// the step adds no label: the configuration is missing.
func withConfig(st Step, root fs.FS, p facts.InputPath, releases []Release, written bool) (Step, bool) {
	text, missing, tooBig := readConfig(root, p)
	var readings []reading
	for _, r := range releases {
		switch {
		case written && r.LocalFirst:
			readings = append(readings, reading{any: true})
		case missing:
			readings = append(readings, reading{}) // the API answers 404, the labeler fails
		case tooBig:
			st.Unknown = true
			return st, true
		default:
			labels, err := ParseConfig(text, r.Format)
			if errors.Is(err, ErrUnsupportedSyntax) {
				st.Unknown = true
				return st, true
			}
			readings = append(readings, reading{labels: labels})
		}
	}
	if slices.ContainsFunc(readings[1:], func(x reading) bool { return !x.equal(readings[0]) }) {
		st.Unknown = true
		return st, true
	}
	if !readings[0].any && len(readings[0].labels) == 0 && missing {
		return Step{}, false
	}
	st.AnyLabel, st.Labels = readings[0].any, readings[0].labels
	return st, true
}

// reading is what one release makes of the configuration.
type reading struct {
	any    bool
	labels map[string]Reach
}

func (x reading) equal(y reading) bool { return x.any == y.any && maps.Equal(x.labels, y.labels) }

// input is the value of the input k of s, when written.
func input(s workflow.Step, k string) (workflow.String, bool) {
	if s.With.Status != workflow.Present {
		return workflow.String{}, false
	}
	e, ok := s.With.Value.Lookup(k)
	if !ok {
		return workflow.String{}, false
	}
	switch e.Value.Status {
	case workflow.Present:
		return e.Value.Value, true
	case workflow.Dynamic:
		return workflow.String{Parts: []workflow.Part{{Expr: true}}}, true
	}
	return workflow.String{}, false
}

// onlyTree is the syntax tree of v when v is one ${{ }} and nothing else.
func onlyTree(v workflow.String) (expr.Node, bool) {
	if !v.IsExpr() {
		return nil, false
	}
	for _, p := range v.Parts {
		if p.Expr {
			return p.Tree, p.Tree != nil
		}
	}
	return nil, false
}

// githubToken is whether v is the GITHUB_TOKEN of the run: empty, or one
// ${{ }} that is github.token or secrets.GITHUB_TOKEN and nothing else.
func githubToken(v workflow.String) bool {
	if v.Parts == nil {
		return strings.TrimSpace(v.AsString()) == ""
	}
	n, ok := onlyTree(v)
	return ok && taint.JobTokenRef(n)
}

// mayBeJobToken is whether a ${{ }} of v reads the job's token, or the
// whole secrets context, which has it.
func mayBeJobToken(v workflow.String) bool {
	may := false
	for _, p := range v.Parts {
		if p.Expr && p.Tree != nil {
			taint.SecretRefs(p.Tree, func(r taint.SecretRef) { may = may || r.Token || r.Whole })
		}
	}
	return may
}

var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var appTokenActions = [][2]string{{"actions", "create-github-app-token"}, {"tibdex", "github-app-token"}}

// tokenSource is where the token v comes from: a secret or a literal is
// the token of an account; the output token of a step before that makes
// the token of an app is the app's.
func tokenSource(v workflow.String, before []workflow.Step) TokenSource {
	if v.Parts == nil {
		return TokenSourceAccount
	}
	n, ok := onlyTree(v)
	if !ok {
		return TokenSourceUnknown
	}
	p, ok := expr.AccessPath(n)
	if !ok {
		return TokenSourceUnknown
	}
	if len(p) == 2 && expr.HasPrefix(p, "secrets") && identifier.MatchString(p[1].Name) {
		return TokenSourceAccount
	}
	if len(p) != 4 || !expr.HasPrefix(p, "steps") || p[1].Name == "" || !expr.EqualName(p[2].Name, "outputs") || !expr.EqualName(p[3].Name, "token") {
		return TokenSourceUnknown
	}
	for _, b := range before {
		if b.ID.Status != workflow.Present || !expr.EqualName(b.ID.Value.AsString(), p[1].Name) || b.Uses.Status != workflow.Present {
			continue
		}
		for _, a := range b.Uses.Value.Actions() {
			for _, app := range appTokenActions {
				if a.Is(app[0], app[1], workflow.RootActionPath) {
					return TokenSourceApp
				}
			}
		}
	}
	return TokenSourceUnknown
}

// runNumber is whether v is the number of the pull request of the run.
func runNumber(v workflow.String) bool {
	n, ok := onlyTree(v)
	return ok && (expr.IsPath(n, "github", "event", "pull_request", "number") || expr.IsPath(n, "github", "event", "number"))
}

// configPath is the path of the configuration of s, from the root of the
// repository: configuration-path, else .github/labeler.yml.
func configPath(s workflow.Step) (facts.InputPath, bool) {
	p := ".github/labeler.yml"
	if v, present := input(s, "configuration-path"); present {
		if v.Parts != nil {
			return facts.InputPath{}, false
		}
		p = strings.TrimSpace(v.AsString())
	}
	c, err := facts.CleanInputPath(path.Clean(p))
	return c, err == nil
}

// configReading is what the steps before a labeler step leave of its
// configuration, on one event of the step and for one choice of the
// attacker among the steps the attacker may make fail: whether the step
// runs, and whether the configuration is the base's or one the attacker
// writes.
type configReading uint8

const (
	readingFails      configReading = iota // the step does not run: a checkout before it stops the job
	readingBaseMay                         // the step may not run; when it runs, it reads the configuration of the base
	readingWrittenMay                      // the step may not run; when it runs, it reads a configuration the attacker writes
	readingBase                            // the step runs and reads the configuration of the base
	readingUnknown                         // what the checkouts bring is not known
	readingWritten                         // the step runs and reads a configuration the attacker writes
)

// mayNotRun is r for a step that may not run.
func (r configReading) mayNotRun() configReading {
	switch r {
	case readingBase:
		return readingBaseMay
	case readingWritten:
		return readingWrittenMay
	}
	return r
}

// mergeReadings is what the attacker gets of the readings rs, among which
// the attacker chooses (one for each event, or for each step the attacker
// may make fail). A reading where the attacker writes the configuration
// and the step runs decides; else a reading where what the checkouts bring
// is not known leaves the configuration unknown, as the attacker may write
// the configuration there. Else the reading where the step surely runs
// with the configuration of the base, and the reading where the step may
// not run, both stand: the one where the attacker writes the
// configuration, else the one with the configuration of the base, which
// adds nothing to a reading that surely runs with the same configuration.
// None when every reading fails.
func mergeReadings(rs []configReading) []configReading {
	has := func(r configReading) bool { return slices.Contains(rs, r) }
	switch {
	case has(readingWritten):
		return []configReading{readingWritten}
	case has(readingUnknown):
		return []configReading{readingUnknown}
	}
	var out []configReading
	if has(readingBase) {
		out = append(out, readingBase)
	}
	switch {
	case has(readingWrittenMay):
		out = append(out, readingWrittenMay)
	case has(readingBaseMay) && !has(readingBase):
		out = append(out, readingBaseMay)
	}
	return out
}

// attackerConfig is, for the labeler step s after the steps before, on the
// events evs read in the table at, what the checkouts of the steps before
// leave of the configuration p: the readings of configOn on each event,
// merged by mergeReadings, as the attacker chooses the event. On an event
// where the job may not run (jobRunMay: an if of the job, or of a job it
// depends on, is false when every job it depends on succeeded), a reading
// where the step runs becomes one where the step may not run; on an event
// where the job does not run (jobRunNever), the step does not run.
func attackerConfig(p facts.InputPath, s workflow.Step, before []workflow.Step, sites []prcode.CheckoutSite, at attacker.Table, evs []analysis.EventActivity, jobRunOf func(analysis.EventActivity) jobRun, wf *workflow.Workflow, job *workflow.Job) []configReading {
	var rs []configReading
	for _, e := range evs {
		run := jobRunOf(e)
		if run == jobRunNever {
			rs = append(rs, readingFails)
			continue
		}
		for _, r := range configOn(p, s, before, sites, at, e, wf, job) {
			if run == jobRunMay {
				r = r.mayNotRun()
			}
			rs = append(rs, r)
		}
	}
	return mergeReadings(rs)
}

// configOn is attackerConfig on the event e. Each checkout is read in the
// state of the job that the checkouts before it leave (attacker.JobState):
// a checkout that fails on the pull request of the attacker (it puts no
// tree, or the guard of actions/checkout refuses the code of the fork)
// stops the job unless continue-on-error is true or s runs after a
// failure. A step s that does not run in a job that succeeded (such as an
// if of failure()) runs only when a step before s fails: unless a checkout
// before s surely fails, the reading is one where s may not run, as the
// rule does not know whether the attacker can make a step before s fail.
// A step that runs the code of the attacker, which a checkout before it
// brought (prcode.CheckoutSite.CodeRunSteps), fails when the attacker
// chooses, so each such step adds the reading where the attacker makes
// that step fail. The steps are of the job job of wf (attacker.StepIf).
func configOn(p facts.InputPath, s workflow.Step, before []workflow.Step, sites []prcode.CheckoutSite, at attacker.Table, e analysis.EventActivity, wf *workflow.Workflow, job *workflow.Job) []configReading {
	steps := append(slices.Clone(before), s)
	siteOf := make([]int, len(before))
	for k, b := range before {
		siteOf[k] = slices.IndexFunc(sites, func(c prcode.CheckoutSite) bool { return c.Step.Base.Node == b.Base.Node })
	}
	w := configWalk{p: p, s: s, before: before, sites: sites, at: at, e: e, wf: wf, job: job,
		steps: steps, siteOf: siteOf, order: workflow.OrderOf(steps)}
	w.afterSuccess, w.afterFailure, w.afterCancel = w.runsIn(s, attacker.JobStateSucceeded), w.runsIn(s, attacker.JobStateFailed), w.runsIn(s, attacker.JobStateCancelled)
	if !w.afterSuccess && !w.afterFailure {
		if w.afterCancel {
			return []configReading{readingUnknown} // s runs only in a cancelled run, which the attacker may not cause
		}
		return []configReading{readingFails} // s runs in no state of the job
	}
	return w.from(0, len(before)+1, false, nil, false, false)
}

// configWalk reads, for configOn, the steps before the labeler step s on
// the event e; afterSuccess, afterFailure and afterCancel are whether s
// runs in a job that succeeded, in a job that failed and in a cancelled
// run, steps are the steps before s
// and s, siteOf is the index in sites of the checkout of each step before
// s (-1 for a step that is not a checkout), and order is when the steps
// end (background steps and the steps of a parallel group end at a wait).
// The steps are of the job job of wf, whose ifs stepIf reads.
type configWalk struct {
	p            facts.InputPath
	s            workflow.Step
	before       []workflow.Step
	sites        []prcode.CheckoutSite
	at           attacker.Table
	e            analysis.EventActivity
	wf           *workflow.Workflow
	job          *workflow.Job
	afterSuccess bool
	afterFailure bool
	afterCancel  bool
	steps        []workflow.Step
	siteOf       []int
	order        workflow.StepOrder
}

// doneBeforeS is whether the step at k of the steps before s ends before s
// starts, so that the tree of a checkout there is there for s: a
// background step ends only at the next wait or wait-all that includes it
// (https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/content/actions/reference/workflows-and-actions/workflow-syntax.md,
// background steps). Where a failure fails the job is failsAt.
func (w configWalk) doneBeforeS(k int) bool { return w.order.DoneBefore(k, len(w.before)) }

// failure is how the failure of a step fails the job.
type failure uint8

const (
	failureNever   failure = iota // the continue-on-error of the step, or of the wait or wait-all that waits for it, is true
	failureAt                     // the failure fails the job from a step on
	failureUnknown                // a continue-on-error with a ${{ }}
)

// failsAt is how the failure of the step at k of steps, in the order
// order, fails the job, and from which step on: the first step that runs
// after the step is done (the next step, the step after the parallel
// group of the step, or the step after the wait or wait-all that waits for
// a background step; the end of the steps when no step waits for it, as
// the implicit wait-all does), unless the continue-on-error of the step,
// or of the wait or wait-all, is true or has a ${{ }}
// (https://github.com/github/docs/blob/404a5f4de6cd5311e3ce2d5c076571291e0107d6/content/actions/reference/workflows-and-actions/workflow-syntax.md,
// background steps, wait and wait-all).
func failsAt(steps []workflow.Step, order workflow.StepOrder, k int) (int, failure) {
	how := failureOf(steps[k].ContinueOnError)
	at, wait, waited := order.DoneAt(k)
	if waited && how == failureAt {
		how = failureOf(steps[wait].ContinueOnError)
	}
	return at, how
}

// failureOf is how a failure fails the job under the continue-on-error c
// of a step.
func failureOf(c workflow.Field[workflow.String]) failure {
	switch {
	case stopsOnFailure(c):
		return failureAt
	case c.Status == workflow.Present && c.Value.Parts == nil:
		return failureNever // true
	}
	return failureUnknown
}

// from reads the steps before s from the one at start, in a job that has
// failed from the step at failAt on (len(before) + 1 when no failure
// reaches s), where written is whether a checkout before start
// brings the tree of the attacker that has the configuration, brought are
// the checkouts before start that surely bring the code of the attacker
// before the job has failed (kept only in the reading that may branch for
// P2a), may is that the
// reading rests on a failure or a cancel that the rule does not know of (a
// checkout that runs only after a failure or in a cancelled run wrote the
// configuration), so s may not run with the configuration of the reading,
// and p2a is that the reading is one where the attacker made a step fail.
// Neither a may reading nor a p2a reading branches again: a may reading
// has the configuration written already, and the may reading of a
// checkout in a p2a reading is the may reading of the same checkout in
// the reading that branched for P2a.
func (w configWalk) from(start, failAt int, written bool, brought []prcode.CheckoutSite, may, p2a bool) []configReading {
	sAt := len(w.before)
	var out []configReading
	for k := start; k < sAt; k++ {
		state := attacker.JobStateUnknown
		if failAt <= k {
			state = attacker.JobStateFailed
		}
		b := w.before[k]
		i := w.siteOf[k]
		if i < 0 {
			if !may && !p2a && w.afterFailure && failAt > k && w.attackerMayFail(b, state, brought) {
				// the attacker makes b fail, when s runs after a failure: the
				// job has failed from where the failure of b fails it, when
				// that is before where a known failure fails the job (a job
				// that has failed already does not change when b fails; in a
				// reading that rests on another failure, the configuration is
				// written already)
				if at, how := failsAt(w.steps, w.order, k); how == failureAt && at < failAt {
					out = append(out, w.from(k+1, at, written, nil, false, true)...)
				}
			}
			continue
		}
		c := w.sites[i]
		run := w.run(b.If, state)
		if run == expr.TruthFalse {
			continue // skipped
		}
		if failsOnAttackerPR(c) {
			at, how := failsAt(w.steps, w.order, k)
			switch {
			case how == failureNever || at > sAt:
				continue // the job goes on, or the failure of b fails the job only after s
			case w.runsIn(w.s, attacker.JobStateFailed):
				// s may run whether b fails or is skipped (skipped, the state
				// of the job is not known, and s passes its if as attackerRuns
				// reads it); the job has failed only when b surely runs and
				// its failure surely fails the job
				if run == expr.TruthTrue && how == failureAt {
					failAt = min(failAt, at)
				}
				continue
			case w.runsIn(w.s, attacker.JobStateCancelled):
				return append(out, readingUnknown) // s runs only in a cancelled run
			case run != expr.TruthTrue:
				return append(out, readingUnknown) // b may be skipped, and then s runs
			case how == failureUnknown:
				return append(out, readingUnknown) // continue-on-error with a ${{ }}
			}
			return append(out, readingFails)
		}
		if !w.doneBeforeS(k) {
			// a background checkout that s does not wait for: its tree may or
			// may not be there, which matters only when the tree may have the
			// configuration
			if c.CheckoutCode == analysis.CodeBase {
				continue
			}
			if dir, known := c.Placement.Dir(); known && dir != "." && !strings.HasPrefix(w.p.String(), dir+"/") {
				continue
			}
			return append(out, readingUnknown)
		}
		switch c.CheckoutCode {
		case analysis.CodeBase:
			continue
		case analysis.CodeUnknown:
			return append(out, readingUnknown)
		}
		if c.Guard == analysis.GuardSHA {
			return append(out, readingUnknown)
		}
		dir, known := c.Placement.Dir()
		switch {
		case !known:
			return append(out, readingUnknown)
		case dir == "." || strings.HasPrefix(w.p.String(), dir+"/"):
			if !may && state == attacker.JobStateUnknown && w.at.CodeTruth(w.stepIf(b.If), w.e, attacker.JobStateSucceeded) == expr.TruthFalse {
				// b runs only after a failure or in a cancelled run that the
				// rule does not know of here: b writes the configuration in a
				// reading of its own, which rests on that failure or cancel,
				// and not in this one
				if !p2a {
					out = append(out, w.from(k+1, failAt, true, nil, true, false)...)
				}
				continue
			}
			written = true
		}
		if run == expr.TruthTrue && !may && !p2a && failAt > k {
			brought = append(slices.Clone(brought), c)
		}
	}
	if may && !w.afterFailure && !w.afterCancel {
		return append(out, readingFails) // s runs neither after a failure nor in a cancelled run, which the reading rests on
	}
	r := readingBase
	if written {
		r = readingWritten
	}
	if may || !w.afterSuccess && failAt > sAt {
		r = r.mayNotRun()
	}
	return append(out, r)
}

// run is whether the step with the if c runs in a job of the state state,
// for the code of the attacker: in a job whose state is not known, an if
// that is true both in a job that succeeded and in a job that failed (such
// as always()) is true.
func (w configWalk) run(c workflow.Field[workflow.If], state attacker.JobState) expr.Truth {
	p := w.stepIf(c)
	t := w.at.CodeTruth(p, w.e, state)
	if state == attacker.JobStateUnknown && t == expr.TruthUnknown &&
		w.at.CodeTruth(p, w.e, attacker.JobStateSucceeded) == expr.TruthTrue && w.at.CodeTruth(p, w.e, attacker.JobStateFailed) == expr.TruthTrue {
		return expr.TruthTrue
	}
	return t
}

// stepFails is whether a step of steps, in a job that runs them from the
// start, fails on the pull request of the attacker, or the attacker can
// make the step fail: a checkout that surely runs and fails
// (failsOnAttackerPR), or a step that runs the code of the attacker that a
// checkout before it surely brings (attackerMayFail), whose
// continue-on-error, and that of the wait or wait-all that waits for the
// step, is absent or written with no ${{ }} and not true (failsAt; a step
// that no step waits for fails the job at the implicit wait-all). The ifs
// are read in a job where no step has failed (attacker.JobStateSucceeded):
// a step before that fails first fails the job too.
func (w configWalk) stepFails(steps []workflow.Step) bool {
	order := workflow.OrderOf(steps)
	failsJob := func(k int) bool { _, how := failsAt(steps, order, k); return how == failureAt }
	var brought []prcode.CheckoutSite
	for k, b := range steps {
		i := slices.IndexFunc(w.sites, func(c prcode.CheckoutSite) bool { return c.Step.Base.Node == b.Base.Node })
		if i < 0 {
			if w.attackerMayFail(b, attacker.JobStateSucceeded, brought) && failsJob(k) {
				return true
			}
			continue
		}
		c := w.sites[i]
		if w.run(b.If, attacker.JobStateSucceeded) != expr.TruthTrue {
			continue
		}
		if failsOnAttackerPR(c) {
			if failsJob(k) {
				return true
			}
			continue
		}
		if c.CheckoutCode == analysis.CodePR && c.Guard != analysis.GuardSHA {
			brought = append(brought, c)
		}
	}
	return false
}

// attackerMayFail is whether the attacker can make the step r fail the
// job: r surely runs, its continue-on-error is absent or written with no
// ${{ }} and not true, and r runs the code of the attacker that a checkout
// of brought brings, in a command that the script does not end by &
// (prcode.CodeRunStep.Asynchronous). The code of the attacker makes the
// step fail by its exit code, or by stopping the shell of the step, its
// parent process or an ancestor, of the same user (observed on 2026-11-16
// for a step whose shell is bash on the ubuntu, macOS and Windows runners
// that GitHub hosts and in a container, sh on ubuntu, and pwsh and cmd on
// Windows; not checked on a self-hosted runner). A command ended by & may run
// after the shell of the step has ended, so the rule does not read such a
// command as one that the attacker can make fail. A command that a wrapper
// runs as another user (sudo -u, su) is read as one that the attacker can
// make fail, also where its failure does not end the step, where the code
// of another user cannot stop the shell of the step (observed on
// 2026-11-16 on ubuntu): the label rules declare that form as a false
// positive.
func (w configWalk) attackerMayFail(r workflow.Step, state attacker.JobState, brought []prcode.CheckoutSite) bool {
	if w.run(r.If, state) != expr.TruthTrue || !stopsOnFailure(r.ContinueOnError) {
		return false
	}
	return slices.ContainsFunc(brought, func(c prcode.CheckoutSite) bool {
		return slices.ContainsFunc(c.CodeRunSteps, func(x prcode.CodeRunStep) bool {
			return x.Step.Base.Node == r.Base.Node && !x.Asynchronous
		})
	})
}

// stepIf is the if c of a step of the job of w.
func (w configWalk) stepIf(c workflow.Field[workflow.If]) attacker.PlacedIf {
	return attacker.StepIf(w.wf, w.job, c)
}

// runsIn is whether an attacker run of w.e passes the if of s, a step of
// the job of w, in a job of the state st, for the attacker's code and as
// its actor.
func (w configWalk) runsIn(s workflow.Step, st attacker.JobState) bool {
	p := w.stepIf(s.If)
	return w.at.CodeTruth(p, w.e, st) != expr.TruthFalse && w.at.ActorTruth(p, w.e, st) != expr.TruthFalse
}

// stopsOnFailure is whether the continue-on-error c of a step or a job is
// absent, or written with no ${{ }} and not true: a failure there fails
// the job, or the job fails the jobs that depend on it.
func stopsOnFailure(c workflow.Field[workflow.String]) bool {
	switch c.Status {
	case workflow.Absent:
		return true
	case workflow.Present:
		return c.Value.Parts == nil && !strings.EqualFold(strings.TrimSpace(c.Value.AsString()), "true")
	}
	return false
}

// failsOnAttackerPR is whether the checkout c fails on the pull request of
// the attacker: it puts no tree, or the guard of actions/checkout refuses
// the code of the fork.
func failsOnAttackerPR(c prcode.CheckoutSite) bool {
	return !c.Placed || c.CheckoutCode == analysis.CodePR && c.Guard == analysis.GuardStatic
}

// readConfig reads p of root: missing when root has none, tooBig above
// maxConfig.
func readConfig(root fs.FS, p facts.InputPath) (text []byte, missing, tooBig bool) {
	if root == nil {
		return nil, true, false
	}
	info, err := fs.Stat(root, p.String())
	if err != nil || info.IsDir() {
		return nil, true, false
	}
	if info.Size() > maxConfig {
		return nil, false, true
	}
	b, err := fs.ReadFile(root, p.String())
	if err != nil {
		return nil, true, false
	}
	return b, false, false
}

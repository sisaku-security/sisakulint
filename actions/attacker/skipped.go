package attacker

import (
	"runtime"
	"sync"
	"weak"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// afterSkipped is whether the if c of the job of j, which is not true only
// when success() is true (TrueOnlyOnSuccess), is false in a run in which
// every job that the job depends on through needs, directly or through
// other jobs, is skipped (afterSkippedFalse, with the values of lookup and
// of override),
// each of those jobs read as skipped with what the run event e knows of
// the event alone (skippedJobs), so skipped in every run that e may be. A
// job with no needs has no such job. A job of no workflow, a job with a
// need that names no job, a job whose needs the model does not read, and a
// job on a cycle of needs or after one of those are not read so.
func (j *jobIf) afterSkipped(c workflow.Field[workflow.If], e runEvent, lookup func([]expr.PathElem) (expr.Value, bool), override func(expr.Node) (expr.Value, bool)) bool {
	if j == nil || j.w == nil || TrueOnlyOnSuccess(c) {
		return false
	}
	if !afterSkippedFalse(c, j.self.Needs.Status == workflow.Present && len(j.self.Needs.Value.Items) > 0, lookup, override) {
		return false // read first: most such ifs, always() and !cancelled() among them, are not false so
	}
	r, ok := skipsOf(j.w).of(j.w, e)[expr.FoldName(j.self.ID.AsString())]
	return ok && r.ancestorsSkipped
}

// eventKnowledge is what a reading of an if knows of the event of the run.
type eventKnowledge uint8

const (
	// knowsNoEvent is that the event is not known (Narrowing.NarrowsAnyEvent).
	knowsNoEvent eventKnowledge = iota + 1
	// knowsEventName is that the name of the event alone is known
	// (EventNameOnly).
	knowsEventName
	// knowsEvent is that the event and its activity type are known.
	knowsEvent
)

// runEvent is the event of the run that an if is read on, as far as the
// reading knows it: eventOf, eventNameOf and noEvent make it. The jobs that
// the job of the if depends on are read with what it knows (afterSkipped).
type runEvent struct {
	knows        eventKnowledge
	name         workflow.EventName
	activityType workflow.ActivityType
}

// eventOf is the run event e, its name and activity type known. An event
// named workflow_call stands for a run of a called workflow, which has the
// event of the run of its caller (github.event_name is the caller's): that
// event is not known (calledRun).
func eventOf(e analysis.EventActivity) runEvent {
	if e.Name() == workflow.EventNameWorkflowCall {
		return calledRun()
	}
	return runEvent{knows: knowsEvent, name: e.Name(), activityType: e.ActivityType()}
}

// eventNameOf is a run event of which the name n alone is known; for
// workflow_call, a run of a called workflow, as eventOf reads it.
func eventNameOf(n workflow.EventName) runEvent {
	if n == workflow.EventNameWorkflowCall {
		return calledRun()
	}
	return runEvent{knows: knowsEventName, name: n}
}

// calledRun is a run of a called workflow: the event name workflow_call is
// the mark of such a run in the lists of events of a workflow on
// workflow_call (job.EventNamesOf, and the names given to taint.EventsAll
// and taint.Callers.Events), and the run has the event of the run of its
// caller, which is not known. Of the readings of an if, eventOf and
// eventNameOf alone read the mark.
func calledRun() runEvent { return runEvent{knows: knowsNoEvent} }

// noEvent is a run event of which nothing is known.
func noEvent() runEvent { return runEvent{knows: knowsNoEvent} }

// lookup knows github.event_name when the name of e is known, and
// github.event.action when its activity type is known and the event has
// one.
func (e runEvent) lookup(p []expr.PathElem) (expr.Value, bool) {
	switch e.knows {
	case knowsNoEvent, knowsEventName, knowsEvent:
	default:
		panic("attacker: a run event made by none of eventOf, eventNameOf and noEvent")
	}
	switch {
	case e.knows >= knowsEventName && len(p) == 2 && expr.HasPrefix(p, "github", "event_name"):
		return expr.String(e.name.String()), true
	case e.knows == knowsEvent && len(p) == 3 && expr.HasPrefix(p, "github", "event", "action") && e.activityType != workflow.ActivityTypeUnset:
		return expr.String(e.activityType.String()), true
	case e.knows == knowsEvent && len(p) == 4 && expr.HasPrefix(p, "github", "event", "pull_request", "merged") && mergedFalse(e):
		return expr.Bool(false), true
	}
	return expr.Value{}, false
}

// mergedFalse is whether github.event.pull_request.merged is false in
// every payload of e: a pull request is merged only when it is closed, and
// a merged pull request is not reopened, so it is false on opened and
// reopened of pull_request and pull_request_target.
func mergedFalse(e runEvent) bool {
	if e.name != workflow.EventNamePullRequest && e.name != workflow.EventNamePullRequestTarget {
		return false
	}
	return e.activityType == workflow.ActivityTypeOpened || e.activityType == workflow.ActivityTypeReopened
}

// skipCache keeps what skippedJobs reads of a workflow on each run event:
// the if of a job is read on many events, for many places of the job. The
// jobs that a job depends on are read on the run event alone, so a job
// read as skipped is skipped in every run of the event.
type skipCache struct {
	mu    sync.Mutex
	reads map[runEvent]map[string]skippedRead
}

func (c *skipCache) of(w *workflow.Workflow, e runEvent) map[string]skippedRead {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.reads[e]; ok {
		return r
	}
	if c.reads == nil {
		c.reads = map[runEvent]map[string]skippedRead{}
	}
	r := skippedJobs(w, e.lookup)
	c.reads[e] = r
	return r
}

// skippedRead is what skippedJobs reads of a job: skipped is that GitHub
// skips the job; ancestorsSkipped is that every job that the job depends
// on through needs, directly or through other jobs, is skipped (true for a
// job with no needs); hasNeeds is that the job depends on a job.
type skippedRead struct {
	skipped, ancestorsSkipped, hasNeeds bool
}

// skippedJobs reads each job of w, by its folded ID, once, in the order of
// needs, with the values of lookup: a job is skipped when its if is false
// as JobIf reads it, or, when every job it depends on is skipped, by
// afterSkippedFalse; or when its if is true only when success() is true and
// a job it depends on directly is skipped, as NeedJobs reads a run of a
// job. A job with a need that names no job, a job whose needs the model
// does not read, a job on a cycle of needs, and a job after one of those,
// has no entry: GitHub does not accept such a workflow.
func skippedJobs(w *workflow.Workflow, lookup func([]expr.PathElem) (expr.Value, bool)) map[string]skippedRead {
	out := map[string]skippedRead{}
	if w.Jobs.Status != workflow.Present {
		return out
	}
	var jobs []*workflow.Job
	for _, e := range w.Jobs.Value.Entries {
		if e.Value.Status == workflow.Present {
			jobs = append(jobs, &e.Value.Value)
		}
	}
	for changed := true; changed; {
		changed = false
		for _, job := range jobs {
			id := expr.FoldName(job.ID.AsString())
			if _, done := out[id]; done {
				continue
			}
			r, ready, needSkipped := skippedRead{ancestorsSkipped: true}, job.Needs.Status != workflow.Invalid, false
			if job.Needs.Status == workflow.Present {
				for _, x := range job.Needs.Value.Items {
					need, ok := out[expr.FoldName(x.AsString())]
					if !ok {
						ready = false // not read yet, or a need that names no job, or a cycle
						break
					}
					r.hasNeeds = true
					r.ancestorsSkipped = r.ancestorsSkipped && need.skipped && need.ancestorsSkipped
					needSkipped = needSkipped || need.skipped
				}
			}
			if !ready {
				continue
			}
			p := JobIf(w, job)
			onSuccess := TrueOnlyOnSuccess(p.c)
			r.skipped = p.plainTruth(lookup, nil) == expr.TruthFalse ||
				onSuccess && needSkipped ||
				!onSuccess && r.ancestorsSkipped && afterSkippedFalse(p.c, r.hasNeeds, lookup, nil)
			out[id] = r
			changed = true
		}
	}
	return out
}

// afterSkippedFalse is whether the if c of a job is false after every job
// that the job depends on is skipped, with the values of lookup and of
// override (the values that the reading gives to other nodes than the calls
// of the status functions, such as a comparison or the labels; the values
// of the status functions come first): failure() is false, as no job that
// the job depends on fails; success() is false when the job has needs, else
// not known (a run may be cancelled); always() is true; cancelled() is not
// known. needs.<job_id>.result is not known: a job that would be skipped
// may be cancelled in a run that is cancelled.
func afterSkippedFalse(c workflow.Field[workflow.If], hasNeeds bool, lookup func([]expr.PathElem) (expr.Value, bool), override func(expr.Node) (expr.Value, bool)) bool {
	tree, ok := IfTree(c)
	if !ok {
		return false
	}
	values := map[analysis.StatusFunction]bool{analysis.StatusFunctionFailure: false, analysis.StatusFunctionAlways: true}
	if hasNeeds {
		values[analysis.StatusFunctionSuccess] = false
	}
	return expr.PartialWith(tree, lookup, overrides(statusValues(values), override)).Truthy() == expr.TruthFalse
}

// skipCaches are the skipCache of each workflow, by a weak pointer to it:
// the entry of a workflow goes when the workflow is collected.
var skipCaches sync.Map

func skipsOf(w *workflow.Workflow) *skipCache {
	k := weak.Make(w)
	if c, ok := skipCaches.Load(k); ok {
		return c.(*skipCache)
	}
	c, loaded := skipCaches.LoadOrStore(k, &skipCache{})
	if !loaded {
		runtime.AddCleanup(w, func(k weak.Pointer[workflow.Workflow]) { skipCaches.Delete(k) }, k)
	}
	return c.(*skipCache)
}

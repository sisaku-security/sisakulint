package ir

import (
	"sync"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// skippedJobs are where the jobs of the workflow of an IR are, and whether
// GitHub skips each in every run (job.AlwaysSkipped), made once for the IR.
type skippedJobs struct {
	once  sync.Once
	jobs  []skippedJob
	all   bool // every job is skipped in every run, and there is one at least
	whole bool // every place of the IR is skipped: the job of the input that calls a remote called workflow is
}

type skippedJob struct {
	span    cst.Span
	skipped bool
	steps   []cst.Span // the run steps GitHub skips in every run (job.StepAlwaysSkipped)
}

// alwaysSkipped is whether GitHub skips, in every run, the job that the
// element b is in: the job whose place has the place of b (b.Primary, the
// outermost alias b is used through), or, for an element of the workflow
// in no job, every job of the workflow. An element of an action.yml is not
// in a job. The job of a remote called workflow is skipped when the job of
// the input that calls it is. An element of a run step that GitHub skips
// in every run (job.StepAlwaysSkipped) is skipped too.
func (x *IR) alwaysSkipped(b workflow.Base) bool {
	return x.skippedAt(b, true)
}

// jobAlwaysSkipped is alwaysSkipped of the job alone, for an element that
// GitHub reads for the whole job whatever the if of its step is: the
// secrets that a job references reach the runner of the job even from a
// step that GitHub skips (testdata/observed/secret-exposure, the job
// if-false of s1-secrets.yml).
func (x *IR) jobAlwaysSkipped(b workflow.Base) bool {
	return x.skippedAt(b, false)
}

func (x *IR) skippedAt(b workflow.Base, steps bool) bool {
	s := x.skippedJobsOf()
	if s.whole {
		return true
	}
	if x.workflow == nil {
		return false
	}
	p := b.Primary()
	for _, j := range s.jobs {
		if j.span.Start <= p.Start && p.End <= j.span.End {
			if j.skipped || !steps {
				return j.skipped
			}
			for _, st := range j.steps {
				if st.Start <= p.Start && p.End <= st.End {
					return true
				}
			}
			return false
		}
	}
	return s.all
}

func (x *IR) skippedJobsOf() *skippedJobs {
	s := &x.skipped
	s.once.Do(func() {
		if x.origin != nil {
			s.whole = x.remoteCallSkipped()
		} else if cl := x.callersOf(); cl != nil && cl.Graph() != nil && !x.name.IsZero() {
			s.whole = calledSkipped(cl.Graph(), x.name, map[calls.Node]bool{})
		}
		w := x.workflow
		if w == nil || w.Jobs.Status != workflow.Present {
			return
		}
		s.all = len(w.Jobs.Value.Entries) > 0
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				s.all = false
				continue
			}
			j := je.Value.Value
			skipped := job.AlwaysSkipped(w, &j)
			sj := skippedJob{span: j.Base.Primary(), skipped: skipped}
			if !skipped && j.Steps.Status == workflow.Present {
				for i := range j.Steps.Value.Items {
					st := &j.Steps.Value.Items[i]
					if job.StepAlwaysSkipped(w, &j, st) {
						sj.steps = append(sj.steps, st.Base.Primary())
					}
				}
			}
			s.jobs = append(s.jobs, sj)
			s.all = s.all && skipped
		}
	})
	return s
}

// remoteCallSkipped is whether GitHub skips, in every run, the job of the
// input that the chain of calls to the remote called workflow of x starts
// at: then no job of the chain runs.
func (x *IR) remoteCallSkipped() bool {
	r, ok := x.name.Remote()
	if !ok || r.TopJob == nil {
		return false
	}
	cl := x.callersOf()
	if cl == nil || cl.Graph() == nil {
		return false
	}
	f, ok := cl.Graph().File(calls.InputNode(r.Top))
	if !ok || f.Workflow == nil {
		return false
	}
	return job.AlwaysSkipped(f.Workflow, r.TopJob)
}

// calledSkipped is whether the local workflow name runs only when called
// (its on has workflow_call and no other event), every caller of it is
// among the inputs (CallerCoverageAll), and GitHub skips each call in every
// run: the job that calls it is skipped (job.AlwaysSkipped), or its caller
// is a workflow that is itself called only by such calls. A call that comes
// back to a workflow on the way is not known to be skipped.
func calledSkipped(g *calls.Graph, name calls.Node, seen map[calls.Node]bool) bool {
	if seen[name] {
		return false
	}
	f, ok := g.File(name)
	if !ok || f.Workflow == nil || f.Workflow.On.Status != workflow.Present {
		return false
	}
	on := f.Workflow.On.Value
	if _, call := on.Event(workflow.EventNameWorkflowCall); !call || len(on.Events) != 1 {
		return false
	}
	if g.Coverage(name) != analysis.CallerCoverageAll {
		return false
	}
	seen[name] = true
	defer delete(seen, name)
	for _, c := range g.CallsOf(name) {
		cf, ok := g.File(c.Caller)
		if !ok || cf.Workflow == nil || c.Job == nil {
			return false
		}
		if !job.AlwaysSkipped(cf.Workflow, c.Job) && !calledSkipped(g, c.Caller, seen) {
			return false
		}
	}
	return true
}

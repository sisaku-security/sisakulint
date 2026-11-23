package ir

import (
	"sync"

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
}

// alwaysSkipped is whether GitHub skips, in every run, the job that the
// element b is in: the job whose place has the place of b (b.Primary, the
// outermost alias b is used through), or, for an element of the workflow
// in no job, every job of the workflow. An element of an action.yml is not
// in a job. The job of a remote called workflow is skipped when the job of
// the input that calls it is.
func (x *IR) alwaysSkipped(b workflow.Base) bool {
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
			return j.skipped
		}
	}
	return s.all
}

func (x *IR) skippedJobsOf() *skippedJobs {
	s := &x.skipped
	s.once.Do(func() {
		if x.origin != nil {
			s.whole = x.remoteCallSkipped()
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
			s.jobs = append(s.jobs, skippedJob{span: j.Base.Primary(), skipped: skipped})
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

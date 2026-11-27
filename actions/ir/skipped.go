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
	steps   []cst.Span // the run steps GitHub skips in every run (job.StepAlwaysSkipped)
	fork    bool       // it runs only for a pull request from a fork (job.ForkPullRequestOnly)
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

// forkPullRequestOnly is whether the job that the element b is in runs
// only on pull_request, for a pull request from a fork
// (job.ForkPullRequestOnly): never of an element in no job, of an
// action.yml, or of a remote called workflow.
func (x *IR) forkPullRequestOnly(b workflow.Base) bool {
	s := x.skippedJobsOf()
	if x.workflow == nil {
		return false
	}
	p := b.Primary()
	for _, j := range s.jobs {
		if j.span.Start <= p.Start && p.End <= j.span.End {
			return j.fork
		}
	}
	return false
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
			sj := skippedJob{span: j.Base.Primary(), skipped: skipped, fork: x.origin == nil && job.ForkPullRequestOnly(w, &j)}
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

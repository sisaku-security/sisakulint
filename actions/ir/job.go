package ir

import (
	"slices"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func (x *IR) allJobs() []*Job {
	x.once(SummaryJob, func() {
		var out []*Job
		g := x.callersOf().Graph()
		for _, j := range job.AnalyzeIn(x.workflow, x.table(), g, x.name) {
			o := x.projectJob(j)
			for _, r := range j.CalledContextReads {
				o.calledContextReads = append(o.calledContextReads, calledReadHandle(g, r))
			}
			out = append(out, o)
		}
		x.jobs = out
	})
	return x.jobs
}

// calledReadHandle is the handle on the ${{ }} of r, in the file of its
// node of g: an input, or a remote called workflow.
func calledReadHandle(g *calls.Graph, r job.CalledContextRead) Handle {
	f, _ := g.File(r.Node)
	v := r.Read.Value
	h := Handle{input: r.Node.String(), tree: f.Tree, base: v.Base}
	if rc, ok := r.Node.Remote(); ok {
		h.input, h.query = "", rc.Called.Origin.Query
	}
	h.value, h.span, h.spanned = v.Value, v.Parts[r.Read.Part].Span, true
	h.src, h.exact = v.Source(h.span)
	return h
}

// projectJob is the projection of the job j: its values without their
// positions and pointers, which the handles keep.
func (x *IR) projectJob(j job.Job) *Job {
	o := &Job{
		key:            keyOf(x.paths, x.input, x.tree, j.Job.Base),
		alwaysSkipped:  x.alwaysSkipped(j.Job.Base),
		at:             x.handleOf(j.Job.Base),
		runsOnAt:       x.handleOf(j.Job.Base),
		privilegedOn:   j.PrivilegedOn,
		approval:       j.Approval,
		environment:    j.Environment,
		tokenWrite:     j.TokenWrite,
		secrets:        Secrets{All: j.Secrets.All, Names: j.Secrets.Names},
		writeAll:       j.WriteAll,
		calledOnly:     j.CalledOnly,
		inheritSecrets: j.Job.InheritSecrets,
		calledKind:     j.CalledKind,
		calledRepo:     j.CalledRepo,
		secretsAt:      x.handleOf(j.Job.Base),
	}
	if x.origin != nil {
		// the on of a remote called workflow starts runs in its repository:
		// here it runs on the events of its caller alone, as a workflow of
		// the inputs with workflow_call alone does
		o.privilegedOn = nil
		o.approval, o.environment = job.ApprovalOf(nil, &j.Job)
		for i := range j.InconclusiveLabels {
			j.InconclusiveLabels[i].Dispatch = false // its own workflow_dispatch starts runs in its repository
		}
	}
	if j.Job.Secrets.Status == workflow.Present {
		o.secretsAt = x.handleOf(j.Job.Secrets.Value.Base)
	}
	if j.Job.Uses.Status != workflow.Absent {
		o.usesText = j.Job.Uses.Value.Text()
	}
	o.cacheModeAt = x.handleOf(j.Job.Base)
	on, mode := x.cacheWrite(&j.Job)
	if len(on) > 0 {
		o.cacheWriteOn = on
		o.cacheApproval, _ = job.ApprovalOf(on, &j.Job)
		o.cacheModeText = mode.Value.Text()
		switch {
		case mode.Status == workflow.Present, mode.Value.HasExpr():
			// a ${{ }} the model refuses (ExprNotAllowed) keeps its value
			o.cacheModeAt = x.handleOf(mode.Value.Base)
		case mode.Expr != nil:
			o.cacheModeText = mode.Expr.Text()
			o.cacheModeAt = x.handleOf(mode.Expr.Base)
		}
		x.cacheModeOf[o] = mode
		x.cacheModeJob[o] = &j.Job
	}
	// the jobs of a reusable workflow of another repository it calls are
	// read where the engine runs the rules on them (a remote called
	// workflow)
	if j.Job.RunsOn.Status == workflow.Present {
		o.runsOnAt = x.handleOf(j.Job.RunsOn.Value.Base)
	}
	for _, r := range j.RunnerLabels {
		o.runnerLabels = append(o.runnerLabels, RunnerLabel{Label: r.Label, HasSelfHostedLabel: r.HasSelfHostedLabel, Matrix: r.Matrix, With: r.With, At: x.handleOf(r.At)})
	}
	for _, g := range j.InconclusiveLabels {
		o.inconclusiveLabels = append(o.inconclusiveLabels, InconclusiveLabel{Text: g.Text, Dispatch: g.Dispatch, At: x.handleOf(g.At)})
	}
	o.automaticApproval = x.automaticApprovalOf(slices.Concat(j.PrivilegedOn, o.cacheWriteOn), &j.Job)
	return o
}

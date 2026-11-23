package ir

import (
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/workflow"
	"strings"
)

// allRemoteCalls are the jobs of the workflow that call a reusable
// workflow of another repository (WithComposite), with what
// composite.Reader.ExpandCall reads of them.
func (x *IR) allRemoteCalls() []*RemoteCall {
	x.once(SummaryRemoteCall, func() {
		w := x.workflow
		if x.composites == nil || w == nil {
			return
		}
		var out []*RemoteCall
		for _, je := range w.Jobs.Value.Entries {
			if je.Value.Status != workflow.Present {
				continue
			}
			j := je.Value.Value
			e := x.composites.ExpandCall(x.ctx, &j)
			if len(e.Workflows)+len(e.Unanswered) == 0 {
				continue
			}
			u := j.Uses.Value
			o := &RemoteCall{key: keyOf(x.paths, x.input, x.tree, u.Base), at: x.handleOf(u.Base), usesText: u.AsString(), called: e.Workflows}
			for _, c := range e.Workflows {
				x.projectCalled(o, c)
			}
			for _, n := range e.Unanswered {
				o.unanswered = append(o.unanswered, UnansweredUses{Chain: n.Chain, Asked: n.Asked, Reason: n.Reason})
			}
			out = append(out, o)
		}
		x.remoteCalls = out
	})
	return x.remoteCalls
}

// projectCalled adds the jobs of the workflow c, and their steps, to o.
func (x *IR) projectCalled(o *RemoteCall, c composite.Called) {
	if c.Workflow == nil {
		return
	}
	origin := c.Origin
	pl := place{x: x, origin: &origin}
	for _, a := range job.Analyze(c.Workflow, x.table()) {
		j := a.Job
		cj := CalledJob{ID: j.ID.AsString(), Chain: c.Chain, Query: c.Origin.Query, At: pl.handle(j.Base), CacheModeAt: pl.handle(j.Base)}
		switch m := j.CacheMode; {
		case m.Status == workflow.Present:
			cj.CacheModeText, cj.CacheModeAt = m.Value.Text(), pl.handle(m.Value.Base)
		case m.Expr != nil:
			cj.CacheModeText, cj.CacheModeAt = m.Expr.Text(), pl.handle(m.Expr.Base)
		}
		for _, r := range a.RunnerLabels {
			cj.RunnerLabels = append(cj.RunnerLabels, RunnerLabel{Label: r.Label, HasSelfHostedLabel: r.HasSelfHostedLabel, Matrix: r.Matrix, At: pl.handle(r.At)})
		}
		for _, g := range a.InconclusiveLabels {
			cj.InconclusiveLabels = append(cj.InconclusiveLabels, InconclusiveLabel{Text: g.Text, Dispatch: g.Dispatch, At: pl.handle(g.At)})
		}
		o.jobs = append(o.jobs, cj)
		for _, s := range j.Steps.Value.Items {
			v := CompositeStep{Chain: c.Chain, Query: c.Origin.Query, At: pl.handle(s.Base)}
			if su := s.Uses; su.Status == workflow.Present {
				v.UsesText = su.Value.AsString()
				kind := su.Value.Kind
				if kind == workflow.UsesFolded {
					kind = su.Value.Folded
				}
				switch kind {
				case workflow.UsesRemote:
					v.Repo, v.Ref = su.Value.Owner.Text+"/"+su.Value.Repo.Text, su.Value.Ref.Text
					if runs := su.Value.Actions(); len(runs) == 1 {
						v.Path = runs[0].Path.String()
					}
					v.RunUses = runUsesOf(su.Value)
				case workflow.UsesDocker:
					ref := workflow.ImageReference{Name: su.Value.Image, Tag: su.Value.Tag, Digest: su.Value.Digest}
					v.Images = appendImageAt(v.Images, ref, strings.TrimPrefix(v.UsesText, "docker://"), false, pl.handle(su.Value.Base))
				}
			}
			o.steps = append(o.steps, v)
		}
	}
}

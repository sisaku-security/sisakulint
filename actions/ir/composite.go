package ir

import (
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/attacker"
	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/prcode"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// allCompositeCalls are the steps of the input that run an action of the
// inputs or of another repository (WithComposite): of each job of a
// workflow, and of an action.yml, whose ./ the reader does not follow.
func (x *IR) allCompositeCalls() []*CompositeCall {
	x.once(SummaryCompositeCall, func() {
		if x.composites == nil {
			return
		}
		var out []*CompositeCall
		each := func(steps []workflow.Step, inAction bool, evs []analysis.EventActivity, jobIf ...attacker.PlacedIf) {
			for i := range steps {
				s := &steps[i]
				if s.Uses.Status != workflow.Present {
					continue
				}
				e := x.composites.Expand(x.ctx, s, inAction)
				if len(e.Actions)+len(e.Unanswered) == 0 {
					continue
				}
				c := x.projectCompositeCall(s, e)
				c.privilegedOn = taint.Filter(x.table(), evs, append(slices.Clone(jobIf), attacker.StepIf(s.If))...)
				out = append(out, c)
			}
		}
		if w := x.workflow; w != nil {
			evs := taint.EventsOf(w, job.Privileged())
			if got, cov := x.callersOf().Events(x.name, job.Privileged(), false); cov == analysis.CallerCoverageAll {
				evs = got
			}
			for _, j := range w.Jobs.Value.Entries {
				job := j.Value.Value
				each(job.Steps.Value.Items, false, evs, attacker.JobIfs(w, &job)...)
			}
		}
		if a := x.action; a != nil && a.Runs.Status == workflow.Present && a.Runs.Value.Kind == workflow.RunsComposite {
			evs := taint.EventsAll(job.Privileged())
			if got, cov := x.callersOf().Events(x.name, job.Privileged(), false); cov == analysis.CallerCoverageAll {
				evs = got
			}
			each(a.Runs.Value.Steps.Value.Items, true, evs)
		}
		x.compositeCalls = out
	})
	return x.compositeCalls
}

// projectCompositeCall is the summary of the step s, which runs what e
// reads.
func (x *IR) projectCompositeCall(s *workflow.Step, e composite.Expansion) *CompositeCall {
	u := s.Uses.Value
	c := &CompositeCall{key: keyOf(x.paths, x.input, x.tree, u.Base), at: x.handleOf(u.Base), usesText: u.AsString()}
	for _, a := range e.Actions {
		v := CompositeAction{Chain: a.Chain, File: a.File, Input: a.Origin.Input, Query: a.Origin.Query, Substituted: a.Substituted}
		if a.Metadata != nil {
			v.At = originHandle(a.Origin, a.Metadata.Base)
			if img := a.Metadata.Runs.Value.Image; a.Metadata.Runs.Status == workflow.Present && img.Status == workflow.Present {
				if ref, ok := workflow.DockerImageOf(img.Value); ok {
					v.Images = appendImageAt(v.Images, ref, img.Value.Text()[len("docker://"):], false, originHandle(a.Origin, img.Value.Base))
				}
			}
		}
		c.actions = append(c.actions, v)
	}
	for _, st := range e.Steps {
		v := CompositeStep{Chain: st.Chain, Input: st.Origin.Input, Query: st.Origin.Query, Substituted: st.Substituted, At: originHandle(st.Origin, st.Step.Base)}
		if su := st.Step.Uses; su.Status == workflow.Present {
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
				v.Images = appendImageAt(v.Images, ref, strings.TrimPrefix(v.UsesText, "docker://"), false, originHandle(st.Origin, su.Value.Base))
			}
		}
		c.steps = append(c.steps, v)
	}
	for _, n := range e.Unanswered {
		c.unanswered = append(c.unanswered, UnansweredUses{Chain: n.Chain, Asked: n.Asked, Reason: n.Reason})
	}
	return c
}

// originHandle is the handle on the element b of the file o: an input, or
// the value of a fact.
func originHandle(o composite.Origin, b workflow.Base) Handle {
	return Handle{input: o.Input.String(), query: o.Query, tree: o.Tree, base: b, exact: true}
}

// inner reads what a step of the input runs, for actions/prcode: nil
// without a reader. The ./ of a step of an action.yml is not followed.
func (x *IR) inner() prcode.Inner {
	if x.composites == nil {
		return nil
	}
	return func(s *workflow.Step) composite.Expansion { return x.composites.Expand(x.ctx, s, x.action != nil) }
}

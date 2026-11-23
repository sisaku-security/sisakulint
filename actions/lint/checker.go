package lint

import (
	"context"
	"github.com/gh-intel/sisakulint/actions/analysis"
	"slices"

	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/composite"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/taint"
)

// checker runs the rules of reg on the files of a run, one file at a time,
// and puts what they report in rep.
type checker struct {
	reg     *Registry
	in      Inputs
	rec     *facts.Recorder
	st      *runState
	callers func() *taint.Callers
	rep     *Report
	fps     map[Fingerprint]bool
	skipped int
	reader  *composite.Reader // the reusable workflows of other repositories, for unansweredGaps
	// barriers are what the attacker of the run gets past: a run that adds
	// attackers does not run the rules that read an outsider alone
	barriers analysis.BarrierPasses
}

// checkFile runs on the IR x the rules that target its file: the input, or,
// when remote is set, the remote called workflow remote, which the chain
// from the job remote.TopJob of the input reaches. What the rules report in
// a remote called workflow is reported at the uses of that job (relocate).
func (k *checker) checkFile(ctx context.Context, x *ir.IR, input Input, remote *calls.RemoteCalled) {
	tree, wf, action, kind := input.Tree, input.Workflow, input.ActionMetadata, input.InputKind
	if remote != nil {
		tree, wf, action, kind = remote.Called.Origin.Tree, remote.Called.Workflow, nil, InputKindWorkflow
	}
	for _, rule := range k.reg.rules {
		m := rule.Meta()
		if !slices.Contains(m.Targets, kind) || !k.barriers.IsZero() && k.reg.readsOutsider(m.ID) {
			continue
		}
		if ctx.Err() != nil {
			k.skipped++
			continue
		}
		c := &RuleContext{input: input, tree: tree, workflow: wf, action: action,
			Resolver: k.rec, inputs: k.in, repo: k.in.Repo, access: x.RuleAccess(), run: k.st, rule: m.ID,
			pullRequestTarget: pullRequestTargetKinds(m, wf), appChecks: appChecksKinds(m, wf)}
		if remote != nil {
			c.remoteQuery = remote.Called.Origin.Query
		}
		err := check(ctx, rule, c)
		c.done = true
		if err != nil {
			k.st.fail(m.ID, input.Name, "%v", err)
			continue
		}
		p := pass{st: k.st, rule: rule, m: m, input: input, inputs: k.in, rec: k.rec, callers: k.callers, quality: k.reg.IsQuality(m.ID), barriers: k.barriers}
		if p.quality && len(c.gaps) > 0 {
			p.fail("a quality rule reports an inconclusive place")
			c.gaps = nil
		}
		if remote == nil {
			c.gaps = append(c.gaps, unansweredGaps(ctx, m, k.in, k.callers().Graph(), input, k.reader)...)
		}
		if remote != nil {
			at := At(input, remote.TopJob.Uses.Value.Base)
			for i := range c.found {
				c.found[i] = relocate(c.found[i], remote, at)
			}
			for i := range c.gaps {
				c.gaps[i] = relocateGap(c.gaps[i], remote, at)
			}
		}
		paths := ir.NewPaths()
		for _, g := range p.inconclusiveOf(paths, c.gaps) {
			if k.fps[g.Fingerprint] {
				k.st.fail(m.ID, input.Name, "the finding %s is reported twice", g.Fingerprint)
				continue
			}
			k.fps[g.Fingerprint] = true
			k.rep.Findings = append(k.rep.Findings, g)
		}
		budget := newFixBudget(c.found)
		var results []Finding
		for _, f := range c.found {
			if res, ok := p.finish(ctx, paths, &budget, f); ok {
				if k.fps[res.Fingerprint] {
					k.st.fail(m.ID, input.Name, "the finding %s is reported twice", res.Fingerprint)
					continue
				}
				k.fps[res.Fingerprint] = true
				results = append(results, res)
			}
		}
		if remote == nil {
			p.checkApplied(ctx, identitiesOf(ctx, k.in, k.rec, c.found), results)
		}
		if p.quality {
			for _, f := range results {
				k.rep.QualityFindings = append(k.rep.QualityFindings, QualityFinding{FindingDraft: f.FindingDraft, Certainty: f.Certainty,
					Fingerprint: f.Fingerprint, Consequence: f.Consequence, Remedy: f.Remedy})
			}
			continue
		}
		k.rep.Findings = append(k.rep.Findings, results...)
	}
}

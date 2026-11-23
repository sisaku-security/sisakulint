package ir

import (
	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/calls"
	"github.com/gh-intel/sisakulint/actions/job"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

func (x *IR) allSecretsContextReads() []*SecretsContextRead {
	x.once(SummarySecretsContextRead, func() {
		var out []*SecretsContextRead
		if w := x.workflow; w != nil {
			calledOnly := job.CalledOnly(w)
			cov, callers := analysis.CallerCoverageNone, []InheritCaller(nil)
			if calledOnly {
				cov, callers = x.inheritCallers()
			}
			for _, r := range job.SecretsContextReads(w) {
				p := r.Value.Parts[r.Part]
				out = append(out, &SecretsContextRead{key: keyOf(x.paths, x.input, x.tree, r.Value.Base),
					alwaysSkipped: x.alwaysSkipped(r.Value.Base), at: x.spanOf(r.Value, p.Span),
					text: r.Text, calledOnly: calledOnly, callerCoverage: cov, inheritCallers: callers})
			}
		}
		x.secretsContextReads = out
	})
	return x.secretsContextReads
}

// inheritCallers are how much of the callers of x's workflow the inputs
// have, and those of its jobs that call it with secrets: inherit (a called
// job that reads the secrets context gets every secret of such a caller).
func (x *IR) inheritCallers() (analysis.CallerCoverage, []InheritCaller) {
	cl := x.callersOf()
	if cl == nil || cl.Graph() == nil {
		return analysis.CallerCoverageNone, nil
	}
	g := cl.Graph()
	var out []InheritCaller
	for _, c := range g.CallsOf(x.name) {
		if c.Job == nil || !c.Job.InheritSecrets || !mayHaveEvery(g, c.Caller, map[calls.Node]bool{x.name: true}) {
			continue
		}
		f, _ := g.File(c.Caller)
		base := c.Job.Base
		if c.Job.Secrets.Status == workflow.Present {
			base = c.Job.Secrets.Value.Base
		}
		at := Handle{input: c.Caller.String(), tree: f.Tree, base: base, exact: true}
		if r, ok := c.Caller.Remote(); ok {
			at.input, at.query = "", r.Called.Origin.Query
		}
		out = append(out, InheritCaller{Caller: c.Caller, Job: c.Job.ID.AsString(), At: at})
	}
	return g.Coverage(x.name), out
}

// mayHaveEvery is whether the secrets context of the workflow of n, which
// calls with secrets: inherit, may have every secret of the repository: a
// workflow that runs on an event of its own (not only workflow_call); a
// workflow only called, through a call of it with secrets: inherit from a
// workflow that may have every secret, or with a value under secrets: that
// reads the secrets context without a name (the value has every secret,
// the caller's whole secrets context as one value), or when the inputs do not
// have all its callers or have none (CallerCoverage not All, as for the
// called workflow itself). A caller that passes only named secrets gives n
// only those (a run showed the inner toJSON(secrets) getting them alone). A
// remote called workflow runs only for its one caller. stack holds the
// workflows being read: a loop of calls, which GitHub refuses, gives
// nothing.
func mayHaveEvery(g *calls.Graph, n calls.Node, stack map[calls.Node]bool) bool {
	if stack[n] {
		return false
	}
	f, ok := g.File(n)
	if !ok || f.Workflow == nil {
		return true
	}
	if _, remote := n.Remote(); !remote && !job.CalledOnly(f.Workflow) {
		return true
	}
	if g.Coverage(n) != analysis.CallerCoverageAll {
		return true
	}
	stack[n] = true
	defer delete(stack, n)
	for _, c := range g.CallsOf(n) {
		switch {
		case c.Job == nil:
		case c.Job.InheritSecrets:
			if mayHaveEvery(g, c.Caller, stack) {
				return true
			}
		default:
			for _, v := range job.MapValues(c.Job.Secrets) {
				if len(job.SecretsContextReadsIn(v)) > 0 {
					return true
				}
			}
		}
	}
	return false
}

func (x *IR) allSecretParts() []*SecretPart {
	x.once(SummarySecretPart, func() {
		var out []*SecretPart
		if w := x.workflow; w != nil {
			for _, s := range job.SecretParts(w) {
				p := s.Value.Parts[s.Part]
				var via []SecretPartVia
				for _, v := range s.Via {
					via = append(via, SecretPartVia{Job: v.Job, Output: v.Output, At: x.spanOf(v.Value, v.Value.Parts[v.Part].Span)})
				}
				out = append(out, &SecretPart{key: keyOf(x.paths, x.input, x.tree, s.Value.Base),
					alwaysSkipped: x.alwaysSkipped(s.Value.Base), at: x.spanOf(s.Value, p.Span),
					secrets: s.Secrets, via: via, text: s.Value.Text()[p.Span.Start:p.Span.End]})
			}
		}
		x.secretParts = out
	})
	return x.secretParts
}

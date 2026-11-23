package ir

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/job"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// requestSiteOf is the projection of r, a request of the run s whose text
// is text, with what the job of s's runs-on and services are.
func (x *IR) requestSiteOf(s taint.Sink, r taint.RequestSite, text string) RequestSite {
	o := RequestSite{Command: r.Command, Occurrence: r.Occurrence, EnterpriseToken: r.EnterpriseToken,
		Destination: r.Destination.Kind, DestinationHost: r.Destination.Host, At: x.spanOf(s.Value, r.DestinationSpan), CommandAt: x.spanOf(s.Value, r.CommandSpan)}
	refs := func(as []taint.CommandArgument) []RequestRef {
		var out []RequestRef
		for _, a := range as {
			at := x.spanOf(s.Value, a.Span)
			out = append(out, RequestRef{Path: expr.PathString(a.Path), Ref: x.exprRefOf(a.Ref, text[a.Span.Start:a.Span.End], at), At: at})
		}
		return out
	}
	o.HostRefs, o.PathRefs = refs(r.HostRefs), refs(r.PathRefs)
	for _, c := range r.Secrets {
		o.Secrets = append(o.Secrets, CarriedSecret{Name: c.Name, Token: c.Token, Whole: c.Whole, At: x.spanOf(s.Value, c.Span)})
	}
	if r.Destination.Kind == analysis.DestinationNamed {
		o.DestinationPath = expr.PathString(r.Destination.Path)
		o.DestinationRef = x.exprRefOf(r.Destination.Ref, o.DestinationPath, o.At)
	}
	o.RunnerHosting, o.RunnerLabels, o.ServiceNames = runnerOf(s.Job)
	return o
}

// runnerOf is who runs the machine of j, the labels of its runs-on and
// the names of its services; nothing known in an action.yml (j nil).
func runnerOf(j *workflow.Job) (analysis.RunnerHosting, []string, []string) {
	if j == nil {
		return analysis.RunnerHostingUnknown, nil, nil
	}
	return job.Hosted(*j), job.RunnerLabelTexts(*j), job.ServiceNames(*j)
}

func (x *IR) allRequestActionSites() []*RequestActionSite {
	x.once(SummaryRequestActionSite, func() {
		var out []*RequestActionSite
		for _, v := range taint.RequestActionSites(x.callersOf(), x.name, x.workflow, x.action) {
			text := v.Value.Text()
			o := &RequestActionSite{key: keyOf(x.paths, x.input, x.tree, v.Value.Base), at: x.handleOf(v.Value.Base), action: v.Action, input: v.Input}
			refs := func(rs []taint.ExprRef) []ExprRef {
				var out []ExprRef
				for _, r := range rs {
					out = append(out, x.exprRefOf(r, text[r.Span.Start:r.Span.End], x.spanOf(v.Value, r.Span)))
				}
				return out
			}
			o.hostRefs, o.pathRefs = refs(v.HostRefs), refs(v.PathRefs)
			for _, sr := range v.Secrets {
				o.secrets = append(o.secrets, CarriedSecret{Name: sr.Name, Token: sr.Token, Whole: sr.Whole})
			}
			o.runnerHosting, o.runnerLabels, _ = runnerOf(v.Job)
			out = append(out, o)
		}
		x.requestActionSites = out
	})
	return x.requestActionSites
}

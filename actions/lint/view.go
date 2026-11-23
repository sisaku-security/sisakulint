package lint

import (
	"context"
	"github.com/sisaku-security/sisakulint/actions/facts"

	"github.com/sisaku-security/sisakulint/actions/ir"
)

// newIR makes the IR of an input; the tests replace it to see the IRs a
// run makes.
var newIR = ir.New

// Name is the name of the input the rule checks.
func (c *RuleContext) Name() facts.InputPath { return c.input.Name }

// Repo is the repository the inputs are of, or the zero Repo when its
// name was not given: what a fact about the repository names.
func (c *RuleContext) Repo() facts.Repo { return c.repo }

// ActionMetadata is whether the input the rule checks is an action
// metadata file (an action.yml), not a workflow.
func (c *RuleContext) ActionMetadata() bool { return c.action != nil }

// RemoteCalled is whether the file the rule checks is a remote called
// workflow (a reusable workflow of another repository, read for a job of
// the input), not the input.
func (c *RuleContext) RemoteCalled() bool { return c.remoteQuery != nil }

// InFile is whether the handle s is in the file the rule checks: the
// input, or the remote called workflow (RemoteCalled).
func (c *RuleContext) InFile(s ir.Handle) bool {
	if c.remoteQuery != nil {
		q, _ := s.Fact()
		return q == c.remoteQuery
	}
	return s.InputName() == c.input.Name.String()
}

// At is where the handle s of a summary is: in the input, or in another
// input of the run (the with of a caller, ir.ExprRef.With), or in a file
// that is the value of a fact (a step of a remote composite action,
// ir.CompositeStep), which a finding has only in Evidence and Related.
func (c *RuleContext) At(s ir.Handle) Location {
	b, sp, exact, spanned := s.Locate()
	if q, t := s.Fact(); q != nil {
		// a file that is the value of a fact (a remote action.yml): for
		// Evidence and Related, not where a finding is
		l := factAt(q, t, b)
		if spanned {
			l.Span, l.Exact = sp, exact
		}
		return l
	}
	in := c.input
	if n := s.InputName(); n != "" && n != c.input.Name.String() && c.inputs != nil {
		if name, err := facts.CleanInputPath(n); err == nil {
			if x, st := c.inputs.Lookup(name); st == LookupFound {
				in = x
			}
		}
	}
	if !spanned {
		return At(in, b)
	}
	return AtSpan(in, b, sp, exact)
}

// ViewRule is a rule that reads the IR through the reader R of a view.
type ViewRule[R any] interface {
	Meta() Meta
	Check(ctx context.Context, c *RuleContext, r R) error
}

// WithView is the rule r, which reads what v declares: its Meta has the
// fields of v as ViewFields, and its Check gets the reader of v on the IR of
// the input.
func WithView[R any](r ViewRule[R], v ir.View[R]) Rule { return viewRule[R]{r, v} }

type viewRule[R any] struct {
	r ViewRule[R]
	v ir.View[R]
}

func (x viewRule[R]) Meta() Meta {
	m := x.r.Meta()
	m.ViewFields = x.v.Fields()
	return m
}

func (x viewRule[R]) Check(ctx context.Context, c *RuleContext) error {
	return x.r.Check(ctx, c, x.v.Reader(c.access))
}

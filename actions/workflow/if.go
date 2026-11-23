package workflow

import (
	"strings"
	"unicode"

	"github.com/sisaku-security/sisakulint/actions/expr"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// IfForm is how an if is written (WorkflowTemplateConverter.ConvertToIfCondition).
type IfForm uint8

const (
	IfExpr  IfForm = iota // one ${{ }}, with at most white space around it; in an action.yml, with nothing around it (exactly ${{ 'x' }} is IfBare)
	IfBare                // no ${{ }}: the whole value, trimmed, is the expression; or exactly ${{ 'x' }}: x, trimmed
	IfMixed               // text and ${{ }}: GitHub makes a string of them, which is true
	IfEmpty               // nothing: GitHub reads it as success()
)

var ifFormNames = [...]string{"IfExpr", "IfBare", "IfMixed", "IfEmpty"}

func (f IfForm) String() string { return ifFormNames[f] }

// If is an if conditional. Expr is the expression it is read as, for IfExpr
// and IfBare; its Tree is nil on a syntax error. Wrapping it in
// success() && (...) is left to its readers. Form, not String.IsExpr, says
// how GitHub reads an if. When an if is exactly ${{ 'x' }}, Expr is read
// from the string x (Folded): the spans of its Tree are in x, and InValue
// maps each of them to the whole value.
type If struct {
	String
	Form IfForm
	Expr *Part
}

// actionBareIf are the contexts the runner allows in the if of an
// action.yml's step beyond those of the schema's step-if, when the if has
// no ${{ }} (PipelineTemplateConverter.ConvertToIfCondition).
var actionBareIf = expr.Names{}.WithContext(expr.ContextNeeds).WithContext(expr.ContextVars)

func (r *reader) condition(e *entry, p pos) Field[If] {
	s := r.str(e, p)
	f := Field[If]{Status: s.Status, Key: s.Key, Expr: s.Expr}
	if s.Status == Absent || s.Value.Node == (cst.Node{}) {
		return f
	}
	c := If{String: s.Value}
	_, folded := c.literal()
	bp := s.Value.pos(p.in(e.def))
	if r.action {
		bp.names = bp.names.Union(actionBareIf)
	}
	switch {
	// GitHub folds exactly ${{ 'x' }} into the string x and reads the
	// string as the expression: the server and the runner for the if of a
	// job and of a step of a workflow, the runner for an action.yml's
	// (TemplateReader.ParseScalar, ConvertToIfCondition).
	case folded:
		c.bare(r, c.AsString(), bp)
	// The runner does not trim the white space around the expression of an
	// action.yml's if, and makes a string of it.
	case c.Parts != nil && (!r.action && c.IsExpr() || len(c.Parts) == 1 && c.Parts[0].Expr):
		c.Form = IfExpr
		for i := range c.Parts {
			if c.Parts[i].Expr {
				c.Expr = &c.Parts[i]
			}
		}
	case c.Parts != nil:
		c.Form = IfMixed
	default:
		c.bare(r, c.AsString(), bp)
	}
	f.Value = c
	return f
}

// Folded is whether Expr is read from the string of an if that is exactly
// ${{ 'x' }}: the spans of its Tree are in the string x, not in the value,
// so a place in the expression is the whole value (Part.InValue).
func (c If) Folded() bool { return c.Form == IfBare && c.Expr != nil && c.Expr.folded }

// bare reads text, trimmed, as the expression of c: IfBare, or
// IfEmpty when nothing is left. text is the value, or the string a
// folded ${{ 'x' }} makes, whose spans are not in the input; the Part is
// then the whole value (Part.InValue), and its errors are reported at the
// whole value.
func (c *If) bare(r *reader, text string, p pos) {
	trimmed := strings.TrimLeftFunc(text, unicode.IsSpace)
	start := len(text) - len(trimmed)
	trimmed = strings.TrimRightFunc(trimmed, unicode.IsSpace)
	if trimmed == "" {
		c.Form = IfEmpty
		return
	}
	c.Form = IfBare
	_, folded := c.literal()
	part := Part{Expr: true, Span: expr.Span{Start: start, End: start + len(trimmed)}}
	if folded {
		part = Part{Expr: true, Span: expr.Span{End: len(c.Text())}, folded: true}
	}
	part.Inner = part.Span
	tree, errs := expr.Parse(trimmed)
	part.Tree = tree
	for _, err := range errs {
		err.Span = part.InValue(err.Span)
		part.Errs = append(part.Errs, err)
		sp, _ := c.Source(err.Span)
		if folded {
			sp = c.Node.ContentSpan()
		}
		r.report(ExprSyntax, sp, p, "%s", err.Msg)
	}
	if tree != nil {
		for _, err := range expr.CheckNames(tree, p.names) {
			sp, _ := c.Source(part.InValue(err.Span))
			if folded {
				sp = c.Node.ContentSpan()
			}
			r.report(ExprSyntax, sp, p, "%s", err.Msg)
		}
	}
	c.Expr = &part
}

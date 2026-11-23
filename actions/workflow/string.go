package workflow

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/expr"
	cst "github.com/sisaku-security/sisakulint/yaml/cst/v1"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/scalar"
)

// String is a scalar's value with the ${{ }} in it.
type String struct {
	Base
	Value scalar.Value
	// Parts are the text and the expressions of the value, in order. It is
	// nil when the value has no ${{.
	Parts []Part
	lit   litKind
	bad   bool // a problem of the YAML value or of its format() was reported
}

// Part is text or an expression of a String. Span and Inner are in the
// value; the spans of Tree are in the expression, and InValue maps them
// into the value.
type Part struct {
	Expr  bool
	Span  expr.Span // an expression's Span includes ${{ and }}
	Inner expr.Span
	Tree  expr.Node    // nil on a syntax error
	Errs  []expr.Error // spans in the value
	// folded is whether Tree is read from the string that an if of exactly
	// ${{ 'x' }} folds into (If.Folded): the spans of Tree are in that
	// string, not in the value, so Span and Inner are the whole value.
	folded bool
}

// InValue maps a span of the Tree into the value; for a Part whose Tree is
// read from a folded string (If.Folded), to the whole value.
func (p Part) InValue(s expr.Span) expr.Span {
	if p.folded {
		return p.Span
	}
	return expr.Span{Start: p.Inner.Start + s.Start, End: p.Inner.Start + s.End}
}

func (s String) Text() string { return s.Value.String() }

// IsExpr reports whether the value is one expression, with at most white
// space around it (such an if is an expression).
func (s String) IsExpr() bool {
	n := 0
	for _, p := range s.Parts {
		switch {
		case p.Expr:
			n++
		case strings.TrimSpace(s.Text()[p.Span.Start:p.Span.End]) != "":
			return false
		}
	}
	return n == 1
}

// Source maps a span of the value to the input. exact is as for
// scalar.Value.Source: false when the span cuts what an escape or a line
// folding made.
func (s String) Source(sp expr.Span) (span cst.Span, exact bool) {
	return s.Value.Source(sp.Start, sp.End)
}

// AsString is the string GitHub makes of the value: a null is empty, a
// bool is true or false, a number is written the shortest way (the
// template reader's ToString), and a value that is exactly ${{ 'x' }} is x
// (the reader folds it). Text is the value as YAML reads it.
func (s String) AsString() string {
	if l, ok := s.literal(); ok {
		return l
	}
	switch t := s.Text(); s.lit {
	case litNull:
		return ""
	case litBool:
		b, _ := scalar.Bool(t)
		return strconv.FormatBool(b)
	case litNumber:
		if n, ok := scalar.Int(t); ok {
			return strconv.FormatInt(n, 10)
		}
		f, _ := scalar.Float(t)
		if f == math.Trunc(f) && math.Abs(f) < 1e15 {
			return strconv.FormatInt(int64(f), 10)
		}
		return strconv.FormatFloat(f, 'G', 15, 64)
	}
	return s.Text()
}

// literal is the string of a value that is exactly one ${{ }} of a string
// literal, with nothing around it (TemplateReader.ParseScalar folds only
// a single segment).
func (s String) literal() (string, bool) {
	if len(s.Parts) != 1 {
		return "", false
	}
	l, ok := s.Parts[0].Tree.(*expr.Literal)
	if !ok || l.Kind != expr.LitString {
		return "", false
	}
	return l.Str, true
}

// HasExpr is whether the template reader reads the value as an expression:
// it has a ${{ }} and is not a folded literal, which GitHub reads as its
// string (AsString).
func (s String) HasExpr() bool {
	_, lit := s.literal()
	return s.Parts != nil && !lit
}

// broken is whether a ${{ }} of the value has a syntax error, or its tag
// or its format() was reported.
func (s String) broken() bool {
	if s.bad {
		return true
	}
	for _, p := range s.Parts {
		if len(p.Errs) > 0 {
			return true
		}
	}
	return false
}

// newString reads the scalar n. Syntax errors of its expressions are
// reported.
func (r *reader) newString(n cst.Node, p pos) String { return r.readString(n, p, false) }

// newKey reads the scalar n, a key of a mapping, where a key that is
// exactly the directive insert is no expression.
func (r *reader) newKey(n cst.Node, p pos) String { return r.readString(n, p, true) }

func (r *reader) readString(n cst.Node, p pos, key bool) String {
	v, _ := scalar.Decode(n)
	if r.read != nil {
		r.read[n] = true
	}
	s := String{Base: Base{Node: n, Via: p.via}, Value: v, lit: r.litOf(n)}
	text := v.String()
	s.bad = r.tagProblem(n) != "" // reported by checkTags
	if !strings.Contains(text, "${{") {
		return s
	}
	segs, errs := expr.Scan(text)
	for _, g := range segs {
		part := Part{Expr: g.Expr, Span: g.Span, Inner: g.Inner}
		for _, e := range errs {
			if e.Span.Start >= g.Span.Start && e.Span.Start < g.Span.End {
				part.Errs = append(part.Errs, e)
			}
		}
		if g.Expr && len(part.Errs) == 0 {
			tree, perrs := expr.Parse(text[g.Inner.Start:g.Inner.End])
			part.Tree = tree
			for _, e := range perrs {
				e.Span = part.InValue(e.Span)
				part.Errs = append(part.Errs, e)
			}
		}
		for _, e := range part.Errs {
			sp, _ := s.Source(e.Span)
			r.report(ExprSyntax, sp, p, "%s", e.Msg)
		}
		if part.Tree != nil && p.exprAllowed() && !(key && len(segs) == 1 && insertDirective(part.Tree)) {
			// GitHub rejects these too, but the tree is still the
			// expression the author wrote: it stays, and so does the
			// value's status, so that the rules read what was written.
			for _, e := range expr.CheckNames(part.Tree, p.names) {
				sp, _ := s.Source(part.InValue(e.Span))
				r.report(ExprSyntax, sp, p, "%s", e.Msg)
			}
		}
		s.Parts = append(s.Parts, part)
	}
	if s.HasExpr() && len(s.Parts) > 1 && formatLen(text, s.Parts) > expr.MaxLength {
		r.report(ExprSyntax, n.ContentSpan(), p, "exceeded max expression length %d", expr.MaxLength)
		s.bad = true
	}
	return s
}

// insertDirective is whether tree is the directive insert, which the
// template reader matches before it parses an expression
// (TemplateReader.MatchesDirective, compared exactly). The reader allows
// the directive only as a whole key; elsewhere it is an error, which the
// name insert, no context, reports.
func insertDirective(tree expr.Node) bool {
	c, ok := tree.(*expr.Context)
	return ok && c.Name == "insert"
}

// formatLen is the length of the format() expression the template reader
// makes of text and expressions (TemplateReader.ParseScalar): the text,
// with ' { } doubled, in one string literal, then the expressions.
func formatLen(text string, parts []Part) int {
	n := len("format('')")
	for _, p := range parts {
		seg := text[p.Span.Start:p.Span.End]
		if p.Expr {
			n += len(", ") + expr.UTF16Len(strings.TrimSpace(text[p.Inner.Start:p.Inner.End])) + len("{0}")
			continue
		}
		n += expr.UTF16Len(seg) + strings.Count(seg, "'") + strings.Count(seg, "{") + strings.Count(seg, "}")
	}
	return n
}

// tagProblem is what YamlObjectReader.AllowLiteral says of the explicit
// tag of the scalar n, other than !!str: the scalar must be plain, and its
// value one of the tag's. It is "" when there is nothing to say.
func (r *reader) tagProblem(n cst.Node) string {
	t, ok := scalar.Explicit(n, r.dirs)
	if !ok || t == scalar.TagStr {
		return ""
	}
	if n.Style() != cst.Plain {
		return fmt.Sprintf("a quoted or block scalar is not valid with the tag %s", t)
	}
	v, _ := scalar.Decode(n)
	text := v.String()
	switch t {
	case scalar.TagBool:
		_, ok = scalar.Bool(text)
	case scalar.TagInt:
		_, ok = scalar.Int(text)
	case scalar.TagFloat:
		_, ok = scalar.Float(text)
	case scalar.TagNull:
		ok = scalar.PlainTag(text) == scalar.TagNull
	default:
		return fmt.Sprintf("unexpected tag %s", t)
	}
	if !ok {
		return fmt.Sprintf("the value %q is invalid for the type %s", text, t)
	}
	return ""
}

// checkUnread reads the ${{ }} of the scalars under n that the model did
// not read, such as those of elements it keeps as nodes: GitHub parses
// every expression of the document, and rejects the file for a syntax
// error in any of them.
func (r *reader) checkUnread(n cst.Node) {
	if n.Kind() == cst.NodeScalar {
		if !r.read[n] && strings.Contains(string(n.Bytes()), "{{") {
			r.newString(n, pos{})
		}
		return
	}
	for e := range n.Children() {
		if c, ok := e.Node(); ok {
			r.checkUnread(c)
		}
	}
}

// checkTags reports tagProblem for every scalar under n, whether or not
// the model reads it: GitHub reads the tags of the whole document.
func (r *reader) checkTags(n cst.Node) {
	if n.Kind() == cst.NodeScalar {
		if msg := r.tagProblem(n); msg != "" {
			r.report(InvalidValue, n.ContentSpan(), pos{}, "%s", msg)
		}
		return
	}
	for e := range n.Children() {
		if c, ok := e.Node(); ok {
			r.checkTags(c)
		}
	}
}

// pos is where s is, for a diagnostic about it: its aliases, and the
// contexts and the functions allowed as at p.
func (s String) pos(p pos) pos { return pos{via: s.Via, names: p.names} }

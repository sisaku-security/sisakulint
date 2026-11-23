package ir

import (
	"errors"

	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/scalar"
)

// Handle is a handle on the YAML of a summary: an element, or a span in
// the value of a scalar. It makes where a finding is (the engine's
// lint.Context.At) and the edits of a fix, which are reversible edits of
// yaml/cst/v1/edit; it has no way to read the text.
type Handle struct {
	ed      *edit.Editor
	input   string      // the name of the input it is in, as the engine names it; "" in the value of a fact
	query   facts.Query // the fact whose value is the file it is in (a remote action.yml); nil in an input
	tree    *cst.Tree
	base    workflow.Base
	value   scalar.Value // when spanned: the scalar span is in
	span    expr.Span    // in the value
	src     cst.Span     // where span is in the bytes of base
	exact   bool
	spanned bool
}

// handleOf is the handle on the element b.
func (x *IR) handleOf(b workflow.Base) Handle {
	if x.origin != nil {
		return Handle{ed: &x.editor, query: x.origin.Query, tree: x.tree, base: b, exact: true}
	}
	return Handle{ed: &x.editor, input: x.input, tree: x.tree, base: b, exact: true}
}

// spanOf is the handle on the span sp of the value of v (workflow.String.Source).
func (x *IR) spanOf(v workflow.String, sp expr.Span) Handle {
	s := x.handleOf(v.Base)
	s.value, s.span, s.spanned = v.Value, sp, true
	s.src, s.exact = v.Source(sp)
	return s
}

// Locate is what the engine makes a location of: the element, and the
// span in it when spanned is true, exact or only near
// (workflow.String.Source). The rules do not call it (the test of
// actions/rules that they touch no model).
func (s Handle) Locate() (b workflow.Base, sp cst.Span, exact, spanned bool) {
	return s.base, s.src, s.exact, s.spanned
}

// InputName is the name of the input the handle is in: the input of the
// IR, or another, the input of a caller (ExprRef.With); "" in the value
// of a fact (Fact).
func (s Handle) InputName() string { return s.input }

// Fact is the fact whose value is the file the handle is in, and the tree
// of that file: an action.yml of another repository (CompositeStep); nil
// for a handle in an input. The rules do not call it, as Locate.
func (s Handle) Fact() (facts.Query, *cst.Tree) {
	if s.query == nil {
		return nil, nil
	}
	return s.query, s.tree
}

// Replace is the edit that writes text in place of the span.
func (s Handle) Replace(text string) (edit.Edit, error) {
	if !s.spanned {
		return edit.Edit{}, errors.New("the handle is not on a span of a value")
	}
	return edit.Replace(s.value, s.span.Start, s.span.End, text)
}

// CommentAtEnd is the edit that puts the comment text at the end of the
// line the element ends on; false when the line has a comment after it
// already, or when none can be written there.
func (s Handle) CommentAtEnd(text string) (edit.Edit, bool) {
	src := s.tree.Bytes()
	for i := s.base.Node.ContentSpan().End; i < len(src) && src[i] != '\n' && src[i] != '\r'; i++ {
		if src[i] == '#' {
			return edit.Edit{}, false
		}
	}
	return s.SetCommentAtEnd(text)
}

// SetCommentAtEnd is the edit that makes the comment at the end of the
// line the element ends on text: it writes one where there is none and
// replaces the one there is, whatever it says (a directive of another
// tool among them). False when none can be written there.
func (s Handle) SetCommentAtEnd(text string) (edit.Edit, bool) {
	e, err := s.ed.LineComment(s.base.Node, text)
	return e, err == nil
}

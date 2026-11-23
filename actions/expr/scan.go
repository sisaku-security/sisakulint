package expr

import "strings"

// Segment is a part of a string: text, or an expression ${{ ... }}.
type Segment struct {
	Expr  bool
	Span  Span // an expression's Span includes ${{ and }}
	Inner Span // an expression's text between ${{ and }}
}

// Scan splits s into text and expressions the way the template reader does
// (TemplateReader.ParseScalar): an expression ends at the first }} outside
// a string literal. s is the value of a scalar, after YAML's
// escapes and folding.
//
// An expression without its }} is an error, and the rest of s is one
// expression segment. An expression of only spaces is an error.
func Scan(s string) ([]Segment, []Error) {
	var segs []Segment
	var errs []Error
	at := 0
	for at < len(s) {
		open := strings.Index(s[at:], "${{")
		if open < 0 {
			break
		}
		open += at
		if open > at {
			segs = append(segs, Segment{Span: Span{at, open}})
		}
		end := closing(s, open+3)
		if end < 0 {
			segs = append(segs, Segment{Expr: true, Span: Span{open, len(s)}, Inner: Span{open + 3, len(s)}})
			errs = append(errs, Error{Code: ErrUnclosed, Span: Span{open, len(s)}, Msg: "the expression is not closed: an unescaped ${{ must be followed by }}"})
			return segs, errs
		}
		g := Segment{Expr: true, Span: Span{open, end + 1}, Inner: Span{open + 3, end - 1}}
		if strings.TrimSpace(s[g.Inner.Start:g.Inner.End]) == "" {
			errs = append(errs, Error{Code: ErrEmpty, Span: g.Span, Msg: "an expression was expected"})
		}
		segs = append(segs, g)
		at = end + 1
	}
	if at < len(s) {
		segs = append(segs, Segment{Span: Span{at, len(s)}})
	}
	return segs, errs
}

// closing returns the index of the second } of the first }} at or after i
// outside a string literal, or -1. Every ' toggles the string, which also
// covers a doubled quote.
func closing(s string, i int) int {
	in := false
	for ; i < len(s); i++ {
		switch {
		case s[i] == '\'':
			in = !in
		case !in && s[i] == '}' && s[i-1] == '}':
			return i
		}
	}
	return -1
}

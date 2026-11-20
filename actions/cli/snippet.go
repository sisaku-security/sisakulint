package cli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/lint"
)

// sourceLine is a line snippet gives: its gutter (the number and the bar),
// and what follows.
type sourceLine struct{ gutter, body string }

func (s sourceLine) String() string { return s.gutter + s.body }

// snippet is the line of the source where l starts, as clean makes it, and
// carets under l, indented: nil when l is not in an input read. The
// carets are under the first line only; "(+N lines)" says how many more
// l spans.
func snippet(in lint.Inputs, l lint.Location) []sourceLine {
	if l.File.Query != nil {
		return nil
	}
	i, st := in.Lookup(l.File.Input)
	if st != lint.LookupFound || i.Tree == nil {
		return nil
	}
	src := i.Tree.Bytes()
	pos := i.Tree.Position(l.Span.Start)
	start := l.Span.Start - (pos.Column - 1)
	end := start
	for end < len(src) && src[end] != '\n' && src[end] != '\r' {
		end++
	}
	stop := min(max(l.Span.End, l.Span.Start), end)
	num := strconv.Itoa(pos.Line)
	out := []sourceLine{
		{"    " + num + " | ", clean(string(src[start:end]))},
		{"    " + strings.Repeat(" ", len(num)) + " | ", pad(string(src[start:l.Span.Start])) + strings.Repeat("^", max(1, width(string(src[l.Span.Start:stop]))))},
	}
	if l.Span.End > l.Span.Start {
		if more := i.Tree.Position(l.Span.End-1).Line - pos.Line; more > 0 {
			out[1].body += fmt.Sprintf(" (+%d lines)", more)
		}
	}
	return out
}

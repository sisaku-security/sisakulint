package reportview

import (
	"github.com/gh-intel/sisakulint/actions/lint"
)

// maxSnippet is the most lines of a step a node shows.
const maxSnippet = 12

// SnippetLine is a line of the step a place is in.
type SnippetLine struct {
	Line int    `json:"line"`
	Text string `json:"text"`
	At   bool   `json:"at,omitempty"` // the line the place starts on
}

// snippetOf is the lines of the step l is in, so that a person sees what
// the place is part of (the uses of a with, the step of an env). A step
// longer than maxSnippet keeps its first lines (its name and its uses or
// run) and the lines around the place, and leaves out what is between.
// Through an alias, they are the lines of the anchor, which is what runs.
// None for a place out of steps.
func snippetOf(in lint.Inputs, l lint.Location) []SnippetLine {
	s, ok := find(in, l)
	if !ok || s.step == nil || s.input.Tree == nil {
		return nil
	}
	t := s.input.Tree
	src := t.Bytes()
	c := s.step.Node.ContentSpan()
	end := c.End
	for end > c.Start && (src[end-1] == '\n' || src[end-1] == '\r') {
		end--
	}
	first, last := t.Position(c.Start).Line, t.Position(max(end-1, c.Start)).Line
	at := l.NodeSpan().Start
	if c.Start <= l.Span.Start && l.Span.Start < c.End {
		at = l.Span.Start // AtSpan: a place inside the element
	}
	mark := t.Position(at).Line
	const head, around = 3, (maxSnippet - 3) / 2
	starts := lineStarts(src)
	var out []SnippetLine
	for n := first; n <= last; n++ {
		if last-first+1 > maxSnippet && n >= first+head && (n < mark-around || n > mark+around) {
			continue
		}
		out = append(out, SnippetLine{Line: n, Text: lineText(src, starts, n), At: n == mark})
	}
	return out
}

// lineStarts are the offsets where the lines of src start, a line break
// being \r\n, \r or \n as YAML reads it.
func lineStarts(src []byte) []int {
	ls := []int{0}
	for i := 0; i < len(src); i++ {
		switch src[i] {
		case '\n':
			ls = append(ls, i+1)
		case '\r':
			if i+1 < len(src) && src[i+1] == '\n' {
				i++
			}
			ls = append(ls, i+1)
		}
	}
	return ls
}

// lineText is the text of the line n (from 1), without its line break.
func lineText(src []byte, starts []int, n int) string {
	b, e := starts[n-1], len(src)
	if n < len(starts) {
		e = starts[n]
	}
	for e > b && (src[e-1] == '\n' || src[e-1] == '\r') {
		e--
	}
	return string(src[b:e])
}

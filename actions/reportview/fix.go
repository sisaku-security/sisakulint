package reportview

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// Fix is the fix of a finding as the page shows it.
type Fix struct {
	KindID      lint.FixKindID  `json:"kind_id"`
	Title       string          `json:"title"`
	Safety      lint.Safety     `json:"safety"`
	SideEffects []FixSideEffect `json:"side_effects"`
	Edits       []FixEdit       `json:"edits"`
}

// FixSideEffect is a side effect of a fix, with what it is.
type FixSideEffect struct {
	ID   ir.SideEffect `json:"id"`
	Text string        `json:"text"`
}

// FixEdit is an edit as the whole lines it changes: from Line on, the
// lines Old become New.
type FixEdit struct {
	Line int      `json:"line"`
	Old  []string `json:"old"`
	New  []string `json:"new"`
}

// NoFix is a finding's reason for no fix.
type NoFix struct {
	Reason ir.NoFixReason `json:"reason"`
	Note   string         `json:"note"`
}

// fixOf is the fix of f as the page shows it: its safety as the registry
// declares its kind, and its edits as the lines of the input of f.
func fixOf(f lint.Finding, in lint.Inputs, reg *lint.Registry) (*Fix, error) {
	x := &Fix{KindID: f.Fix.KindID, Title: f.Fix.Title, SideEffects: []FixSideEffect{}, Edits: []FixEdit{}}
	if m, ok := reg.Meta(f.Rule); ok {
		if k, ok := m.FixKind(f.Fix.KindID); ok {
			x.Safety = k.Safety
		}
	}
	for _, e := range f.Fix.SideEffects {
		x.SideEffects = append(x.SideEffects, FixSideEffect{ID: e, Text: e.Text()})
	}
	input, st := in.Lookup(f.Location.File.Input)
	if st != lint.LookupFound || input.Tree == nil {
		return nil, fmt.Errorf("the input %s of the fix is not read", f.Location.File.Input)
	}
	x.Edits = editsOf(input.Tree.Bytes(), f.Fix.Edits)
	return x, nil
}

// editsOf are the edits es of src as changes of whole lines, in the order
// of their lines: edits on the same lines are one change, the lines as
// they are after all of them. The edits of a fix do not overlap.
func editsOf(src []byte, es []edit.Edit) []FixEdit {
	es = slices.Clone(es)
	slices.SortStableFunc(es, func(a, b edit.Edit) int { return a.Span.Start - b.Span.Start })
	out := []FixEdit{}
	for i := 0; i < len(es); {
		from, to := lineSpan(src, es[i].Span.Start, es[i].Span.End)
		j := i + 1
		for j < len(es) && es[j].Span.Start <= to {
			_, to = lineSpan(src, es[j].Span.Start, max(es[j].Span.End, to))
			j++
		}
		var b strings.Builder
		at := from
		for _, e := range es[i:j] {
			b.Write(src[at:e.Span.Start])
			b.Write(e.New)
			at = e.Span.End
		}
		b.Write(src[at:to])
		out = append(out, FixEdit{Line: bytes.Count(src[:from], []byte{'\n'}) + 1, Old: textLines(string(src[from:to])), New: textLines(b.String())})
		i = j
	}
	return out
}

// lineSpan is from the start of the line of start to the end of the line
// of end, without its line break.
func lineSpan(src []byte, start, end int) (int, int) {
	from := bytes.LastIndexByte(src[:start], '\n') + 1
	to := len(src)
	if i := bytes.IndexByte(src[end:], '\n'); i >= 0 {
		to = end + i
	}
	return from, to
}

// textLines are the lines of s without their line breaks (and a CR before
// one): none for an empty s, and no empty line after a last break.
func textLines(s string) []string {
	if s == "" {
		return []string{}
	}
	ls := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i, l := range ls {
		ls[i] = strings.TrimSuffix(l, "\r")
	}
	return ls
}

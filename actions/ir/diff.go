package ir

import (
	"slices"

	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// ChangedSummary is a summary that differs between the IRs of an input before and
// after its fixes: where it is, the fields that differ, and the handles
// of the summary before, which tell whether an edit is in it (Holds). A
// summary there only before, or only after, has every field compared.
type ChangedSummary struct {
	Key    Key
	Fields []SummaryField // in the order of Field
	before []Handle
}

// Holds is whether the edit e, of the bytes before the fixes, is in the
// summary as it was: within the element of one of its handles. A summary
// only after holds none.
func (c ChangedSummary) Holds(e edit.Edit) bool {
	for _, s := range c.before {
		sp := s.base.Node.Span()
		if sp.Start <= e.Span.Start && e.Span.End <= sp.End {
			return true
		}
	}
	return false
}

// Diff is how the summaries of after differ from those of before, in the
// fields given: the summaries of the types of those fields are made, in
// both, and one whose fields given did not change is not given. before
// and after are the IRs of one input, before and after its fixes. It asks
// no fact.
func Diff(before, after *IR, fields []SummaryField) []ChangedSummary {
	var types []SummaryType
	for _, f := range fields {
		if !slices.Contains(types, f.Summary()) {
			types = append(types, f.Summary())
		}
	}
	slices.Sort(types)
	var out []ChangedSummary
	for _, t := range types {
		for _, c := range changesOf(before, after, t) {
			c.Fields = slices.DeleteFunc(c.Fields, func(f SummaryField) bool { return !slices.Contains(fields, f) })
			if len(c.Fields) > 0 {
				out = append(out, c)
			}
		}
	}
	return out
}

// summaryOf is a summary type, as the generated code makes it.
type summaryOf[S any] interface {
	*S
	summaryKey() Key
	summaryHandles() []Handle
	diff(o *S) []SummaryField
}

// pair are the changes between the summaries a (before) and b (after) of
// one type: those of one key are paired in their order, and one without a
// pair has all the fields compared of its type.
func pair[S any, P summaryOf[S]](a, b []P, all []SummaryField) []ChangedSummary {
	bs := map[Key][]P{}
	for _, s := range b {
		bs[s.summaryKey()] = append(bs[s.summaryKey()], s)
	}
	var out []ChangedSummary
	used := map[Key]int{}
	for _, s := range a {
		k := s.summaryKey()
		i := used[k]
		used[k]++
		if i < len(bs[k]) {
			if d := s.diff(bs[k][i]); len(d) > 0 {
				out = append(out, ChangedSummary{Key: k, Fields: d, before: s.summaryHandles()})
			}
			continue
		}
		out = append(out, ChangedSummary{Key: k, Fields: slices.Clone(all), before: s.summaryHandles()})
	}
	seen := map[Key]int{}
	for _, s := range b {
		k := s.summaryKey()
		if seen[k]++; seen[k] > used[k] {
			out = append(out, ChangedSummary{Key: k, Fields: slices.Clone(all)})
		}
	}
	return out
}

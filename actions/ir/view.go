package ir

import "slices"

// View is what a group of rules reads, as views.json declares it: the
// fields, and how to make its reader R. The generator makes one for each
// view (NView); lint.WithView gives a rule its reader.
type View[R any] struct {
	fields []SummaryField
	make   func(*RuleAccess) R
}

// Fields are the fields the rules of v read, those of the operations they
// use among them, in the order of Field.
func (v View[R]) Fields() []SummaryField { return slices.Clone(v.fields) }

// Reader is the reader of v on q.
func (v View[R]) Reader(q *RuleAccess) R { return v.make(q) }

// Summary is a summary as a rule reads it: a value of a summary type,
// through the reader of its view, with the key of its place.
type Summary interface{ Key() Key }

package lint

import (
	"context"
	"fmt"
	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"
)

// Unchecked is a rule the registry does not run, a field of the IR of
// which the fixes change: --fix does not check the fixes against it.
type Unchecked struct {
	Rule    RuleID
	Changed []Changed // by input, then as ir.Diff gives them
}

// Changed is a summary the fixes change, in fields the rule reads.
type Changed struct {
	Input  facts.InputPath
	Path   string            // the YAML path of the summary (ir.Key.Path)
	Fields []ir.SummaryField // of those the rule reads, in the order of ir.Field
	By     []FixBy           // the fixes with an edit in the summary as it was; none when no edit is
}

// FixBy is a fix of a rule that ran.
type FixBy struct {
	Rule RuleID
	Fix  FixKindID
}

// fixOf is a fix ApplyFixes applies to an input, and its edits.
type fixOf struct {
	FixBy
	edits []edit.Edit
}

// uncheckedOf are the rules reg skipped a field of which the fixes change:
// for each input of changed (indexes of in.List and after.List), and each
// input it calls (calls.Graph), whose events and inputs it decides, the
// IRs of it before and after the fixes are compared in the fields the
// rules skipped for its kind read. Those rules do not run, and no fact is asked.
// A making of summaries that panics is an error.
func uncheckedOf(reg *Registry, in, after Inputs, fixes map[int][]fixOf, changed []int) (out []Unchecked, err error) {
	if len(reg.skippedMeta) == 0 {
		return nil, nil
	}
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, fmt.Errorf("the summaries of the inputs could not be compared for the rules skipped: %v", p)
		}
	}()
	var ids []RuleID
	for id := range reg.skippedMeta {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b RuleID) int { return strings.Compare(a.s, b.s) })
	by := map[RuleID][]Changed{}
	before, now := lazyCallers(context.Background(), in, nil), lazyCallers(context.Background(), after, nil)
	labelersBefore, labelersNow := lazyLabelers(in), lazyLabelers(after)
	compared := map[int]bool{}
	var order []int // changed and the inputs they call, each once
	for _, i := range changed {
		if !compared[i] {
			compared[i] = true
			order = append(order, i)
		}
	}
	for _, i := range changed {
		for _, node := range now().Graph().Dependents(calls.InputNode(after.List[i].Name)) {
			name, isInput := node.Input()
			if !isInput {
				continue
			}
			if j, ok := slices.BinarySearchFunc(after.List, name, func(x Input, n facts.InputPath) int { return facts.CompareInputPaths(x.Name, n) }); ok && !compared[j] {
				compared[j] = true
				order = append(order, j)
			}
		}
	}
	slices.Sort(order) // by input: the list is in the order of the names
	for _, i := range order {
		b, a := in.List[i], after.List[i]
		var fields []ir.SummaryField
		for _, id := range ids {
			if m := reg.skippedMeta[id]; slices.Contains(m.Targets, b.InputKind) {
				fields = append(fields, m.ViewFields...)
			}
		}
		if len(fields) == 0 {
			continue
		}
		bx := newIR(b.Name.String(), b.Tree, b.Workflow, b.ActionMetadata).WithCallers(before).WithLabelers(labelersBefore).WithComposite(context.Background(), compositeReader(in, unasked{}))
		ax := newIR(a.Name.String(), a.Tree, a.Workflow, a.ActionMetadata).WithCallers(now).WithLabelers(labelersNow).WithComposite(context.Background(), compositeReader(after, unasked{}))
		cs := ir.Diff(bx, ax, fields)
		for _, c := range cs {
			var fb []FixBy
			for _, f := range fixes[i] {
				if slices.ContainsFunc(f.edits, c.Holds) && !slices.Contains(fb, f.FixBy) {
					fb = append(fb, f.FixBy)
				}
			}
			for _, id := range ids {
				m := reg.skippedMeta[id]
				if !slices.Contains(m.Targets, b.InputKind) {
					continue
				}
				hit := slices.DeleteFunc(slices.Clone(c.Fields), func(f ir.SummaryField) bool { return !slices.Contains(m.ViewFields, f) })
				if len(hit) > 0 {
					by[id] = append(by[id], Changed{Input: b.Name, Path: c.Key.Path(), Fields: hit, By: fb})
				}
			}
		}
	}
	for _, id := range ids {
		if cs := by[id]; len(cs) > 0 {
			out = append(out, Unchecked{Rule: id, Changed: cs})
		}
	}
	return out, nil
}

// unasked answers no fact, asking no one: the comparison of uncheckedOf
// reads the actions of the inputs, not those of other repositories.
type unasked struct{}

func (unasked) Resolve(context.Context, facts.Query) facts.RawAnswer {
	return facts.RawAnswer{State: facts.StateUnknown, Reason: "not asked: the rule was skipped"}
}

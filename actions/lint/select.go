package lint

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Selector names what a Selection takes in or leaves out: now, a rule by
// its ID. What it holds is not exported, so that it may name a kind of
// finding too when that is decided.
type Selector struct{ rule RuleID }

// ParseSelector reads s, the ID of a rule. The ID of a kind of finding
// (commit-sha.unpinned) is not taken yet.
func ParseSelector(s string) (Selector, error) {
	if _, err := ParseFindingKindID(s); err == nil {
		return Selector{}, fmt.Errorf("%q: a kind of finding is not taken yet; give the ID of its rule", s)
	}
	id, err := ParseRuleID(s)
	if err != nil {
		return Selector{}, err
	}
	return Selector{id}, nil
}

// Selection is which rules run. The zero Selection runs every rule whose
// DefaultRun holds (Select).
type Selection struct {
	skip bool
	of   []Selector
}

// Only runs the rules s names, and no other, whatever their DefaultRun.
// Only with no Selector is the zero Selection.
func Only(s ...Selector) Selection { return Selection{of: slices.Clone(s)} }

// Skip runs every rule but those s names and those whose DefaultRun does
// not hold. It may name a rule whose DefaultRun does not hold.
func Skip(s ...Selector) Selection { return Selection{skip: true, of: slices.Clone(s)} }

// Select is the registry of the rules of r that s runs in a run of src; r
// is not changed. An ID r does not have, and a selection that leaves no
// rule, are errors. Skipped of what it gives is what r skipped and what s
// leaves out; NotRunByDefault tells those of the DefaultRun. The registry
// of NewRegistry has every rule: it is Select that leaves out those whose
// DefaultRun does not hold.
func (r *Registry) Select(s Selection, src FactSources) (*Registry, error) {
	if !s.skip && len(s.of) == 0 {
		if !slices.ContainsFunc(r.rules, func(rule Rule) bool { return !r.meta[rule.Meta().ID].DefaultRun.holds(src) }) {
			return r, nil
		}
		s = Selection{skip: true}
	}
	named := map[RuleID]bool{}
	for _, x := range s.of {
		if _, ok := r.meta[x.rule]; !ok {
			return nil, fmt.Errorf("no rule has the ID %q (the rules are %s)", x.rule.s, strings.Join(r.ids(), ", "))
		}
		named[x.rule] = true
	}
	out := &Registry{meta: map[RuleID]Meta{}, quality: map[RuleID]QualityMeta{}, skipped: slices.Clone(r.skipped), skippedMeta: maps.Clone(r.skippedMeta), byDefault: maps.Clone(r.byDefault), barriers: r.barriers, outsider: slices.Clone(r.outsider)}
	if out.skippedMeta == nil {
		out.skippedMeta = map[RuleID]Meta{}
	}
	if out.byDefault == nil {
		out.byDefault = map[RuleID]bool{}
	}
	for _, rule := range r.rules {
		id := rule.Meta().ID
		byDefault := s.skip && !named[id] && !r.meta[id].DefaultRun.holds(src)
		if named[id] == s.skip || byDefault {
			out.skipped = append(out.skipped, id)
			out.skippedMeta[id] = r.meta[id]
			if byDefault {
				out.byDefault[id] = true
			}
			continue
		}
		out.rules = append(out.rules, rule)
		out.meta[id] = r.meta[id]
		if q, ok := r.quality[id]; ok {
			out.quality[id] = q
		}
	}
	if len(out.rules) == 0 {
		return nil, errors.New("no rule is left to run")
	}
	slices.SortFunc(out.skipped, func(a, b RuleID) int { return strings.Compare(a.s, b.s) })
	return out, nil
}

// Skipped are the rules Select left out, by ID; none for a registry of
// NewRegistry.
func (r *Registry) Skipped() []RuleID { return slices.Clone(r.skipped) }

// ids are the IDs of r's rules, in their order.
func (r *Registry) ids() []string {
	var out []string
	for _, rule := range r.rules {
		out = append(out, rule.Meta().ID.s)
	}
	return out
}

package attacker

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
)

// LabelTruth is what the if p is in the run of e that the label label
// starts, on the attacker's pull request from a fork whose labels are
// labels: github.event.label.name is label, and
// github.event.pull_request.labels.*.name is labels. The if of a job reads
// the needs context (PlacedIf), so in an if that is true only when
// success() is true (TrueOnlyOnSuccess) needs.<id>.result and
// needs.*.result are success.
func (t Table) LabelTruth(p PlacedIf, e analysis.EventActivity, label string, labels []string) expr.Truth {
	lookup := t.lookupFor(e, RunOwn)
	names := make([]expr.Value, len(labels))
	for i, l := range labels {
		names[i] = expr.String(l)
	}
	set := func(path []expr.PathElem) (expr.Value, bool) {
		if len(path) == 4 && expr.HasPrefix(path, "github", "event", "label", "name") {
			return expr.String(label), true
		}
		return lookup(path)
	}
	override := func(n expr.Node) (expr.Value, bool) {
		p, ok := expr.AccessPath(n)
		if !ok || len(p) != 6 || !expr.HasPrefix(p[:4], "github", "event", "pull_request", "labels") || !p[4].Star || p[5].Star || p[5].Dynamic != nil || !expr.EqualName(p[5].Name, "name") {
			return expr.Value{}, false
		}
		return expr.Array(names...), true
	}
	return p.truth(eventOf(e), set, override)
}

// LabelBypasses are the comparisons of the if p by contains, startsWith or
// endsWith of github.event.label.name with a string that a label of names,
// which the attacker gets, passes as a part: a label that is not the string
// but has the string as a part (the reference first), or is a part of the
// string. None when the string itself is in names: the attacker gets that
// label, so the part adds nothing.
func LabelBypasses(p PlacedIf, names []string) []Comparison {
	var out []Comparison
	for _, cmp := range comparisons(p.c) {
		if cmp.Func == "" || cmp.Array {
			continue
		}
		p, ok := expr.AccessPath(cmp.Path)
		if !ok || len(p) != 4 || !expr.HasPrefix(p, "github", "event", "label", "name") {
			continue
		}
		if slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, cmp.Literal) }) {
			continue
		}
		passes := func(n string) bool {
			whole, part := strings.ToLower(cmp.Literal), strings.ToLower(n)
			if cmp.ReferenceFirst {
				whole, part = part, whole
			}
			switch strings.ToLower(cmp.Func) {
			case "contains":
				return strings.Contains(whole, part)
			case "startswith":
				return strings.HasPrefix(whole, part)
			}
			return strings.HasSuffix(whole, part)
		}
		if slices.ContainsFunc(names, passes) {
			cmp.Fits = cmp.ReferenceFirst
			out = append(out, cmp)
		}
	}
	return out
}

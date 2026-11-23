package boundary

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
	"github.com/gh-intel/sisakulint/actions/lint"
)

// HoldingsOf are the holdings the gains gs need, of the gains the tables
// compare, each once, in the order of Holdings.
func HoldingsOf(gs []lint.Gain) []Holding {
	var out []Holding
	for _, h := range Holdings() {
		for _, g := range gs {
			if slices.Contains(ComparedGains(), g) && HoldingOf(g) == h {
				out = append(out, h)
				break
			}
		}
	}
	return out
}

// RunGroups are the runs of the run grants, put together where, for every
// answer of the facts the rows of every run read, they run alike and hold
// alike each of hs. The groups, and the runs in a group, are in the order
// of their first row.
func RunGroups(hs []Holding) [][]RunRef {
	return rows().runGroups(hs)
}

func (t tables) runGroups(hs []Holding) [][]RunRef {
	answers := everyAnswer(t.allRunQueries())
	var out [][]RunRef
	var keys []string
	for _, ref := range t.refs() {
		k := t.runKey(ref, hs, answers)
		if i := slices.Index(keys, k); i >= 0 {
			out[i] = append(out[i], ref)
			continue
		}
		keys = append(keys, k)
		out = append(out, []RunRef{ref})
	}
	return out
}

// refs are the runs of the grants, in the order of their first row.
func (t tables) refs() []RunRef {
	var out []RunRef
	for _, g := range t.grants {
		if ref := (RunRef{g.Event, g.Head}); !slices.Contains(out, ref) {
			out = append(out, ref)
		}
	}
	return out
}

// allRunQueries are the facts the rows of every run read.
func (t tables) allRunQueries() []facts.Query {
	var cs []lint.Condition
	for _, g := range t.grants {
		cs = append(cs, g.Condition)
	}
	return queries(cs)
}

// runKey is, for each of answers, whether a run of ref runs and what it
// holds of hs.
func (t tables) runKey(ref RunRef, hs []Holding, answers []Answer) string {
	var b strings.Builder
	for _, a := range answers {
		ran, has, _ := t.runHas(ref, a)
		b.WriteString(ran.String())
		for _, h := range hs {
			b.WriteString(" " + has[h].String())
		}
		b.WriteString(";")
	}
	return b.String()
}

// everyAnswer is every answer of qs: each fact true, false or not known.
func everyAnswer(qs []facts.Query) []Answer {
	states := []facts.RawAnswer{
		{State: facts.StateFound, Value: json.RawMessage("true")},
		{State: facts.StateFound, Value: json.RawMessage("false")},
		{State: facts.StateUnknown, Reason: "not chosen"},
	}
	out := []Answer{}
	n := 1
	for range qs {
		n *= len(states)
	}
	for i := range n {
		by := map[facts.Kind]facts.RawAnswer{}
		for j, x := 0, i; j < len(qs); j, x = j+1, x/len(states) {
			by[qs[j].Kind()] = states[x%len(states)]
		}
		out = append(out, func(q facts.Query) facts.RawAnswer { return by[q.Kind()] })
	}
	return out
}

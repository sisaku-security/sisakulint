package reportview

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/boundary"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// CatalogBoundary is what the page shows of actions/boundary: its rows
// with their grounds, and, for each set of answers of the facts their
// conditions read, what a run holds, what one of a role held, and whether
// one of a role can write what an attacker writes. The crossing of a gain
// is looked up in Crossings by the truth of the run and of the role, so
// that the script decides nothing itself. Each row has its truth for each
// set of answers of the facts its condition reads, and each run and role
// what it holds, by Holding, so that the script draws how the facts decide
// a cell by looking them up.
type CatalogBoundary struct {
	Unreachable   []string                                `json:"unreachable"` // "<attacker> <head>" that no channel reaches
	RoleOrder     []boundary.Role                         `json:"role_order"`  // the least first
	Gains         []lint.Gain                             `json:"gains"`
	Crossings     map[string]map[string]boundary.Crossing `json:"crossings"` // by the truth of the run, then of the role
	Grants        []boundaryGrant                         `json:"grants"`
	Baselines     []boundaryBaseline                      `json:"baselines"`
	ChannelRows   []boundaryChannel                       `json:"channel_rows"`
	Runs          map[string]boundaryCell                 `json:"runs"`           // by "<event> <head>"
	Roles         map[string]boundaryCell                 `json:"roles"`          // by role
	ChannelCells  map[string]boundaryCell                 `json:"channel_cells"`  // by "<attacker> <role>"
	GainHoldings  map[string]boundary.Holding             `json:"gain_holdings"`  // by gain: what it needs
	HoldingTexts  map[string]string                       `json:"holding_texts"`  // by holding
	CrossingTexts map[string]string                       `json:"crossing_texts"` // by crossing: what it means and what to do
	HoldingOrder  []boundary.Holding                      `json:"holding_order"`  // the order of the holdings in a key of RunGroups
	PathwayRows   []boundaryPathway                       `json:"pathway_rows"`
	PathwayCells  map[string]boundaryCell                 `json:"pathway_cells"` // by "<attacker> <role>"
	RunGroups     map[string][][]string                   `json:"run_groups"`    // by the holdings an actor with no event needs, joined by ",": the runs "<event> <head>" of each group
}

// boundaryCell is a run, a role or a channel: the facts its rows read, and
// its value for each set of their answers, by a key of one letter a fact
// (t, f or u, in the order of Facts).
type boundaryCell struct {
	Facts  []string                 `json:"facts"`
	Values map[string]boundaryValue `json:"values"`
}

type boundaryValue struct {
	Dims     map[string]string `json:"dims,omitempty"`     // by gain: true, false or unknown
	Ran      string            `json:"ran,omitempty"`      // of a run: whether it runs at all
	Has      map[string]string `json:"has,omitempty"`      // of a run or a role, by holding
	Writable string            `json:"writable,omitempty"` // of a channel
	Usable   string            `json:"usable,omitempty"`   // of a pathway
	Basis    boundary.Basis    `json:"basis"`
}

type boundaryGrounds struct {
	Basis       boundary.Basis        `json:"basis"`
	Quotes      []boundaryQuote       `json:"quotes"`
	Observed    []boundaryObservation `json:"observed"`
	Uncertainty string                `json:"uncertainty,omitempty"`
}

// boundaryHolds is, of a row, the facts its condition reads and its truth
// for each set of their answers, by the keys of boundaryCell.
type boundaryHolds struct {
	Facts []string          `json:"facts"`
	Holds map[string]string `json:"holds"`
}

func holdsOf(c lint.Condition) boundaryHolds {
	qs := boundary.QueriesOf(c)
	h := boundaryHolds{Facts: kinds(qs), Holds: map[string]string{}}
	for _, k := range assignments(len(qs)) {
		h.Holds[k] = truthName(boundary.ConditionTruth(c, answerOf(qs, k)))
	}
	return h
}

func hasJSON(has map[boundary.Holding]expr.Truth) map[string]string {
	out := map[string]string{}
	for h, t := range has {
		out[h.String()] = truthName(t)
	}
	return out
}

type boundaryQuote struct {
	Citation  lint.Citation `json:"citation"`
	Text      string        `json:"text"`
	Retrieved lint.Date     `json:"retrieved"`
}

type boundaryObservation struct {
	Date   lint.Date `json:"date"`
	Runner string    `json:"runner,omitempty"`
	What   string    `json:"what"`
}

type boundaryGrant struct {
	Event     workflow.EventName     `json:"event"`
	Head      boundary.PRHead        `json:"head"`
	Condition lint.Condition         `json:"condition"`
	Token     boundary.Access        `json:"token"`
	Cache     boundary.Access        `json:"cache"`
	Secrets   boundary.SecretsAccess `json:"secrets"`
	boundaryGrounds
	boundaryHolds
}

type boundaryBaseline struct {
	Role             boundary.Role  `json:"role"`
	Condition        lint.Condition `json:"condition"`
	Runs             []string       `json:"runs"` // "<event> <head>"
	SelfHostedRunner string         `json:"self_hosted_runner"`
	boundaryGrounds
	boundaryHolds
}

type boundaryChannel struct {
	Attacker  lint.Attacker  `json:"attacker"`
	Role      boundary.Role  `json:"role"`
	Condition lint.Condition `json:"condition"`
	Writable  bool           `json:"writable"`
	boundaryGrounds
	boundaryHolds
}

type boundaryPathway struct {
	Attacker  lint.Attacker  `json:"attacker"`
	Role      boundary.Role  `json:"role"`
	Condition lint.Condition `json:"condition"`
	Usable    string         `json:"usable"`
	boundaryGrounds
	boundaryHolds
}

func grounds(b boundary.Basis, qs []boundary.Quote, os []lint.Observation, unknown string) boundaryGrounds {
	g := boundaryGrounds{Basis: b, Quotes: []boundaryQuote{}, Observed: []boundaryObservation{}, Uncertainty: unknown}
	for _, q := range qs {
		g.Quotes = append(g.Quotes, boundaryQuote{Citation: q.Citation, Text: q.Text, Retrieved: q.Retrieved})
	}
	for _, o := range os {
		x := boundaryObservation{Date: o.Date, What: o.What}
		if !o.Runner.IsZero() {
			x.Runner = o.Runner.String()
		}
		g.Observed = append(g.Observed, x)
	}
	return g
}

func refKey(r boundary.RunRef) string { return r.Event.String() + " " + r.Head.String() }

var letters = []string{"t", "f", "u"}

// assignments are the keys of every set of answers of n facts.
func assignments(n int) []string {
	out := []string{""}
	for range n {
		var next []string
		for _, k := range out {
			for _, l := range letters {
				next = append(next, k+l)
			}
		}
		out = next
	}
	return out
}

// answerOf answers the facts of qs by key, a letter a fact.
func answerOf(qs []facts.Query, key string) boundary.Answer {
	by := map[facts.Kind]byte{}
	for i, q := range qs {
		by[q.Kind()] = key[i]
	}
	return func(q facts.Query) facts.RawAnswer {
		switch by[q.Kind()] {
		case 't':
			return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage("true")}
		case 'f':
			return facts.RawAnswer{State: facts.StateFound, Value: json.RawMessage("false")}
		}
		return facts.RawAnswer{State: facts.StateUnknown, Reason: "not chosen"}
	}
}

func kinds(qs []facts.Query) []string {
	out := []string{}
	for _, q := range qs {
		out = append(out, q.Kind().String())
	}
	return out
}

func dimsJSON(d boundary.Dims) map[string]string {
	out := map[string]string{}
	for g, t := range d {
		out[g.String()] = truthName(t)
	}
	return out
}

func truthName(t expr.Truth) string {
	switch t {
	case expr.TruthTrue:
		return "true"
	case expr.TruthFalse:
		return "false"
	}
	return "unknown"
}

// cellOf is a cell of the facts qs, by value.
func cellOf(qs []facts.Query, value func(boundary.Answer) boundaryValue) boundaryCell {
	c := boundaryCell{Facts: kinds(qs), Values: map[string]boundaryValue{}}
	for _, k := range assignments(len(qs)) {
		c.Values[k] = value(answerOf(qs, k))
	}
	return c
}

// buildBoundary is the boundary of the page, with the groups of runs the
// actors with no event of actors need.
func buildBoundary(actors []lint.Actor) (*CatalogBoundary, error) {
	b := &CatalogBoundary{Gains: boundary.ComparedGains(), RoleOrder: boundary.Roles(), Crossings: map[string]map[string]boundary.Crossing{},
		Runs: map[string]boundaryCell{}, Roles: map[string]boundaryCell{}, ChannelCells: map[string]boundaryCell{},
		GainHoldings: map[string]boundary.Holding{}, HoldingTexts: map[string]string{}, CrossingTexts: map[string]string{},
		HoldingOrder: boundary.Holdings(), PathwayRows: []boundaryPathway{}, PathwayCells: map[string]boundaryCell{}, RunGroups: map[string][][]string{}}
	for _, g := range b.Gains {
		b.GainHoldings[g.String()] = boundary.HoldingOf(g)
	}
	for _, h := range boundary.Holdings() {
		b.HoldingTexts[h.String()] = h.Text()
	}
	for _, c := range boundary.Crossings() {
		b.CrossingTexts[c.String()] = c.Text()
	}
	for _, run := range []expr.Truth{expr.TruthTrue, expr.TruthFalse, expr.TruthUnknown} {
		b.Crossings[truthName(run)] = map[string]boundary.Crossing{}
		for _, held := range []expr.Truth{expr.TruthTrue, expr.TruthFalse, expr.TruthUnknown} {
			b.Crossings[truthName(run)][truthName(held)] = boundary.CrossingOf(run, held)
		}
	}
	refs := map[string]boundary.RunRef{}
	for _, g := range boundary.Grants() {
		b.Grants = append(b.Grants, boundaryGrant{Event: g.Event, Head: g.Head, Condition: g.Condition, Token: g.Token, Cache: g.Cache, Secrets: g.Secrets, boundaryGrounds: grounds(g.Basis, g.Quotes, g.Observed, g.Uncertainty), boundaryHolds: holdsOf(g.Condition)})
		refs[refKey(boundary.RunRef{Event: g.Event, Head: g.Head})] = boundary.RunRef{Event: g.Event, Head: g.Head}
	}
	for _, r := range boundary.Baselines() {
		x := boundaryBaseline{Role: r.Role, Condition: r.Condition, Runs: []string{}, SelfHostedRunner: truthName(r.SelfHostedRunner), boundaryGrounds: grounds(r.Basis, r.Quotes, r.Observed, r.Uncertainty), boundaryHolds: holdsOf(r.Condition)}
		for _, ref := range r.Runs {
			x.Runs = append(x.Runs, refKey(ref))
		}
		b.Baselines = append(b.Baselines, x)
	}
	type pair struct {
		a lint.Attacker
		r boundary.Role
	}
	pairs := map[string]pair{}
	for _, c := range boundary.Channels() {
		b.ChannelRows = append(b.ChannelRows, boundaryChannel{Attacker: c.Attacker, Role: c.Role, Condition: c.Condition, Writable: c.Writable, boundaryGrounds: grounds(c.Basis, c.Quotes, c.Observed, c.Uncertainty), boundaryHolds: holdsOf(c.Condition)})
		pairs[c.Attacker.String()+" "+c.Role.String()] = pair{c.Attacker, c.Role}
	}
	for k, ref := range refs {
		b.Runs[k] = cellOf(boundary.RunQueries(ref), func(a boundary.Answer) boundaryValue {
			d, basis := boundary.RunDims(ref, a)
			ran, has, _ := boundary.RunHas(ref, a)
			return boundaryValue{Dims: dimsJSON(d), Ran: truthName(ran), Has: hasJSON(has), Basis: basis}
		})
	}
	for _, role := range boundary.Roles() {
		b.Roles[role.String()] = cellOf(boundary.RoleQueries(role), func(a boundary.Answer) boundaryValue {
			d, basis := boundary.RoleDims(role, a)
			has, _ := boundary.RoleHas(role, a)
			return boundaryValue{Dims: dimsJSON(d), Has: hasJSON(has), Basis: basis}
		})
	}
	b.Unreachable = []string{}
	for _, p := range pairs {
		for _, h := range boundary.PRHeads() {
			if k := p.a.String() + " " + h.String(); !boundary.ReachesHead(p.a, h) && !slices.Contains(b.Unreachable, k) {
				b.Unreachable = append(b.Unreachable, k)
			}
		}
	}
	slices.Sort(b.Unreachable)
	for k, p := range pairs {
		at, role := p.a, p.r
		b.ChannelCells[k] = cellOf(boundary.ChannelQueries(at, role), func(a boundary.Answer) boundaryValue {
			open, basis := boundary.ChannelWritable(at, role, a)
			return boundaryValue{Writable: truthName(open), Basis: basis}
		})
	}
	for _, p := range boundary.Pathways() {
		b.PathwayRows = append(b.PathwayRows, boundaryPathway{Attacker: p.Attacker, Role: p.Role, Condition: p.Condition, Usable: truthName(p.Usable), boundaryGrounds: grounds(p.Basis, p.Quotes, p.Observed, p.Uncertainty), boundaryHolds: holdsOf(p.Condition)})
		k := p.Attacker.String() + " " + p.Role.String()
		if _, ok := b.PathwayCells[k]; ok {
			continue
		}
		at, role := p.Attacker, p.Role
		b.PathwayCells[k] = cellOf(boundary.PathwayQueries(at, role), func(a boundary.Answer) boundaryValue {
			u, basis := boundary.PathwayUsable(at, role, a)
			return boundaryValue{Usable: truthName(u), Basis: basis}
		})
	}
	for _, a := range actors {
		hs := boundary.HoldingsOf(a.Gains)
		if len(a.Events) > 0 || len(hs) == 0 {
			continue
		}
		var names []string
		for _, h := range hs {
			names = append(names, h.String())
		}
		k := strings.Join(names, ",")
		if _, ok := b.RunGroups[k]; ok {
			continue
		}
		groups := [][]string{}
		for _, g := range boundary.RunGroups(hs) {
			var refs []string
			for _, r := range g {
				refs = append(refs, refKey(r))
			}
			groups = append(groups, refs)
		}
		b.RunGroups[k] = groups
	}
	return b, nil
}

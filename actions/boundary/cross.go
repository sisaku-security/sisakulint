package boundary

import (
	"bytes"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// Answer answers a fact of the condition of a row.
type Answer func(facts.Query) facts.RawAnswer

// Dims are, of each Gain the tables compare, whether a run gives it, or
// whether one of a role held it: true, false or unknown.
type Dims map[lint.Gain]expr.Truth

// ComparedGains are the gains the tables compare. The others need what an
// attacker holds outside a run (an artifact, a registry), which the tables
// do not hold.
func ComparedGains() []lint.Gain {
	return []lint.Gain{lint.GainRunCode, lint.GainReadSecrets, lint.GainWriteWithToken, lint.GainWriteCache, lint.GainSetEnv, lint.GainSetOutputs, lint.GainSetPath, lint.GainPersistOnRunner, lint.GainReachRunnerNetwork}
}

const (
	truthT = expr.TruthTrue
	truthF = expr.TruthFalse
	truthU = expr.TruthUnknown
)

func truthOf(b bool) expr.Truth {
	if b {
		return truthT
	}
	return truthF
}

// and and or are Kleene's.
func and(a, b expr.Truth) expr.Truth {
	switch {
	case a == truthF || b == truthF:
		return truthF
	case a == truthT && b == truthT:
		return truthT
	}
	return truthU
}

func or(a, b expr.Truth) expr.Truth {
	switch {
	case a == truthT || b == truthT:
		return truthT
	case a == truthF && b == truthF:
		return truthF
	}
	return truthU
}

func holds(c lint.Condition, answer Answer) expr.Truth {
	return lint.Eval(c, answer, func(facts.InputPath) lint.LookupState { return lint.LookupUnknown })
}

// HoldingOf is the Holding a gain needs; the zero Holding for a gain the
// tables do not compare.
func HoldingOf(g lint.Gain) Holding {
	switch g {
	case lint.GainReadSecrets:
		return HoldingSecrets
	case lint.GainWriteWithToken:
		return HoldingWriteToken
	case lint.GainWriteCache:
		return HoldingWriteCache
	case lint.GainRunCode, lint.GainSetEnv, lint.GainSetOutputs, lint.GainSetPath:
		// code in the job gets what the job holds
		return HoldingWriteTokenSecretsOrCache
	case lint.GainPersistOnRunner, lint.GainReachRunnerNetwork:
		return HoldingSelfHostedRunner
	}
	return HoldingUnset
}

// hasOf is, of each Holding, whether a token that may write, the secrets,
// a cache of the default branch's scope that may be written and a
// self-hosted runner are held.
func hasOf(write, secrets, cache, runner expr.Truth) map[Holding]expr.Truth {
	return map[Holding]expr.Truth{
		HoldingSecrets: secrets, HoldingWriteToken: write, HoldingWriteTokenOrSecrets: or(write, secrets), HoldingSelfHostedRunner: runner,
		HoldingWriteCache: cache, HoldingWriteTokenSecretsOrCache: or(or(write, secrets), cache),
	}
}

// dimsOf is has by gain.
func dimsOf(has map[Holding]expr.Truth) Dims {
	d := Dims{}
	for _, g := range ComparedGains() {
		d[g] = has[HoldingOf(g)]
	}
	return d
}

// runHolds is what a run of ref holds by the rows that may hold: whether
// it runs at all (a row whose token is none is no run), its token may
// write, it has secrets, it may write the cache of the default branch's
// scope; the weakest basis of those rows; and whether a
// row may hold at all. The rows of a ref cover every answer of their facts
// (TestRowsExhaustive), so the rows that may hold have the one that does
// among them, and what they all say holds.
func (t tables) runHolds(ref RunRef, answer Answer) (ran, write, secrets, cache expr.Truth, basis Basis, seen bool) {
	ran, write, secrets, cache, basis = truthF, truthF, truthF, truthF, BasisObserved
	for _, g := range t.grants {
		if g.Event != ref.Event || g.Head != ref.Head {
			continue
		}
		h := holds(g.Condition, answer)
		if h == truthF {
			continue
		}
		seen = true
		basis = min(basis, g.Basis)
		ran = or(ran, and(h, truthOf(g.Token != AccessNone)))
		write = or(write, and(h, truthOf(g.Token == AccessWrite)))
		secrets = or(secrets, and(h, truthOf(g.Secrets == SecretsAccessAll)))
		cache = or(cache, and(h, truthOf(g.Cache == AccessWrite)))
	}
	if !seen {
		return truthU, truthU, truthU, truthU, BasisUnverified, false
	}
	return ran, write, secrets, cache, basis, true
}

// runHas is whether a run of ref runs at all, and what it holds.
func (t tables) runHas(ref RunRef, answer Answer) (expr.Truth, map[Holding]expr.Truth, Basis) {
	ran, w, s, c, b, seen := t.runHolds(ref, answer)
	if !seen {
		return truthU, hasOf(truthU, truthU, truthU, truthU), b
	}
	// the rule that reads persist-on-runner holds that the job is on a
	// self-hosted runner: its runs-on, not the event, decides it, when the
	// run happens
	return ran, hasOf(w, s, c, ran), b
}

func (t tables) runDims(ref RunRef, answer Answer) (Dims, Basis) {
	_, has, b := t.runHas(ref, answer)
	return dimsOf(has), b
}

// roleHas is what one of role held in runs of their own.
func (t tables) roleHas(role Role, answer Answer) (map[Holding]expr.Truth, Basis) {
	write, secrets, cache, runner := truthF, truthF, truthF, truthF
	basis := BasisObserved
	seen := false
	for _, r := range t.baselines {
		if r.Role != role {
			continue
		}
		h := holds(r.Condition, answer)
		if h == truthF {
			continue
		}
		seen = true
		basis = min(basis, r.Basis)
		ranAny := truthF // their own code runs somewhere: a run of theirs to put on a runner
		for _, ref := range r.Runs {
			ran, w, s, c, b, _ := t.runHolds(ref, answer)
			basis = min(basis, b)
			ranAny = or(ranAny, ran)
			write, secrets, cache = or(write, and(h, w)), or(secrets, and(h, s)), or(cache, and(h, c))
		}
		runner = or(runner, and(h, and(r.SelfHostedRunner, ranAny)))
	}
	if !seen {
		return hasOf(truthU, truthU, truthU, truthU), BasisUnverified
	}
	return hasOf(write, secrets, cache, runner), basis
}

func (t tables) roleDims(role Role, answer Answer) (Dims, Basis) {
	has, b := t.roleHas(role, answer)
	return dimsOf(has), b
}

func (t tables) channelWritable(a lint.Attacker, role Role, answer Answer) (expr.Truth, Basis) {
	out, basis := truthF, BasisObserved
	seen := false
	for _, c := range t.channels {
		if c.Attacker != a || c.Role != role {
			continue
		}
		h := holds(c.Condition, answer)
		if h == truthF {
			continue
		}
		seen = true
		basis = min(basis, c.Basis)
		out = or(out, and(h, truthOf(c.Writable)))
	}
	if !seen {
		return truthU, BasisUnverified
	}
	return out, basis
}

func (t tables) pathwayUsable(a lint.Attacker, role Role, answer Answer) (expr.Truth, Basis) {
	out, basis := truthF, BasisObserved
	seen := false
	for _, p := range t.pathways {
		if p.Attacker != a || p.Role != role {
			continue
		}
		h := holds(p.Condition, answer)
		if h == truthF {
			continue
		}
		seen = true
		basis = min(basis, p.Basis)
		out = or(out, and(h, p.Usable))
	}
	if !seen {
		return truthU, BasisUnverified
	}
	return out, basis
}

// CrossingOf is the crossing of a gain a run gives (run) and the attacker
// held before any flaw of the workflow (held).
func CrossingOf(run, held expr.Truth) Crossing {
	switch {
	case held == truthT:
		return CrossingByBaseline
	case held == truthU:
		return CrossingUnknown
	case run == truthT:
		return CrossingByWorkflow
	case run == truthU:
		return CrossingUnknown
	}
	return CrossingNone
}

// Result is what one of role who writes what a gets in a run of ref:
// whether they can write it (Channel), and, when they may, the crossing of
// each compared gain, with the weakest basis of the rows read.
type Result struct {
	Channel   expr.Truth
	Crossings map[lint.Gain]Crossing
	Basis     Basis
}

// ReachesHead is whether what a writes can be on a run of a pull request
// whose head is h: the author of a pull request from a fork writes none
// from a branch of the repository (lint.AttackerForkPRAuthor).
func ReachesHead(a lint.Attacker, h PRHead) bool {
	return !(a == lint.AttackerForkPRAuthor && h == PRHeadRepository)
}

func (t tables) cross(a lint.Attacker, role Role, ref RunRef, answer Answer) Result {
	if !ReachesHead(a, ref.Head) {
		return Result{Channel: truthF, Basis: BasisDocumented}
	}
	ch, cb := t.channelWritable(a, role, answer)
	r := Result{Channel: ch, Basis: cb}
	if ch == truthF {
		return r
	}
	run, rb := t.runDims(ref, answer)
	held, hb := t.roleDims(role, answer)
	r.Basis = min(cb, rb, hb)
	r.Crossings = map[lint.Gain]Crossing{}
	for _, g := range ComparedGains() {
		r.Crossings[g] = CrossingOf(run[g], held[g])
	}
	return r
}

// PathwayResult is what one of role who gets at a run of ref the way a does,
// with no event, gets: whether they can (Usable), and, when they may, the
// crossing of each compared gain, with the weakest basis of the rows read.
type PathwayResult struct {
	Usable    expr.Truth
	Crossings map[lint.Gain]Crossing
	Basis     Basis
}

func (t tables) crossByPathway(a lint.Attacker, role Role, ref RunRef, answer Answer) PathwayResult {
	pw, pb := t.pathwayUsable(a, role, answer)
	r := PathwayResult{Usable: pw, Basis: pb}
	if pw == truthF {
		return r
	}
	run, rb := t.runDims(ref, answer)
	held, hb := t.roleDims(role, answer)
	r.Basis = min(pb, rb, hb)
	r.Crossings = map[lint.Gain]Crossing{}
	for _, g := range ComparedGains() {
		r.Crossings[g] = CrossingOf(run[g], held[g])
	}
	return r
}

// RunHas is whether a run of ref runs at all, what it holds, and the
// weakest basis of the rows read.
func RunHas(ref RunRef, answer Answer) (expr.Truth, map[Holding]expr.Truth, Basis) {
	return rows().runHas(ref, answer)
}

// RoleHas is what one of role held in runs of their own.
func RoleHas(role Role, answer Answer) (map[Holding]expr.Truth, Basis) {
	return rows().roleHas(role, answer)
}

// ConditionTruth is the truth of the condition of a row: a leaf of an
// input is not known, as the rows read facts only.
func ConditionTruth(c lint.Condition, answer Answer) expr.Truth { return holds(c, answer) }

// QueriesOf are the facts c reads, each once, in the order of their
// EncodeQuery bytes.
func QueriesOf(c lint.Condition) []facts.Query { return queries([]lint.Condition{c}) }

// RunDims are the dimensions of a run of ref.
func RunDims(ref RunRef, answer Answer) (Dims, Basis) { return rows().runDims(ref, answer) }

// RoleDims are the dimensions one of role held.
func RoleDims(role Role, answer Answer) (Dims, Basis) { return rows().roleDims(role, answer) }

// ChannelWritable is whether one of role can write what a writes.
func ChannelWritable(a lint.Attacker, role Role, answer Answer) (expr.Truth, Basis) {
	return rows().channelWritable(a, role, answer)
}

// Cross is what one of role who writes what a gets in a run of ref.
func Cross(a lint.Attacker, role Role, ref RunRef, answer Answer) Result {
	return rows().cross(a, role, ref, answer)
}

// PathwayUsable is whether one of role gets at a run the way a does.
func PathwayUsable(a lint.Attacker, role Role, answer Answer) (expr.Truth, Basis) {
	return rows().pathwayUsable(a, role, answer)
}

// CrossByPathway is what one of role who gets at a run of ref the way a
// does, with no event, gets.
func CrossByPathway(a lint.Attacker, role Role, ref RunRef, answer Answer) PathwayResult {
	return rows().crossByPathway(a, role, ref, answer)
}

// queries are the facts of cs, each once, in the order of their
// EncodeQuery bytes.
func queries(cs []lint.Condition) []facts.Query {
	var out []facts.Query
	for _, c := range cs {
		for _, q := range c.Queries() {
			if !slices.Contains(out, q) {
				out = append(out, q)
			}
		}
	}
	slices.SortFunc(out, func(a, b facts.Query) int {
		x, _ := facts.EncodeQuery(a)
		y, _ := facts.EncodeQuery(b)
		return bytes.Compare(x, y)
	})
	return out
}

func (t tables) runConditions(ref RunRef) []lint.Condition {
	var cs []lint.Condition
	for _, g := range t.grants {
		if g.Event == ref.Event && g.Head == ref.Head {
			cs = append(cs, g.Condition)
		}
	}
	return cs
}

func (t tables) runQueries(ref RunRef) []facts.Query { return queries(t.runConditions(ref)) }

func (t tables) roleQueries(role Role) []facts.Query {
	var cs []lint.Condition
	for _, r := range t.baselines {
		if r.Role != role {
			continue
		}
		cs = append(cs, r.Condition)
		for _, ref := range r.Runs {
			cs = append(cs, t.runConditions(ref)...)
		}
	}
	return queries(cs)
}

func (t tables) channelQueries(a lint.Attacker, role Role) []facts.Query {
	var cs []lint.Condition
	for _, c := range t.channels {
		if c.Attacker == a && c.Role == role {
			cs = append(cs, c.Condition)
		}
	}
	return queries(cs)
}

// RunQueries are the facts the rows of a run of ref read.
func RunQueries(ref RunRef) []facts.Query { return rows().runQueries(ref) }

// RoleQueries are the facts the rows of role read, with those of its runs.
func RoleQueries(role Role) []facts.Query { return rows().roleQueries(role) }

// ChannelQueries are the facts the rows of a and role read.
func ChannelQueries(a lint.Attacker, role Role) []facts.Query {
	return rows().channelQueries(a, role)
}

func (t tables) pathwayQueries(a lint.Attacker, role Role) []facts.Query {
	var cs []lint.Condition
	for _, p := range t.pathways {
		if p.Attacker == a && p.Role == role {
			cs = append(cs, p.Condition)
		}
	}
	return queries(cs)
}

// PathwayQueries are the facts the rows of a and role read.
func PathwayQueries(a lint.Attacker, role Role) []facts.Query {
	return rows().pathwayQueries(a, role)
}

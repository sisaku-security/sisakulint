package taint

import (
	"reflect"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/shell"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// RequestSite is a request a simple command of a run of bash or sh sends
// (curl, wget, gh api) to one of its destinations: what an attacker may
// decide of the destination, the secrets the request carries there, and
// where the host of the destination comes from. A
// command with two URLs sends two requests, each with every credential of
// the command.
type RequestSite struct {
	Command    string // curl, wget, gh api
	Occurrence int    // the n-th request of the same command in the run, from 1
	// HostRefs are the values an attacker may control before the path of
	// the destination, where the value can end the authority and write
	// its own host; PathRefs those in its path, query or fragment.
	HostRefs []CommandArgument
	PathRefs []CommandArgument
	// Secrets are those the request carries: in its credentials (headers,
	// user and password, cookies, bodies), in the userinfo, path, query or
	// fragment of its destination, and, for gh api, the enterprise token
	// of env. A secret at the place of the host is not carried: it names
	// the destination.
	Secrets []CarriedSecret
	// EnterpriseToken: gh api with GH_ENTERPRISE_TOKEN or
	// GITHUB_ENTERPRISE_TOKEN in its environment, which it sends to any
	// host not of GitHub.
	EnterpriseToken bool
	Destination     DestinationOrigin
	DestinationSpan expr.Span // the word that names the host in the run
	CommandSpan     expr.Span // the command's word in the run
}

// enterpriseTokenVars are the variables gh reads the token for a host not
// of GitHub from.
var enterpriseTokenVars = []string{"GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// ghHostVar is the variable gh api sends a path of the API to the host of,
// when --hostname is not given.
const ghHostVar = "GH_HOST"

// requests reads the requests of the run of s, a run of bash or sh, into
// s.Requests, with f, its secret flow.
func (c scope) requests(s *Sink, f *secretFlow) {
	seen := map[string]int{}
	add := func(r RequestSite) {
		r.Secrets = uniqueCarried(r.Secrets)
		seen[r.Command]++
		r.Occurrence = seen[r.Command]
		s.Requests = append(s.Requests, r)
	}
	shell.WalkSimple(f.script.List, func(x *shell.Simple) {
		if len(x.Words) == 0 {
			return // assignments alone
		}
		words := make([]shell.CommandWord, len(x.Words))
		args := make([][]CommandArgument, len(x.Words))
		for i, w := range x.Words {
			args[i] = c.argumentsIn(s, f.text, f.holes, w, i)
			if t, ok := shell.Literal(f.text, w); ok && !overlaps(w.Span, f.holes) {
				words[i] = shell.CommandWord{Text: t, Known: true}
			} else {
				words[i].Prefix = f.prefixOf(w)
			}
		}
		roles := shell.ArgumentRoles(words)
		rws := shell.RequestRoles(roles, words)
		base := RequestSite{Command: roles.Name, CommandSpan: expr.Span{Start: x.Words[0].Span.Start, End: x.Words[0].Span.End}}
		var dests []int
		hostname := -1
		sends := false
		for i, rw := range rws {
			switch rw.Reading {
			case shell.RequestReadingUnset:
				continue
			case shell.RequestReadingCredential:
				w := x.Words[i]
				base.Secrets = append(base.Secrets, f.secretsInParts(w.Parts, f.literalPos(w, rw.ValueAt), w.Span.Start, 0)...)
			case shell.RequestReadingHostname:
				hostname = i // the last one counts
			default:
				dests = append(dests, i)
			}
			sends = true
		}
		if !sends {
			return
		}
		if base.Command == "gh api" {
			for _, n := range enterpriseTokenVars {
				var cs []CarriedSecret
				if a := f.programAssign(x, n); a != nil {
					cs = f.assignSecrets(a, 0)
				} else if f.inEnv(n) {
					cs = f.envSecrets(n, 0, 0)
				} else {
					continue
				}
				base.EnterpriseToken = true
				for _, s := range cs {
					s.Span, s.Var = base.CommandSpan, shell.VarName{}
					base.Secrets = append(base.Secrets, s)
				}
			}
		}
		if len(dests) == 0 {
			add(base)
			return
		}
		for _, i := range dests {
			r := base
			r.Secrets = slices.Clone(base.Secrets)
			w := x.Words[i]
			if words[i].Known && words[i].Text == "" {
				continue // an empty word names no destination
			}
			r.DestinationSpan = expr.Span{Start: w.Span.Start, End: w.Span.End}
			// each value that may reach the word is judged: one site for
			// each origin of the host they give, with what every value of
			// that origin carries
			var sites []RequestSite
			for _, segs := range f.valuesOf(w.Parts, f.literalPos(w, rws[i].ValueAt), w.Span.Start, 0) {
				v := r
				v.Secrets = slices.Clone(r.Secrets)
				form := urlFull
				if rws[i].Reading == shell.RequestReadingEndpoint && !urlAtHead(segs) {
					form = urlAPIPath
				}
				f.place(&v, segs, form, args[i], w.Span.Start)
				if form == urlAPIPath {
					c.apiHost(&v, s, f, x, hostname, rws, args)
				}
				sites = mergeSite(sites, v)
			}
			add(sites[0])
			for _, v := range sites[1:] {
				v.Secrets = uniqueCarried(v.Secrets)
				v.Occurrence = seen[v.Command] // the same request as the first
				s.Requests = append(s.Requests, v)
			}
		}
	})
}

// place adds to r what the value segs of its destination word, at at in
// the run, holds: the origin of its host (GitHub for a path of an API), the
// attacker's values args before the path and after it, and the secrets it
// carries. A variable of env the script assigns before at holds what the
// script gives it, not the attacker's value of env.
func (f *secretFlow) place(r *RequestSite, segs []seg, form urlForm, args []CommandArgument, at int) {
	l := layoutOf(segs, form)
	if form == urlAPIPath {
		r.Destination = DestinationOrigin{Kind: analysis.DestinationGitHub}
	} else {
		r.Destination = f.originOfSegs(segs, l)
	}
	for _, a := range args {
		if a.Var != (shell.VarName{}) && f.assigned(a.Var.String(), at) {
			continue
		}
		i := pieceOf(segs, l, a)
		if i < 0 && form != urlAPIPath || i >= 0 && l.decidesHost(i) {
			r.HostRefs = append(r.HostRefs, a)
		} else {
			r.PathRefs = append(r.PathRefs, a)
		}
	}
	for i, sg := range segs {
		if l.namesHost(i) {
			continue
		}
		switch sg.kind {
		case segExpr:
			r.Secrets = append(r.Secrets, f.exprSecrets(sg.tree, sg.span, sg.v, 0)...)
		case segUnknown:
			for _, cs := range sg.secrets {
				cs.Span = sg.span
				if sg.v != (shell.VarName{}) {
					cs.Var = sg.v
				}
				r.Secrets = append(r.Secrets, cs)
			}
		}
	}
}

// pieceOf is the piece of segs the attacker's value a is in, the one
// nearest the head of the URL; -1 when none is. a is a ${{ }} of the word,
// or a variable whose pieces come from env: of those, the ones whose ${{ }}
// read the reference the value comes from, or all when none does.
func pieceOf(segs []seg, l urlLayout, a CommandArgument) int {
	best, any := -1, -1
	for i, s := range segs {
		if s.span != a.Span {
			continue
		}
		if any < 0 {
			any = i
		}
		if best < 0 && s.kind == segExpr && s.tree != nil && (len(a.Path) == 0 || reads(s.tree, a.Path)) {
			best = i
		}
	}
	if best < 0 {
		return any
	}
	return best
}

// reads is whether the expression n reads the reference path.
func reads(n expr.Node, path []expr.PathElem) bool {
	if p, ok := expr.AccessPath(n); ok {
		return strings.EqualFold(expr.PathString(p), expr.PathString(path))
	}
	for _, c := range expr.Children(n) {
		if reads(c, path) {
			return true
		}
	}
	return false
}

// apiHost sets the host of r, a request of gh api x to a path of the API:
// the value of --hostname (the word hostname), or else of GH_HOST, or else
// GitHub's.
func (c scope) apiHost(r *RequestSite, s *Sink, f *secretFlow, x *shell.Simple, hostname int, rws []shell.RequestWord, args [][]CommandArgument) {
	if hostname >= 0 {
		w := x.Words[hostname]
		segs := f.valueOf(w.Parts, f.literalPos(w, rws[hostname].ValueAt), w.Span.Start, 0)
		r.Destination = f.originOfSegs(segs, layoutOf(segs, urlHostname))
		r.DestinationSpan = expr.Span{Start: w.Span.Start, End: w.Span.End}
		r.HostRefs = append(r.HostRefs, args[hostname]...)
		return
	}
	var segs []seg
	switch a := f.programAssign(x, ghHostVar); {
	case a != nil:
		segs = f.assignValue(a, 0)
		for _, w := range x.Assigns {
			if a.cmd == x && w.Span.Start == a.at {
				r.HostRefs = append(r.HostRefs, c.argumentsIn(s, f.text, f.holes, w, 0)...)
			}
		}
	case f.inEnv(ghHostVar):
		segs = f.varValue(ghHostVar, x.Span().Start, 0)
		if ref, ok := c.varRef(ghHostVar); ok && ref.Verdict != analysis.NotControlled {
			name, _ := shell.NameOf(ghHostVar)
			r.HostRefs = append(r.HostRefs, CommandArgument{Command: r.Command, Span: r.CommandSpan, Ref: ref, Path: ref.Source, RefIndex: -1, Var: name})
		}
	default:
		return
	}
	r.Destination = f.originOfSegs(segs, layoutOf(segs, urlHostname))
}

// mergeSite is sites with v: added to the site of the same origin of its
// host, or as a site of its own.
func mergeSite(sites []RequestSite, v RequestSite) []RequestSite {
	for i := range sites {
		o := &sites[i]
		if o.Destination.String() != v.Destination.String() || !slices.Equal(o.Destination.Ref.Source, v.Destination.Ref.Source) {
			continue
		}
		o.HostRefs = appendNewArgs(o.HostRefs, v.HostRefs)
		o.PathRefs = appendNewArgs(o.PathRefs, v.PathRefs)
		o.Secrets = append(o.Secrets, v.Secrets...)
		o.EnterpriseToken = o.EnterpriseToken || v.EnterpriseToken
		return sites
	}
	return append(sites, v)
}

// appendNewArgs is as with each of bs that as does not hold.
func appendNewArgs(as, bs []CommandArgument) []CommandArgument {
	for _, b := range bs {
		if !slices.ContainsFunc(as, func(a CommandArgument) bool { return reflect.DeepEqual(a, b) }) {
			as = append(as, b)
		}
	}
	return as
}

// uniqueCarried is cs with each secret at a place once.
func uniqueCarried(cs []CarriedSecret) []CarriedSecret {
	var out []CarriedSecret
	for _, c := range cs {
		if !slices.ContainsFunc(out, func(o CarriedSecret) bool {
			return o.Name == c.Name && o.Token == c.Token && o.Whole == c.Whole && o.Span == c.Span && o.Var == c.Var
		}) {
			out = append(out, c)
		}
	}
	return out
}

// literalPos is where in the run the n-th byte of the literal text at the
// head of w is (the text Literal and prefixOf read, without quotes): the
// end of the literal head when n is its length.
func (f *secretFlow) literalPos(w shell.Word, n int) int {
	end := w.Span.Start
	for _, p := range w.Parts {
		if p.Kind != shell.PartLiteral {
			break
		}
		if n < p.Span.End-p.Span.Start {
			return p.Span.Start + n
		}
		n -= p.Span.End - p.Span.Start
		end = p.Span.End
	}
	if n == 0 {
		return end
	}
	return w.Span.Start
}

// prefixOf is the literal text at the head of w, up to what is not known:
// a ${{ }} or an expansion.
func (f *secretFlow) prefixOf(w shell.Word) string {
	var b strings.Builder
	for _, p := range w.Parts {
		if p.Kind != shell.PartLiteral {
			break
		}
		end := p.Span.End
		for _, h := range f.holes {
			if h.span.Start >= p.Span.Start && h.span.Start < end {
				end = h.span.Start
			}
		}
		b.WriteString(f.text[p.Span.Start:end])
		if end < p.Span.End {
			break
		}
	}
	return b.String()
}

// inEnv is whether a level of the env the step sees has name.
func (f *secretFlow) inEnv(name string) bool {
	if _, ok := f.c.runnerVariable(name); ok {
		return false // the runner writes it over env
	}
	for _, e := range f.c.envs {
		if e.Status == workflow.Present {
			if _, ok := e.Value.Lookup(name); ok {
				return true
			}
		}
	}
	return false
}

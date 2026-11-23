package prcode

import (
	"github.com/sisaku-security/sisakulint/actions/analysis"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

// CheckoutRef is a reference in a checkout's input that names the code of a pull
// request.
type CheckoutRef struct {
	Text    string    // as written: a context, or refs/pull/<n>/merge with its ${{ }}
	Span    expr.Span // in the value of Input
	Input   analysis.CheckoutInput
	Mutable bool // a branch's name, or a ref GitHub moves

	events   []workflow.EventName // the events whose payload has it
	bypasses bool                 // the guard lets it through: refs/pull/ with capitals, github.event.before
	path     []expr.PathElem      // the reference's, read from its syntax; nil for refs/pull/<n>/merge
}

// HeadBranch is whether r is the name of the pull request's branch on
// pull_request_target, in any spelling: github.event.pull_request.head.ref
// or github.head_ref.
func (r CheckoutRef) HeadBranch() bool {
	return expr.PathIs(r.path, "github", "event", "pull_request", "head", "ref") || expr.PathIs(r.path, "github", "head_ref")
}

// Value is the value of the input in of s's with, or the zero String.
func (s CheckoutSite) Value(in analysis.CheckoutInput) workflow.String {
	if s.Step.With.Status != workflow.Present {
		return workflow.String{}
	}
	e, ok := s.Step.With.Value.Lookup(in.String())
	if !ok || e.Value.Status != workflow.Present {
		return workflow.String{}
	}
	return e.Value.Value
}

// read reads the with of s: what the checkout brings, on which of its
// events, and its guard.
func (s *CheckoutSite) read() {
	s.readGuard()
	w := s.Step.With
	switch w.Status {
	case workflow.Absent:
		s.NoRef = true
		return
	case workflow.Dynamic:
		s.CheckoutCode, s.Dynamic = analysis.CodeUnknown, true
		if w.Expr != nil {
			s.InconclusiveValues = append(s.InconclusiveValues, *w.Expr)
		}
		return
	case workflow.Present:
	default:
		return // not a mapping: the model reports it
	}
	var branches []CheckoutRef
	if e, ok := w.Value.Lookup(analysis.CheckoutInputRef.String()); !ok || e.Value.Status == workflow.Present && e.Value.Value.Text() == "" {
		s.NoRef = true // no ref, or an empty one: the default branch of the repository
	}
	for _, in := range []analysis.CheckoutInput{analysis.CheckoutInputRepository, analysis.CheckoutInputRef} {
		e, ok := w.Value.Lookup(in.String())
		switch {
		case !ok:
			continue
		case e.Value.Status == workflow.Dynamic:
			if e.Value.Expr != nil {
				s.InconclusiveValues = append(s.InconclusiveValues, *e.Value.Expr)
			}
			continue
		case e.Value.Status != workflow.Present:
			continue
		}
		v := e.Value.Value
		unknown := false
		for i, p := range v.Parts {
			if !p.Expr || p.Tree == nil {
				continue
			}
			taint.WrittenRefs(p.Tree, func(n expr.Node) {
				path, _ := expr.AccessPath(n)
				sp := p.InValue(n.Span())
				text := v.Text()[sp.Start:sp.End]
				row, isRow := matchRow(path, in)
				switch {
				case in == analysis.CheckoutInputRef && isNumber(path):
					if r, ok := pullRef(v, i, path); ok {
						s.Refs = append(s.Refs, r)
					} else {
						unknown = true // a number of a pull request in a ref of another form
					}
				case isRow && row.kind == refFork:
					s.Fork = true
					s.Refs = append(s.Refs, CheckoutRef{Text: text, Span: sp, Input: in, events: row.events, path: path})
				case isRow && row.kind == refCommit:
					s.Refs = append(s.Refs, CheckoutRef{Text: text, Span: sp, Input: in, events: row.events, bypasses: row.bypasses, path: path})
				case isRow && row.kind == refBranch:
					branches = append(branches, CheckoutRef{Text: text, Span: sp, Input: in, Mutable: true, events: row.events, path: path})
				case s.dispatcherChooses(path):
					// the dispatcher's: input-dispatch reports it
				case s.shaped(path, in):
					unknown = true
				}
			})
		}
		if unknown {
			s.InconclusiveValues = append(s.InconclusiveValues, v)
		}
	}
	if s.Fork {
		s.Refs = append(s.Refs, branches...) // a branch's name is the fork's only with it
	}
	s.narrow()
	switch {
	case len(s.Refs) > 0:
		s.CheckoutCode = analysis.CodePR
	case len(s.InconclusiveValues) > 0:
		s.CheckoutCode = analysis.CodeUnknown
	}
	for _, r := range s.Refs {
		if r.bypasses {
			s.Guard, s.SHA = analysis.GuardNone, facts.SHA{} // the guard does not compare it
		}
	}
}

// narrow keeps the events of s on which a reference of s.Refs has a value:
// github.event.pull_request is empty on issue_comment, and
// github.event.issue on pull_request_target. A reference with no such event
// is dropped.
func (s *CheckoutSite) narrow() {
	if len(s.Refs) == 0 {
		return
	}
	var evs []analysis.EventActivity
	for _, e := range s.PRCodeOn {
		if slices.ContainsFunc(s.Refs, func(r CheckoutRef) bool { return r.on(e) }) {
			evs = append(evs, e)
		}
	}
	var refs []CheckoutRef
	for _, r := range s.Refs {
		if slices.ContainsFunc(evs, r.on) {
			refs = append(refs, r)
		}
	}
	s.PRCodeOn, s.Refs = evs, refs
	if len(refs) == 0 {
		s.Fork = false
	}
}

// on is whether r names the code of a pull request on e: e is one of its
// events, and not an activity type of issue_comment whose comment is never
// on a pull request (notOnPullRequest), where the issue's number, the only
// reference of issue_comment the tables have, names none.
func (r CheckoutRef) on(e analysis.EventActivity) bool {
	if e.Name() == workflow.EventNameIssueComment && slices.Contains(notOnPullRequest, e.ActivityType()) {
		return false
	}
	return slices.Contains(r.events, e.Name())
}

// dispatcherChooses is whether path is an input of workflow_dispatch that
// only the one who dispatches the workflow chooses: s refers to one
// (DispatchInput), and no caller on an event of a pull request may give the
// inputs (CallFromPR).
func (s *CheckoutSite) dispatcherChooses(path []expr.PathElem) bool {
	return s.DispatchInput && !s.CallFromPR && isDispatchInput(path)
}

// shaped is whether the reference path, in the input in, may be what an
// attacker chooses although no row of the tables names it: in ref, a
// context an attacker shapes on one of s's events (actions/taint's table)
// or one the tables cannot tell (unknownRoots); in repository, any context
// but those of the base repository.
func (s *CheckoutSite) shaped(path []expr.PathElem, in analysis.CheckoutInput) bool {
	if len(path) == 0 {
		return false
	}
	if slicesContainsFold(unknownRoots, path[0].Name) {
		return true
	}
	if !expr.EqualName(path[0].Name, "github") {
		return false
	}
	if in == analysis.CheckoutInputRepository {
		for _, b := range baseRepos {
			if match(path, b) {
				return false
			}
		}
		return true
	}
	for _, b := range baseRefs {
		if match(path, b) {
			return false
		}
	}
	for _, e := range s.PRCodeOn {
		switch taint.Lookup(e.Name(), e.ActivityType(), path) {
		case taint.ControlUnknown, taint.ControlStructured, taint.ControlArbitrary:
			return true
		}
	}
	return false
}

// matchRow is the row of treeRefs that path is, for the input in.
func matchRow(path []expr.PathElem, in analysis.CheckoutInput) (treeRef, bool) {
	for _, t := range treeRefs {
		if (t.kind == refFork) != (in == analysis.CheckoutInputRepository) {
			continue
		}
		if match(path, t.path) {
			return t, true
		}
	}
	return treeRef{}, false
}

// isNumber is whether path is the number of a pull request.
func isNumber(path []expr.PathElem) bool {
	_, ok := numberRow(path)
	return ok
}

func numberRow(path []expr.PathElem) (treeRef, bool) {
	for _, r := range prNumbers {
		if match(path, r.path) {
			return r, true
		}
	}
	return treeRef{}, false
}

// match is whether path is names, a star or any index standing for *.
func match(path []expr.PathElem, names []string) bool {
	if len(path) != len(names) {
		return false
	}
	for i, n := range names {
		switch {
		case n == "*":
			if path[i].Name != "" && !path[i].Star && path[i].Dynamic == nil {
				// an index by a string literal is a name, not a number
				if _, err := strconv.Atoi(path[i].Name); err != nil {
					return false
				}
			}
		case path[i].Name == "" || !expr.EqualName(path[i].Name, n):
			return false
		}
	}
	return true
}

func slicesContainsFold(names []string, name string) bool {
	for _, n := range names {
		if name != "" && expr.EqualName(n, name) {
			return true
		}
	}
	return false
}

// pullRef reads refs/pull/<n>/head or refs/pull/<n>/merge, the whole of the
// value v, whose part i is the ${{ }} of <n> (the reference path). The
// literals are compared without case, as actions/checkout reads a ref
// (src/ref-helper.ts upper-cases it); one with capitals is marked, as the
// guard's pattern is of lower case.
func pullRef(v workflow.String, i int, path []expr.PathElem) (CheckoutRef, bool) {
	if i != 1 || len(v.Parts) != 3 || v.Parts[0].Expr || v.Parts[2].Expr || !v.Parts[1].Expr {
		return CheckoutRef{}, false
	}
	text := v.Text()
	before, after := text[v.Parts[0].Span.Start:v.Parts[0].Span.End], text[v.Parts[2].Span.Start:v.Parts[2].Span.End]
	if !strings.EqualFold(before, "refs/pull/") || !strings.EqualFold(after, "/head") && !strings.EqualFold(after, "/merge") {
		return CheckoutRef{}, false
	}
	row, _ := numberRow(path)
	sp := expr.Span{Start: v.Parts[0].Span.Start, End: v.Parts[2].Span.End}
	return CheckoutRef{Text: text[sp.Start:sp.End], Span: sp, Input: analysis.CheckoutInputRef, Mutable: true, events: row.events,
		bypasses: before != "refs/pull/" || after != "/head" && after != "/merge"}, true
}

var (
	fullSHA = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	semver  = regexp.MustCompile(`^v([0-9]+)(?:\.([0-9]+)(?:\.([0-9]+))?)?$`)
)

// readGuard reads whether s's release of actions/checkout refuses a fork's
// code: by its ref, unless allow-unsafe-pr-checkout is written true or with
// a ${{ }}.
func (s *CheckoutSite) readGuard() {
	switch w := s.Step.With; {
	case w.Status == workflow.Dynamic:
		return
	case w.Status == workflow.Present:
		if e, ok := w.Value.Lookup("allow-unsafe-pr-checkout"); ok {
			// true, or what is not known; empty or null is false, as for the checkout
			if e.Value.Status == workflow.Dynamic || e.Value.Status == workflow.Present && (e.Value.Value.Parts != nil || strings.EqualFold(strings.TrimSpace(e.Value.Value.AsString()), "true")) {
				return
			}
		}
	}
	ref, _ := calls.CheckoutRef(s.Step.Uses.Value)
	if fullSHA.MatchString(ref) {
		sha, err := facts.ParseSHA(ref)
		switch {
		case err != nil:
		case slices.Contains(releaseCommits, sha.String()):
			s.Guard = analysis.GuardStatic
		default:
			s.Guard, s.SHA = analysis.GuardSHA, sha
		}
		return
	}
	if TagGuarded(ref) {
		s.Guard = analysis.GuardStatic
	}
}

// TagGuarded is whether the release of actions/checkout named tag (v4,
// v4.4, v4.4.0) refuses a fork's code: a major tag from v2, or a release
// from the guard of its major (guardedFrom); a major above 7 is taken as
// one. A branch, v1 and a release before the guard are not.
func TagGuarded(tag string) bool {
	m := semver.FindStringSubmatch(tag)
	if m == nil {
		return false
	}
	major, _ := strconv.Atoi(m[1])
	switch {
	case major < 2:
		return false
	case m[2] == "" || major > 7:
		return true
	}
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3]) // "" is 0
	v := [3]int{major, minor, patch}
	return v == guardedFrom[major] || less(guardedFrom[major], v)
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

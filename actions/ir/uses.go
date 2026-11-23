package ir

import (
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/workflow"
	"github.com/gh-intel/sisakulint/yaml/cst/v1"
)

// UsesLevel is where a uses is.
type UsesLevel uint8

const (
	usesLevelUnset UsesLevel = iota
	UsesInJob                // a job's: a reusable workflow
	UsesInStep               // a step's, of a workflow or of a composite action
)

var usesLevelNames = [...]string{"", "job", "step"}

func (p UsesLevel) String() string { return usesLevelNames[p] }

// UsesForm is how a step's uses is written apart from how GitHub reads it.
type UsesForm uint8

const (
	usesFormUnset             UsesForm = iota
	UsesFormUnnormalized               // with parts that GitHub drops or resolves
	UsesFormOutsideRepository          // a path above the root of the repository
	UsesFormOutsideWorkspace           // a ./ path above the root of the workspace
)

var usesFormNames = [...]string{"", "unnormalized", "outside-repository", "outside-workspace"}

func (f UsesForm) String() string { return usesFormNames[f] }

// projectUses is the summary of fu, a uses at level at, or nil when it is
// not the uses of an action or a reusable workflow of another repository.
func (x *IR) projectUses(fu workflow.Field[workflow.Uses], at UsesLevel) *Uses {
	if fu.Status != workflow.Present {
		return nil
	}
	u := fu.Value
	kind := u.Kind
	if kind == workflow.UsesFolded {
		kind = u.Folded
	}
	if kind != workflow.UsesRemote {
		return nil
	}
	refAt := x.spanOf(u.String, u.Ref.Span)
	pathAt := refAt
	if u.Path.Text != "" {
		pathAt = x.spanOf(u.String, u.Path.Span)
	}
	outside := u.Outside == workflow.OutsideRepository
	var path string
	var runActions []string
	runUses := runUsesOf(u)
	switch {
	case !outside && len(u.Runs) == 1:
		path = u.Runs[0].Path.String()
	case outside && !u.Matched:
		for _, a := range u.Runs {
			if r := a.Owner + "/" + a.Repo + "@" + a.Ref; !slices.Contains(runActions, r) {
				runActions = append(runActions, r)
			}
		}
	}
	return &Uses{
		key:           keyOf(x.paths, x.input, x.tree, u.Base),
		alwaysSkipped: x.alwaysSkipped(u.Base),
		refAt:         refAt,
		pathAt:        pathAt,
		repo:          u.Owner.Text + "/" + u.Repo.Text,
		path:          path,
		ref:           u.Ref.Text,
		exact:         refAt.exact,
		level:         at,
		usesText:      u.AsString(),
		folded:        u.Kind == workflow.UsesFolded,
		lineComment:   lineComment(x.tree, u.Base.Node),
		outside:       outside,
		runActions:    runActions,
		runUses:       runUses,
		readByOutside: u.ReadByOutside,
	}
}

// runUsesOf is each reading of the action that u runs (Runs), as
// owner/repo[/path]@ref with the path as the runner reads it, each once.
func runUsesOf(u workflow.Uses) []string {
	var out []string
	for _, a := range u.Runs {
		r := a.Owner + "/" + a.Repo
		if !a.Path.IsZero() {
			r += "/" + a.Path.String()
		}
		if r += "@" + a.Ref; !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}

// lineComment is the text of the comment at the end of the line n ends on:
// after the #, without the white space around it; empty when only white
// space follows n there, or something else than a comment does, or when a
// tab comes right before the #, where Renovate (parseUsesLine) sees no
// comment.
func lineComment(t *cst.Tree, n cst.Node) string {
	src := t.Bytes()
	i := n.ContentSpan().End
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	if i >= len(src) || src[i] != '#' || src[i-1] != ' ' {
		return "" // Renovate reads a comment only after " #"
	}
	end := i
	for end < len(src) && src[end] != '\n' && src[end] != '\r' {
		end++
	}
	return strings.TrimSpace(string(src[i+1 : end]))
}

func (x *IR) allUses() []*Uses {
	x.once(SummaryUses, func() {
		var out []*Uses
		each := func(fu workflow.Field[workflow.Uses], at UsesLevel) {
			if u := x.projectUses(fu, at); u != nil {
				out = append(out, u)
			}
		}
		if w := x.workflow; w != nil {
			for _, j := range w.Jobs.Value.Entries {
				each(j.Value.Value.Uses, UsesInJob)
				for _, s := range j.Value.Value.Steps.Value.Items {
					each(s.Uses, UsesInStep)
				}
			}
		}
		if a := x.action; a != nil {
			for _, s := range a.Runs.Value.Steps.Value.Items {
				each(s.Uses, UsesInStep)
			}
		}
		x.uses = out
	})
	return x.uses
}

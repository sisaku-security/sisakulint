package lint

import (
	"context"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/calls"
	"github.com/sisaku-security/sisakulint/actions/composite"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/workflow"
	"github.com/sisaku-security/sisakulint/yaml/cst/v1"
)

// remoteNoFixNote is the reason for no fix of a finding in a remote called
// workflow: its fix would write a file of another repository.
const remoteNoFixNote = "the place is in a reusable workflow of another repository. The linter's fix edits only the files of this repository and cannot change that reusable workflow: change the reusable workflow in its repository, or call another reusable workflow or another version of the reusable workflow"

// relocate is f, which a rule reports in the remote called workflow r, at
// at, the uses of the job of the input the chain of r starts at: where f
// was is the first of its Evidence, with a note that says which reusable
// workflow it is in, and the uses of the jobs of the chain between are in
// Related. A finding already in an input stays where it is. A fix, which
// would write the file of the other repository, is dropped for the reason
// manual.
func relocate(f FindingDraft, r *calls.RemoteCalled, at Location) FindingDraft {
	if f.Location.File.Query == nil {
		// at a place of an input (the with of a caller): told apart by the
		// chain, as the rule reports it once for each remote called
		// workflow, and with no fix, which the check after a fix does not
		// run on a remote called workflow
		f.Anchor = remoteAnchor(f.Anchor, r, f.Location)
		if f.Fix != nil {
			f.Fix, f.NoFix = nil, &NoFix{Reason: ir.NoFixReasonManual, Note: remoteNoFixNote}
		}
		return f
	}
	was := f.Location
	f.Location = at
	f.Evidence = append([]Related{{Location: was, Note: remoteNote(r)}}, f.Evidence...)
	f.Related = append(slices.Clip(f.Related), chainRelated(r)...)
	f.Anchor = remoteAnchor(f.Anchor, r, was)
	if f.Fix != nil {
		f.Fix, f.NoFix = nil, &NoFix{Reason: ir.NoFixReasonManual, Note: remoteNoFixNote}
	}
	return f
}

// relocateGap is g, which a rule reports in the remote called workflow r,
// at at, as relocate moves a finding: where it was, with a note that says
// which reusable workflow it is in, and the uses of the jobs of the chain
// between are in Related (an inconclusive place has no Evidence), and its
// anchor is remoteAnchor of where it was. A place in an input stays where
// it is. An acceptance matches the place at at (Acceptance.matches), so it
// matches each place of the same rule and kind in the workflows the job
// calls.
func relocateGap(g InconclusiveDraft, r *calls.RemoteCalled, at Location) InconclusiveDraft {
	was := g.Location
	span, _ := was.identityText()
	// told apart by the chain, as relocate tells apart the findings: the
	// rule reports a place of an input (the with of a caller) once for each
	// remote called workflow
	g.anchor = remoteAnchor(gapAnchor(g.KindID, span), r, was)
	if g.Location.File.Query == nil {
		return g
	}
	g.Location = at
	g.Related = append(append([]Related{{Location: was, Note: remoteNote(r)}}, chainRelated(r)...), g.Related...)
	return g
}

// remoteNote says which reusable workflow a place is in, and which job
// calls it.
func remoteNote(r *calls.RemoteCalled) string {
	return "the place is in the reusable workflow " + r.String()
}

// chainRelated are the uses of the jobs of the remote called workflows
// before r in its chain, in the files of those workflows.
func chainRelated(r *calls.RemoteCalled) []Related {
	var out []Related
	for p := r.Parent; p != nil; p = p.Parent {
		u := r.Called.By
		if u == nil || u.Uses.Status != workflow.Present {
			break
		}
		out = append(out, Related{Location: factAt(p.Called.Origin.Query, p.Called.Origin.Tree, u.Uses.Value.Base), Note: "the job " + u.ID.AsString() + " of the reusable workflow " + p.String() + " calls the next reusable workflow of the chain"})
		r = p
	}
	return out
}

// remoteAnchor tells apart the findings of a rule at the uses of one job:
// the anchor the rule gave, the repository and the path of each reusable
// workflow of the chain with the job that calls it, and the path of where
// the finding was. The refs are not in it: a fix that pins the uses keeps
// the findings it does not remove.
func remoteAnchor(anchor string, r *calls.RemoteCalled, was Location) string {
	var hops []string
	for x := r; x != nil; x = x.Parent {
		h := ""
		if q, ok := x.Called.Origin.Query.(facts.WorkflowDefinition); ok {
			h = q.Repo.String() + "/" + q.Path.String()
		}
		if x.Called.By != nil {
			h = x.Called.By.ID.AsString() + " " + h
		}
		hops = append(hops, h)
	}
	slices.Reverse(hops)
	return anchor + "\x00" + strings.Join(hops, "\x00") + "\x00" + pathOf(was)
}

// factAt is where the element b of the file tree, the value of the fact q,
// is: for Evidence and Related.
func factAt(q facts.Query, tree *cst.Tree, b workflow.Base) Location {
	l := Location{File: File{Query: q}, Span: b.Primary(), Exact: true, node: b.Node, vias: slices.Clone(b.Via), tree: tree}
	for _, v := range b.Via {
		l.Via = append(l.Via, v.ContentSpan())
	}
	return l
}

// RemoteCalleeForm is the undetected form each rule that reads workflows
// declares: a remote called workflow is read only from the answer of
// workflow.definition, and a run with no answer does not read it.
var RemoteCalleeForm = UndetectedForm{ID: MustUndetectedFormID("remote-callee"),
	Text:        "a job or a step inside a reusable workflow of another repository (uses: owner/repo/.github/workflows/<file>@<ref>) whose content the fact workflow.definition does not give. For every rule: a run that does not ask the fact (a run without --online and without the answer in --facts). For a quality rule, also: a run where the linter asked the fact and got no answer (an answer of unknown: the GitHub API did not give the file), and a call deeper than the 3 levels of reusable workflows that the linter reads, for which the linter does not ask the fact. The rule reads a reusable workflow of another repository only from the answer of workflow.definition. For a rule that is not a quality rule (a rule with a threat), the last two forms are the inconclusive kind remote-callee-unknown, not this form",
	Disposition: Todo(NeedFact)}

// RemoteCalleeUnknownKind is the kind of inconclusive place each rule that
// reads workflows, and is not a quality rule, declares: the engine reports
// one at the uses of a job whose reusable workflow of another repository
// was asked of workflow.definition and has no answer.
var RemoteCalleeUnknownKind = InconclusiveKind{ID: MustInconclusiveKindID("remote-callee-unknown"),
	Text:        "a job that calls a reusable workflow of another repository, when the linter asked the fact workflow.definition for the reusable workflow and got no answer (the token that the linter uses cannot read the file, the file is larger than the limit, or the linter has used up the requests it may send to the GitHub API), or when the call is deeper than the 3 levels of reusable workflows that the linter reads, for which the linter does not ask the fact: the rule does not read the jobs and the steps of the reusable workflow",
	Disposition: Todo(NeedFact)}

// unansweredGaps are the inconclusive places of the kind
// RemoteCalleeUnknownKind in input, when m declares the kind: one at the
// uses of each job whose reusable workflows of other repositories, or
// those they call, were asked of workflow.definition and have no answer.
func unansweredGaps(ctx context.Context, m Meta, in Inputs, g *calls.Graph, input Input, r *composite.Reader) []InconclusiveDraft {
	w := input.Workflow
	if r == nil || w == nil || w.Jobs.Status != workflow.Present || !slices.ContainsFunc(m.InconclusiveKinds, func(k InconclusiveKind) bool { return k.ID == RemoteCalleeUnknownKind.ID }) {
		return nil
	}
	var out []InconclusiveDraft
	for i := range w.Jobs.Value.Entries {
		j := &w.Jobs.Value.Entries[i].Value.Value
		if boundToInput(g, in, input.Name, j) {
			continue // a call of an input
		}
		for _, u := range r.ExpandCall(ctx, j).Unanswered {
			if !u.Asked {
				continue
			}
			uses := u.Chain[len(u.Chain)-1].Uses
			note := "the rule does not read the jobs and the steps of the reusable workflow " + uses + ", as the linter asked the fact workflow.definition for the reusable workflow and got no answer (" + u.Reason + ")"
			if u.Deep {
				note = "the rule does not read the jobs and the steps of the reusable workflow " + uses + ", as the call is deeper than the 3 levels of reusable workflows that the linter reads, and the linter does not ask the fact workflow.definition for the reusable workflow"
			}
			out = append(out, InconclusiveDraft{KindID: RemoteCalleeUnknownKind.ID, Location: At(input, j.Uses.Value.Base), Note: note})
		}
	}
	return out
}

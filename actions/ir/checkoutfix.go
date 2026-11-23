package ir

import (
	"strings"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/prcode"
	"github.com/gh-intel/sisakulint/actions/workflow"
	cst "github.com/gh-intel/sisakulint/yaml/cst/v1"
	"github.com/gh-intel/sisakulint/yaml/cst/v1/edit"
)

// The fixes of the rules of checkouts of a pull request's code, moved from
// actions/rules (base-checkout of untrusted-checkout, pin-head-sha of
// untrusted-checkout-toctou): they read the with of the step, which no
// field of CheckoutSite has, from the site prcode gave (IR.checkoutSiteOf).

// entryOf is the entry of a mapping whose key is key: what edit.Delete
// takes.
func entryOf(key cst.Node) (cst.Node, bool) {
	for n, ok := key.Parent(); ok; n, ok = n.Parent() {
		if n.Kind() == cst.NodeBlockMappingEntry || n.Kind() == cst.NodeFlowPair {
			return n, true
		}
	}
	return cst.Node{}, false
}

// whole is whether the value v is its references to the pull request's
// code and nothing else: one ${{ }}, or refs/pull/<n>/… whole.
func whole(v workflow.String, refs []prcode.CheckoutRef) bool {
	if v.IsExpr() {
		return true
	}
	for _, r := range refs {
		if r.Span.Start == 0 && r.Span.End == len(v.Text()) {
			return true
		}
	}
	return false
}

// baseCheckout is the fix that makes the checkout cs bring the base's
// code: the inputs that name the pull request's (ref, and repository when
// it names the fork) go, and with goes when nothing else is left in it.
func (cs *CheckoutSite) baseCheckout(q *RuleAccess) FixPlan {
	s, e := q.ir.checkoutSiteOf[cs], &q.ir.editor
	w := s.Step.With
	if len(w.Value.Via) > 0 || len(s.Step.Via) > 0 {
		return FixPlan{NoFix: form("the step or its with is reached through an alias; change the anchor by hand")}
	}
	byInput := map[analysis.CheckoutInput][]prcode.CheckoutRef{}
	for _, r := range s.Refs {
		byInput[r.Input] = append(byInput[r.Input], r)
	}
	var drop []workflow.Entry[workflow.String]
	for _, in := range []analysis.CheckoutInput{analysis.CheckoutInputRepository, analysis.CheckoutInputRef} {
		refs := byInput[in]
		if len(refs) == 0 {
			continue
		}
		ent, _ := w.Value.Lookup(in.String())
		if !whole(ent.Value.Value, refs) {
			return FixPlan{NoFix: manual("the " + in.String() + " has more than the reference to the pull request's code; take it out by hand, or run the pull request's code in a pull_request workflow and pass only data to a privileged one")}
		}
		drop = append(drop, ent)
	}
	var keys []string
	for _, ent := range drop {
		keys = append(keys, ent.Key.AsString())
	}
	targets := []cst.Node{}
	if len(drop) == len(w.Value.Entries) {
		n, ok := entryOf(w.Key)
		if !ok {
			return FixPlan{NoFix: form("with is not an entry of the step")}
		}
		targets = append(targets, n)
	} else {
		for _, ent := range drop {
			n, ok := entryOf(ent.Key.Node)
			if !ok {
				return FixPlan{NoFix: form(ent.Key.AsString() + " is not an entry of with")}
			}
			targets = append(targets, n)
		}
	}
	var edits []edit.Edit
	for _, n := range targets {
		ed, err := e.Delete(n)
		if err != nil {
			return FixPlan{NoFix: form("the input cannot be taken out here (" + err.Error() + "); take it out by hand")}
		}
		edits = append(edits, ed)
	}
	return FixPlan{Fix: &Fix{Kind: FixBaseCheckout, Title: "check out the base's code: take out " + strings.Join(keys, " and "), Edits: edits, SideEffects: []SideEffect{SideEffectPRCodeNotBuilt}}}
}

// HeadSHAContext is the commit a labeled or an approved run of pull_request_target
// saw.
const HeadSHAContext = "github.event.pull_request.head.sha"

// pinHeadSHA is the fix that makes the checkout cs bring the commit the
// approval saw, on the events evs: the reference i of its refs, which can move, becomes
// github.event.pull_request.head.sha; for the fork alone, a ref of it is
// put in with. refs/pull/<n>/merge becomes the head too, which is not the
// merge, so that fix is to review.
func (cs *CheckoutSite) pinHeadSHA(q *RuleAccess, i int, evs []analysis.EventActivity) FixPlan {
	s, e := q.ir.checkoutSiteOf[cs], &q.ir.editor
	r := s.Refs[i]
	for _, ev := range evs {
		if ev.Name() != workflow.EventNamePullRequestTarget {
			return FixPlan{NoFix: manual("on " + ev.Name().String() + " the event does not name the commit the approval saw; check out a commit recorded at the approval")}
		}
	}
	if len(s.Step.With.Value.Via) > 0 || len(s.Step.Via) > 0 {
		return FixPlan{NoFix: form("the step or its with is reached through an alias; change the anchor by hand")}
	}
	title := "check out the commit the approval saw: " + r.Text + " becomes " + HeadSHAContext
	if r.Input == analysis.CheckoutInputRepository { // the fork alone: its default branch
		ref, ok := s.Step.With.Value.Lookup(analysis.CheckoutInputRef.String())
		var ed edit.Edit
		var err error
		if ok {
			ed, err = e.SetValue(ref.Value.Value.Node, edit.Str("${{ "+HeadSHAContext+" }}"))
		} else {
			ed, err = e.Insert(s.Step.With.Value.Node, edit.After(analysis.CheckoutInputRepository.String()), edit.Map{{Key: analysis.CheckoutInputRef.String(), Value: edit.Str("${{ " + HeadSHAContext + " }}")}})
		}
		if err != nil {
			return FixPlan{NoFix: form("the ref cannot be written here (" + err.Error() + "); write ref: ${{ " + HeadSHAContext + " }} by hand")}
		}
		return FixPlan{Fix: &Fix{Kind: FixPinHeadSHA, Title: "check out the commit the approval saw: ref ${{ " + HeadSHAContext + " }}", Edits: []edit.Edit{ed}}}
	}
	v := s.Value(r.Input)
	kind, text := FixPinHeadSHA, HeadSHAContext
	if strings.HasPrefix(strings.ToLower(r.Text), "refs/pull/") {
		text = "${{ " + HeadSHAContext + " }}"
		if strings.HasSuffix(strings.ToLower(r.Text), "/merge") {
			kind = FixPinHeadSHAReview
		}
	} else if !r.HeadBranch() || !onlyRef(v, r) {
		return FixPlan{NoFix: manual("write the commit the approval saw, " + HeadSHAContext + ", in place of " + r.Text)}
	}
	ed, err := edit.Replace(v.Value, r.Span.Start, r.Span.End, text)
	if err != nil {
		return FixPlan{NoFix: form("the reference cannot be written in place (" + err.Error() + "); write " + HeadSHAContext + " by hand")}
	}
	var effects []SideEffect
	if kind == FixPinHeadSHAReview {
		effects = []SideEffect{SideEffectMergeCommitReplaced}
	}
	return FixPlan{Fix: &Fix{Kind: kind, Title: title, Edits: []edit.Edit{ed}, SideEffects: effects}}
}

// onlyRef is whether the value v is one ${{ }} that is the reference r and
// nothing else: refs/heads/${{ github.head_ref }} or a default after || is
// not a branch's name the head's SHA can stand in for.
func onlyRef(v workflow.String, r prcode.CheckoutRef) bool {
	if !v.IsExpr() {
		return false
	}
	for _, p := range v.Parts {
		if p.Expr {
			return p.Tree != nil && p.InValue(p.Tree.Span()) == r.Span
		}
	}
	return false
}

// hasAnchor is whether n has an anchor.
func hasAnchor(n cst.Node) bool {
	_, ok := n.Anchor()
	return ok
}

// persistCredentialsFalseFix is the fix that writes persist-credentials false in the
// with of the checkout s, which is made when there is none: the checkout
// then leaves no credential in .git/config.
func persistCredentialsFalseFix(ed *edit.Editor, s workflow.Step) FixPlan {
	if len(s.Via) > 0 || s.With.Status == workflow.Present && len(s.With.Value.Via) > 0 {
		return FixPlan{NoFix: form("the step or its with is reached through an alias; set persist-credentials: false by hand")}
	}
	if _, ok := s.Node.Anchor(); ok || s.With.Status == workflow.Present && hasAnchor(s.With.Value.Node) {
		return FixPlan{NoFix: form("the step or its with has an anchor, whose aliases would change too; set persist-credentials: false by hand where it is needed")}
	}
	key := analysis.CheckoutInputPersistCredentials.String()
	var out edit.Edit
	var err error
	switch s.With.Status {
	case workflow.Absent:
		out, err = ed.Insert(s.Node, edit.After("uses"), edit.Map{{Key: "with", Value: edit.Map{{Key: key, Value: edit.Bool(false)}}}})
	case workflow.Present:
		if ent, ok := s.With.Value.Lookup(key); ok && ent.Value.Status == workflow.Present {
			out, err = ed.SetValue(ent.Value.Value.Node, edit.Bool(false))
		} else {
			out, err = ed.Insert(s.With.Value.Node, edit.Last(), edit.Map{{Key: key, Value: edit.Bool(false)}})
		}
	default:
		return FixPlan{NoFix: form("with is not a mapping; set persist-credentials: false by hand")}
	}
	if err != nil {
		return FixPlan{NoFix: form(key + " cannot be written here (" + err.Error() + "); set it to false by hand")}
	}
	return FixPlan{Fix: &Fix{Kind: FixPersistCredentialsFalse, Title: "keep the checkout's credential out of .git/config: persist-credentials: false", Edits: []edit.Edit{out}, SideEffects: []SideEffect{SideEffectCredentialNotPersisted}}}
}

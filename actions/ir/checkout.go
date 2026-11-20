package ir

import (
	"slices"

	"github.com/sisaku-security/sisakulint/actions/attacker"
	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/prcode"
	"github.com/sisaku-security/sisakulint/actions/taint"
)

// GuardCommits are the commits of actions/checkout that have the guard
// (prcode.GuardCommits), and CheckoutRepo its repository, for the rules,
// which do not import prcode.
func GuardCommits() []facts.SHA { return prcode.GuardCommits() }

var CheckoutRepo = prcode.CheckoutRepo

func (x *IR) allCheckoutSites() []*CheckoutSite {
	x.once(SummaryCheckoutSite, func() {
		var out []*CheckoutSite
		for _, s := range prcode.AnalyzeComposite(x.callersOf(), x.name, x.workflow, x.action, x.scripts, x.inner()) {
			if !s.Placed {
				continue // the checkout fails on its path: it brings no code
			}
			if len(s.PRCodeOn) > 0 || s.DispatchInput && len(s.DispatchOn) > 0 {
				out = append(out, x.projectCheckoutSite(s))
			}
		}
		x.checkoutSites = out
	})
	return x.checkoutSites
}

// projectCheckoutSite is the projection of the site s: its values without their
// positions and pointers, which the handles keep.
func (x *IR) projectCheckoutSite(s prcode.CheckoutSite) *CheckoutSite {
	cs := &CheckoutSite{
		key:           keyOf(x.paths, x.input, x.tree, s.Step.Base),
		at:            x.handleOf(s.Step.Base),
		checkoutCode:  s.CheckoutCode,
		fork:          s.Fork,
		noRef:         s.NoRef,
		dynamic:       s.Dynamic,
		prCodeOn:      s.PRCodeOn,
		dispatchOn:    s.DispatchOn,
		dispatchInput: s.DispatchInput,
		guard:         s.Guard,
		sha:           s.SHA,
		approval:      s.Approval,
		environment:   s.Environment,
		mutable:       s.Mutable(),
		stepPath:      s.Path,
		usesText:      s.Uses.Text(),
	}
	cs.automaticApproval = x.automaticApprovalOf(s.PRCodeOn, s.Job, attacker.StepIf(s.Step.If))
	for _, r := range s.Refs {
		cs.refs = append(cs.refs, CheckoutRef{Text: r.Text, Input: r.Input, Mutable: r.Mutable, At: x.spanOf(s.Value(r.Input), r.Span)})
	}
	for _, v := range s.InconclusiveValues {
		cs.inconclusiveValues = append(cs.inconclusiveValues, v.Text())
	}
	cs.codeRunSteps = x.codeRunSteps(s.CodeRunSteps)
	if s.Job != nil {
		cs.dispatchCacheOn = taint.Filter(x.table(), x.dispatchSaveOn(s.Job), attacker.StepIf(s.Step.If))
		on := x.cacheSaveOn(s.Job)
		for _, e := range s.PRCodeOn {
			if slices.Contains(on, e) {
				cs.cacheWriteOn = append(cs.cacheWriteOn, e)
			}
		}
	}
	cs.cacheSaves = x.cacheSaveSteps(s.CacheSaves, cs.cacheWriteOn)
	for _, u := range s.Unanswered {
		cs.unansweredCalls = append(cs.unansweredCalls, UnansweredCall{Via: u.Unanswered.Chain, Reason: u.Unanswered.Reason, At: x.handleOf(u.Via.Uses.Value.Base)})
	}
	x.checkoutSiteOf[cs] = s
	return cs
}

// codeRunSteps is the projection of the steps that run what a site brings.
func (x *IR) codeRunSteps(runs []prcode.CodeRunStep) []CodeRunStep {
	return x.inputPlace().codeRunSteps(runs)
}

package lint

import (
	"fmt"
	"slices"
)

// The bits of the exit code. A gate picks the ones it
// wants; a gate that takes a conditional finding but nothing it cannot
// check picks ConfirmedBit|UnreadBit.
const (
	ConfirmedBit    uint8 = 1  // a confirmed finding at or above the threshold
	UndecidedBit    uint8 = 2  // a conditional finding at or above it, or no input but those excluded
	ErrorBit        uint8 = 4  // an internal error
	InconclusiveBit uint8 = 8  // an inconclusive finding not accepted, of a rule whose severity is at or above the threshold
	UnreadBit       uint8 = 16 // a counted input not read or not valid, an input it calls not read or not valid, and in a pull request run a change of the base after the merge base or a changed input left out (RemoteRevision)
)

// Classify is the exit code of r: the sum of the bits that hold, of the
// findings of threshold and above; SeverityInfo is every severity. A
// finding whose certainty is CertaintyInconclusive counts by the severity
// of its rule (Report.Rules), the worst of the kinds of the rule; one of a
// rule the report does not list counts whatever the threshold; an
// accepted one (Accept) counts for nothing. Of the inputs, only the counted ones count, and of
// the places, only those of the counted inputs (Report.CountedInputs,
// Report.Counted). It panics when threshold is not a severity. That a
// finding has no fix counts for nothing.
func Classify(r Report, threshold Severity) uint8 {
	code, _ := classify(r, threshold)
	return code
}

// ClassifyReasons are the reasons of the bits UndecidedBit and UnreadBit
// that Classify sets, by bit.
func ClassifyReasons(r Report, threshold Severity) map[uint8][]string {
	_, why := classify(r, threshold)
	return why
}

func classify(r Report, threshold Severity) (uint8, map[uint8][]string) {
	if !threshold.valid() {
		panic(fmt.Sprintf("lint: Classify: the threshold %v is not a severity", threshold))
	}
	why := map[uint8][]string{}
	add := func(bit uint8, reason string) {
		if !slices.Contains(why[bit], reason) {
			why[bit] = append(why[bit], reason)
		}
	}
	outside := r.outside             // the places Narrow left out of the arrays, of counted inputs
	r = r.narrowTo(r.countedNames()) // the places of the inputs not counted count for nothing
	r.Findings = slices.Concat(r.Findings, outside.findings)
	var pr *PullRequestRevision
	if r.Remote != nil {
		pr = r.Remote.PullRequest
	}
	for _, f := range r.Findings {
		if f.Severity >= threshold && f.Certainty == CertaintyConditional {
			add(UndecidedBit, "conditional findings")
			break
		}
	}
	anyRead := slices.ContainsFunc(r.Inputs, func(i Input) bool { return i.State != InputStateExcluded })
	counted := r.CountedInputs()
	switch {
	case !anyRead:
		add(UndecidedBit, "no input")
	case pr == nil && len(counted) > 0 && !slices.ContainsFunc(counted, func(i Input) bool { return i.State != InputStateExcluded }):
		add(UndecidedBit, "no input") // only excluded ones are counted (--read-all)
	}
	if pr != nil && pr.BaseChangeCount > 0 {
		add(UnreadBit, "the base changed after the merge base")
	}
	for _, i := range counted {
		switch i.State {
		case InputStateExcluded:
			if pr != nil && slices.Contains(pr.ChangedInputs, i.Name) {
				add(UnreadBit, "changed inputs left out (--exclude)")
			}
		case InputStateInvalid:
			add(UnreadBit, "inputs not valid")
		case InputStateUnreadable:
			add(UnreadBit, "inputs not read")
		}
		if len(r.unreadCalls[i.Name]) > 0 {
			add(UnreadBit, "inputs called and not read")
		}
	}
	var code uint8
	for _, f := range r.Findings {
		if f.Severity >= threshold && f.Certainty == CertaintyConfirmed {
			code |= ConfirmedBit
		}
	}
	if len(why[UndecidedBit]) > 0 {
		code |= UndecidedBit
	}
	if len(why[UnreadBit]) > 0 {
		code |= UnreadBit
	}
	severities := map[RuleID]Severity{}
	for _, ref := range r.Rules {
		severities[ref.ID] = ref.Severity
	}
	for _, g := range r.FindingsWith(CertaintyInconclusive) {
		if g.Acceptance != nil {
			continue
		}
		if s, ok := severities[g.Rule]; !ok || s >= threshold {
			code |= InconclusiveBit
			break
		}
	}
	if len(r.Errors) > 0 {
		code |= ErrorBit
	}
	return code, why
}

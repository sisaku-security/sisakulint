package rules

import (
	"context"
	"fmt"

	"github.com/gh-intel/sisakulint/actions/analysis"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/lint"
	"github.com/gh-intel/sisakulint/actions/workflow"
)

// fileCommand is a rule of a value an attacker writes to a file command of
// the runner, which reads the file by lines after the step:
// envvar-injection ($GITHUB_ENV) and output-clobbering ($GITHUB_OUTPUT),
// where a line break in the value starts a name of the attacker's, and
// envpath-injection ($GITHUB_PATH), where any value is a directory of the
// PATH after. They read the sinks of the IR. The fixes of the first two are
// the plan of the step (ir.StepFix); a rule whose Meta declares no fixes
// gives a finding neither a fix nor a reason for none.
type fileCommand struct {
	file       analysis.EnvironmentFile
	meta       *lint.Meta
	controlled func(ref string, evs []workflow.EventName) lint.FindingArgs
	wiki       func(ref string) lint.FindingArgs
}

func (r fileCommand) Meta() lint.Meta { return *r.meta }

func (r fileCommand) Check(_ context.Context, c *lint.RuleContext, v ir.FileCommandReader) error {
	for _, s := range v.Sinks() {
		reportCallsNotRead(c, s.CallsNotRead())
		seen := anchors{}
		refs := s.Refs()
		for i, w := range s.EnvironmentFileWrites() {
			if w.File != r.file {
				continue
			}
			ref := w.Var
			if w.RefIndex >= 0 {
				ref = refs[w.RefIndex]
			}
			o := s.WriteFix(i)
			anchor := seen.next(w.Text, o) // every write of a text counts, whatever it gives
			at := c.At(w.At)
			switch {
			case len(w.Reach) > 0:
				evidence, related := valueEvidence(c, ref, w.Text)
				f := lint.FindingDraft{Location: at, Args: r.controlled(w.Text, eventsOf(w.Reach)), Anchor: anchor, Evidence: evidence, Related: related}
				if onlyGollum(w.Reach) {
					f.Args, f.Condition = r.wiki(w.Text), wikiOpenCond(c)
				}
				if len(r.meta.FixKinds) > 0 {
					withFix(&f, o)
				}
				c.Report(f)
			case ref.Verdict == analysis.Inconclusive:
				c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(ref.InconclusiveKind), Location: at,
					Note: fmt.Sprintf("%s is written to $%s; whether an attacker controls it is not analyzed (%s)", w.Text, r.file, ref.InconclusiveKind)})
			}
		}
		for _, g := range s.InconclusiveWrites() {
			if g.File != r.file {
				continue
			}
			c.Inconclusive(lint.InconclusiveDraft{KindID: inconclusiveKind(g.Kind), Location: c.At(g.At),
				Note: fmt.Sprintf("what is written to $%s here is not analyzed (%s)", r.file, g.Kind)})
		}
	}
	return nil
}

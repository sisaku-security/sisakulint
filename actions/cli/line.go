package cli

import (
	"io"
	"strconv"
	"strings"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// writeLines writes rep as --format line: a line
// for each finding, in the order of the report, that starts where it is, a
// finding whose certainty is conditional or inconclusive tagged so, and an
// inconclusive finding that an entry of --accept matched tagged with the
// reason of the entry; then a line for each quality finding, whose severity
// is the word quality; then the inputs not valid or not read, the internal
// errors, and why the fixes failed, so that bits 2, 4 and 8 and the exit
// code 70 have their reasons here. The count is left out. It is not a
// contract; --format json is.
func writeLines(w io.Writer, rep lint.Report, in lint.Inputs, reg *lint.Registry, color bool) error {
	p := &printer{in: in, reg: reg, color: color}
	for _, r := range rep.Findings {
		p.line("%s %s %s: %s%s", p.place(r.Location), p.paint(severityColor[r.Severity], r.Severity.String()), p.paint(bold, r.KindText()), clean(r.Detected()), p.tags(r))
	}
	for _, f := range rep.QualityFindings {
		tag := ""
		if f.Certainty == lint.CertaintyConditional {
			tag = " " + p.paint(gray, "[conditional]")
		}
		p.line("%s quality %s: %s%s", p.place(f.Location), p.paint(bold, f.Args.KindID().String()), clean(f.Detected()), tag)
	}
	for _, i := range rep.ReportedInputs() {
		switch {
		case i.State == lint.InputStateRead, i.State == lint.InputStateExcluded:
		case i.State == lint.InputStateInvalid && len(i.Diagnostics) > 0:
			for _, d := range i.Diagnostics {
				p.line("%s%s invalid %s: %s", p.paint(cyan, clean(i.Name.String())), p.paint(gray, ":"+p.lineCol(i.Name, d.Span.Start)+":"), d.Code, clean(d.Msg))
			}
		default:
			p.line("%s%s %s: %s", p.paint(cyan, clean(i.Name.String())), p.paint(gray, ":"), i.State, clean(i.Reason))
		}
	}
	for _, e := range rep.Errors {
		if who := errorWho(e); who != "" {
			p.line("sisakulint: error: %s: %s", who, clean(e.Message))
		} else {
			p.line("sisakulint: error: %s", clean(e.Message))
		}
	}
	if rep.Fix != nil && rep.Fix.Error != "" {
		p.line("sisakulint: fix: %s", clean(rep.Fix.Error))
	}
	if rep.Fix != nil {
		for _, u := range rep.Fix.UncheckedRules {
			p.line("sisakulint: fix: %s", uncheckedText(u))
		}
	}
	_, err := w.Write(p.b.Bytes())
	return err
}

// place is where l is, as a line starts: path:line:column: with no ~ (the
// tags say not exact), so that what reads path:line:column: reads it.
func (p *printer) place(l lint.Location) string {
	if l.File.Query != nil {
		return "fact " + queryText(l.File.Query) + p.paint(gray, " @"+strconv.Itoa(l.Span.Start)+":")
	}
	return p.paint(cyan, clean(l.File.Input.String())) + p.paint(gray, ":"+p.lineCol(l.File.Input, l.Span.Start)+":")
}

// tags are what a line of r adds after what it detects: whether it is
// conditional, whether --accept accepts it, the flag of its fix,
// the aliases it was reached through, and whether its place is not exact.
func (p *printer) tags(r lint.Finding) string {
	var tags []string
	switch r.Certainty {
	case lint.CertaintyConditional:
		tags = append(tags, "conditional")
	case lint.CertaintyInconclusive:
		tags = append(tags, "inconclusive")
	}
	if a := r.Acceptance; a != nil {
		tags = append(tags, "accepted by --accept: "+clean(a.Reason))
	}
	if r.Fix != nil {
		k, _ := fixKind(p.reg, r.Rule, r.Fix.KindID) // a kind not in the registry has no safety: review
		tags = append(tags, applyFlag(k.Safety))
	}
	for _, v := range r.Location.Via {
		tags = append(tags, "via alias at "+p.lineCol(r.Location.File.Input, v.Start))
	}
	if !r.Location.Exact {
		tags = append(tags, "not exact")
	}
	if len(tags) == 0 {
		return ""
	}
	return " " + p.paint(gray, "["+strings.Join(tags, ", ")+"]")
}

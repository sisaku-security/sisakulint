package cli

import (
	"bytes"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/facts"
	"io"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/lint"
)

// textOptions are how the text is written: --detail, whether to color it,
// and the threshold of the bits (--fail-on).
type textOptions struct {
	detail    detail
	color     bool
	threshold lint.Severity
}

// shown is how many places, or facts, a group shows before "… N more".
const shown = 3

const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	cyan  = "\x1b[36m"
	gray  = "\x1b[90m"
)

var severityColor = map[lint.Severity]string{
	lint.SeverityCritical: "\x1b[1;31m",
	lint.SeverityHigh:     "\x1b[31m",
	lint.SeverityMedium:   "\x1b[33m",
}

// writeText writes rep for people: the confirmed
// findings, the conditional ones, the inconclusive places, the inputs,
// the internal errors, what came of --fix, the worst findings, and the
// bits; a section with nothing is left out. It is not a contract;
// --format json is.
func writeText(w io.Writer, rep lint.Report, in lint.Inputs, reg *lint.Registry, o textOptions) error {
	p := &printer{in: in, reg: reg, color: o.color}
	open, accepted := splitAccepted(rep.FindingsWith(lint.CertaintyInconclusive))
	listed := rep // what the sections count: the inconclusive findings not accepted
	listed.Findings = slices.Concat(rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional), open)
	v := buildView(listed, in, reg)
	p.revision(rep)
	if o.detail == detailSummary {
		p.brief(listed, v, accepted)
	} else {
		full := o.detail == detailFull
		p.confirmed(v.confirmed, full)
		p.conditional(v.conditional, full)
		p.inconclusive(open, v.inconclusive, full)
		p.accepted(accepted, o.detail)
		p.quality(rep.QualityFindings, full)
		p.inputs(rep, v.inputs, full)
	}
	p.errors(rep.Errors)
	p.fix(rep.Fix)
	if o.detail != detailSummary {
		p.worst(v.confirmed, open) // the lines of the folds of summary have it
	}
	p.summary(rep, o.threshold)
	_, err := w.Write(p.b.Bytes())
	return err
}

type printer struct {
	b     bytes.Buffer
	in    lint.Inputs
	reg   *lint.Registry
	color bool
}

func (p *printer) line(format string, a ...any) { fmt.Fprintf(&p.b, format+"\n", a...) }

// cut is whether to stop before item i of n: after shown items, unless
// verbose, it writes how many more there are.
func (p *printer) cut(i, n int, verbose bool) bool {
	if i < shown || verbose {
		return false
	}
	p.line("    … %d more (-v)", n-shown)
	return true
}

func (p *printer) paint(code, s string) string {
	if !p.color || code == "" {
		return s
	}
	return code + s + reset
}

func (p *printer) head(sev lint.Severity, what, rest string) {
	p.line("%s  %s  %s", p.paint(severityColor[sev], sev.String()), p.paint(bold, what), rest)
}

// loc is where l is: path:line:column, ~ when only nearly, and the
// aliases it was reached through.
func (p *printer) loc(l lint.Location) string {
	var s string
	if l.File.Query != nil {
		s = "fact " + queryText(l.File.Query) + factLineCol(l)
	} else {
		s = p.paint(cyan, clean(l.File.Input.String())) + ":" + p.lineCol(l.File.Input, l.Span.Start)
	}
	if !l.Exact {
		s += "~"
	}
	for _, v := range l.Via {
		s += " via alias at " + p.lineCol(l.File.Input, v.Start)
	}
	return s
}

// factLineCol is where l, a place in the file of a fact, starts:
// :line:column, or @offset for a Location with no tree.
func factLineCol(l lint.Location) string {
	pos := l.Position()
	if pos.Line == 0 {
		return fmt.Sprintf(" @%d", l.Span.Start)
	}
	return fmt.Sprintf(":%d:%d", pos.Line, pos.Column)
}

func (p *printer) lineCol(n facts.InputPath, off int) string {
	i, st := p.in.Lookup(n)
	if st != lint.LookupFound || i.Tree == nil {
		return fmt.Sprintf("@%d", off)
	}
	pos := i.Tree.Position(off)
	return fmt.Sprintf("%d:%d", pos.Line, pos.Column)
}

// confirmed writes the folds: in full, every finding by itself.
func (p *printer) confirmed(folds []fold, full bool) {
	for _, f := range folds {
		if !full {
			p.fold(f)
			continue
		}
		for _, g := range f.rows {
			for _, r := range g.results {
				p.finding(r, "")
				p.tail(f, findingFix(p.reg, r), f.factsOf[r.Fingerprint], true)
			}
		}
	}
}

// fold writes f under one head, a line for each row. A fold of one
// finding is that finding.
func (p *printer) fold(f fold) {
	if len(f.rows) == 1 && len(f.rows[0].results) == 1 {
		p.finding(f.rows[0].results[0], "")
		p.tail(f, f.fix, f.facts, false)
		return
	}
	p.head(f.severity, f.kind.String(), fmt.Sprintf("×%d", f.count()))
	p.line("  impact: %s", clean(f.impact))
	for _, g := range f.rows {
		// the count is of what is detected, so it ends that line, and
		// the places are under it
		p.line("  %s%s", clean(g.detected), p.boldTimes(len(g.results)))
		if f.severity != lint.SeverityCritical {
			// what is detected holds the uses: the first place and its source are
			// enough
			more := ""
			if n := len(g.results); n > 1 {
				more = fmt.Sprintf("  (+%d more, -v)", n-1)
			}
			p.line("    %s%s", p.loc(g.results[0].Location), more)
			p.added(g.results[0].AddedAttackers, "    ")
			p.source(snippet(p.in, g.results[0].Location))
			continue
		}
		// what to decide on is in the source, which what is detected does not hold
		// as it does for a uses
		for i, r := range g.results {
			if p.cut(i, len(g.results), false) { // full does not come here
				break
			}
			p.line("    %s", p.loc(r.Location))
			p.added(r.AddedAttackers, "    ")
			p.places(r)
		}
	}
	p.tail(f, f.fix, f.facts, false)
}

// tail is what a fold, or a finding of it, ends with: the remedy, the
// facts found out that it rests on, the fix, and why there is none.
func (p *printer) tail(f fold, fix *fixLine, found []factLine, verbose bool) {
	p.line("  remedy: %s", clean(f.remedy))
	for i, x := range found {
		if p.cut(i, len(found), verbose) {
			break
		}
		p.line("  fact: %s", x.text())
	}
	if x := fix; x != nil {
		p.line("  fix (%s): %s  [%s]", x.safety, clean(x.title), applyFlag(x.safety))
		for _, e := range x.sideEffects {
			p.line("    side effect: %s", clean(e.Text()))
		}
	}
	if f.noFix != nil {
		p.line("  no fix: %s", clean(f.noFix.Note))
	}
	p.line("")
}

// applyFlag is the flag that applies a fix of safety s.
func applyFlag(s lint.Safety) string {
	if s != lint.SafetySafe {
		return "--fix=review"
	}
	return "--fix"
}

// quality writes the findings of the quality rules, by kind in the order
// first seen: each kind with how many, then where, as many as shown unless
// full. They count for nothing in the bits.
func (p *printer) quality(fs []lint.QualityFinding, full bool) {
	if len(fs) == 0 {
		return
	}
	p.line("quality")
	var kinds []lint.FindingKindID
	by := map[lint.FindingKindID][]lint.QualityFinding{}
	for _, f := range fs {
		k := f.Args.KindID()
		if by[k] == nil {
			kinds = append(kinds, k)
		}
		by[k] = append(by[k], f)
	}
	for _, k := range kinds {
		g := by[k]
		p.line("  %s%s", p.paint(bold, k.String()), times(len(g)))
		for i, f := range g {
			if p.cut(i, len(g), full) {
				break
			}
			cond := ""
			if f.Certainty == lint.CertaintyConditional {
				cond = p.paint(gray, " [conditional]")
			}
			p.line("    %s  %s%s", p.loc(f.Location), clean(f.Detected()), cond)
		}
	}
	p.line("")
}

// times is "  ×n", or nothing for one.
func times(n int) string {
	if n == 1 {
		return ""
	}
	return fmt.Sprintf("  ×%d", n)
}

// finding is one finding with its source, evidence and related places;
// tag, when not empty, follows its place.
func (p *printer) finding(r lint.Finding, tag string) {
	at := p.loc(r.Location)
	if tag != "" {
		at += "  " + tag
	}
	p.head(r.Severity, r.KindText(), at)
	p.line("  %s", clean(r.Detected()))
	p.line("  impact: %s", clean(r.Consequence))
	p.added(r.AddedAttackers, "  ")
	p.places(r)
}

// added is the line of the added attackers of a finding or a place that a
// run adding no attacker does not report; none for none.
func (p *printer) added(vs []lint.AddedAttacker, indent string) {
	if len(vs) == 0 {
		return
	}
	names := make([]string, len(vs))
	for i, v := range vs {
		names[i] = v.String()
	}
	label := "added attacker"
	if len(names) > 1 {
		label = "added attackers"
	}
	p.line("%s%s: %s", indent, label, strings.Join(names, ", "))
}

// places are the source of r, its evidence and its related places.
func (p *printer) places(r lint.Finding) {
	p.source(snippet(p.in, r.Location))
	for _, e := range append(append([]lint.Related(nil), r.Evidence...), r.Related...) {
		p.line("    %s  %s", p.loc(e.Location), clean(e.Note))
		p.source(snippet(p.in, e.Location))
	}
}

// source writes the lines snippet gives, the gutter gray.
func (p *printer) source(ls []sourceLine) {
	for _, s := range ls {
		p.line("%s%s", p.paint(gray, s.gutter), s.body)
	}
}

// boldTimes is times with ×n bold: the count of a row of a fold.
func (p *printer) boldTimes(n int) string {
	if n == 1 {
		return ""
	}
	return "  " + p.paint(bold, fmt.Sprintf("×%d", n))
}

func (p *printer) conditional(rcs []ruleConditionals, verbose bool) {
	n := 0
	for _, c := range rcs {
		n += len(c.results)
	}
	if n == 0 {
		return
	}
	p.line("conditional  %s hold only if what is not known here is so", count(n, "finding"))
	for _, c := range rcs {
		p.line("  %s (%s)  %s, %s", p.paint(bold, kindsText(c.kinds)), p.paint(severityColor[c.severity], c.severity.String()), count(len(c.results), "finding"), count(len(c.by), "unknown"))
		for i, d := range c.by {
			if p.cut(i, len(c.by), verbose) {
				break
			}
			p.line("    %s  → %s", d.what(), count(len(d.results), "place"))
		}
		if len(c.why) > 0 {
			p.line("  why: %s", strings.Join(c.why, "; "))
		}
		// every decider, those not shown too
		if slices.ContainsFunc(c.by, func(d decider) bool { return len(d.inputs) > 0 }) {
			p.line("  or give the whole repository (no PATH)")
		}
	}
	p.line("")
	if verbose {
		for _, c := range rcs {
			for _, d := range c.by {
				for _, r := range d.results {
					p.finding(r, "conditional")
					p.line("  decided by: %s", d.what())
					p.line("  remedy: %s", clean(r.Remedy))
					p.line("")
				}
			}
		}
	}
}

// inconclusive writes the findings whose certainty is inconclusive that
// no acceptance matched: how many of each kind of each rule, then each
// finding, as a conditional finding is written; past shown of them, only
// when verbose.
func (p *printer) inconclusive(gaps []lint.Finding, rules []ruleInconclusive, verbose bool) {
	if len(gaps) == 0 {
		return
	}
	p.line("inconclusive  %s: the rules could not decide whether the place of each finding has the problem that the rule of the finding looks for; a person decides", count(len(gaps), "finding"))
	for _, r := range rules {
		var parts []string
		for _, k := range r.kinds {
			parts = append(parts, fmt.Sprintf("%s %d", k.kind, k.n))
		}
		p.line("  %s  %s", p.paint(bold, r.rule.String()), strings.Join(parts, ", "))
	}
	p.line("")
	for i, g := range gaps {
		if p.cut(i, len(gaps), verbose) {
			p.line("")
			break
		}
		p.finding(g, "inconclusive")
		p.line("  remedy: %s", clean(g.Remedy))
		p.line("")
	}
}

// splitAccepted are the findings of gaps that no acceptance matched, and
// those an acceptance matched (lint.Accept), each in the order of gaps.
func splitAccepted(gaps []lint.Finding) (open, accepted []lint.Finding) {
	for _, g := range gaps {
		if g.Acceptance != nil {
			accepted = append(accepted, g)
		} else {
			open = append(open, g)
		}
	}
	return open, accepted
}

// accepted writes how many inconclusive findings --accept accepted: in the
// summary, as a line of it; in full, each with the reason of its entry.
func (p *printer) accepted(gaps []lint.Finding, d detail) {
	if len(gaps) == 0 {
		return
	}
	what := count(len(gaps), "inconclusive finding") + " that an entry of --accept matches; the finding does not set bit 8"
	if len(gaps) > 1 {
		what = count(len(gaps), "inconclusive finding") + " that entries of --accept match; the findings do not set bit 8"
	}
	switch d {
	case detailSummary:
		p.line("%s  %s", padRight("accepted", labelWidth), what)
		return
	case detailNormal:
		p.line("accepted  %s (-v)", what)
	default:
		p.line("accepted  %s", what)
		for _, g := range gaps {
			p.line("    %s  %s %s: accepted: %s", p.loc(g.Location), g.Rule, g.InconclusiveKind, clean(g.Acceptance.Reason))
			p.source(snippet(p.in, g.Location))
		}
	}
	p.line("")
}

// inputCounts are how many inputs are in each state, and whether they are
// all there are.
func (p *printer) inputCounts(rep lint.Report) string {
	reported := rep.ReportedInputs()
	if len(reported) == 0 {
		return "no input"
	}
	by := map[lint.InputState]int{}
	for _, i := range reported {
		by[i.State]++
	}
	var parts []string
	for _, s := range []lint.InputState{lint.InputStateRead, lint.InputStateInvalid, lint.InputStateUnreadable, lint.InputStateExcluded} {
		if by[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", by[s], s))
		}
	}
	scope := "every workflow and action.yml under --root"
	switch {
	case rep.Reported != nil:
		scope = fmt.Sprintf("the PATHs of --read-all; %d more inputs under --root, not reported", len(rep.Inputs)-len(reported))
	case !rep.Complete:
		scope = "not every workflow and action.yml of the repository"
	}
	return fmt.Sprintf("%s  (%s)", strings.Join(parts, ", "), scope)
}

func (p *printer) inputs(rep lint.Report, groups []inputGroup, verbose bool) {
	p.line("inputs  %s", p.inputCounts(rep))
	for _, g := range groups {
		why := g.reason
		if g.diagnostics {
			why = "diagnostics"
		}
		p.line("  %s ×%d: %s", g.state, len(g.inputs), why)
		for i, in := range g.inputs {
			if p.cut(i, len(g.inputs), verbose) {
				break
			}
			p.line("    %s", p.paint(cyan, clean(in.Name.String())))
			if verbose {
				for _, d := range in.Diagnostics {
					p.line("      %s %s: %s", p.lineCol(in.Name, d.Span.Start), d.Code, clean(d.Msg))
					for _, l := range snippet(p.in, lint.Location{File: lint.File{Input: in.Name}, Span: d.Span}) {
						p.line("  %s%s", p.paint(gray, l.gutter), l.body) // under the diagnostic, which is indented more than a place
					}
				}
			}
		}
	}
	p.line("")
}

// labelWidth is the width of the labels of summary: inconclusive, the
// longest.
const labelWidth = len("inconclusive")

// brief is --detail summary: a line for each fold, then a line each for
// the conditional findings of each rule, the inconclusive places, those
// accepted, and the inputs.
func (p *printer) brief(rep lint.Report, v view, accepted []lint.Finding) {
	w := 0
	for _, f := range v.confirmed {
		w = max(w, len(f.kind.String()))
	}
	for _, f := range v.confirmed {
		n := fmt.Sprintf("×%d", f.count())
		if len(f.rows) > 1 {
			n += " (" + count(len(f.rows), "message") + ")"
		}
		p.line("%s  %s  %s  %s", p.paint(severityColor[f.severity], padRight(f.severity.String(), len("critical"))), p.paint(bold, padRight(f.kind.String(), w)), n, p.loc(f.rows[0].results[0].Location))
	}
	if len(v.confirmed) > 0 {
		p.line("")
	}
	for _, c := range v.conditional {
		s := fmt.Sprintf("%s  %s  ×%d, %s", padRight("conditional", labelWidth), p.paint(bold, kindsText(c.kinds)), len(c.results), count(len(c.by), "unknown"))
		if len(c.why) > 0 {
			s += "  (" + strings.Join(c.why, "; ") + ")"
		}
		p.line("%s", s)
	}
	if gaps := rep.FindingsWith(lint.CertaintyInconclusive); len(gaps) > 0 {
		var rules []string
		for _, r := range v.inconclusive {
			rules = append(rules, r.rule.String())
		}
		p.line("%s  %s (%s)", padRight("inconclusive", labelWidth), count(len(gaps), "finding"), strings.Join(rules, ", "))
	}
	p.accepted(accepted, detailSummary)
	p.line("%s  %s", padRight("inputs", labelWidth), p.inputCounts(rep))
	p.line("")
}

// padRight is s with spaces after it, to n bytes; s is ASCII (a severity, an
// ID or a label).
func padRight(s string, n int) string { return s + strings.Repeat(" ", max(0, n-len(s))) }

func (p *printer) errors(errs []lint.RunError) {
	if len(errs) == 0 {
		return
	}
	p.line("errors  %d (a rule or a fix broke its contract; the report is not whole)", len(errs))
	for _, e := range errs {
		p.line("  %s: %s", errorWho(e), clean(e.Message))
	}
	p.line("")
}

// errorWho is the rule and the input of e, as far as it has them.
func errorWho(e lint.RunError) string {
	var who []string
	if !e.Rule.IsZero() {
		who = append(who, e.Rule.String())
	}
	if !e.Input.IsZero() {
		who = append(who, clean(e.Input.String()))
	}
	return strings.Join(who, " ")
}

func (p *printer) fix(f *lint.FixResult) {
	if f == nil {
		return
	}
	p.line("fix (%s)  wrote %s", f.Safety, count(len(f.Written), "file"))
	for _, n := range f.Written {
		p.line("  %s", p.paint(cyan, clean(n.String())))
	}
	if f.Error != "" {
		p.line("  error: %s", clean(f.Error))
	}
	for _, u := range f.UncheckedRules {
		p.line("  %s", uncheckedText(u))
	}
	p.line("")
}

// uncheckedText says that the fixes were not checked against u's rule,
// which did not run, and which fields of it the fixes change, where, and
// by which fix when an edit of it is in the summary.
func uncheckedText(u lint.Unchecked) string {
	var at []string
	for _, c := range u.Changed {
		var fields []string
		for _, f := range c.Fields {
			fields = append(fields, f.String())
		}
		if len(c.By) == 0 {
			at = append(at, "the fixes of "+clean(c.Input.String())+" change "+strings.Join(fields, ", ")+" at "+clean(c.Path))
			continue
		}
		var by []string
		for _, b := range c.By {
			by = append(by, b.Rule.String()+"."+b.Fix.String())
		}
		verb := " changes "
		if len(by) > 1 {
			verb = " change "
		}
		at = append(at, strings.Join(by, ", ")+verb+strings.Join(fields, ", ")+" at "+clean(c.Input.String())+" "+clean(c.Path))
	}
	return "not checked: " + u.Rule.String() + " (skipped; " + strings.Join(at, "; ") + ")"
}

// rules is the line of the rules that ran, when not every rule did: it
// names the fewer of those that ran and those skipped. The quality rules
// count with the rules; a rule its DefaultRun left out, and a rule of
// DefaultRunNamed, count for nothing, since nobody left them out.
func (p *printer) rules(rep lint.Report) {
	var skipped []lint.RuleID
	for _, id := range rep.SkippedRules {
		if !p.reg.DefaultRun(id).IsNamed() && !p.reg.NotRunByDefault(id) {
			skipped = append(skipped, id)
		}
	}
	if len(skipped) == 0 {
		return
	}
	ran := len(rep.Rules) + len(rep.QualityRules)
	all := ran + len(skipped)
	var ids []string
	if ran <= len(skipped) {
		for _, r := range rep.Rules {
			ids = append(ids, r.ID.String())
		}
		for _, id := range rep.QualityRules {
			ids = append(ids, id.String())
		}
		slices.Sort(ids)
		p.line("rules  %d of %d ran: %s", ran, all, strings.Join(ids, ", "))
		return
	}
	for _, id := range skipped {
		ids = append(ids, id.String())
	}
	p.line("rules  %d of %d ran; skipped: %s", ran, all, strings.Join(ids, ", "))
}

// worst writes the rows of the highest severity, at the end, where they
// are seen when the head has scrolled away.
func (p *printer) worst(folds []fold, inconclusive []lint.Finding) {
	rows, more := worst(folds, inconclusive, worstShown)
	if len(rows) == 0 {
		return
	}
	p.line("worst")
	for _, w := range rows {
		tag := ""
		if w.inconclusive {
			tag = "  inconclusive"
		}
		p.line("  %s  %s%s  %s%s", p.paint(severityColor[w.severity], w.severity.String()), p.paint(bold, w.kind), times(len(w.row.results)), p.loc(w.row.results[0].Location), tag)
		p.line("    %s", clean(w.row.detected))
	}
	if more > 0 {
		p.line("  … %d more", more)
	}
	p.line("")
}

func (p *printer) summary(rep lint.Report, threshold lint.Severity) {
	p.rules(rep)
	p.notRun(rep)
	var confirmed, conditional, below int
	bySev := map[lint.Severity]int{}
	decided := rep.FindingsWith(lint.CertaintyConfirmed, lint.CertaintyConditional)
	open, _ := splitAccepted(rep.FindingsWith(lint.CertaintyInconclusive))
	for _, f := range decided {
		if f.Severity < threshold {
			below++
		}
		if f.Certainty == lint.CertaintyConditional {
			conditional++
			continue
		}
		confirmed++
		bySev[f.Severity]++
	}
	var sevs []string
	for s := lint.SeverityCritical; s >= lint.SeverityInfo; s-- {
		if bySev[s] > 0 {
			sevs = append(sevs, fmt.Sprintf("%s %d", s, bySev[s]))
		}
	}
	line := count(len(decided)+len(open), "finding")
	if len(decided)+len(open) > 0 {
		line += fmt.Sprintf(": %d confirmed", confirmed)
		if len(sevs) > 0 {
			line += " (" + strings.Join(sevs, ", ") + ")"
		}
		line += fmt.Sprintf(", %d conditional, %d inconclusive", conditional, len(open))
	}
	p.line("%s", line)
	if n := len(rep.QualityFindings); n > 0 {
		p.line("%s: the bits do not count quality findings", count(n, "quality finding"))
	}
	if below > 0 {
		p.line("%d below --fail-on %s: they count for nothing in the bits", below, threshold)
	}
	if n := inconclusiveBelow(rep, threshold); n > 0 {
		if n == 1 {
			p.line("1 inconclusive finding is of a rule whose severity is below --fail-on %s, and does not count toward bit 8", threshold)
		} else {
			p.line("%d inconclusive findings are of rules whose severity is below --fail-on %s, and do not count toward bit 8", n, threshold)
		}
	}
	code := lint.Classify(rep, threshold)
	if code == 0 {
		p.line("bits 0: nothing at or above %s", threshold)
		return
	}
	var why []string
	if code&lint.ConfirmedBit != 0 {
		why = append(why, "1 (confirmed findings)")
	}
	reasons := lint.ClassifyReasons(rep, threshold)
	if code&lint.UndecidedBit != 0 {
		why = append(why, "2 ("+strings.Join(reasons[lint.UndecidedBit], ", ")+")")
	}
	if code&lint.ErrorBit != 0 {
		why = append(why, "4 (internal errors)")
	}
	if code&lint.InconclusiveBit != 0 {
		why = append(why, "8 (inconclusive findings)")
	}
	if code&lint.UnreadBit != 0 {
		why = append(why, "16 ("+strings.Join(reasons[lint.UnreadBit], ", ")+")")
	}
	p.line("bits %d = %s", code, strings.Join(why, " + "))
}

// notRun is a line for each rule a DefaultRun of facts left out
// (lint.Registry.NotRunByDefault): the rule did not run though nobody left
// it out, and the line says when the rule runs.
func (p *printer) notRun(rep lint.Report) {
	for _, id := range rep.SkippedRules {
		d := p.reg.DefaultRun(id)
		if _, ok := d.FactKinds(); ok && p.reg.NotRunByDefault(id) {
			p.line("not run  %s: %s", id, d.Text())
		}
	}
}

// inconclusiveBelow is how many inconclusive places of rep, not accepted,
// are of rules below threshold, which lint.Classify does not count.
func inconclusiveBelow(rep lint.Report, threshold lint.Severity) int {
	severities := map[lint.RuleID]lint.Severity{}
	for _, r := range rep.Rules {
		severities[r.ID] = r.Severity
	}
	n := 0
	for _, g := range rep.FindingsWith(lint.CertaintyInconclusive) {
		if s, ok := severities[g.Rule]; ok && s < threshold && g.Acceptance == nil {
			n++
		}
	}
	return n
}

// revision is the head of the text of a remote run: the repository and
// the commit it read (lint.RemoteRevision), and a blank line.
func (p *printer) revision(rep lint.Report) {
	r := rep.Remote
	if r == nil {
		return
	}
	line := "remote  " + r.Repository.String() + " at " + r.Commit.String()
	if r.Ref != "" {
		line += " (" + r.Ref + ")"
	}
	p.line("%s", line)
	if pr := r.PullRequest; pr != nil {
		p.line("pull request #%d: head %s, base %s", pr.Number, r.Commit, pr.Base)
		if len(pr.ChangedInputs) == 0 {
			p.line("the pull request changes no workflow and no action.yml")
		}
		if pr.BehindBy > 0 {
			p.line("the base is %s past the merge base: the run read the head, without those commits; run again after updating the head with the base", count(pr.BehindBy, "commit"))
		}
		if pr.BaseChangeCount > 0 {
			p.line("%s that the base changed after the merge base %s: bit 16", count(pr.BaseChangeCount, "path"), plural(pr.BaseChangeCount, "is a workflow, an action.yml or a file the run read", "are workflows, action.yml files or files the run read"))
		}
		if u := pr.UnreportedCount; u.Findings+u.QualityFindings+u.Inconclusive > 0 {
			p.line("the PATHs leave out %d findings (%d of the findings inconclusive) and %d quality findings of the changed inputs; with --pull-request, unlike --read-all, the bits of the exit code count the findings left out too; run without PATHs to see them", u.Findings, u.Inconclusive, u.QualityFindings)
		}
		if pr.AcceptedCount > 0 {
			p.line("%s in the changed inputs %s (a caution, not an error): an entry of --accept matches only the place and its text, and does not see what the pull request changed around the place; read the changes of the pull request around the accepted places", count(pr.AcceptedCount, "accepted inconclusive finding"), plural(pr.AcceptedCount, "is", "are"))
		}
	}
	p.line("")
}

// plural is one when n is 1, and many otherwise.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// count is "1 finding" or "2 findings".
func count(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

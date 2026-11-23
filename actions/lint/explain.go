package lint

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode"

	"github.com/gh-intel/sisakulint/actions/cvss4"
	"github.com/gh-intel/sisakulint/actions/facts"
)

// Explain is the rules and quality rules ids (all of them when ids is empty) as Markdown for
// people, in the order of the registry, each once; commit is the commit of
// the binary. It is CommonMark: every string of the rules' Meta is written
// by MarkdownText, and a Citation as an autolink, so that each is shown as
// it is. The machine-readable form is MarshalJSON;
// this one may change. It reads the examples of an ExampledRule asked for,
// and is an error when the registry refuses them.
func (r *Registry) Explain(ids []RuleID, commit string) ([]byte, error) {
	for _, id := range ids {
		if _, ok := r.meta[id]; !ok {
			return nil, fmt.Errorf("no rule %s in the registry", id)
		}
	}
	var w mdWriter
	w.heading(1, "sisakulint rules")
	w.list([]mdItem{{text: nCommit.is(md(commit))}, {text: nTerms.is(md("sisakulint --explain=terms"))}})
	for _, rule := range r.rules {
		if len(ids) != 0 && !slices.Contains(ids, rule.Meta().ID) {
			continue
		}
		m, err := r.exampledMeta(rule)
		if err != nil {
			return nil, err
		}
		if r.IsQuality(m.ID) {
			explainQualityRule(&w, m)
			continue
		}
		explainRule(&w, m, r.findingFiles(m.ID))
	}
	return []byte(w.b.String()), nil
}

// findingFiles finds, for an example of several files of the rule id, the
// files of the findings of kinds on it: with its facts, or else with flip
// answered the other way, as CheckExamples runs a true positive. The
// examples carry their facts and ask no network, so it runs them without a
// context of its caller's.
func (r *Registry) findingFiles(id RuleID) exampleFiles {
	return func(e Example, kinds []FindingKindID, flip []facts.Kind) []facts.InputPath {
		if len(e.Others) == 0 {
			return nil
		}
		if len(e.Notes.AddedAttackers) != 0 {
			// a true positive of an added attacker: its run, marked
			var out []facts.InputPath
			for _, v := range e.Notes.AddedAttackers {
				run, err := r.runExampleMarked(context.Background(), id, e, v)
				if err != nil {
					return nil // CheckExamples tells the error; the text leaves the line out
				}
				for _, x := range run.Report.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
					if p := x.Location.File.Input; slices.Contains(kinds, x.Args.KindID()) && slices.Contains(x.AddedAttackers, v) && !slices.Contains(out, p) {
						out = append(out, p)
					}
				}
			}
			return out
		}
		for _, f := range [][]facts.Kind{nil, flip} {
			run, err := r.runExample(context.Background(), id, e, f)
			if err != nil {
				return nil // CheckExamples tells the error; the text leaves the line out
			}
			var out []facts.InputPath
			for _, x := range run.Report.FindingsWith(CertaintyConfirmed, CertaintyConditional) {
				if p := x.Location.File.Input; slices.Contains(kinds, x.Args.KindID()) && !slices.Contains(out, p) {
					out = append(out, p)
				}
			}
			if len(out) != 0 || len(flip) == 0 {
				return out
			}
		}
		return nil
	}
}

// exampleFiles gives the files of the findings of kinds on an example of
// several files (Registry.findingFiles); nil for none, or where no example
// is written (ExplainRule).
type exampleFiles func(e Example, kinds []FindingKindID, flip []facts.Kind) []facts.InputPath

// ExplainRule is the section of the rule or quality rule id in Explain,
// without its examples and without the head of the document: what a person
// approves of the rule apart from its examples (a review document), and
// what a tool that shows one rule at a time (the help of a rule in SARIF)
// shows. It runs no example. It is an error for an ID not registered.
func (r *Registry) ExplainRule(id RuleID) ([]byte, error) {
	m, ok := r.meta[id]
	if !ok {
		return nil, fmt.Errorf("no rule %s in the registry", id)
	}
	var w mdWriter
	if r.IsQuality(id) {
		explainQualityRule(&w, m.withoutExamples())
	} else {
		explainRule(&w, m.withoutExamples(), nil)
	}
	return []byte(w.b.String()), nil
}

func explainRule(w *mdWriter, m Meta, files exampleFiles) {
	w.heading(2, md(m.ID.String()))
	items := []mdItem{
		{text: nProblem.is(md(m.Problem))},
		{text: nExpected.is(md(m.Expected))},
		{text: nSeverity.is(md(m.Severity().String()) + worstOfKinds(m))},
		{text: nTargets.is(mdJoin(strs(m.Targets)))},
		facetsItem(m.Facets),
	}
	items = append(items, mdItem{text: nDefaultRun.is(m.DefaultRun.markdown())})
	w.list(items)
	var kinds, fixes, undetected, inconclusive, falsePositives, citations []mdItem
	for _, k := range m.FindingKinds {
		sub := argumentsField([]mdItem{{text: nDetected.is(md(k.Detected))}}, k.FindingText)
		sub = append(sub, mdItem{text: nConsequence.is(md(k.Consequence))}, mdItem{text: nRemedy.is(md(k.Remedy))},
			mdItem{text: nSeverity.is(md(k.Severity().String()) + " (found from the CVSS metrics below by the table)")})
		sub = field(sub, nFixKinds, strs(k.Fixes))
		if len(k.FactKinds) != 0 {
			var ks []string
			for _, f := range k.FactKinds {
				ks = append(ks, factKindText(f))
			}
			sub = append(sub, mdItem{text: nFactKinds.is(strings.Join(ks, ", "))})
		}
		sub = field(sub, nAttackers, strs(k.Attackers))
		sub = field(sub, nPreconditions, strs(k.Preconditions))
		sub = field(sub, nIncidents, strs(k.Incidents))
		sub = examples(sub, nTruePositives, k.TruePositives, ExampleTruePositive, found(files, []FindingKindID{k.ID}, k.FactKinds))
		sub = examples(sub, nTrueNegatives, k.TrueNegatives, ExampleTrueNegative, nil)
		kinds = append(kinds, mdItem{text: md(k.ID.String()), sub: sub})
	}
	for _, f := range m.FixKinds {
		sub := field([]mdItem{{text: nSafety.is(md(f.Safety.String()))}}, nFactKinds, strs(f.FactKinds))
		if len(f.PossibleSideEffects) > 0 {
			it := mdItem{text: nPossibleSideEffects.name + ":"}
			for _, e := range f.PossibleSideEffects {
				it.sub = append(it.sub, mdItem{text: md(e.String()) + ": " + md(e.Text())})
			}
			sub = append(sub, it)
		}
		fixes = append(fixes, mdItem{text: md(f.ID.String()) + ": " + md(f.Title), sub: sub})
	}
	undetected = undetectedItems(m)
	for _, k := range m.InconclusiveKinds {
		inconclusive = append(inconclusive, mdItem{text: md(k.ID.String()) + ": " + md(k.Text), sub: exampleField([]mdItem{{text: nDisposition.is(k.Disposition.markdown())}}, k.Examples, ExampleInconclusive, nil)})
	}
	falsePositives = falsePositiveItems(m, files)
	for _, c := range m.citations() {
		citations = append(citations, mdItem{text: autolink(c)})
	}
	w.group(nFindingKinds.name, kinds)
	w.group(nFixKinds.name, fixes)
	w.group(nUndetectedForms.name, undetected)
	w.group(nInconclusive.name, inconclusive)
	w.group(nFalsePositiveForms.name, falsePositives)
	w.group(nThreat.name, threatItems(m.Threat))
	w.heading(3, nCVSS.name)
	for _, k := range m.FindingKinds {
		w.heading(4, md(k.ID.String()))
		w.list(cvssItems(k))
	}
	w.group(nCitations.name, citations)
}

// explainQualityRule writes the quality rule m (QualityMeta.AsMeta): as a
// rule, without severity, facets, fixes, inconclusive kinds, threat or CVSS.
func explainQualityRule(w *mdWriter, m Meta) {
	w.heading(2, md(m.ID.String()))
	items := []mdItem{
		{text: nProblem.is(md(m.Problem))},
		{text: nExpected.is(md(m.Expected))},
		{text: nTargets.is(mdJoin(strs(m.Targets)))},
		{text: nQuality.is(md("a finding of the quality rule alone gives no attacker a gain, and the findings of the quality rule set no bit of the exit code"))},
	}
	items = append(items, mdItem{text: nDefaultRun.is(m.DefaultRun.markdown())})
	w.list(items)
	var kinds, citations []mdItem
	for _, k := range m.FindingKinds {
		sub := argumentsField([]mdItem{{text: nDetected.is(md(k.Detected))}}, k.FindingText)
		sub = append(sub, mdItem{text: nConsequence.is(md(k.Consequence))}, mdItem{text: nRemedy.is(md(k.Remedy))})
		sub = field(sub, nFactKinds, strs(k.FactKinds))
		sub = examples(sub, nTruePositives, k.TruePositives, ExampleTruePositive, nil)
		sub = examples(sub, nTrueNegatives, k.TrueNegatives, ExampleTrueNegative, nil)
		kinds = append(kinds, mdItem{text: md(k.ID.String()), sub: sub})
	}
	for _, c := range m.citations() {
		citations = append(citations, mdItem{text: autolink(c)})
	}
	w.group(nFindingKinds.name, kinds)
	w.group(nUndetectedForms.name, undetectedItems(m))
	w.group(nFalsePositiveForms.name, falsePositiveItems(m, nil))
	w.group(nCitations.name, citations)
}

// worstOfKinds is what the severity of m is of: the worst of its kinds,
// said when it has more than one.
func worstOfKinds(m Meta) string {
	if len(m.FindingKinds) > 1 {
		return " (the worst of its kinds)"
	}
	return ""
}

// argumentsField is items with the item of the arguments of t, each by
// its {name} and what it holds, when t has arguments.
func argumentsField(items []mdItem, t FindingText) []mdItem {
	if len(t.Arguments) == 0 {
		return items
	}
	it := mdItem{text: nArguments.name + ":"}
	for _, a := range t.Arguments {
		s := md("{"+a.Name.String()+"}") + ": " + md(a.Text)
		if !a.InDetected {
			s += " (not in the text of detected)"
		}
		it.sub = append(it.sub, mdItem{text: s})
	}
	return append(items, it)
}

// undetectedItems are the items of m's undetected forms.
func undetectedItems(m Meta) []mdItem {
	var out []mdItem
	for _, l := range m.UndetectedForms {
		sub := []mdItem{{text: nFindingKinds.is(mdJoin(strs(m.UndetectedKinds(l))))}, {text: nDisposition.is(l.Disposition.markdown())}}
		sub = field(sub, nAddedAttackers, strs(l.AddedAttackers))
		out = append(out, mdItem{text: md(l.ID.String()) + ": " + md(l.Text), sub: exampleField(sub, l.Examples, ExampleUndetected, nil)})
	}
	return out
}

// falsePositiveItems are the items of m's false positive forms; files
// finds the files of the findings of an example of several files.
func falsePositiveItems(m Meta, files exampleFiles) []mdItem {
	var out []mdItem
	for _, f := range m.FalsePositiveForms {
		sub := []mdItem{{text: nFindingKinds.is(mdJoin(strs(f.FindingKinds)))}}
		if !f.Disposition.IsZero() {
			sub = append(sub, mdItem{text: nDisposition.is(f.Disposition.markdown())})
		}
		sub = field(sub, nAddedAttackers, strs(f.AddedAttackers))
		if len(f.FactKinds) != 0 {
			it := mdItem{text: nFactKinds.name + ":"}
			for _, k := range f.FactKinds {
				it.sub = append(it.sub, mdItem{text: factKindText(k)})
			}
			sub = append(sub, it)
		}
		sub = exampleField(sub, f.Examples, ExampleFalsePositive, found(files, f.FindingKinds, m.FalsePositiveFlip(f)))
		out = append(out, mdItem{text: md(f.ID.String()) + ": " + md(f.Text), sub: sub})
	}
	return out
}

// factKindText is the kind of fact k with its provider and its assumed
// value (none for a kind without one).
func factKindText(k facts.Kind) string {
	i := kindInfoOf(k)
	assumed := "none"
	if i.AssumedValue != nil {
		assumed = string(i.AssumedValue)
	}
	return md(k.String()) + " (" + nProvider.is(md(i.Provider.String())) + ", " + nAssumed.is(md(assumed)) + ")"
}

// likelihood is the item of the likelihood of b: why it is what it is,
// when the table says.
func likelihood(b SeverityBasis) string {
	s := nLikelihood.is(md(b.Likelihood.String()))
	var why []string
	if len(b.LikelihoodFrom) > 0 {
		why = append(why, nFrom.name+" "+mdJoin(b.LikelihoodFrom))
	}
	if len(b.LoweredBy) > 0 {
		why = append(why, nLoweredBy.name+" "+mdJoin(b.LoweredBy))
	}
	if len(why) > 0 {
		s += " (" + strings.Join(why, "; ") + ")"
	}
	return s
}

// threatItems are the preconditions, each by its ID, the actors, and the
// incidents, each by its ID: what the kinds refer to.
func threatItems(t Threat) []mdItem {
	var items []mdItem
	for _, p := range t.Preconditions {
		var sub []mdItem
		for _, o := range p.Observed {
			s := nObserved.is(md(o.Date.String()))
			if !o.Runner.IsZero() {
				s += ", " + nRunner.name + " " + md(o.Runner.String())
			}
			sub = append(sub, mdItem{text: s + ": " + md(o.What)})
		}
		items = append(items, mdItem{text: nPrecondition.name + " " + md(p.ID.String()) + ": " + md(p.Text), sub: cites(sub, nCites, p.Cites, false)})
	}
	for _, a := range t.Actors {
		sub := field([]mdItem{{text: nVia.is(md(a.Via))}}, nEvents, strs(a.Events))
		var starters []string
		for _, e := range a.Events {
			starters = append(starters, e.String()+": "+a.RunStarters[e].String())
		}
		sub = field(sub, nRunStarters, starters)
		items = append(items, mdItem{text: nActor.is(md(a.Attacker.String())), sub: field(sub, nGains, strs(a.Gains))})
	}
	for _, x := range t.Incidents {
		s := nIncident.name + " " + md(x.ID.String()) + ": " + md(x.Date.String())
		if !x.CVE.IsZero() {
			s += ", " + md(x.CVE.String())
		}
		sub := []mdItem{{text: nAdvisory.is(autolink(x.Advisory))}}
		sub = field(sub, nCompromised, strs(x.Compromised))
		items = append(items, mdItem{text: s + ": " + md(x.Summary), sub: field(sub, nDownstream, strs(x.Downstream))})
	}
	return items
}

// cvssItems are the vector of k, its scores, how its severity was found,
// and each metric; a metric that cites nothing says so.
func cvssItems(k FindingKind) []mdItem {
	b := k.SeverityBasis()
	sb, sbt, _ := k.scores() // NewRegistry refuses a kind package cvss4 does not score
	score := func(s cvss4.Score) string { return md(s.String()) + " (" + md(ratingOf(s.Tenths()).String()) + ")" }
	items := []mdItem{
		{text: nVector.is(md(k.vector()))},
		{text: nCVSSB.is(score(sb))},
		{text: nCVSSBT.is(score(sbt))},
		{text: nImpact.is(md(b.Impact.String()) + " (" + nFrom.name + " " + mdJoin(b.ImpactFrom) + ")")},
		{text: likelihood(b)},
		{text: nSeverity.is(md(b.Severity.String()) + " (" + nImpact.name + " " + md(b.Impact.String()) + ", " + nLikelihood.name + " " + md(b.Likelihood.String()) +
			"; the table: " + md("sisakulint --explain=terms") + ")")},
	}
	for _, e := range k.metrics() {
		sub := cites([]mdItem{{text: nReason.is(md(e.reason))}}, nCites, e.cites, true)
		items = append(items, mdItem{text: md(e.name) + ": " + md(e.value), sub: sub})
	}
	return items
}

// markdown is c as --explain writes it, with the names of the JSON.
func (c Disposition) markdown() string {
	switch c.kind {
	case dispositionNoAddedGain:
		return md("no-added-gain")
	case dispositionOtherRule:
		return md("other-rule") + " (" + nRule.is(md(c.rule.String())) + ")"
	case dispositionLimitation:
		return md("limitation") + " (" + nDecidedBy.is(md(c.decider.String())) + ")"
	case dispositionTodo:
		return md("todo") + " (" + nNeeds.is(mdJoin(strs(slices.Sorted(slices.Values(c.needs))))) + ")"
	}
	return "" // NewRegistry refuses the zero Disposition
}

// mdItem is an item of a list, with a code block of YAML in it (code, when
// it is not empty) and the items under it.
type mdItem struct {
	text string
	code string
	sub  []mdItem
}

// field is items with the item "n: names", when there are names.
func field(items []mdItem, n itemName, names []string) []mdItem {
	if len(names) == 0 {
		return items
	}
	return append(items, mdItem{text: n.is(mdJoin(names))})
}

// cites is items with the item n and the citations cs under it; when
// there are none, "n: none" if none is said, and nothing otherwise.
func cites(items []mdItem, n itemName, cs []Citation, none bool) []mdItem {
	if len(cs) == 0 {
		if none {
			items = append(items, mdItem{text: n.is("none")})
		}
		return items
	}
	it := mdItem{text: n.name + ":"}
	for _, c := range cs {
		it.sub = append(it.sub, mdItem{text: autolink(c)})
	}
	return append(items, it)
}

// mdWriter writes blocks, a blank line between two.
type mdWriter struct{ b strings.Builder }

func (w *mdWriter) block() {
	if w.b.Len() > 0 {
		w.b.WriteString("\n")
	}
}

func (w *mdWriter) heading(level int, text string) {
	w.block()
	w.b.WriteString(strings.Repeat("#", level) + " " + text + "\n")
}

func (w *mdWriter) list(items []mdItem) {
	w.block()
	w.items(items, 0)
}

func (w *mdWriter) items(items []mdItem, depth int) {
	for _, it := range items {
		w.b.WriteString(strings.Repeat("  ", depth) + "- " + it.text + "\n")
		if it.code != "" {
			w.code(it.code, depth+1)
		}
		w.items(it.sub, depth+1)
	}
}

// code is s as a fenced code block of YAML in an item of the list at
// depth: indented to the item's text (codeBlock).
func (w *mdWriter) code(s string, depth int) {
	w.b.WriteString(codeBlock("yaml", s, strings.Repeat("  ", depth)))
}

// found is files asked of the findings of kinds, with flip, for each
// example; nil when files is.
func found(files exampleFiles, kinds []FindingKindID, flip []facts.Kind) func(Example) []facts.InputPath {
	if files == nil {
		return nil
	}
	return func(e Example) []facts.InputPath { return files(e, kinds, flip) }
}

// exampleItem is the item of the example e of the declaration what: its
// name, input kind and what, and its text as a code block; under it, the
// files of the findings on e when files gives them, then each other file
// of e the same way as e.
func exampleItem(e Example, what ExampleWhat, files func(Example) []facts.InputPath) mdItem {
	it := mdItem{text: md(e.Name.String()) + " (" + md(e.InputKind.String()) + ", " + md(what.String()) + ")", code: e.Text}
	if len(e.Notes.AddedAttackers) != 0 {
		it.sub = append(it.sub, mdItem{text: nAddedAttackers.is(mdJoin(strs(e.Notes.AddedAttackers)))})
	}
	if files != nil {
		if fs := files(e); len(fs) != 0 {
			it.sub = append(it.sub, mdItem{text: nFindingOn.is(mdJoin(strs(fs)))})
		}
	}
	for _, o := range e.Others {
		it.sub = append(it.sub, mdItem{text: md(o.Name.String()) + " (" + md(o.InputKind.String()) + ")", code: o.Text})
	}
	return it
}

// exampleField is items with an item "example: <name> (<input kind>,
// <what>)" and the text of the example as a code block (exampleItem) for
// each of es, the examples of a declaration, in their order.
func exampleField(items []mdItem, es []Example, what ExampleWhat, files func(Example) []facts.InputPath) []mdItem {
	for _, e := range es {
		it := exampleItem(e, what, files)
		it.text = nExample.is(it.text)
		items = append(items, it)
	}
	return items
}

// examples is items with the item n and the examples es of the
// declaration what under it (exampleItem), when there are examples.
func examples(items []mdItem, n itemName, es []Example, what ExampleWhat, files func(Example) []facts.InputPath) []mdItem {
	if len(es) == 0 {
		return items
	}
	it := mdItem{text: n.name + ":"}
	for _, e := range es {
		it.sub = append(it.sub, exampleItem(e, what, files))
	}
	return append(items, it)
}

// paragraph is a paragraph of text.
func (w *mdWriter) paragraph(text string) {
	w.block()
	w.b.WriteString(text + "\n")
}

// group is a heading of the third level and its list; nothing when the
// list is empty.
func (w *mdWriter) group(title string, items []mdItem) {
	if len(items) == 0 {
		return
	}
	w.heading(3, title)
	w.list(items)
}

// md is s as text of Markdown (MarkdownText).
func md(s string) string { return MarkdownText(s) }

// MarkdownText is s as text of Markdown that GitHub shows as s, written as
// s wherever that is so, for the Markdown to be read as it is too. It
// escapes only what CommonMark 0.31.2, its GFM extensions or GitHub would
// read as markup:
//
//   - the spaces and tabs it starts with, which would start an indented
//     code block, as character references;
//   - at its start, what starts a block (startsBlock) and the . or ) after
//     digits that a space follows (an ordered list), by a backslash (after
//     the spaces it starts with, which are character references, none
//     starts a block); and the # it ends with after a space (the end of a
//     heading);
//   - \ * ` ~ and $ (an escape, emphasis, a code span, a strikethrough, a
//     formula) by a backslash, and _ but between two letters or digits,
//     where it is no emphasis;
//   - [ (a link, an image, a task or a footnote) as a character
//     reference, as a backslash before a bracket starts a formula in a
//     renderer with math; for the same reason, ( ) and ] after a backslash
//     of s, which is written \\, as character references;
//   - < before what is not a space (HTML, an autolink) as &lt;, and & that
//     starts a character reference as &amp;;
//   - in a URL that GFM makes a link of its words (http://, https://,
//     ftp:// or www. up to a space), which shows them as they are written,
//     the : or the . that starts it, by a backslash, when anything in it is
//     escaped: the URL is then text.
//
// GitHub shows an emoji for :name: whatever is escaped. It reads s as one
// line.
func MarkdownText(s string) string {
	rs := []rune(s)
	urls := urlEscapes(rs)
	var b strings.Builder
	lead := true
	digits := 0 // the digits s starts with, while it does
	for i, r := range rs {
		lead = lead && (r == ' ' || r == '\t')
		switch {
		case lead:
			fmt.Fprintf(&b, "&#%d;", r)
		case urls[i]:
			b.WriteString("\\" + string(r))
		default:
			b.WriteString(escapeAt(rs, i, digits))
		}
		if r >= '0' && r <= '9' && digits == i {
			digits++
		}
	}
	return b.String()
}

// escapeAt is rs[i] as MarkdownText writes it, but in a URL; digits are
// the digits rs starts with before i, when they are all before it.
func escapeAt(rs []rune, i, digits int) string {
	r := rs[i]
	switch {
	case i == 0 && startsBlock(string(rs)),
		digits > 0 && digits == i && (r == '.' || r == ')') && endsMarker(rs[i+1:]),
		strings.ContainsRune("\\*`~$", r),
		r == '_' && !(i > 0 && i+1 < len(rs) && alnum(rs[i-1]) && alnum(rs[i+1])),
		r == '#' && closesHeading(rs, i):
		return "\\" + string(r)
	case r == '[':
		return "&#91;"
	case strings.ContainsRune("()]", r) && i > 0 && rs[i-1] == '\\':
		return fmt.Sprintf("&#%d;", r)
	case r == '<' && i+1 < len(rs) && rs[i+1] != ' ' && rs[i+1] != '\t':
		return "&lt;"
	case r == '&' && startsReference(rs[i+1:]):
		return "&amp;"
	}
	return string(r)
}

// urlEscapes are the indices of rs to escape by a backslash so that a URL
// GFM would make a link of (http://, https://, ftp:// or www. after no
// letter or digit, up to a space) is text: the : or the . that starts it,
// when escapeAt writes anything else of it otherwise than it is.
func urlEscapes(rs []rune) map[int]bool {
	out := map[int]bool{}
	ls := make([]rune, len(rs)) // rs in lower case, a rune for a rune
	for i, r := range rs {
		ls[i] = unicode.ToLower(r)
	}
	for i := range ls {
		if i > 0 && alnum(rs[i-1]) {
			continue
		}
		at := -1
		head := string(ls[i:min(i+len("https://"), len(ls))]) // the longest prefix asked; not the rest of rs, at each i
		for _, p := range []string{"http://", "https://", "ftp://"} {
			if strings.HasPrefix(head, p) {
				at = i + strings.Index(p, ":")
			}
		}
		if strings.HasPrefix(head, "www.") {
			at = i + 3
		}
		if at < 0 {
			continue
		}
		for j := i; j < len(rs) && rs[j] != ' ' && rs[j] != '\t'; j++ {
			if j != at && escapeAt(rs, j, -1) != string(rs[j]) {
				out[at] = true
				break
			}
		}
	}
	return out
}

// closesHeading is whether rs[i], a #, is in the run of # rs ends with,
// after a space or a tab: the end of a heading, which a heading drops.
func closesHeading(rs []rune, i int) bool {
	j := i
	for j < len(rs) && rs[j] == '#' {
		j++
	}
	k := i
	for k > 0 && rs[k-1] == '#' {
		k--
	}
	return j == len(rs) && k > 0 && (rs[k-1] == ' ' || rs[k-1] == '\t')
}

// startsBlock is whether s starts a block of CommonMark in a line: a
// bullet list (- or + and a space), a thematic break (three - or more,
// and spaces), a heading (# to ###### and a space) or a quote (>).
func startsBlock(s string) bool {
	h := len(s) - len(strings.TrimLeft(s, "#"))
	switch {
	case strings.HasPrefix(s, ">"), strings.Trim(s, "- \t") == "" && strings.Count(s, "-") >= 3:
		return true
	case strings.HasPrefix(s, "-"), strings.HasPrefix(s, "+"):
		return endsMarker([]rune(s[1:]))
	case h >= 1 && h <= 6:
		return endsMarker([]rune(s[h:]))
	}
	return false
}

// endsMarker is whether rs, after the marker of a list or a heading, makes
// it one: rs is empty or starts with a space or a tab.
func endsMarker(rs []rune) bool { return len(rs) == 0 || rs[0] == ' ' || rs[0] == '\t' }

func alnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

func isASCIILetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// startsReference is whether rs, after an &, is the rest of a character
// reference: an optional #, ASCII letters or digits, then ;.
func startsReference(rs []rune) bool {
	if len(rs) > 0 && rs[0] == '#' {
		rs = rs[1:]
	}
	n := 0
	for n < len(rs) && (isASCIILetter(rs[n]) || rs[n] >= '0' && rs[n] <= '9') {
		n++
	}
	return n > 0 && n < len(rs) && rs[n] == ';'
}

// MarkdownCodeBlock is s as a fenced code block of lang at the start of a
// line (codeBlock at depth 0).
func MarkdownCodeBlock(lang, s string) string { return codeBlock(lang, s, "") }

// codeBlock is s as a fenced code block of lang, each line after pad: its
// fence a backquote longer than the longest run of backquotes in s, three
// at least; a blank line of s is left blank, so that no line has spaces at
// its end.
func codeBlock(lang, s, pad string) string {
	run, longest := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	var b strings.Builder
	b.WriteString(pad + fence + lang + "\n")
	for _, l := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if l != "" {
			b.WriteString(pad + l)
		}
		b.WriteString("\n")
	}
	b.WriteString(pad + fence + "\n")
	return b.String()
}

// facetsItem is the facets of a rule: a line of each axis and the values
// the rule has.
func facetsItem(f Facets) mdItem {
	it := mdItem{text: nFacets.name + ":"}
	for _, a := range f.Axes() {
		it.sub = append(it.sub, mdItem{text: md(a.Facet.String()) + ": " + mdJoin(strs(a.Values))})
	}
	return it
}

// mdJoin is each of ss as md writes it, joined by commas.
func mdJoin(ss []string) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = md(s)
	}
	return strings.Join(out, ", ")
}

// autolink is c as an autolink: Citation has no space, control, < or >,
// which an autolink cannot hold, and a backslash in one is itself.
func autolink(c Citation) string { return "<" + c.s + ">" }

func strs[T fmt.Stringer](xs []T) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = x.String()
	}
	return out
}

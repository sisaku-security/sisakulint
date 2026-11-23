package lint

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gh-intel/sisakulint/actions/facts"
)

// DefaultRun is whether a rule runs in a run that does not name the rule
// with --rule: a run that names no rule, and a run of Skip. It is made by
// DefaultRunNamed, DefaultRunFacts and
// DefaultRunGivenFacts; the zero DefaultRun is always, the default run of
// every rule but those.
type DefaultRun struct {
	kind      defaultRunKind
	factKinds []facts.Kind
}

type defaultRunKind uint8

const (
	defaultRunAlways defaultRunKind = iota
	defaultRunNamed
	defaultRunFacts
	defaultRunGivenFacts
)

// DefaultRunNamed is a DefaultRun: the rule runs only when Only names the
// rule.
func DefaultRunNamed() DefaultRun { return DefaultRun{kind: defaultRunNamed} }

// DefaultRunFacts is a DefaultRun: the rule runs when the run asks GitHub,
// or has an answer of a fact of k or more (FactSources), or when Only
// names the rule. It is for a rule that, with no answer of those facts,
// reports every place that needs one of the facts alike (each
// conditional, or each inconclusive), whatever the place's form: such
// results tell no place from another. The kinds of the rule's findings
// that need no fact run with the rule.
func DefaultRunFacts(k facts.Kind, more ...facts.Kind) DefaultRun {
	return DefaultRun{kind: defaultRunFacts, factKinds: append([]facts.Kind{k}, more...)}
}

// DefaultRunGivenFacts is a DefaultRun: the rule runs when the run has an
// answer of a fact of k or more from --facts or --fact (FactSources), or
// when Only names the rule. --online alone does not run the rule: for a
// kind that --online does not answer, or answers only with a token that a
// run in CI does not have, a rule of DefaultRunFacts would run in such a
// run with no answer.
func DefaultRunGivenFacts(k facts.Kind, more ...facts.Kind) DefaultRun {
	return DefaultRun{kind: defaultRunGivenFacts, factKinds: append([]facts.Kind{k}, more...)}
}

// IsNamed is whether d is DefaultRunNamed.
func (d DefaultRun) IsNamed() bool { return d.kind == defaultRunNamed }

// FactKinds are the kinds of facts of d, when d is of DefaultRunFacts or
// of DefaultRunGivenFacts.
func (d DefaultRun) FactKinds() ([]facts.Kind, bool) {
	return slices.Clone(d.factKinds), d.kind == defaultRunFacts || d.kind == defaultRunGivenFacts
}

// FactSources are what a run answers facts from, as a DefaultRun of facts
// asks: whether the run asks GitHub (--online), and the kinds of the facts
// the run was given an answer of, found or absent (--facts, --fact), with
// those a file of facts derives (facts.Store.AnsweredKinds).
type FactSources struct {
	Online        bool
	AnsweredKinds []facts.Kind
}

// holds is whether a rule of d runs by default in a run of src.
func (d DefaultRun) holds(src FactSources) bool {
	switch d.kind {
	case defaultRunNamed:
		return false
	case defaultRunFacts:
		return src.Online || d.answered(src)
	case defaultRunGivenFacts:
		return d.answered(src)
	}
	return true
}

// answered is whether src has an answer of a kind of d.
func (d DefaultRun) answered(src FactSources) bool {
	return slices.ContainsFunc(d.factKinds, func(k facts.Kind) bool { return slices.Contains(src.AnsweredKinds, k) })
}

// check is whether the kinds of facts of d are kinds, each once.
func (d DefaultRun) check() error {
	for i, k := range d.factKinds {
		if _, err := facts.ParseKind(k.String()); err != nil {
			return fmt.Errorf("the DefaultRun: %v is not a kind of fact", k)
		}
		if slices.Contains(d.factKinds[:i], k) {
			return fmt.Errorf("the DefaultRun: the kind %v twice", k)
		}
	}
	return nil
}

// Text is the sentence of d for people (--explain, the text of the CLI).
func (d DefaultRun) Text() string {
	switch d.kind {
	case defaultRunNamed:
		return "the rule runs only when --rule names the rule"
	case defaultRunFacts:
		return "the rule runs, with all its kinds of findings (also those that need no fact), when --rule names the rule; in a run without --rule, the rule runs when --online is given, or when --facts or --fact gives a found or absent answer to any fact of " + d.kindsText()
	case defaultRunGivenFacts:
		return "the rule runs, with all its kinds of findings, when --rule names the rule; in a run without --rule, the rule runs only when --facts or --fact (also the key facts or fact of a configuration file) answers " + d.givenText() + " with found (a value) or with absent (an answer, written in a file of facts or in --fact, that the fact does not exist); a fact that the file of facts and --fact leave out has no answer, and then the rule does not run, and --online alone does not make the rule run either"
	}
	return "in a run without --rule, the rule runs unless --skip-rule names the rule"
}

// kindsText is the kinds of facts of d, joined by or.
func (d DefaultRun) kindsText() string {
	var ks []string
	for _, k := range d.factKinds {
		ks = append(ks, k.String())
	}
	return strings.Join(ks, " or ")
}

// givenText names the kinds of facts of d for the sentence of
// DefaultRunGivenFacts: the fact of the one kind, or a fact of any kind.
func (d DefaultRun) givenText() string {
	if len(d.factKinds) == 1 {
		return "the fact " + d.factKinds[0].String()
	}
	return "a fact of " + d.kindsText()
}

// markdown is d as --explain writes it: the value, then the sentence.
func (d DefaultRun) markdown() string { return md(d.json().DefaultRun) + ": " + md(d.Text()) }

// defaultRunJSON is a DefaultRun as the JSON of a rule holds it: in the
// object of the rule ($defs/meta and $defs/quality-meta of
// schema/registry-v0.json).
type defaultRunJSON struct {
	DefaultRun string       `json:"default_run"`
	FactKinds  []facts.Kind `json:"default_run_fact_kinds,omitempty"`
}

func (d DefaultRun) json() defaultRunJSON {
	switch d.kind {
	case defaultRunNamed:
		return defaultRunJSON{DefaultRun: "named"}
	case defaultRunFacts:
		return defaultRunJSON{DefaultRun: "facts", FactKinds: slices.Clone(d.factKinds)}
	case defaultRunGivenFacts:
		return defaultRunJSON{DefaultRun: "given-facts", FactKinds: slices.Clone(d.factKinds)}
	}
	return defaultRunJSON{DefaultRun: "always"}
}

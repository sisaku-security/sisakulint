package reportview

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/internal/attackrun"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// Catalog is what an example catalog shows: for each rule, the examples of
// its declarations, whether each is what its declaration says, and the
// page of each run.
type Catalog struct {
	Rules    []CatalogRule    `json:"rules"`
	Boundary *CatalogBoundary `json:"boundary"`
	// Facets are the axes the page groups the rules by (lint.FacetAxes),
	// each with all its values.
	Facets []CatalogFacet `json:"facets"`
	// Terms are what the terms say, for the page to show them and to
	// tell what a key and a value of the meta of a rule mean.
	Terms CatalogTerms `json:"terms"`
	// Advisories are the advisories whose form an example is (the notes
	// advisory of the examples), in the order of their keys.
	Advisories []CatalogAdvisory `json:"advisories"`
}

// CatalogAdvisory is an advisory's page, and the examples whose form is
// the advisory's, in the order of the rules and their entries.
type CatalogAdvisory struct {
	ID      lint.AdvisoryID        `json:"id"`
	URL     lint.Citation          `json:"url"`
	Entries []CatalogAdvisoryEntry `json:"entries"`
}

// CatalogAdvisoryEntry is an example of a CatalogAdvisory: its rule, the
// index of its CatalogEntry among the entries of the rule (two examples of
// several files have the same name, called.yml), and the values of the
// entry.
type CatalogAdvisoryEntry struct {
	Rule    lint.RuleID `json:"rule"`
	Entry   int         `json:"entry"`
	What    exampleWhat `json:"what"`
	ID      string      `json:"id"`
	Example string      `json:"example"`
	Holds   bool        `json:"holds"`
}

// CatalogTerms are the terms (lint.Definitions), and which of them each key
// of the meta of a rule has, by its registry path (lint.TermPathsOf).
type CatalogTerms struct {
	Definitions lint.TermDefinitions `json:"definitions"`
	Paths       lint.TermPaths       `json:"paths"`
}

// CatalogFacet is an axis of the facets of the rules: its key in the facets
// of a rule's meta, what it is, and its values in the order of the schema.
type CatalogFacet struct {
	Facet       lint.Facet          `json:"facet"`
	Key         string              `json:"key"`
	Description string              `json:"description"`
	Values      []CatalogFacetValue `json:"values"`
}

// CatalogFacetValue is a value of an axis, and what it is.
type CatalogFacetValue struct {
	Value       lint.FacetValue `json:"value"`
	Description string          `json:"description"`
}

// catalogFacets are the axes of lint.FacetAxes as the page reads them.
func catalogFacets() []CatalogFacet {
	var out []CatalogFacet
	for _, a := range lint.FacetAxes() {
		f := CatalogFacet{Facet: a.Facet, Key: a.Facet.Key(), Description: a.Facet.Description(), Values: []CatalogFacetValue{}}
		for _, v := range a.Values {
			f.Values = append(f.Values, CatalogFacetValue{v, v.Description()})
		}
		out = append(out, f)
	}
	return out
}

// CatalogRule is a rule or a quality rule (Quality), its Meta or
// QualityMeta as the registry's JSON has it without the examples
// (lint.Registry.MetaJSON), and the examples of its declarations, in the
// order CheckExamples gives them.
type CatalogRule struct {
	Rule    lint.RuleID     `json:"rule"`
	Quality bool            `json:"quality"`
	Meta    json.RawMessage `json:"meta"`
	Entries []CatalogEntry  `json:"entries"`
	// MetaReviewed and Reviewed are whether a person approved the rule's
	// Meta, and the rule with all its examples, as they are now
	// (ReviewStatus).
	MetaReviewed bool `json:"meta_reviewed"`
	Reviewed     bool `json:"reviewed"`
	// Arguments are the arguments of each kind of the rule that has any,
	// which the registry's JSON does not have.
	Arguments map[lint.FindingKindID][]CatalogArgument `json:"arguments"`
}

// CatalogArgument is an argument of a kind (lint.KindArgument).
type CatalogArgument struct {
	Name       lint.KindArgumentName `json:"name"`
	Text       string                `json:"text"`
	InDetected bool                  `json:"in_detected"`
}

// catalogArguments are the arguments of the kinds that have any.
func catalogArguments(kinds []lint.FindingText) map[lint.FindingKindID][]CatalogArgument {
	out := map[lint.FindingKindID][]CatalogArgument{}
	for _, k := range kinds {
		for _, a := range k.Arguments {
			out[k.ID] = append(out[k.ID], CatalogArgument{Name: a.Name, Text: a.Text, InDetected: a.InDetected})
		}
	}
	return out
}

// ReviewStatus is what a person approved of the rules as they are now
// (rules.ReviewState).
type ReviewStatus interface {
	ExampleReviewed(rule lint.RuleID, what lint.ExampleWhat, e lint.Example) bool
	MetaReviewed(rule lint.RuleID) bool
	RuleReviewed(rule lint.RuleID) bool
}

// CatalogEntry is an example of a declaration and what came of it. The
// texts are for the page's script to show.
type CatalogEntry struct {
	What    exampleWhat `json:"what"`
	ID      string      `json:"id"`      // the declaration's ID, to show
	Text    string      `json:"text"`    // what the declaration says
	Example string      `json:"example"` // the name of the example's file
	Holds   bool        `json:"holds"`
	Why     string      `json:"why,omitempty"`
	// Situation, Reason and Cause are the example's notes (lint.ExampleNotes).
	Situation string `json:"situation"`
	Reason    string `json:"reason"`
	Cause     string `json:"cause,omitempty"`
	// Attack, AttackCarrier, AttackValue and AttackRunBehavior are the
	// example's notes of the attack; Substitutions, the values with the
	// attack value put in; Checked, whether a test runs it
	// (attackrun.Check).
	Attack            string                   `json:"attack,omitempty"`
	AttackCarrier     string                   `json:"attack_carrier,omitempty"`
	AttackValue       string                   `json:"attack_value,omitempty"`
	AttackRunBehavior string                   `json:"attack_run_behavior,omitempty"`
	Substitutions     []attackrun.Substitution `json:"substitutions,omitempty"`
	Checked           string                   `json:"checked,omitempty"`
	// Advisories are the pages of the advisories whose form the example
	// is (lint.ExampleNotes.Advisories).
	Advisories []lint.AdvisoryPage `json:"advisories,omitempty"`
	// Sources are the files of repositories whose steps the example
	// reproduces, for a form no advisory reports (lint.ExampleNotes.Sources).
	Sources []lint.SourceFile `json:"sources,omitempty"`
	// Reviewed is whether a person approved the example as it is now
	// (ReviewStatus.ExampleReviewed).
	Reviewed bool         `json:"reviewed"`
	Runs     []CatalogRun `json:"runs"`
}

// CatalogRun is a run of an example: the facts it ran with, or the added
// attacker it adds, to show, the page of the rule of its declaration, and
// the page of every rule on the example run the same way
// (lint.Registry.RunExampleAs). FactLines and
// AllFactLines are the facts the rule, and every rule, asked and their
// answers (lint.ExampleRun.FactLines).
type CatalogRun struct {
	Facts        string   `json:"facts"`
	Page         Page     `json:"page"`
	AllRules     Page     `json:"all_rules"`
	FactLines    []string `json:"fact_lines"`
	AllFactLines []string `json:"all_fact_lines"`
}

// exampleWhat is a lint.ExampleWhat as the script reads it.
type exampleWhat lint.ExampleWhat

func (w exampleWhat) MarshalJSON() ([]byte, error) { return json.Marshal(lint.ExampleWhat(w).String()) }

// BuildCatalog is the catalog of checks, with the Meta of each rule of
// them from reg, and each run again with every rule of reg. markers are
// the rules whose examples a test runs (rules.AttackMarkers); review, what a
// person approved, or nil for nothing. The checks may be of rules and of
// quality rules.
func BuildCatalog(ctx context.Context, reg *lint.Registry, checks []lint.ExampleCheck, markers map[lint.RuleID]attackrun.Marker, review ReviewStatus) (Catalog, error) {
	metas, err := reg.MetaJSON()
	if err != nil {
		return Catalog{}, err
	}
	var actors []lint.Actor
	for _, r := range reg.Rules() {
		actors = append(actors, r.Meta().Threat.Actors...)
	}
	bd, err := buildBoundary(actors)
	if err != nil {
		return Catalog{}, err
	}
	c := Catalog{Rules: []CatalogRule{}, Boundary: bd, Facets: catalogFacets(), Terms: CatalogTerms{lint.Definitions(), lint.TermPathsOf()}}
	for _, x := range checks {
		if n := len(c.Rules); n == 0 || c.Rules[n-1].Rule != x.Rule {
			var kinds []lint.FindingText
			if q, ok := reg.QualityMeta(x.Rule); ok {
				for _, k := range q.FindingKinds {
					kinds = append(kinds, k.FindingText)
				}
			} else {
				m, _ := reg.Meta(x.Rule)
				for _, k := range m.FindingKinds {
					kinds = append(kinds, k.FindingText)
				}
			}
			r := CatalogRule{Rule: x.Rule, Quality: reg.IsQuality(x.Rule), Meta: metas[x.Rule], Entries: []CatalogEntry{}, Arguments: catalogArguments(kinds)}
			if review != nil {
				r.MetaReviewed, r.Reviewed = review.MetaReviewed(x.Rule), review.RuleReviewed(x.Rule)
			}
			c.Rules = append(c.Rules, r)
		}
		e := CatalogEntry{What: exampleWhat(x.What), ID: x.Declaration.String(), Text: x.Text, Example: x.Example.Name.String(), Holds: x.Holds, Why: x.Why, Situation: x.Example.Notes.Situation, Reason: x.Example.Notes.Reason, Cause: x.Example.Notes.Cause, Runs: []CatalogRun{}}
		if review != nil {
			e.Reviewed = review.ExampleReviewed(x.Rule, x.What, x.Example)
		}
		n := x.Example.Notes
		e.Attack, e.AttackRunBehavior = n.Attack, n.AttackRunBehavior
		if !n.AttackValue.IsZero() {
			e.AttackCarrier, e.AttackValue = n.AttackValue.Carrier(), n.AttackValue.Value()
		}
		e.Advisories, e.Sources = n.Advisories, n.Sources
		e.Substitutions = attackrun.Substitute(x.Example)
		e.Checked = attackrun.Check(x.Example, markers[x.Rule])
		for _, run := range x.Runs {
			p, err := runPage(run, reg)
			if err != nil {
				return Catalog{}, err
			}
			every, err := reg.RunExampleAs(ctx, x.Example, run)
			if err != nil {
				return Catalog{}, err
			}
			all, err := runPage(every, reg)
			if err != nil {
				return Catalog{}, err
			}
			name := "answers"
			switch {
			case len(run.Added) != 0:
				var vs []string
				for _, v := range run.Added {
					vs = append(vs, v.String())
				}
				name = "added attacker: " + strings.Join(vs, ", ")
			case len(run.Flipped) != 0:
				var ks []string
				for _, k := range run.Flipped {
					ks = append(ks, k.String())
				}
				name = "flipped: " + strings.Join(ks, ", ")
			}
			e.Runs = append(e.Runs, CatalogRun{Facts: name, Page: p, AllRules: all, FactLines: run.FactLines(), AllFactLines: every.FactLines()})
		}
		r := &c.Rules[len(c.Rules)-1]
		r.Entries = append(r.Entries, e)
	}
	c.Advisories = catalogAdvisories(c.Rules)
	return c, nil
}

// catalogAdvisories are the advisories of the entries of rules, in the
// order of their keys.
func catalogAdvisories(rules []CatalogRule) []CatalogAdvisory {
	by := map[lint.AdvisoryID]*CatalogAdvisory{}
	for _, r := range rules {
		for i, e := range r.Entries {
			for _, p := range e.Advisories {
				a, ok := by[p.ID()]
				if !ok {
					a = &CatalogAdvisory{ID: p.ID(), URL: p.URL()}
					by[a.ID] = a
				}
				a.Entries = append(a.Entries, CatalogAdvisoryEntry{Rule: r.Rule, Entry: i, What: e.What, ID: e.ID, Example: e.Example, Holds: e.Holds})
			}
		}
	}
	keys := slices.SortedFunc(maps.Keys(by), func(a, b lint.AdvisoryID) int { return strings.Compare(a.String(), b.String()) })
	out := []CatalogAdvisory{}
	for _, k := range keys {
		out = append(out, *by[k])
	}
	return out
}

// runPage is the page of run, with every file of the example: an example
// is shown whole, also a file nothing is found in, so that the pages of a
// run show the same files.
func runPage(run lint.ExampleRun, reg *lint.Registry) (Page, error) {
	p, err := Build(run.Report, run.Inputs, reg)
	if err != nil {
		return Page{}, err
	}
	p.Files = filesOfInputs(run.Inputs)
	return p, nil
}

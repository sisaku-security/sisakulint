package lint

import "github.com/gh-intel/sisakulint/actions/facts"

// Definition is a name and what it means, as the terms say: an item name,
// a word in the texts, or a value of an enumeration. Text is not escaped
// for Markdown.
type Definition struct {
	Name string `json:"name"`
	Text string `json:"text"`
	// Items are what the text has under it, one to an item of a list, not
	// escaped for Markdown either: the symbols and the formulas of the
	// credential premise.
	Items []string `json:"items,omitempty"`
}

// ValueGroupID is a value group: the name of its definition in
// schema/registry-v0.json ($defs), fact-kind for the kinds of facts. The
// value groups of Definitions are all there are; the variables below and
// facetGroup make them.
type ValueGroupID struct{ def string }

var (
	vgAttacker           = ValueGroupID{"attacker"}
	vgRunStarter         = ValueGroupID{"run-starter"}
	vgGain               = ValueGroupID{"gain"}
	vgDisposition        = ValueGroupID{"disposition"}
	vgNeed               = ValueGroupID{"need"}
	vgAddedAttacker      = ValueGroupID{"added-attacker"}
	vgDecider            = ValueGroupID{"decider"}
	vgSafety             = ValueGroupID{"safety"}
	vgSeverity           = ValueGroupID{"severity"}
	vgLikelihood         = ValueGroupID{"likelihood"}
	vgInputKind          = ValueGroupID{"input-kind"}
	vgFactKind           = ValueGroupID{"fact-kind"}
	vgAttackVector       = ValueGroupID{"attack-vector"}
	vgAttackComplexity   = ValueGroupID{"attack-complexity"}
	vgAttackRequirements = ValueGroupID{"attack-requirements"}
	vgPrivilegesRequired = ValueGroupID{"privileges-required"}
	vgUserInteraction    = ValueGroupID{"user-interaction"}
	vgImpact             = ValueGroupID{"impact"}
	vgExploitMaturity    = ValueGroupID{"exploit-maturity"}
	vgScoreRating        = ValueGroupID{"score-rating"}
)

// facetGroup is the value group of the axis f of the facets.
func facetGroup(f Facet) ValueGroupID { return ValueGroupID{f.String()} }

func (id ValueGroupID) String() string { return id.def }

func (id ValueGroupID) MarshalText() ([]byte, error) { return []byte(id.def), nil }

// ValueGroup is the values of an enumeration the terms write, each with
// what it means, under Heading. Where Description is not empty, Terms writes
// it as a paragraph under the heading. A CVSS group is written under the
// heading CVSS, its own heading "Heading: Description".
type ValueGroup struct {
	ID          ValueGroupID `json:"id"`
	Heading     string       `json:"heading"`
	Description string       `json:"description,omitempty"`
	CVSS        bool         `json:"cvss,omitempty"`
	Values      []Definition `json:"values"`
}

// TermDefinitions is what the terms say, in their order: what the item
// names are, the item names, the words in the texts, and the value groups.
type TermDefinitions struct {
	ItemNamesDescription string       `json:"item_names_description"`
	ItemNames            []Definition `json:"item_names"`
	TextTerms            []Definition `json:"text_terms"`
	ValueGroups          []ValueGroup `json:"value_groups"`
}

// Definitions is what the terms say, which Terms writes as Markdown and an
// example catalog shows.
func Definitions() TermDefinitions {
	d := TermDefinitions{ItemNamesDescription: itemNamesDoc}
	for _, n := range itemNames {
		d.ItemNames = append(d.ItemNames, Definition{Name: n.name, Text: n.doc})
	}
	for _, t := range textTerms {
		d.TextTerms = append(d.TextTerms, Definition{Name: t.name, Text: t.doc, Items: t.items})
	}
	group := func(id ValueGroupID, heading, description string, cvss bool, vs []Definition) {
		d.ValueGroups = append(d.ValueGroups, ValueGroup{id, heading, description, cvss, vs})
	}
	group(vgAttacker, "attacker", "", false, valueDefinitions(attackerValues()))
	group(vgRunStarter, "run-starter", "", false, valueDefinitions(runStarterValues()))
	group(vgGain, "gain", "", false, valueDefinitions(gainValues()))
	for _, a := range FacetAxes() {
		var vs []Definition
		for _, v := range a.Values {
			vs = append(vs, Definition{Name: v.String(), Text: v.Description()})
		}
		group(facetGroup(a.Facet), a.Facet.String(), a.Facet.Description(), false, vs)
	}
	var dispositions []Definition
	for _, c := range dispositionValues {
		dispositions = append(dispositions, Definition{Name: c.name, Text: c.doc})
	}
	group(vgDisposition, "disposition", "", false, dispositions)
	group(vgNeed, "need", "", false, valueDefinitions(needValues()))
	group(vgAddedAttacker, "added-attacker", addedAttackerDescription, false, valueDefinitions(addedAttackerValues()))
	group(vgDecider, "decider", "", false, valueDefinitions(deciderValues()))
	group(vgSafety, "safety", "", false, valueDefinitions(safetyValues()))
	group(vgSeverity, "severity", severityDescription, false, valueDefinitions(severityValues()))
	group(vgLikelihood, "likelihood", likelihoodDescription, false, valueDefinitions(likelihoodValues()))
	group(vgInputKind, "input-kind", "", false, valueDefinitions(inputKindValues()))
	var fs []Definition
	for _, k := range facts.Kinds() {
		if k.Provider != facts.ProviderTest {
			fs = append(fs, Definition{Name: k.Kind.String(), Text: k.Description, Items: factKindItems(k)})
		}
	}
	group(vgFactKind, "facts", "", false, fs)
	group(vgAttackVector, "AV", attackVectorDescription, true, valueDefinitions(attackVectorValues()))
	group(vgAttackComplexity, "AC", attackComplexityDescription, true, valueDefinitions(attackComplexityValues()))
	group(vgAttackRequirements, "AT", attackRequirementsDescription, true, valueDefinitions(attackRequirementsValues()))
	group(vgPrivilegesRequired, "PR", privilegesRequiredDescription, true, valueDefinitions(privilegesRequiredValues()))
	group(vgUserInteraction, "UI", userInteractionDescription, true, valueDefinitions(userInteractionValues()))
	group(vgImpact, "VC, VI, VA, SC, SI, SA", impactDescription, true, valueDefinitions(impactValues()))
	group(vgExploitMaturity, "E", exploitMaturityDescription, true, valueDefinitions(exploitMaturityValues()))
	group(vgScoreRating, "CVSS-B, CVSS-BT", scoreRatingDescription, true, valueDefinitions(scoreRatingValues()))
	return d
}

// factKindItems are what the terms say under the kind of fact k: where
// its facts come from, whether --online answers them, and the answer that
// removes the findings of the false positive forms that name k.
func factKindItems(k facts.KindInfo) []string {
	return []string{nProvider.is(k.Provider.String() + ": " + k.Provider.Description()), onlineLines[facts.OnlineAnswerOf(k.Kind)], nRemovingAnswer.is(removingAnswerOf(k))}
}

// onlineLines are what the terms say of each facts.OnlineAnswer.
var onlineLines = map[facts.OnlineAnswer]string{
	facts.OnlineNone:                 "--online does not answer the facts of the kind",
	facts.OnlineAll:                  "--online answers the facts of the kind",
	facts.OnlineNamedRepository:      "--online answers a fact of the kind only when the fact names a repository (--repo)",
	facts.OnlineNamedRepositoryFalse: "--online answers a fact of the kind only when the fact names a repository (--repo), and only when the answer is false",
}

// removingAnswerOf is the answer that removes the findings of the false
// positive forms that name the kind of fact k, and when to write it; none
// for a kind without x-assume, which no false positive form names.
func removingAnswerOf(k facts.KindInfo) string {
	if k.AssumedValue == nil {
		return "none"
	}
	return removingAnswer(k) + " (" + k.AssumedReason + ")"
}

// removingAnswer is the boolean other than the x-assume value of k: the
// answer with which the findings of the false positive forms that name k
// do not hold (none for a kind without x-assume).
func removingAnswer(k facts.KindInfo) string {
	switch string(k.AssumedValue) {
	case "true":
		return "false"
	case "false":
		return "true"
	}
	return "none"
}

// valueDefinitions are vs, each with what it is.
func valueDefinitions[T described](vs []T) []Definition {
	var out []Definition
	for _, v := range vs {
		out = append(out, Definition{Name: v.String(), Text: v.description()})
	}
	return out
}

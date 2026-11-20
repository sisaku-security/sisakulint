package lint

// RegistryPath is where a key is in the JSON of a rule of the registry:
// the keys from the object of the rule to the key, joined by dots, the
// arrays on the way left out (threat.actors.run_starters). A key means a
// different thing in a different place (preconditions under a finding kind
// is a list of IDs, under the threat the preconditions themselves), so the
// terms are looked up by the path.
type RegistryPath struct{ keys string }

// registryPath is the registry path p; only the tables below make one.
func registryPath(p string) RegistryPath { return RegistryPath{p} }

func (p RegistryPath) String() string { return p.keys }

func (p RegistryPath) MarshalText() ([]byte, error) { return []byte(p.keys), nil }

// child is the path of the key k under p.
func (p RegistryPath) child(k string) RegistryPath {
	if p.keys == "" {
		return RegistryPath{k}
	}
	return RegistryPath{p.keys + "." + k}
}

// MetricName is the name of a metric of CVSS v4.0 that a finding kind
// gives a value (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA, E); the table
// metricGroups makes them.
type MetricName struct{ name string }

func (m MetricName) String() string { return m.name }

func (m MetricName) MarshalText() ([]byte, error) { return []byte(m.name), nil }

// TermPaths says which terms are of the keys of the JSON of a rule of the
// registry: the item name of a key, the value group of its values, the
// value group whose heading and description a facet axis key has, and the
// value group of the value of a CVSS metric by the name of the metric.
type TermPaths struct {
	ItemNames map[RegistryPath]itemName     `json:"item_names"`
	Values    map[RegistryPath]ValueGroupID `json:"values"`
	Axes      map[RegistryPath]ValueGroupID `json:"axes"`
	Metrics   map[MetricName]ValueGroupID   `json:"metrics"`
}

// itemNamePaths are the paths of each item name that is a key of the JSON
// of a rule.
var itemNamePaths = []struct {
	n     itemName
	paths []string
}{
	{nProblem, []string{"problem"}},
	{nExpected, []string{"expected"}},
	{nSeverity, []string{"severity", "finding_kinds.severity"}},
	{nTargets, []string{"targets"}},
	{nDefaultRun, []string{"default_run", "default_run_fact_kinds"}},
	{nFacets, []string{"facets"}},
	{nFindingKinds, []string{"finding_kinds", "false_positive_forms.finding_kinds", "undetected_forms.finding_kinds"}},
	{nDetected, []string{"finding_kinds.detected"}},
	{nConsequence, []string{"finding_kinds.consequence"}},
	{nImpact, []string{"finding_kinds.severity_basis.impact"}},
	{nRemedy, []string{"finding_kinds.remedy"}},
	{nFixKinds, []string{"fix_kinds", "finding_kinds.fixes"}},
	{nFactKinds, []string{"finding_kinds.fact_kinds", "fix_kinds.fact_kinds", "false_positive_forms.fact_kinds"}},
	{nSafety, []string{"fix_kinds.safety"}},
	{nPossibleSideEffects, []string{"fix_kinds.possible_side_effects"}},
	{nUndetectedForms, []string{"undetected_forms"}},
	{nInconclusive, []string{"inconclusive_kinds"}},
	{nFalsePositiveForms, []string{"false_positive_forms"}},
	{nProvider, []string{"false_positive_forms.fact_kinds.provider"}},
	{nDisposition, []string{"undetected_forms.disposition", "inconclusive_kinds.disposition", "false_positive_forms.disposition"}},
	{nRule, []string{"undetected_forms.rule"}},
	{nDecidedBy, []string{"undetected_forms.decided_by", "inconclusive_kinds.decided_by", "false_positive_forms.decided_by"}},
	{nNeeds, []string{"undetected_forms.needs", "inconclusive_kinds.needs", "false_positive_forms.needs"}},
	{nAddedAttackers, []string{"undetected_forms.added_attackers", "false_positive_forms.added_attackers"}},
	{nThreat, []string{"threat"}},
	{nPreconditions, []string{"finding_kinds.preconditions"}},
	{nPrecondition, []string{"threat.preconditions"}},
	{nObserved, []string{"threat.preconditions.observed"}},
	{nRunner, []string{"threat.preconditions.observed.runner"}},
	{nCites, []string{"threat.preconditions.cites", "finding_kinds.cvss.metrics.cites"}},
	{nAttackers, []string{"finding_kinds.attackers"}},
	{nActor, []string{"threat.actors"}},
	{nVia, []string{"threat.actors.via"}},
	{nEvents, []string{"threat.actors.events", "threat.actors.run_starters.event"}},
	{nRunStarters, []string{"threat.actors.run_starters"}},
	{nGains, []string{"threat.actors.gains"}},
	{nIncidents, []string{"finding_kinds.incidents"}},
	{nIncident, []string{"threat.incidents"}},
	{nAdvisory, []string{"threat.incidents.advisory"}},
	{nCompromised, []string{"threat.incidents.compromised"}},
	{nDownstream, []string{"threat.incidents.downstream"}},
	{nCVSS, []string{"finding_kinds.cvss"}},
	{nVector, []string{"finding_kinds.cvss.vector"}},
	{nCVSSB, []string{"finding_kinds.cvss.b"}},
	{nCVSSBT, []string{"finding_kinds.cvss.bt"}},
	{nLikelihood, []string{"finding_kinds.severity_basis.likelihood"}},
	{nFrom, []string{"finding_kinds.severity_basis.impact.from", "finding_kinds.severity_basis.likelihood.from"}},
	{nLoweredBy, []string{"finding_kinds.severity_basis.likelihood.lowered_by"}},
	{nReason, []string{"finding_kinds.cvss.metrics.reason"}},
	{nCitations, []string{"citations"}},
}

// itemNamesWithoutPath are the item names that are no key of the JSON of a
// rule an example catalog shows, each with why.
var itemNamesWithoutPath = []struct {
	n   itemName
	why string
}{
	{nCommit, "the commit of the binary, which --explain writes and the JSON of a rule does not have"},
	{nTerms, "the command that writes the terms, which --explain writes"},
	{nQuality, "a quality rule, which --explain says of itself; an example catalog shows no quality rule"},
	{nExample, "the example of a declaration, which the JSON of a rule an example catalog shows leaves out"},
	{nTruePositives, "examples, which the JSON of a rule an example catalog shows leaves out"},
	{nTrueNegatives, "examples, which the JSON of a rule an example catalog shows leaves out"},
	{nAssumed, "the assumed value of a kind of fact, which the terms and --explain write and the JSON of a rule does not have"},
	{nFindingOn, "the files of the findings on an example, which the JSON of a rule leaves out with the examples"},
	{nArguments, "the arguments of a kind, which the JSON of a rule leaves out; an example catalog shows the arguments from data of its own"},
}

// valuePaths are the paths whose values are of each value group.
var valuePaths = []struct {
	group ValueGroupID
	paths []string
}{
	{vgAttacker, []string{"finding_kinds.attackers", "threat.actors.attacker"}},
	{vgRunStarter, []string{"threat.actors.run_starters.run_starter"}},
	{vgGain, []string{"threat.actors.gains"}},
	{vgDisposition, []string{"undetected_forms.disposition", "inconclusive_kinds.disposition", "false_positive_forms.disposition"}},
	{vgNeed, []string{"undetected_forms.needs", "inconclusive_kinds.needs", "false_positive_forms.needs"}},
	{vgAddedAttacker, []string{"undetected_forms.added_attackers", "false_positive_forms.added_attackers"}},
	{vgDecider, []string{"undetected_forms.decided_by", "inconclusive_kinds.decided_by", "false_positive_forms.decided_by"}},
	{vgSafety, []string{"fix_kinds.safety"}},
	{vgSeverity, []string{"severity", "finding_kinds.severity"}},
	{vgLikelihood, []string{"finding_kinds.severity_basis.likelihood.level"}},
	{vgInputKind, []string{"targets"}},
	{vgFactKind, []string{"default_run_fact_kinds", "finding_kinds.fact_kinds", "fix_kinds.fact_kinds", "false_positive_forms.fact_kinds.kind"}},
	{vgImpact, []string{"finding_kinds.severity_basis.impact.level"}},
	{vgScoreRating, []string{"finding_kinds.cvss.b.rating", "finding_kinds.cvss.bt.rating"}},
}

// metricGroups are the value groups of the values of the CVSS metrics, by
// the name of the metric.
var metricGroups = []struct {
	m     MetricName
	group ValueGroupID
}{
	{MetricName{"AV"}, vgAttackVector}, {MetricName{"AC"}, vgAttackComplexity}, {MetricName{"AT"}, vgAttackRequirements},
	{MetricName{"PR"}, vgPrivilegesRequired}, {MetricName{"UI"}, vgUserInteraction},
	{MetricName{"VC"}, vgImpact}, {MetricName{"VI"}, vgImpact}, {MetricName{"VA"}, vgImpact},
	{MetricName{"SC"}, vgImpact}, {MetricName{"SI"}, vgImpact}, {MetricName{"SA"}, vgImpact},
	{MetricName{"E"}, vgExploitMaturity},
}

// pathsWithoutItemName are the keys of the JSON of a rule with no item
// name, each with why; a key whose values are of a value group is in
// valuePaths too.
var pathsWithoutItemName = []struct {
	p   string
	why string
}{
	{"id", "the ID of the rule"},
	{"finding_kinds.id", "the ID of the kind"},
	{"finding_kinds.severity_basis", "how the severity is found, which --explain writes in the item severity"},
	{"finding_kinds.severity_basis.impact.level", "the impact (values: impact)"},
	{"finding_kinds.severity_basis.likelihood.level", "the likelihood (values: likelihood)"},
	{"finding_kinds.cvss.metrics", "the metrics of the CVSS item"},
	{"finding_kinds.cvss.metrics.metric", "the name of the metric"},
	{"finding_kinds.cvss.metrics.value", "the value of the metric (values: the group of the metric)"},
	{"finding_kinds.cvss.b.score", "the score of the CVSS-B item"},
	{"finding_kinds.cvss.b.rating", "the rating of the CVSS-B item (values: score-rating)"},
	{"finding_kinds.cvss.bt.score", "the score of the CVSS-BT item"},
	{"finding_kinds.cvss.bt.rating", "the rating of the CVSS-BT item (values: score-rating)"},
	{"fix_kinds.id", "the ID of the fix"},
	{"fix_kinds.title", "what the fix does"},
	{"fix_kinds.possible_side_effects.id", "the ID of the side effect"},
	{"fix_kinds.possible_side_effects.text", "what the side effect is"},
	{"undetected_forms.id", "the ID of the form"},
	{"undetected_forms.text", "what the form is"},
	{"inconclusive_kinds.id", "the ID of the kind"},
	{"inconclusive_kinds.text", "what the kind is"},
	{"false_positive_forms.id", "the ID of the form"},
	{"false_positive_forms.text", "what the form is"},
	{"false_positive_forms.fact_kinds.kind", "the kind of fact (values: facts)"},
	{"threat.actors.attacker", "the attacker of the actor (values: attacker), which the item name actor says"},
	{"threat.actors.run_starters.run_starter", "who starts the run of the event (values: run-starter)"},
	{"threat.preconditions.id", "the ID of the precondition"},
	{"threat.preconditions.text", "what the precondition says"},
	{"threat.preconditions.observed.date", "the day of what was seen"},
	{"threat.preconditions.observed.what", "what was seen"},
	{"threat.incidents.id", "the ID of the incident"},
	{"threat.incidents.date", "the day of the incident"},
	{"threat.incidents.cve", "the CVE of the incident"},
	{"threat.incidents.summary", "what happened in the incident"},
}

// TermPathsOf is the terms of the keys of the JSON of a rule.
func TermPathsOf() TermPaths {
	t := TermPaths{ItemNames: map[RegistryPath]itemName{}, Values: map[RegistryPath]ValueGroupID{}, Axes: map[RegistryPath]ValueGroupID{}, Metrics: map[MetricName]ValueGroupID{}}
	for _, x := range itemNamePaths {
		for _, p := range x.paths {
			t.ItemNames[registryPath(p)] = x.n
		}
	}
	for _, x := range valuePaths {
		for _, p := range x.paths {
			t.Values[registryPath(p)] = x.group
		}
	}
	for _, a := range FacetAxes() {
		t.Axes[registryPath("facets").child(a.Facet.Key())] = facetGroup(a.Facet)
	}
	for _, x := range metricGroups {
		t.Metrics[x.m] = x.group
	}
	return t
}

// withoutItemName says why the path p has no item name, or "" when it is
// not in pathsWithoutItemName.
func withoutItemName(p RegistryPath) string {
	for _, x := range pathsWithoutItemName {
		if x.p == p.keys {
			return x.why
		}
	}
	return ""
}

package lint

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
)

// testRule is a rule for the tests of this package.
type testRule struct {
	meta  Meta
	check func(ctx context.Context, c *RuleContext) error
}

func (r testRule) Meta() Meta { return r.meta }

func (r testRule) Check(ctx context.Context, c *RuleContext) error {
	if r.check == nil {
		return nil
	}
	return r.check(ctx, c)
}

func meta(id string) Meta {
	return Meta{
		ID:       MustRuleID(id),
		Problem:  "a rule " + id + " detects",
		Expected: "a rule " + id + " holds",
		Facets:   Facets{Weakness: []Weakness{WeaknessScriptInjection}, AttackMeans: []AttackMeans{AttackMeansString}},
		Threat: Threat{
			Actors:        []Actor{{Attacker: AttackerCommenter, Via: "comments", Gains: []Gain{GainRunCode}}},
			Preconditions: []Precondition{{ID: preconditionP, Text: "a", Cites: []Citation{MustCitation("https://example.com/p")}}},
		},
		Citations:    []Citation{MustCitation("https://example.com/x")},
		Targets:      []InputKind{InputKindWorkflow},
		FindingKinds: []FindingKind{saidOf(saidKind)},
	}
}

// formL, kindG, preconditionP and incidentI are the undetected form, the
// inconclusive kind, the precondition and the incident the tests' rules
// declare.
var (
	formL         = MustUndetectedFormID("l")
	kindG         = MustInconclusiveKindID("g")
	preconditionP = MustPreconditionID("p")
	incidentI     = MustIncidentID("i")
)

// baseFor is a CVSS whose severity is sev.
func baseFor(sev Severity) CVSS {
	n := ImpactNone
	switch sev {
	case SeverityCritical:
		return base(AttackVectorNetwork, AttackComplexityLow, AttackRequirementsNone, PrivilegesRequiredNone, UserInteractionNone, ImpactHigh, n, n, n, n, n)
	case SeverityHigh:
		return base(AttackVectorNetwork, AttackComplexityLow, AttackRequirementsPresent, PrivilegesRequiredNone, UserInteractionNone, ImpactHigh, n, n, n, n, n)
	case SeverityMedium:
		return base(AttackVectorLocal, AttackComplexityLow, AttackRequirementsNone, PrivilegesRequiredNone, UserInteractionNone, ImpactHigh, n, n, n, n, n)
	case SeverityLow:
		return base(AttackVectorNetwork, AttackComplexityLow, AttackRequirementsPresent, PrivilegesRequiredNone, UserInteractionNone, ImpactLow, n, n, n, n, n)
	}
	return base(AttackVectorNetwork, AttackComplexityLow, AttackRequirementsNone, PrivilegesRequiredNone, UserInteractionNone, n, n, n, n, n, n)
}

func TestBaseFor(t *testing.T) {
	for _, s := range []Severity{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		if got := severityOf(baseFor(s)).Severity; got != s {
			t.Errorf("baseFor(%v) is %v", s, got)
		}
	}
}

func TestRegistry(t *testing.T) {
	b := asking(fixing(ruleOf("b-rule"), FixKind{ID: MustFixKindID("pin"), Title: "pin it", FactKinds: []facts.Kind{facts.KindTestText}, Safety: SafetySafe}), facts.KindTestFlag)
	b.UndetectedForms = []UndetectedForm{{ID: MustUndetectedFormID("docker"), Text: "docker:// is not looked at", Disposition: Todo(NeedFact), Examples: []Example{withCause(exampleOf("docker.yml"))}}}
	b.InconclusiveKinds = []InconclusiveKind{{ID: MustInconclusiveKindID("step-output"), Text: "the output of a step", Disposition: Todo(NeedSameFile), Examples: []Example{exampleOf("step-output.yml")}}}
	a := ruleOf("a-rule")
	reg, err := NewRegistry([]Rule{testRule{meta: b}, testRule{meta: a}})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range reg.Rules() {
		ids = append(ids, r.Meta().ID.String())
	}
	if strings.Join(ids, " ") != "a-rule b-rule" {
		t.Errorf("Rules = %v, want by ID", ids)
	}
	if m, ok := reg.Meta(b.ID); !ok || m.Severity() != SeverityHigh {
		t.Errorf("Meta(b-rule) = %+v, %v", m, ok)
	}
	if _, ok := reg.Meta(MustRuleID("c-rule")); ok {
		t.Error("Meta of a rule not registered")
	}
	j, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	var metrics []string
	for _, nv := range []string{"AV:N", "AC:L", "AT:P", "PR:N", "UI:N", "VC:H", "VI:N", "VA:N", "SC:N", "SI:N", "SA:N", "E:U"} {
		n, v, _ := strings.Cut(nv, ":")
		metrics = append(metrics, `{"metric":"`+n+`","value":"`+v+`","reason":"for the test","cites":[]}`)
	}
	cvss := `"cvss":{"vector":"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U","metrics":[` + strings.Join(metrics, ",") + `],` +
		`"b":{"score":"8.2","rating":"high"},"bt":{"score":"4.6","rating":"medium"}}`
	example := func(name string) string { return `{"input_kind":"workflow","name":"` + name + `","text":"on: push\n"}` }
	kind := func(id, fixes, fs string) string {
		return `{"id":"` + id + `.said","detected":"{text}","consequence":"it was said","remedy":"say it not","severity":"high",` +
			`"severity_basis":{"impact":{"level":"H","from":["VC"]},"likelihood":{"level":"medium","from":["AV:N","AT:P","PR:N"],"lowered_by":[]}},` +
			cvss + `,"attackers":["commenter"],"preconditions":["p"],"incidents":[],"fixes":[` + fixes + `],"fact_kinds":[` + fs + `],` +
			`"true_positives":[` + example(id+".said.yml") + `],"true_negatives":[` + example(id+".said.yml") + `]}`
	}
	rest := `"severity":"high",` +
		`"threat":{"actors":[{"attacker":"commenter","via":"comments","events":[],"run_starters":[],"gains":["run-code"]}],"preconditions":[{"id":"p","text":"a","observed":[],"cites":["https://example.com/p"]}],"incidents":[]},` +
		`"citations":["https://example.com/x"],"targets":["workflow"],`
	want := `{"schema":"sisakulint/registry/v0","rules":[` +
		`{"id":"a-rule","default_run":"always","problem":"a rule a-rule detects","expected":"a rule a-rule holds","facets":{"weakness":["script-injection"],"attack_means":["string"]},` + rest + `"finding_kinds":[` + kind("a-rule", "", "") + `],"fix_kinds":[],"undetected_forms":[],"inconclusive_kinds":[],"false_positive_forms":[]},` +
		`{"id":"b-rule","default_run":"always","problem":"a rule b-rule detects","expected":"a rule b-rule holds","facets":{"weakness":["script-injection"],"attack_means":["string"]},` + rest + `"finding_kinds":[` + kind("b-rule", `"pin"`, `"test.flag"`) + `],"fix_kinds":[{"id":"pin","title":"pin it","fact_kinds":["test.text"],"safety":"safe","possible_side_effects":[]}],` +
		`"undetected_forms":[{"id":"docker","text":"docker:// is not looked at","finding_kinds":["b-rule.said"],"disposition":"todo","needs":["fact"],"examples":[` + example("docker.yml") + `]}],` +
		`"inconclusive_kinds":[{"id":"step-output","text":"the output of a step","disposition":"todo","needs":["same-file"],"examples":[` + example("step-output.yml") + `]}],"false_positive_forms":[]}],"quality_rules":[]}`
	if string(j) != want {
		t.Errorf("JSON =\n%s\nwant\n%s", j, want)
	}
}

// TestMetaSeverity: a rule is as bad as the worst of its kinds; each kind
// keeps its own.
func TestMetaSeverity(t *testing.T) {
	m := ruleOf("a-rule")
	worse := saidOf(MustFindingKindID("a-rule.worse"))
	worse.CVSS = baseFor(SeverityCritical)
	m.FindingKinds = append([]FindingKind{worse}, m.FindingKinds...) // the worst first: not the last one's
	if m.Severity() != SeverityCritical || m.FindingKinds[1].Severity() != SeverityHigh {
		t.Errorf("Severity = %v, the second kind's %v; want critical and high", m.Severity(), m.FindingKinds[1].Severity())
	}
	if _, err := NewRegistry([]Rule{testRule{meta: m}}); err != nil {
		t.Errorf("two kinds of one actor and precondition: %v", err)
	}
}

func TestRegistryRejects(t *testing.T) {
	with := func(f func(*Meta)) Rule {
		m := ruleOf("a-rule")
		f(&m)
		return testRule{meta: m}
	}
	for _, c := range []struct {
		name  string
		rules []Rule
		want  string
	}{
		{"no ID", []Rule{with(func(m *Meta) { m.ID = RuleID{} })}, "ID"},
		{"two rules, one ID", []Rule{with(func(*Meta) {}), with(func(*Meta) {})}, "twice"},
		{"unknown fact", []Rule{with(func(m *Meta) { m.FindingKinds[0].FactKinds = []facts.Kind{facts.Kind(200)} })}, "Kind(200)"},
		{"unknown fact of a fix", []Rule{with(func(m *Meta) {
			m.FixKinds = []FixKind{{ID: fixF, Title: "t", FactKinds: []facts.Kind{facts.Kind(200)}, Safety: SafetySafe}}
		})}, "Kind(200)"},
		{"fix ID twice", []Rule{with(func(m *Meta) {
			*m = fixing(*m, FixKind{ID: fixF, Title: "t", Safety: SafetySafe}, FixKind{ID: fixF, Title: "u", Safety: SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord}})
		})}, "twice"},
		{"bad fix ID", []Rule{with(func(m *Meta) { m.FixKinds = []FixKind{{ID: FixKindID{}, Title: "t", Safety: SafetySafe}} })}, "ID"},
		{"unset safety", []Rule{with(func(m *Meta) { m.FixKinds = []FixKind{{ID: fixF, Title: "t", Safety: SafetyUnset}} })}, "SafetyUnset"},
		{"a safe fix with a side effect", []Rule{with(func(m *Meta) {
			m.FixKinds = []FixKind{{ID: fixF, Title: "t", Safety: SafetySafe, PossibleSideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord}}}
		})}, "a safe one none"},
		{"a fix to review without one", []Rule{with(func(m *Meta) { m.FixKinds = []FixKind{{ID: fixF, Title: "t", Safety: SafetyReview}} })}, "a safe one none"},
		{"a side effect twice", []Rule{with(func(m *Meta) {
			m.FixKinds = []FixKind{{ID: fixF, Title: "t", Safety: SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffectUnquotedOneWord, ir.SideEffectUnquotedOneWord}}}
		})}, "twice"},
		{"side effects out of order", []Rule{with(func(m *Meta) {
			m.FixKinds = []FixKind{{ID: fixF, Title: "t", Safety: SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffectPatternLiteral, ir.SideEffectUnquotedOneWord}}}
		})}, "order"},
		{"a side effect not a value", []Rule{with(func(m *Meta) {
			m.FixKinds = []FixKind{{ID: fixF, Title: "t", Safety: SafetyReview, PossibleSideEffects: []ir.SideEffect{ir.SideEffect(200)}}}
		})}, "SideEffect(200)"},
		{"no sources", []Rule{with(func(m *Meta) {
			m.Citations = nil
			m.Threat.Preconditions[0].Cites = nil
			m.Threat.Preconditions[0].Observed = []Observation{{Date: MustDate("2026-09-27"), What: "seen"}}
		})}, "Citations"},
		{"no targets", []Rule{with(func(m *Meta) { m.Targets = nil })}, "Targets"},
		{"unset target", []Rule{with(func(m *Meta) { m.Targets = []InputKind{InputKindUnset} })}, "Targets"},
		{"a metric left out", []Rule{with(func(m *Meta) { m.FindingKinds[0].CVSS.AV = Metric[AttackVector]{Reason: "x"} })}, "the metric AV is not written"},
		{"a metric without a reason", []Rule{with(func(m *Meta) { m.FindingKinds[0].CVSS.VC.Reason = "" })}, "VC"},
		{"exploit maturity left out", []Rule{with(func(m *Meta) { m.FindingKinds[0].ExploitMaturity = Metric[ExploitMaturity]{Reason: "x"} })}, "the metric E is not written"},
		{"attacked without incidents", []Rule{with(func(m *Meta) {
			m.FindingKinds[0].ExploitMaturity = Metric[ExploitMaturity]{Value: ExploitMaturityAttacked, Reason: "x"}
		})}, "Incidents"},
		{"an incident without a source", []Rule{with(func(m *Meta) {
			m.Threat.Incidents = []Incident{{Date: MustDate("2025-03-14"), Summary: "s"}}
		})}, "incident"},
		// a zero Citation once passed and only the JSON failed
		{"a zero source", []Rule{with(func(m *Meta) { m.Citations = []Citation{{}} })}, "citation"},
		{"a zero cite of a metric", []Rule{with(func(m *Meta) { m.FindingKinds[0].CVSS.AV.Cites = []Citation{{}} })}, "citation"},
		{"a zero cite of exploit maturity", []Rule{with(func(m *Meta) { m.FindingKinds[0].ExploitMaturity.Cites = []Citation{{}} })}, "citation"},
		{"an incident without a date", []Rule{with(func(m *Meta) {
			m.Threat.Incidents = []Incident{{Advisory: MustCitation("https://example.com/i"), Summary: "s"}}
		})}, "incident"},
		{"no problem", []Rule{with(func(m *Meta) { m.Problem = "" })}, "Problem"},
		{"no expected", []Rule{with(func(m *Meta) { m.Expected = "" })}, "Expected"},
		{"an undetected form without an ID", []Rule{with(func(m *Meta) { m.UndetectedForms = []UndetectedForm{{Text: "t", Disposition: NoAddedGain()}} })}, "undetected form"},
		{"an undetected form without text", []Rule{with(func(m *Meta) { m.UndetectedForms = []UndetectedForm{{ID: formL, Disposition: NoAddedGain()}} })}, "undetected form"},
		{"an undetected form twice", []Rule{with(func(m *Meta) {
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "t", Disposition: NoAddedGain()}, {ID: formL, Text: "u", Disposition: NoAddedGain()}}
		})}, "twice"},
		{"an inconclusive kind without an ID", []Rule{with(func(m *Meta) { m.InconclusiveKinds = []InconclusiveKind{{Text: "t", Disposition: Todo(NeedSameFile)}} })}, "inconclusive"},
		{"an inconclusive kind without a text", []Rule{with(func(m *Meta) { m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Disposition: Todo(NeedSameFile)}} })}, "inconclusive"},
		{"an inconclusive kind twice", []Rule{with(func(m *Meta) {
			m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "t", Disposition: Todo(NeedSameFile)}, {ID: kindG, Text: "u", Disposition: Todo(NeedSameFile)}}
		})}, "twice"},
		{"an undetected form without a disposition", []Rule{with(func(m *Meta) { m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "t"}} })}, "Disposition"},
		{"an inconclusive kind without a disposition", []Rule{with(func(m *Meta) { m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "t"}} })}, "Disposition"},
		{"an inconclusive kind of no added gain", []Rule{with(func(m *Meta) {
			m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "t", Disposition: NoAddedGain()}}
		})}, "limitation or a todo"},
		{"an inconclusive kind of another rule", []Rule{with(func(m *Meta) {
			m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "t", Disposition: OtherRule(MustRuleID("b-rule"))}}
		})}, "limitation or a todo"},
		{"an undetected form of itself", []Rule{with(func(m *Meta) {
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "t", Disposition: OtherRule(MustRuleID("a-rule"))}}
		})}, "itself"},
		{"an undetected form of the zero rule", []Rule{with(func(m *Meta) {
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "t", Disposition: OtherRule(RuleID{})}}
		})}, "rule"},
		{"a limitation decided by none", []Rule{with(func(m *Meta) {
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "t", Disposition: Limitation(DeciderUnset)}}
		})}, "Decider"},
		{"a todo of an unset need", []Rule{with(func(m *Meta) {
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "t", Disposition: Todo(NeedUnset)}}
		})}, "Need"},
		{"a todo of a need twice", []Rule{with(func(m *Meta) {
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "t", Disposition: Todo(NeedFact, NeedFact)}}
		})}, "twice"},
		{"nil rule", []Rule{nil}, "nil"},
		{"no kinds", []Rule{with(func(m *Meta) { m.FindingKinds = nil })}, "Kinds"},
		{"a kind of another rule", []Rule{with(func(m *Meta) { m.FindingKinds = ownKinds("b-rule") })}, "not of the rule"},
		{"a kind of the tests", []Rule{with(func(m *Meta) {
			m.FindingKinds = []FindingKind{{FindingText: FindingText{ID: saidKind, Detected: "m", Consequence: "i", Remedy: "r"}}}
		})}, "not of the rule"},
		{"a kind twice", []Rule{with(func(m *Meta) { m.FindingKinds = append(ownKinds("a-rule"), ownKinds("a-rule")...) })}, "twice"},
		{"a kind without detected", []Rule{with(func(m *Meta) {
			m.FindingKinds = []FindingKind{{FindingText: FindingText{ID: MustFindingKindID("a-rule.k"), Consequence: "i", Remedy: "r"}}}
		})}, "Detected"},
		{"a kind without an impact", []Rule{with(func(m *Meta) {
			m.FindingKinds = []FindingKind{{FindingText: FindingText{ID: MustFindingKindID("a-rule.k"), Detected: "f", Remedy: "r"}}}
		})}, "Consequence"},
		{"a kind without a remedy", []Rule{with(func(m *Meta) {
			m.FindingKinds = []FindingKind{{FindingText: FindingText{ID: MustFindingKindID("a-rule.k"), Detected: "f", Consequence: "i"}}}
		})}, "Remedy"},
		{"a Problem of two lines", []Rule{with(func(m *Meta) { m.Problem = "a\nb" })}, "line break"},
		{"an Expected of two lines", []Rule{with(func(m *Meta) { m.Expected = "a\rb" })}, "line break"},
		{"a Via of two lines", []Rule{with(func(m *Meta) { m.Threat.Actors[0].Via = "a\rb" })}, "line break"},
		{"a precondition of two lines", []Rule{with(func(m *Meta) { m.Threat.Preconditions[0].Text = "a\nb" })}, "line break"},
		{"an observation of two lines", []Rule{with(func(m *Meta) {
			m.Threat.Preconditions[0].Observed = []Observation{{Date: MustDate("2026-09-27"), What: "a\nb"}}
		})}, "line break"},
		{"a summary of two lines", []Rule{with(func(m *Meta) {
			r, _ := facts.ParseRepo("o/r")
			m.Threat.Incidents = []Incident{{ID: incidentI, Date: MustDate("2026-09-27"), Advisory: MustCitation("https://example.com/a"),
				Compromised: []facts.Repo{r}, Summary: "a\nb"}}
			m.FindingKinds[0].Incidents = []IncidentID{incidentI}
			m.FindingKinds[0].ExploitMaturity = metric(ExploitMaturityAttacked)
		})}, "line break"},
		{"a reason of two lines", []Rule{with(func(m *Meta) { m.FindingKinds[0].CVSS.SA.Reason = "a\nb" })}, "line break"},
		{"a detected of two lines", []Rule{with(func(m *Meta) { m.FindingKinds[0].Detected = "a\nb" })}, "line break"},
		{"an impact of two lines", []Rule{with(func(m *Meta) { m.FindingKinds[0].Consequence = "a\nb" })}, "line break"},
		{"a remedy of two lines", []Rule{with(func(m *Meta) { m.FindingKinds[0].Remedy = "a\nb" })}, "line break"},
		{"a fix of two lines", []Rule{with(func(m *Meta) { *m = fixing(*m, FixKind{ID: fixF, Title: "a\nb", Safety: SafetySafe}) })}, "line break"},
		{"an undetected form of two lines", []Rule{with(func(m *Meta) {
			m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "a\nb", Disposition: NoAddedGain()}}
		})}, "line break"},
		{"a kind of place of two lines", []Rule{with(func(m *Meta) {
			m.InconclusiveKinds = []InconclusiveKind{{ID: kindG, Text: "a\nb", Disposition: Todo(NeedSameFile)}}
		})}, "line break"},
		{"a kind with no actor", []Rule{with(func(m *Meta) { m.FindingKinds[0].Attackers = nil })}, "no actor"},
		{"an actor the rule does not have", []Rule{with(func(m *Meta) { m.FindingKinds[0].Attackers = []Attacker{AttackerWikiEditor} })}, "does not have"},
		{"a precondition the rule does not have", []Rule{with(func(m *Meta) {
			m.FindingKinds[0].Preconditions = []PreconditionID{MustPreconditionID("q")}
		})}, "does not have"},
		{"an incident the rule does not have", []Rule{with(func(m *Meta) { m.FindingKinds[0].Incidents = []IncidentID{incidentI} })}, "does not have"},
		{"a fix the rule does not have", []Rule{with(func(m *Meta) { m.FindingKinds[0].Fixes = []FixKindID{fixF} })}, "does not have"},
		{"an actor referred to twice", []Rule{with(func(m *Meta) { m.FindingKinds[0].Attackers = []Attacker{AttackerCommenter, AttackerCommenter} })}, "twice"},
		{"an actor no kind refers to", []Rule{with(func(m *Meta) {
			m.Threat.Actors = append(m.Threat.Actors, Actor{Attacker: AttackerWikiEditor, Via: "edits", Gains: []Gain{GainRunCode}})
		})}, "no kind"},
		{"a precondition no kind refers to", []Rule{with(func(m *Meta) {
			m.Threat.Preconditions = append(m.Threat.Preconditions, Precondition{ID: MustPreconditionID("q"), Text: "q", Cites: []Citation{MustCitation("https://example.com/q")}})
		})}, "no kind"},
		{"an incident no kind refers to", []Rule{with(func(m *Meta) {
			r, _ := facts.ParseRepo("o/r")
			m.Threat.Incidents = []Incident{{ID: incidentI, Date: MustDate("2026-09-27"), Advisory: MustCitation("https://example.com/a"), Compromised: []facts.Repo{r}, Summary: "s"}}
		})}, "no kind"},
		{"a fix no kind refers to", []Rule{with(func(m *Meta) { m.FixKinds = []FixKind{{ID: fixF, Title: "t", Safety: SafetySafe}} })}, "no kind"},
		{"an attacker twice", []Rule{with(func(m *Meta) {
			m.Threat.Actors = append(m.Threat.Actors, Actor{Attacker: AttackerCommenter, Via: "again", Gains: []Gain{GainRunCode}})
		})}, "twice"},
		{"a precondition without an ID", []Rule{with(func(m *Meta) { m.Threat.Preconditions[0].ID = PreconditionID{} })}, "ID"},
		{"a precondition ID twice", []Rule{with(func(m *Meta) {
			m.Threat.Preconditions = append(m.Threat.Preconditions, Precondition{ID: preconditionP, Text: "q", Cites: []Citation{MustCitation("https://example.com/q")}})
		})}, "twice"},
		{"an incident without an ID", []Rule{with(func(m *Meta) {
			r, _ := facts.ParseRepo("o/r")
			m.Threat.Incidents = []Incident{{Date: MustDate("2026-09-27"), Advisory: MustCitation("https://example.com/a"), Compromised: []facts.Repo{r}, Summary: "s"}}
		})}, "ID"},
		{"an incident ID twice", []Rule{with(func(m *Meta) {
			r, _ := facts.ParseRepo("o/r")
			x := Incident{ID: incidentI, Date: MustDate("2026-09-27"), Advisory: MustCitation("https://example.com/a"), Compromised: []facts.Repo{r}, Summary: "s"}
			m.Threat.Incidents = []Incident{x, x}
		})}, "twice"},
		{"a source twice", []Rule{with(func(m *Meta) { m.Citations = append(m.Citations, m.Citations[0]) })}, "twice"},
		{"a source cited in the text", []Rule{with(func(m *Meta) { m.Citations = []Citation{MustCitation("https://example.com/p")} })}, "cited"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewRegistry(c.rules)
			if err == nil {
				t.Fatal("no error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

// TestRegistryRestsOnWhatItCites: a rule with no Sources rests on what its
// text cites; only a rule with neither is refused.
func TestRegistryRestsOnWhatItCites(t *testing.T) {
	m := ruleOf("a-rule")
	m.Citations = nil // the precondition cites https://example.com/p
	if _, err := NewRegistry([]Rule{testRule{meta: m}}); err != nil {
		t.Errorf("a rule whose precondition cites: %v", err)
	}
}

func TestRegistryForTests(t *testing.T) {
	m := meta("a-rule")
	m.Citations = nil
	m.Threat.Preconditions[0].Cites = nil
	m.Threat.Preconditions[0].Observed = []Observation{{Date: MustDate("2026-09-27"), What: "seen"}}
	if _, err := newRegistry([]Rule{testRule{meta: m}}, true); err != nil {
		t.Errorf("a test rule without sources: %v", err)
	}
}

func TestParseDate(t *testing.T) {
	d, err := ParseDate("2025-03-14")
	if err != nil || d.String() != "2025-03-14" {
		t.Errorf("ParseDate = %v, %v", d, err)
	}
	for _, s := range []string{"", "2025-3-14", "2025-02-30", "14/03/2025"} {
		if _, err := ParseDate(s); err == nil {
			t.Errorf("ParseDate(%q): no error", s)
		}
	}
}

// TestRegistryRefusesNotes: an example without the notes its kind needs
// is refused, with the declaration named.
func TestRegistryRefusesNotes(t *testing.T) {
	m := meta("test")
	m.FindingKinds = slices.Clone(m.FindingKinds)
	m.FindingKinds[0].TruePositives = []Example{exampleOf("t.yml")}
	m.FindingKinds[0].TruePositives[0].Notes.Cause = "a cause"
	_, err := NewRegistry([]Rule{testRule{meta: m}})
	if err == nil || !strings.Contains(err.Error(), "has no cause") || !strings.Contains(err.Error(), "a true positive of") {
		t.Errorf("a true positive with a cause: %v", err)
	}
	m = meta("test")
	m.UndetectedForms = []UndetectedForm{{ID: formL, Text: "l", Disposition: Todo(NeedFact), Examples: []Example{exampleOf("l.yml")}}}
	if _, err := NewRegistry([]Rule{testRule{meta: m}}); err == nil || !strings.Contains(err.Error(), "needs its cause") {
		t.Errorf("an undetected form without a cause: %v", err)
	}
}

// TestRegistryInconclusiveKindCollides: an inconclusive kind with the name
// of a finding kind of its rule is refused, as the two would have the same
// args.kind_id.
func TestRegistryInconclusiveKindCollides(t *testing.T) {
	m := gapMeta("test")
	_, name, _ := strings.Cut(m.FindingKinds[0].ID.String(), ".")
	m.InconclusiveKinds[0].ID = MustInconclusiveKindID(name)
	if _, err := newRegistry([]Rule{testRule{meta: m}}, true); err == nil || !strings.Contains(err.Error(), "has the name of a finding kind") {
		t.Errorf("newRegistry = %v, want the inconclusive kind refused", err)
	}
}

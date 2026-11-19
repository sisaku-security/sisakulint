package lint

import (
	"testing"

	"github.com/sisaku-security/sisakulint/actions/internal/enumtest"
)

// TestEnums: every type of enum_gen.go, by enumtest.Check.
func TestEnums(t *testing.T) {
	s := schemas(t)
	in := func(file, def string) func([]byte) error {
		return func(b []byte) error { return s.Validate(file, "#/$defs/"+def, b) }
	}
	for _, c := range []struct {
		def   string
		check func(t *testing.T)
	}{
		{"attacker", func(t *testing.T) {
			enumtest.Check(t, len(attackerNames), false, ParseAttacker, in("registry-v0.json", "attacker"))
		}},
		{"gain", func(t *testing.T) {
			enumtest.Check(t, len(gainNames), false, ParseGain, in("registry-v0.json", "gain"))
		}},
		{"weakness", func(t *testing.T) {
			enumtest.Check(t, len(weaknessNames), false, ParseWeakness, in("registry-v0.json", "weakness"))
		}},
		{"attack-means", func(t *testing.T) {
			enumtest.Check(t, len(attackMeansNames), false, ParseAttackMeans, in("registry-v0.json", "attack-means"))
		}},
		{"severity", func(t *testing.T) {
			enumtest.Check(t, len(severityNames), false, ParseSeverity, in("registry-v0.json", "severity"))
		}},
		{"safety", func(t *testing.T) {
			enumtest.Check(t, len(safetyNames), false, ParseSafety, in("registry-v0.json", "safety"))
		}},
		{"kind", func(t *testing.T) {
			enumtest.Check(t, len(inputKindNames), false, ParseInputKind, in("registry-v0.json", "input-kind"))
		}},
		{"certainty", func(t *testing.T) {
			enumtest.Check(t, len(certaintyNames), false, ParseCertainty, in("report-v0.json", "certainty"))
		}},
		{"attack-vector", func(t *testing.T) {
			enumtest.Check(t, len(attackVectorNames), false, ParseAttackVector, in("registry-v0.json", "attack-vector"))
		}},
		{"attack-complexity", func(t *testing.T) {
			enumtest.Check(t, len(attackComplexityNames), false, ParseAttackComplexity, in("registry-v0.json", "attack-complexity"))
		}},
		{"attack-requirements", func(t *testing.T) {
			enumtest.Check(t, len(attackRequirementsNames), false, ParseAttackRequirements, in("registry-v0.json", "attack-requirements"))
		}},
		{"privileges-required", func(t *testing.T) {
			enumtest.Check(t, len(privilegesRequiredNames), false, ParsePrivilegesRequired, in("registry-v0.json", "privileges-required"))
		}},
		{"user-interaction", func(t *testing.T) {
			enumtest.Check(t, len(userInteractionNames), false, ParseUserInteraction, in("registry-v0.json", "user-interaction"))
		}},
		{"impact", func(t *testing.T) {
			enumtest.Check(t, len(impactNames), false, ParseImpact, in("registry-v0.json", "impact"))
		}},
		{"exploited", func(t *testing.T) {
			enumtest.Check(t, len(exploitMaturityNames), false, ParseExploitMaturity, in("registry-v0.json", "exploit-maturity"))
		}},
		{"likelihood", func(t *testing.T) {
			enumtest.Check(t, len(likelihoodNames), false, ParseLikelihood, in("registry-v0.json", "likelihood"))
		}},
		{"score-rating", func(t *testing.T) {
			enumtest.Check(t, len(scoreRatingNames), false, ParseScoreRating, in("registry-v0.json", "score-rating"))
		}},
		{"need", func(t *testing.T) {
			enumtest.Check(t, len(needNames), false, ParseNeed, in("registry-v0.json", "need"))
		}},
		{"decider", func(t *testing.T) {
			enumtest.Check(t, len(deciderNames), false, ParseDecider, in("registry-v0.json", "decider"))
		}},
		// x-go-zero: read is the zero InputState, and a value
		{"input-state", func(t *testing.T) {
			enumtest.Check(t, len(inputStateNames), true, ParseInputState, in("report-v0.json", "input-state"))
		}},
	} {
		t.Run(c.def, c.check)
	}
	if b, err := InputState(0).MarshalJSON(); err != nil || string(b) != `"read"` {
		t.Errorf("the zero InputState is written %s, %v", b, err)
	}
	if v, err := ParseInputState("read"); err != nil || v != 0 {
		t.Errorf("read is %v, %v", v, err)
	}
}

// TestEnumOrder: Classify and severityOf compare the values of these
// types, so the order of their schema is part of what they mean.
func TestEnumOrder(t *testing.T) {
	if !(SeverityInfo < SeverityLow && SeverityLow < SeverityMedium && SeverityMedium < SeverityHigh && SeverityHigh < SeverityCritical) {
		t.Error("the severities are not in the order info, low, medium, high, critical")
	}
	if !(ImpactHigh < ImpactLow && ImpactLow < ImpactNone) {
		t.Error("the impacts are not in the order H, L, N")
	}
	if !(LikelihoodLow < LikelihoodMedium && LikelihoodMedium < LikelihoodHigh) {
		t.Error("the likelihoods are not in the order low, medium, high")
	}
}

// TestEnumsInTheSchema: a value the schemas do not list is not a report's.
func TestEnumsInTheSchema(t *testing.T) {
	s := schemas(t)
	for _, def := range []string{"severity", "safety", "input-kind"} {
		if s.Validate("registry-v0.json", "#/$defs/"+def, []byte(`"severe"`)) == nil {
			t.Errorf("$defs/%s takes severe", def)
		}
	}
	for _, def := range []string{"certainty", "no-fix-reason", "input-state"} {
		if s.Validate("report-v0.json", "#/$defs/"+def, []byte(`"severe"`)) == nil {
			t.Errorf("$defs/%s takes severe", def)
		}
	}
}

// TestMetricValues: a metric takes the values of its own definition only.
func TestMetricValues(t *testing.T) {
	s := schemas(t)
	metric := func(m, v string) []byte {
		return []byte(`{"metric": "` + m + `", "value": "` + v + `", "reason": "r", "cites": []}`)
	}
	for _, ok := range [][2]string{{"AV", "N"}, {"AV", "P"}, {"AC", "H"}, {"VC", "N"}, {"SA", "H"}, {"E", "U"}} {
		if err := s.Validate("registry-v0.json", "#/$defs/metric", metric(ok[0], ok[1])); err != nil {
			t.Errorf("%s:%s: %v", ok[0], ok[1], err)
		}
	}
	for _, bad := range [][2]string{{"AV", "H"}, {"AC", "N"}, {"AT", "L"}, {"UI", "L"}, {"VC", "A"}, {"E", "X"}, {"XX", "N"}} {
		if s.Validate("registry-v0.json", "#/$defs/metric", metric(bad[0], bad[1])) == nil {
			t.Errorf("%s:%s is taken", bad[0], bad[1])
		}
	}
}

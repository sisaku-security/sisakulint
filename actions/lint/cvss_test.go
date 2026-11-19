package lint

import (
	"slices"
	"testing"
)

// metric is the metric of value v, with a reason for the tests.
func metric[T any](v T) Metric[T] { return Metric[T]{Value: v, Reason: "for the test"} }

// base is a CVSS with every metric set: av, pr, at, ac, ui as given,
// and the six impacts.
func base(av AttackVector, ac AttackComplexity, at AttackRequirements, pr PrivilegesRequired, ui UserInteraction, vc, vi, va, sc, si, sa Impact) CVSS {
	return CVSS{AV: metric(av), AC: metric(ac), AT: metric(at), PR: metric(pr), UI: metric(ui),
		VC: metric(vc), VI: metric(vi), VA: metric(va), SC: metric(sc), SI: metric(si), SA: metric(sa)}
}

func TestVector(t *testing.T) {
	b := base(AttackVectorNetwork, AttackComplexityLow, AttackRequirementsPresent, PrivilegesRequiredNone, UserInteractionPassive, ImpactHigh, ImpactHigh, ImpactLow, ImpactHigh, ImpactHigh, ImpactNone)
	if got, want := b.Vector(), "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:L/SC:H/SI:H/SA:N"; got != want {
		t.Errorf("Vector = %s, want %s", got, want)
	}
	b = base(AttackVectorPhysical, AttackComplexityHigh, AttackRequirementsNone, PrivilegesRequiredHigh, UserInteractionActive, ImpactNone, ImpactLow, ImpactNone, ImpactNone, ImpactNone, ImpactLow)
	if got, want := b.Vector(), "CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:L"; got != want {
		t.Errorf("Vector = %s, want %s", got, want)
	}
	if got := (AttackVectorAdjacent).String(); got != "A" {
		t.Errorf("AttackVectorAdjacent = %s", got)
	}
}

// TestSeverityTable is the table that derives the severity, every cell.
func TestSeverityTable(t *testing.T) {
	likely := []struct {
		name       string
		av         AttackVector
		at         AttackRequirements
		pr         PrivilegesRequired
		likelihood Likelihood
		from       []string
	}{
		{"network, none, none", AttackVectorNetwork, AttackRequirementsNone, PrivilegesRequiredNone, LikelihoodHigh, []string{"AV:N", "AT:N", "PR:N"}},
		{"network, present, none", AttackVectorNetwork, AttackRequirementsPresent, PrivilegesRequiredNone, LikelihoodMedium, []string{"AV:N", "AT:P", "PR:N"}},
		{"network, none, low", AttackVectorNetwork, AttackRequirementsNone, PrivilegesRequiredLow, LikelihoodMedium, []string{"AV:N", "AT:N", "PR:L"}},
		{"network, present, low", AttackVectorNetwork, AttackRequirementsPresent, PrivilegesRequiredLow, LikelihoodLow, nil},
		{"network, none, high", AttackVectorNetwork, AttackRequirementsNone, PrivilegesRequiredHigh, LikelihoodLow, nil},
		{"adjacent", AttackVectorAdjacent, AttackRequirementsNone, PrivilegesRequiredNone, LikelihoodLow, nil},
		{"local", AttackVectorLocal, AttackRequirementsNone, PrivilegesRequiredNone, LikelihoodLow, nil},
	}
	want := map[Impact][3]Severity{ // by LikelihoodLow, LikelihoodMedium, LikelihoodHigh
		ImpactHigh: {SeverityMedium, SeverityHigh, SeverityCritical},
		ImpactLow:  {SeverityInfo, SeverityLow, SeverityMedium},
		ImpactNone: {SeverityInfo, SeverityInfo, SeverityInfo},
	}
	for _, l := range likely {
		for _, imp := range []Impact{ImpactHigh, ImpactLow, ImpactNone} {
			b := base(l.av, AttackComplexityLow, l.at, l.pr, UserInteractionNone, ImpactNone, imp, ImpactNone, ImpactNone, ImpactNone, ImpactNone)
			got := severityOf(b)
			if w := want[imp][l.likelihood-1]; got.Severity != w {
				t.Errorf("%s, impact %v: %v, want %v", l.name, imp, got.Severity, w)
			}
			if got.Likelihood != l.likelihood || !slices.Equal(got.LikelihoodFrom, l.from) {
				t.Errorf("%s: likelihood %v from %v, want %v from %v", l.name, got.Likelihood, got.LikelihoodFrom, l.likelihood, l.from)
			}
		}
	}
}

func TestSeverityLowered(t *testing.T) {
	for _, c := range []struct {
		name string
		ac   AttackComplexity
		ui   UserInteraction
		at   AttackRequirements
		want Likelihood
		by   []string
	}{
		{"AC:H lowers high to medium", AttackComplexityHigh, UserInteractionNone, AttackRequirementsNone, LikelihoodMedium, []string{"AC:H"}},
		{"UI:A lowers high to medium", AttackComplexityLow, UserInteractionActive, AttackRequirementsNone, LikelihoodMedium, []string{"UI:A"}},
		{"both lower once", AttackComplexityHigh, UserInteractionActive, AttackRequirementsNone, LikelihoodMedium, []string{"AC:H", "UI:A"}},
		{"UI:P does not lower", AttackComplexityLow, UserInteractionPassive, AttackRequirementsNone, LikelihoodHigh, nil},
		{"medium to low", AttackComplexityHigh, UserInteractionNone, AttackRequirementsPresent, LikelihoodLow, []string{"AC:H"}},
	} {
		b := base(AttackVectorNetwork, c.ac, c.at, PrivilegesRequiredNone, c.ui, ImpactHigh, ImpactNone, ImpactNone, ImpactNone, ImpactNone, ImpactNone)
		got := severityOf(b)
		if got.Likelihood != c.want || !slices.Equal(got.LoweredBy, c.by) {
			t.Errorf("%s: %v lowered by %v, want %v by %v", c.name, got.Likelihood, got.LoweredBy, c.want, c.by)
		}
	}
	// low is not lowered further, and says nothing lowered it
	b := base(AttackVectorLocal, AttackComplexityHigh, AttackRequirementsNone, PrivilegesRequiredNone, UserInteractionActive, ImpactHigh, ImpactNone, ImpactNone, ImpactNone, ImpactNone, ImpactNone)
	if got := severityOf(b); got.Likelihood != LikelihoodLow || got.LoweredBy != nil || got.Severity != SeverityMedium {
		t.Errorf("low: %+v", got)
	}
}

func TestSeverityImpactFrom(t *testing.T) {
	b := base(AttackVectorNetwork, AttackComplexityLow, AttackRequirementsPresent, PrivilegesRequiredNone, UserInteractionPassive, ImpactHigh, ImpactHigh, ImpactLow, ImpactHigh, ImpactHigh, ImpactNone)
	got := severityOf(b)
	if got.Impact != ImpactHigh || !slices.Equal(got.ImpactFrom, []string{"VC", "VI", "SC", "SI"}) {
		t.Errorf("impact %v from %v", got.Impact, got.ImpactFrom)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("the vector of commit-sha: %v, want high", got.Severity)
	}
	b = base(AttackVectorNetwork, AttackComplexityLow, AttackRequirementsNone, PrivilegesRequiredNone, UserInteractionNone, ImpactNone, ImpactNone, ImpactNone, ImpactNone, ImpactNone, ImpactNone)
	if got := severityOf(b); got.Impact != ImpactNone || !slices.Equal(got.ImpactFrom, []string{"VC", "VI", "VA", "SC", "SI", "SA"}) {
		t.Errorf("no impact: %v from %v", got.Impact, got.ImpactFrom)
	}
}

// TestRatingOf: the ends of each rating of Table 22.
func TestRatingOf(t *testing.T) {
	for tenths, want := range map[int]ScoreRating{
		0: ScoreRatingNone, 1: ScoreRatingLow, 39: ScoreRatingLow, 40: ScoreRatingMedium, 69: ScoreRatingMedium,
		70: ScoreRatingHigh, 89: ScoreRatingHigh, 90: ScoreRatingCritical, 100: ScoreRatingCritical,
	} {
		if got := ratingOf(tenths); got != want {
			t.Errorf("ratingOf(%d) = %v, want %v", tenths, got, want)
		}
	}
}

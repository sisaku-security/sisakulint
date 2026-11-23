package lint

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sisaku-security/sisakulint/actions/cvss4"
)

// Metric is the value of one CVSS metric of a kind of finding, and why it
// is that value. The reason is the only place it is written: the registry of rules
// is what goes out of this repository.
type Metric[T any] struct {
	Value  T
	Reason string     // why this value; NewRegistry refuses an empty one
	Cites  []Citation // what it rests on, if anything
}

// The CVSS v4.0 Base metrics (FIRST, https://www.first.org/cvss/v4.0/specification-document)
// and Exploit Maturity. Their values, as the vector writes them (N, A, L,
// P, ...), are the oneOf of $defs/attack-vector and the others of
// schema/registry-v0.json (enum_gen.go). The zero value of each is not
// written: NewRegistry refuses it, so that a metric left out is never
// scored as one.

type AttackVector uint8

type AttackComplexity uint8

type AttackRequirements uint8

type PrivilegesRequired uint8

type UserInteraction uint8

// Impact is the value of VC, VI, VA, SC, SI and SA; ImpactHigh is the least.
type Impact uint8

// ExploitMaturity is Exploit Maturity (E) without its X (Not Defined): the
// specification scores X as Attacked, so a rule always says which it is.
// ExploitedUnreported is that no report was found, not that nothing
// happened.
type ExploitMaturity uint8

// CVSS is the eleven Base metrics of CVSS v4.0, in the order of the
// vector (Table 23 of the specification). VC, VI and VA are the job
// itself; SC, SI and SA what is past it.
type CVSS struct {
	AV         Metric[AttackVector]
	AC         Metric[AttackComplexity]
	AT         Metric[AttackRequirements]
	PR         Metric[PrivilegesRequired]
	UI         Metric[UserInteraction]
	VC, VI, VA Metric[Impact]
	SC, SI, SA Metric[Impact]
}

// metricEntry is one metric of a vector: its abbreviation, its value as
// the vector writes it, whether it is written, and why.
type metricEntry struct {
	name, value, reason string
	written             bool
	cites               []Citation
}

// metricValue is the value of a metric: an enumeration of enum_gen.go.
type metricValue interface {
	fmt.Stringer
	valid() bool
}

func entry[T metricValue](name string, m Metric[T]) metricEntry {
	return metricEntry{name, m.Value.String(), m.Reason, m.Value.valid(), m.Cites}
}

func (b CVSS) entries() []metricEntry {
	return []metricEntry{
		entry("AV", b.AV), entry("AC", b.AC), entry("AT", b.AT), entry("PR", b.PR), entry("UI", b.UI),
		entry("VC", b.VC), entry("VI", b.VI), entry("VA", b.VA), entry("SC", b.SC), entry("SI", b.SI), entry("SA", b.SA),
	}
}

// Vector is the CVSS v4.0 vector of the Base metrics:
// CVSS:4.0/AV:N/AC:L/.../SA:N.
func (b CVSS) Vector() string {
	var s strings.Builder
	s.WriteString("CVSS:4.0")
	for _, e := range b.entries() {
		s.WriteString("/" + e.name + ":" + e.value)
	}
	return s.String()
}

// Likelihood is how readily a finding's threat comes about, in the three
// steps of the table below ($defs/likelihood of schema/registry-v0.json).
type Likelihood uint8

// ScoreRating is the rating of a CVSS score ($defs/score-rating of
// schema/registry-v0.json): what the registry writes beside cvss.b and
// cvss.bt. It is not a Severity.
type ScoreRating uint8

// ratingOf is the rating of a score of tenths tenths (Table 22 of the CVSS
// v4.0 specification).
func ratingOf(tenths int) ScoreRating {
	switch {
	case tenths == 0:
		return ScoreRatingNone
	case tenths < 40:
		return ScoreRatingLow
	case tenths < 70:
		return ScoreRatingMedium
	case tenths < 90:
		return ScoreRatingHigh
	}
	return ScoreRatingCritical
}

// scoreJSON is a score as the registry writes it ($defs/cvss-score).
type scoreJSON struct {
	Score  string      `json:"score"`
	Rating ScoreRating `json:"rating"`
}

func scoreOf(s cvss4.Score) scoreJSON { return scoreJSON{s.String(), ratingOf(s.Tenths())} }

// SeverityBasis is how a severity was found from a CVSS, for the
// registry's JSON (severity_basis).
type SeverityBasis struct {
	Severity       Severity
	Impact         Impact
	ImpactFrom     []string // the metrics whose value is Impact, in the order of the vector
	Likelihood     Likelihood
	LikelihoodFrom []string // the metrics of the row of the table that matched; none for low
	LoweredBy      []string // AC:H, UI:A, when they lowered it one step
}

// severityOf finds the severity of b by the table of FindingKind.Severity.
func severityOf(b CVSS) SeverityBasis {
	var s SeverityBasis
	impacts := []struct {
		name string
		v    Impact
	}{{"VC", b.VC.Value}, {"VI", b.VI.Value}, {"VA", b.VA.Value}, {"SC", b.SC.Value}, {"SI", b.SI.Value}, {"SA", b.SA.Value}}
	s.Impact = ImpactNone
	for _, i := range impacts {
		if i.v.valid() && i.v < s.Impact { // ImpactHigh is the least
			s.Impact = i.v
		}
	}
	for _, i := range impacts {
		if i.v == s.Impact {
			s.ImpactFrom = append(s.ImpactFrom, i.name)
		}
	}
	av, at, pr := "AV:"+b.AV.Value.String(), "AT:"+b.AT.Value.String(), "PR:"+b.PR.Value.String()
	network := b.AV.Value == AttackVectorNetwork
	noPrivileges, lowPrivileges := b.PR.Value == PrivilegesRequiredNone, b.PR.Value == PrivilegesRequiredLow
	noRequirements, requirements := b.AT.Value == AttackRequirementsNone, b.AT.Value == AttackRequirementsPresent
	switch {
	case network && noPrivileges && noRequirements:
		s.Likelihood, s.LikelihoodFrom = LikelihoodHigh, []string{av, at, pr}
	case network && (noPrivileges && requirements || lowPrivileges && noRequirements):
		s.Likelihood, s.LikelihoodFrom = LikelihoodMedium, []string{av, at, pr}
	default:
		s.Likelihood = LikelihoodLow
	}
	if s.Likelihood > LikelihoodLow {
		if b.AC.Value == AttackComplexityHigh {
			s.LoweredBy = append(s.LoweredBy, "AC:H")
		}
		if b.UI.Value == UserInteractionActive {
			s.LoweredBy = append(s.LoweredBy, "UI:A")
		}
		if s.LoweredBy != nil {
			s.Likelihood--
		}
	}
	table := map[Impact][3]Severity{
		ImpactHigh: {SeverityMedium, SeverityHigh, SeverityCritical},
		ImpactLow:  {SeverityInfo, SeverityLow, SeverityMedium},
		ImpactNone: {SeverityInfo, SeverityInfo, SeverityInfo},
	}
	s.Severity = table[s.Impact][s.Likelihood-1]
	return s
}

func (s SeverityBasis) MarshalJSON() ([]byte, error) {
	type impactJSON struct {
		Level string   `json:"level"`
		From  []string `json:"from"`
	}
	type likelihoodJSON struct {
		Level     string   `json:"level"`
		From      []string `json:"from"`
		LoweredBy []string `json:"lowered_by"`
	}
	return json.Marshal(struct {
		Impact     impactJSON     `json:"impact"`
		Likelihood likelihoodJSON `json:"likelihood"`
	}{impactJSON{s.Impact.String(), nonNil(s.ImpactFrom)}, likelihoodJSON{s.Likelihood.String(), nonNil(s.LikelihoodFrom), nonNil(s.LoweredBy)}})
}

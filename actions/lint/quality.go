package lint

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/sisaku-security/sisakulint/actions/facts"
	"github.com/sisaku-security/sisakulint/actions/ir"
)

// QualityRule is a rule whose finding alone gives no attacker a Gain: an
// attack needs another flaw, though the flaw a quality rule finds may let
// an attack through another flaw give the attacker more, or keep a
// vulnerability unfixed for longer. Its
// findings are reliability or maintainability issues of a workflow, in the
// words of GitHub Code Quality. It has no Threat, no CVSS and no Severity;
// its findings are QualityFindings, which set no bit of the exit code
// (Classify). Its ID is of the same namespace as the rules' (--rule,
// --skip-rule). Check is as a Rule's and reports with RuleContext.Report; a
// quality rule reports no fix and no inconclusive place.
type QualityRule interface {
	QualityMeta() QualityMeta
	Check(ctx context.Context, c *RuleContext) error
}

// QualityMeta is the description of a quality rule in the registry.
type QualityMeta struct {
	ID       RuleID
	Problem  string // what the rule detects, and why it is a problem: one sentence
	Expected string // the state it asks for (the ideal), as for Meta.Expected
	// Citations are what the rule rests on: one at least.
	Citations    []Citation
	Targets      []InputKind
	FindingKinds []QualityFindingKind // one at least
	// UndetectedForms and FalsePositiveForms are as a rule's; no form of a
	// quality rule is no-added-gain, since it has no Threat.
	UndetectedForms    []UndetectedForm
	FalsePositiveForms []FalsePositiveForm
	ViewFields         []ir.SummaryField // a rule of WithQualityView has those of its view
	// DefaultRun is as a rule's (Meta.DefaultRun).
	DefaultRun DefaultRun
}

// QualityFindingKind is a kind of finding a quality rule reports: what it
// says, and the kinds of facts its condition asks about.
type QualityFindingKind struct {
	FindingText
	FactKinds []facts.Kind
	// TruePositives and TrueNegatives are as a FindingKind's: one of each
	// at least.
	TruePositives []Example
	TrueNegatives []Example
}

// QualityFinding is a finding of a quality rule as the engine finished it:
// a Finding without Severity, fix or reason for none. Fix and NoFix of its
// FindingDraft are always nil: of a draft of a quality rule that gives one,
// the engine keeps the finding without them and reports a RunError.
type QualityFinding struct {
	FindingDraft
	Certainty   Certainty
	Fingerprint Fingerprint
	Consequence string // of its kind, from the registry
	Remedy      string // of its kind, too
}

// AsMeta is m as the Meta of a rule without a Threat, CVSS or fixes: what
// the checks of the registry and of the examples, Select and the engine
// share with the rules.
func (m QualityMeta) AsMeta() Meta {
	out := Meta{ID: m.ID, Problem: m.Problem, Expected: m.Expected, Citations: m.Citations, Targets: m.Targets,
		UndetectedForms: m.UndetectedForms, FalsePositiveForms: m.FalsePositiveForms, ViewFields: m.ViewFields, DefaultRun: m.DefaultRun}
	for _, k := range m.FindingKinds {
		out.FindingKinds = append(out.FindingKinds, FindingKind{FindingText: k.FindingText, FactKinds: k.FactKinds,
			TruePositives: k.TruePositives, TrueNegatives: k.TrueNegatives})
	}
	return out
}

// ExampledQualityRule is a quality rule whose examples are read apart from
// its QualityMeta, as an ExampledRule's: its QualityMeta may lack them,
// and ExampledQualityMeta is its QualityMeta with them. Only what shows
// the examples reads them (MarshalJSON, MarshalJSONFull, Explain,
// CheckExamples), and checks them as NewRegistry checks those of another
// quality rule.
type ExampledQualityRule interface {
	QualityRule
	ExampledQualityMeta() QualityMeta
}

// withoutExamples is m without the examples of its declarations.
func (m QualityMeta) withoutExamples() QualityMeta {
	m.FindingKinds = slices.Clone(m.FindingKinds)
	for i := range m.FindingKinds {
		m.FindingKinds[i].TruePositives, m.FindingKinds[i].TrueNegatives = nil, nil
	}
	m.UndetectedForms = slices.Clone(m.UndetectedForms)
	for i := range m.UndetectedForms {
		m.UndetectedForms[i].Examples = nil
	}
	m.FalsePositiveForms = slices.Clone(m.FalsePositiveForms)
	for i := range m.FalsePositiveForms {
		m.FalsePositiveForms[i].Examples = nil
	}
	return m
}

// asRule is a quality rule as the registry keeps it, beside the rules.
type asRule struct{ q QualityRule }

func (a asRule) Meta() Meta                                      { return a.q.QualityMeta().AsMeta() }
func (a asRule) Check(ctx context.Context, c *RuleContext) error { return a.q.Check(ctx, c) }

// QualityViewRule is a quality rule that reads the IR through the reader R
// of a view.
type QualityViewRule[R any] interface {
	QualityMeta() QualityMeta
	Check(ctx context.Context, c *RuleContext, r R) error
}

// WithQualityView is the quality rule r, which reads what v declares, as
// WithView is for a rule.
func WithQualityView[R any](r QualityViewRule[R], v ir.View[R]) QualityRule {
	return qualityViewRule[R]{r, v}
}

type qualityViewRule[R any] struct {
	r QualityViewRule[R]
	v ir.View[R]
}

func (x qualityViewRule[R]) QualityMeta() QualityMeta {
	m := x.r.QualityMeta()
	m.ViewFields = x.v.Fields()
	return m
}

func (x qualityViewRule[R]) Check(ctx context.Context, c *RuleContext) error {
	return x.r.Check(ctx, c, x.v.Reader(c.access))
}

// checkQuality checks a quality rule's description: what NewRegistry checks
// of a rule's that a quality rule has, and that no form of it is out of
// threat.
func checkQuality(m QualityMeta, knownFacts func(string, []facts.Kind) error, allowNoCitations, examplesRequired bool) error {
	if m.Problem == "" || m.Expected == "" {
		return errors.New("a quality rule needs a Problem and an Expected")
	}
	if len(m.Citations) == 0 && !allowNoCitations {
		return errors.New("no Citations; a quality rule must say what it rests on")
	}
	for i, s := range m.Citations {
		if s == (Citation{}) {
			return errors.New("a source is the zero citation")
		}
		if slices.Contains(m.Citations[:i], s) {
			return fmt.Errorf("the source %s twice", s.s)
		}
	}
	if len(m.Targets) == 0 || slices.ContainsFunc(m.Targets, func(k InputKind) bool { return k != InputKindWorkflow && k != InputKindActionMetadata }) {
		return errors.New("Targets must be workflow or action, and at least one")
	}
	if len(m.FindingKinds) == 0 {
		return errors.New("no FindingKinds; a quality rule must declare the kinds of findings it reports")
	}
	seen := map[FindingKindID]bool{}
	for _, k := range m.FindingKinds {
		if k.ID.IsZero() || k.Detected == "" || k.Consequence == "" || k.Remedy == "" {
			return fmt.Errorf("a kind of finding needs an ID, a Detected, a Consequence and a Remedy (%s has %q, %q, %q)", k.ID, k.Detected, k.Consequence, k.Remedy)
		}
		if k.ID.Rule() != m.ID {
			return fmt.Errorf("the kind %s is not of the rule", k.ID)
		}
		if seen[k.ID] {
			return fmt.Errorf("the kind %s is declared twice", k.ID)
		}
		seen[k.ID] = true
		if err := knownFacts(m.ID.s+": kind "+k.ID.s, k.FactKinds); err != nil {
			return err
		}
	}
	for _, l := range m.UndetectedForms {
		if l.Disposition.kind == dispositionNoAddedGain {
			return fmt.Errorf("the undetected form %s is no-added-gain; a quality rule has no Threat", l.ID)
		}
	}
	mm := m.AsMeta()
	for _, err := range []error{checkUndetectedForms(mm), checkFalsePositiveForms(mm), checkLines(mm), checkExamples(mm, examplesRequired, true)} {
		if err != nil {
			return err
		}
	}
	return nil
}

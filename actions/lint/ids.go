package lint

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gh-intel/sisakulint/actions/internal/ident"
	"net/url"
	"strings"
)

// kebabID is an ID in kebab-case. Each kind of ID is a type of its own
// around it, so that the ID of one kind is never taken for another.
type kebabID struct{ s string }

func parseKebab(s, of string) (kebabID, error) {
	if !ident.IsKebab(s) {
		return kebabID{}, fmt.Errorf("the ID %q of %s is not kebab-case", s, of)
	}
	return kebabID{s}, nil
}

func (id kebabID) String() string               { return id.s }
func (id kebabID) IsZero() bool                 { return id.s == "" }
func (id kebabID) MarshalJSON() ([]byte, error) { return marshalID(id.s, "ID") }

// RuleID is the ID of a rule: kebab-case, and it never changes. It has no
// dot, so it is never taken for the name of a kind of fact. The zero
// RuleID is none.
type RuleID struct{ kebabID }

// ParseRuleID checks s and makes the RuleID.
func ParseRuleID(s string) (RuleID, error) { k, err := parseKebab(s, "a rule"); return RuleID{k}, err }

// MustRuleID is ParseRuleID for the literal in a rule's Meta: it panics on
// an error.
func MustRuleID(s string) RuleID { return must(ParseRuleID(s)) }

// FixKindID is the ID of a kind of fix, unique in its rule. The zero
// FixKindID is none.
type FixKindID struct{ kebabID }

// ParseFixKindID checks s and makes the FixKindID.
func ParseFixKindID(s string) (FixKindID, error) {
	k, err := parseKebab(s, "a fix")
	return FixKindID{k}, err
}

// MustFixKindID is ParseFixKindID that panics on an error.
func MustFixKindID(s string) FixKindID { return must(ParseFixKindID(s)) }

// FindingKindID is the ID of a kind of finding: the rule's ID and the
// kind's, joined by a dot (commit-sha.unpinned), as schema/findings-v0.json
// of actions/rules names it. The zero FindingKindID is none.
type FindingKindID struct{ s string }

// ParseFindingKindID checks s: two kebab-case parts joined by a dot.
func ParseFindingKindID(s string) (FindingKindID, error) {
	rule, kind, ok := strings.Cut(s, ".")
	if !ok || !ident.IsKebab(rule) || !ident.IsKebab(kind) {
		return FindingKindID{}, fmt.Errorf("the ID %q of a kind of finding is not <rule>.<kind> in kebab-case", s)
	}
	return FindingKindID{s}, nil
}

// MustFindingKindID is ParseFindingKindID for a literal: it panics on an
// error.
func MustFindingKindID(s string) FindingKindID { return must(ParseFindingKindID(s)) }

func (id FindingKindID) String() string               { return id.s }
func (id FindingKindID) IsZero() bool                 { return id.s == "" }
func (id FindingKindID) MarshalJSON() ([]byte, error) { return marshalID(id.s, "FindingKindID") }

// MarshalText is the ID as a key of a JSON object (an example catalog's
// arguments of each kind); the zero ID is an error, as in MarshalJSON.
func (id FindingKindID) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return nil, errors.New("lint: the zero FindingKindID has no text")
	}
	return []byte(id.s), nil
}

// Rule is the ID of the rule the kind is of: the part before the dot,
// kebab-case since ParseFindingKindID checked it.
func (id FindingKindID) Rule() RuleID { r, _, _ := strings.Cut(id.s, "."); return RuleID{kebabID{r}} }

// UndetectedFormID is the ID of an undetected form of a rule
// (Meta.UndetectedForms), unique in its rule. The zero UndetectedFormID is none.
type UndetectedFormID struct{ kebabID }

// ParseUndetectedFormID checks s and makes the UndetectedFormID.
func ParseUndetectedFormID(s string) (UndetectedFormID, error) {
	k, err := parseKebab(s, "an undetected form")
	return UndetectedFormID{k}, err
}

// MustUndetectedFormID is ParseUndetectedFormID that panics on an error.
func MustUndetectedFormID(s string) UndetectedFormID { return must(ParseUndetectedFormID(s)) }

// InconclusiveKindID is the ID of a kind of place a rule reports as
// inconclusive (Meta.InconclusiveKinds), unique in its rule. The zero InconclusiveKindID is none.
type InconclusiveKindID struct{ kebabID }

// ParseInconclusiveKindID checks s and makes the InconclusiveKindID.
func ParseInconclusiveKindID(s string) (InconclusiveKindID, error) {
	k, err := parseKebab(s, "an inconclusive kind")
	return InconclusiveKindID{k}, err
}

// MustInconclusiveKindID is ParseInconclusiveKindID that panics on an error.
func MustInconclusiveKindID(s string) InconclusiveKindID { return must(ParseInconclusiveKindID(s)) }

// FalsePositiveFormID is the ID of a false positive form of a rule
// (Meta.FalsePositiveForms), unique in its rule. The zero
// FalsePositiveFormID is none.
type FalsePositiveFormID struct{ kebabID }

// ParseFalsePositiveFormID checks s and makes the FalsePositiveFormID.
func ParseFalsePositiveFormID(s string) (FalsePositiveFormID, error) {
	k, err := parseKebab(s, "a false positive form")
	return FalsePositiveFormID{k}, err
}

// MustFalsePositiveFormID is ParseFalsePositiveFormID that panics on an
// error.
func MustFalsePositiveFormID(s string) FalsePositiveFormID {
	return must(ParseFalsePositiveFormID(s))
}

// PreconditionID is the ID of a precondition of a rule's threat
// (Threat.Preconditions), unique in its rule. A kind refers to it, and
// --explain lists a kind's by it, so it names what the precondition is.
// The zero PreconditionID is none.
type PreconditionID struct{ kebabID }

// ParsePreconditionID checks s and makes the PreconditionID.
func ParsePreconditionID(s string) (PreconditionID, error) {
	k, err := parseKebab(s, "a precondition")
	return PreconditionID{k}, err
}

// MustPreconditionID is ParsePreconditionID that panics on an error.
func MustPreconditionID(s string) PreconditionID { return must(ParsePreconditionID(s)) }

// IncidentID is the ID of an incident of a rule's threat
// (Threat.Incidents), unique in its rule; a kind refers to it. The zero
// IncidentID is none.
type IncidentID struct{ kebabID }

// ParseIncidentID checks s and makes the IncidentID.
func ParseIncidentID(s string) (IncidentID, error) {
	k, err := parseKebab(s, "an incident")
	return IncidentID{k}, err
}

// MustIncidentID is ParseIncidentID that panics on an error.
func MustIncidentID(s string) IncidentID { return must(ParseIncidentID(s)) }

// Fingerprint identifies a finding across runs. Only the engine makes one.
type Fingerprint struct{ hex string }

func (f Fingerprint) String() string               { return f.hex }
func (f Fingerprint) MarshalJSON() ([]byte, error) { return marshalID(f.hex, "Fingerprint") }

// Citation is what a rule rests on: an https URL, which stays readable when
// sisakulint is taken out of its repository. A path in the repository
// is not one. It has no < or >, so that --explain can
// write it as an autolink.
type Citation struct{ s string }

// ParseCitation checks s and makes the Citation.
func ParseCitation(s string) (Citation, error) {
	u, err := url.Parse(s)
	if err != nil || !strings.HasPrefix(s, "https://") || u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
		strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f || r == '<' || r == '>' }) {
		return Citation{}, fmt.Errorf("%q is not an https URL with a host", s)
	}
	return Citation{s}, nil
}

// MustCitation is ParseCitation that panics on an error.
func MustCitation(s string) Citation { return must(ParseCitation(s)) }

func (c Citation) String() string               { return c.s }
func (c Citation) MarshalJSON() ([]byte, error) { return marshalID(c.s, "Citation") }

func marshalID(s, what string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("the zero " + what)
	}
	return json.Marshal(s)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

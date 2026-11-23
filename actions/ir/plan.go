package ir

//go:generate go run github.com/sisaku-security/sisakulint/actions/internal/enumgen -pkg ir -out enum_gen.go -only no-fix-reason -only side-effect -ref ../facts/schema/facts-v0.json ../lint/schema/registry-v0.json ../lint/schema/report-v0.json

import "github.com/sisaku-security/sisakulint/yaml/cst/v1/edit"

// FixPlan is what a fix's plan gives a place: the fix, or why none.
type FixPlan struct {
	Fix   *Fix
	NoFix *NoFix
}

// Fix is a fix: edits of the tree of the input, and what they may change
// besides the finding.
type Fix struct {
	Kind        FixKind
	Title       string
	Edits       []edit.Edit
	SideEffects []SideEffect // in the order of the values; none for a safe fix
}

// NoFix is why there is no fix.
type NoFix struct {
	Reason NoFixReason
	Note   string // how to fix it by hand
}

// NoFixReason is why there is no fix: $defs/no-fix-reason of
// actions/lint/schema/report-v0.json (enum_gen.go), the definition
// ir.NoFixReason is made of too.
type NoFixReason uint8

// SideEffect is what applying a fix may change besides the finding:
// $defs/side-effect of actions/lint/schema/registry-v0.json (enum_gen.go).
// A fix to review has one at least.
type SideEffect uint8

// Text is what v is, as the schema says.
func (v SideEffect) Text() string { return v.description() }

// SideEffects are the values of SideEffect, in the order of the schema.
func SideEffects() []SideEffect { return sideEffectValues() }

// FixKind is a kind of fix a plan of this package makes. Its String is
// the ID of the kind: the rules make their lint.FixKindID of it.
type FixKind uint8

const (
	fixKindUnset FixKind = iota
	FixBaseCheckout
	FixPinHeadSHA
	FixPinHeadSHAReview
	FixEnvVar
	FixEnvVarReview
	FixPersistCredentialsFalse
	FixRunnerTempPath
	FixAuthorContext
	FixContainsArray
	FixCacheModeNoWrite
	FixEquality
)

var fixKindNames = [...]string{"", "base-checkout", "pin-head-sha", "pin-head-sha-review", "env-var", "env-var-review", "persist-credentials-false", "runner-temp-path", "author-context", "contains-array", "cache-mode-no-write", "equality"}

func (k FixKind) String() string { return fixKindNames[k] }

func manual(note string) *NoFix { return &NoFix{Reason: NoFixReasonManual, Note: note} }
func form(note string) *NoFix   { return &NoFix{Reason: NoFixReasonForm, Note: note} }

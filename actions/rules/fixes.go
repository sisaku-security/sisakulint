package rules

import (
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/lint"
)

// fixOf is the fix of o, or its reason for none; both nil when o has
// neither. The ID of the kind is the name ir gives it.
func fixOf(o ir.FixPlan) (*lint.Fix, *lint.NoFix) {
	switch {
	case o.Fix != nil:
		return &lint.Fix{KindID: lint.MustFixKindID(o.Fix.Kind.String()), Title: o.Fix.Title, Edits: o.Fix.Edits, SideEffects: o.Fix.SideEffects}, nil
	case o.NoFix != nil:
		return nil, &lint.NoFix{Reason: o.NoFix.Reason, Note: o.NoFix.Note}
	}
	return nil, nil
}

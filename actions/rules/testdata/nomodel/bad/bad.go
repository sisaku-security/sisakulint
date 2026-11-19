// Package bad touches what a rule must not: the test of actions/rules
// checks that each line marked want is an error, and no other.
package bad

import (
	"github.com/sisaku-security/sisakulint/actions/expr"
	"github.com/sisaku-security/sisakulint/actions/ir"
	"github.com/sisaku-security/sisakulint/actions/taint"
	"github.com/sisaku-security/sisakulint/actions/workflow"
)

func touch(v ir.UntrustedCheckoutReader) {
	_ = taint.Analyze(nil, nil)  // want taint
	_ = expr.EqualName("a", "b") // want expr: a function of a forbidden package, of no forbidden type
	_ = workflow.EventNamePush   // allowed: a value of workflow.EventName
	var evs []workflow.EventName
	_ = evs
	for _, s := range v.CheckoutSites() {
		b, _, _, _ := s.At().Locate() // want workflow
		_ = b                         // want workflow
	}
}

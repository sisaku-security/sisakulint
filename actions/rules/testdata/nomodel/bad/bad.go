// Package bad touches what a rule must not: the test of actions/rules
// checks that each line marked want is an error, and no other.
package bad

import (
	"github.com/gh-intel/sisakulint/actions/expr"
	"github.com/gh-intel/sisakulint/actions/ir"
	"github.com/gh-intel/sisakulint/actions/taint"
	"github.com/gh-intel/sisakulint/actions/workflow"
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

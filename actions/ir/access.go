package ir

import "github.com/gh-intel/sisakulint/actions/analysis"

// RuleAccess is what the engine makes of an IR for one rule: its reader reads
// the IR through it. A rule never gets one.
type RuleAccess struct {
	ir *IR
}

// Barriers are the barriers the attacker of the run gets past.
func (a *RuleAccess) Barriers() analysis.BarrierPasses { return a.ir.barriers }

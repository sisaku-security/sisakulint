package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

func ArgumentInjectionCriticalRule(wfTaintMap *WorkflowTaintMap) *ArgumentInjectionRule {
	return newArgumentInjectionRule("critical", true, wfTaintMap)
}

// ArgumentInjectionCriticalRuleWithCollector is like ArgumentInjectionCriticalRule but
// additionally pushes a chain.SinkRecord to collector for every detected finding, feeding
// the leakage-path chain visualization (`-format "{{mermaid .}}"`). collector may be nil,
// in which case no records are pushed (equivalent to ArgumentInjectionCriticalRule).
func ArgumentInjectionCriticalRuleWithCollector(wfTaintMap *WorkflowTaintMap, collector *chain.SinkCollector) *ArgumentInjectionRule {
	r := ArgumentInjectionCriticalRule(wfTaintMap)
	r.collector = collector
	return r
}

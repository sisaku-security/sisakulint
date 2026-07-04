package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

func ArgumentInjectionMediumRule(wfTaintMap *WorkflowTaintMap) *ArgumentInjectionRule {
	return newArgumentInjectionRule("medium", false, wfTaintMap)
}

// ArgumentInjectionMediumRuleWithCollector is like ArgumentInjectionMediumRule but
// additionally pushes a chain.SinkRecord to collector for every detected finding, feeding
// the leakage-path chain visualization (`-format "{{mermaid .}}"`). collector may be nil,
// in which case no records are pushed (equivalent to ArgumentInjectionMediumRule).
func ArgumentInjectionMediumRuleWithCollector(wfTaintMap *WorkflowTaintMap, collector *chain.SinkCollector) *ArgumentInjectionRule {
	r := ArgumentInjectionMediumRule(wfTaintMap)
	r.collector = collector
	return r
}

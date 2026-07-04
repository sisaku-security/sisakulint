package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// OutputClobberingMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in OutputClobberingRule
type OutputClobberingMedium = OutputClobberingRule

// OutputClobberingMediumRule creates a rule for detecting output clobbering in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making output clobbering medium severity
func OutputClobberingMediumRule() *OutputClobberingRule {
	return newOutputClobberingRule("medium", false)
}

// OutputClobberingMediumRuleWithCollector is like OutputClobberingMediumRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to OutputClobberingMediumRule).
func OutputClobberingMediumRuleWithCollector(collector *chain.SinkCollector) *OutputClobberingRule {
	r := OutputClobberingMediumRule()
	r.collector = collector
	return r
}

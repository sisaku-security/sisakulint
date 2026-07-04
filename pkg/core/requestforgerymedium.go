package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// RequestForgeryMediumRule creates a medium severity request forgery rule
// that checks for SSRF vulnerabilities in workflows with normal triggers
// (pull_request, push, schedule, etc.)
func RequestForgeryMediumRule(wfTaintMap *WorkflowTaintMap) *RequestForgeryRule {
	return newRequestForgeryRule("medium", false, wfTaintMap)
}

// RequestForgeryMediumRuleWithCollector is like RequestForgeryMediumRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to RequestForgeryMediumRule).
func RequestForgeryMediumRuleWithCollector(wfTaintMap *WorkflowTaintMap, collector *chain.SinkCollector) *RequestForgeryRule {
	r := RequestForgeryMediumRule(wfTaintMap)
	r.collector = collector
	return r
}

package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// RequestForgeryCriticalRule creates a critical severity request forgery rule
// that checks for SSRF vulnerabilities in workflows with privileged triggers.
func RequestForgeryCriticalRule(wfTaintMap *WorkflowTaintMap) *RequestForgeryRule {
	return newRequestForgeryRule("critical", true, wfTaintMap)
}

// RequestForgeryCriticalRuleWithCollector is like RequestForgeryCriticalRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to RequestForgeryCriticalRule).
func RequestForgeryCriticalRuleWithCollector(wfTaintMap *WorkflowTaintMap, collector *chain.SinkCollector) *RequestForgeryRule {
	r := RequestForgeryCriticalRule(wfTaintMap)
	r.collector = collector
	return r
}

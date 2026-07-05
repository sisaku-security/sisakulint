package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// OutputClobberingCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in OutputClobberingRule
type OutputClobberingCritical = OutputClobberingRule

// OutputClobberingCriticalRule creates a rule for detecting output clobbering in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making output clobbering critical severity
func OutputClobberingCriticalRule() *OutputClobberingRule {
	return newOutputClobberingRule("critical", true)
}

// OutputClobberingCriticalRuleWithCollector is like OutputClobberingCriticalRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to OutputClobberingCriticalRule).
func OutputClobberingCriticalRuleWithCollector(collector *chain.SinkCollector) *OutputClobberingRule {
	r := OutputClobberingCriticalRule()
	r.collector = collector
	return r
}

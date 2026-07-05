package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// CodeInjectionCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in CodeInjectionRule
type CodeInjectionCritical = CodeInjectionRule

// CodeInjectionCriticalRule creates a rule for detecting code injection in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making code injection critical severity
// CodeInjectionCriticalRule creates a rule for detecting code injection in privileged workflow contexts.
// Pass a shared *WorkflowTaintMap to enable cross-job taint propagation detection, or nil to disable it.
func CodeInjectionCriticalRule(wfTaintMap *WorkflowTaintMap) *CodeInjectionRule {
	return newCodeInjectionRule("critical", true, wfTaintMap)
}

// CodeInjectionCriticalRuleWithCollector is like CodeInjectionCriticalRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to CodeInjectionCriticalRule).
func CodeInjectionCriticalRuleWithCollector(wfTaintMap *WorkflowTaintMap, collector *chain.SinkCollector) *CodeInjectionRule {
	r := CodeInjectionCriticalRule(wfTaintMap)
	r.collector = collector
	return r
}

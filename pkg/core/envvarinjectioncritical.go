package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// EnvVarInjectionCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvVarInjectionRule
type EnvVarInjectionCritical = EnvVarInjectionRule

// EnvVarInjectionCriticalRule creates a rule for detecting environment variable injection in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making envvar injection critical severity
func EnvVarInjectionCriticalRule(wfTaintMap *WorkflowTaintMap) *EnvVarInjectionRule {
	return newEnvVarInjectionRule("critical", true, wfTaintMap)
}

// EnvVarInjectionCriticalRuleWithCollector is like EnvVarInjectionCriticalRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to EnvVarInjectionCriticalRule).
func EnvVarInjectionCriticalRuleWithCollector(wfTaintMap *WorkflowTaintMap, collector *chain.SinkCollector) *EnvVarInjectionRule {
	r := EnvVarInjectionCriticalRule(wfTaintMap)
	r.collector = collector
	return r
}

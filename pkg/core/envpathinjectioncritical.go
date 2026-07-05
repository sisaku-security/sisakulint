package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// EnvPathInjectionCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvPathInjectionRule
type EnvPathInjectionCritical = EnvPathInjectionRule

// EnvPathInjectionCriticalRule creates a rule for detecting PATH injection in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making PATH injection critical severity
func EnvPathInjectionCriticalRule() *EnvPathInjectionRule {
	return newEnvPathInjectionRule("critical", true)
}

// EnvPathInjectionCriticalRuleWithCollector is like EnvPathInjectionCriticalRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to EnvPathInjectionCriticalRule).
func EnvPathInjectionCriticalRuleWithCollector(collector *chain.SinkCollector) *EnvPathInjectionRule {
	r := EnvPathInjectionCriticalRule()
	r.collector = collector
	return r
}

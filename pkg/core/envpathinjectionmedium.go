package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// EnvPathInjectionMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvPathInjectionRule
type EnvPathInjectionMedium = EnvPathInjectionRule

// EnvPathInjectionMediumRule creates a rule for detecting PATH injection in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making PATH injection medium severity
func EnvPathInjectionMediumRule() *EnvPathInjectionRule {
	return newEnvPathInjectionRule("medium", false)
}

// EnvPathInjectionMediumRuleWithCollector is like EnvPathInjectionMediumRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to EnvPathInjectionMediumRule).
func EnvPathInjectionMediumRuleWithCollector(collector *chain.SinkCollector) *EnvPathInjectionRule {
	r := EnvPathInjectionMediumRule()
	r.collector = collector
	return r
}

package core

import "github.com/sisaku-security/sisakulint/pkg/core/chain"

// EnvVarInjectionMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvVarInjectionRule
type EnvVarInjectionMedium = EnvVarInjectionRule

// EnvVarInjectionMediumRule creates a rule for detecting environment variable injection in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making envvar injection medium severity
func EnvVarInjectionMediumRule(wfTaintMap *WorkflowTaintMap) *EnvVarInjectionRule {
	return newEnvVarInjectionRule("medium", false, wfTaintMap)
}

// EnvVarInjectionMediumRuleWithCollector is like EnvVarInjectionMediumRule but additionally
// pushes a chain.SinkRecord to collector for every detected finding, feeding the leakage-path
// chain visualization (`-format "{{mermaid .}}"`). collector may be nil, in which case no
// records are pushed (equivalent to EnvVarInjectionMediumRule).
func EnvVarInjectionMediumRuleWithCollector(wfTaintMap *WorkflowTaintMap, collector *chain.SinkCollector) *EnvVarInjectionRule {
	r := EnvVarInjectionMediumRule(wfTaintMap)
	r.collector = collector
	return r
}

package core

// EnvVarInjectionMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvVarInjectionRule
type EnvVarInjectionMedium = EnvVarInjectionRule

// EnvVarInjectionMediumRule creates a rule for detecting environment variable injection in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making envvar injection medium severity
func EnvVarInjectionMediumRule(wfTaintMap *WorkflowTaintMap) *EnvVarInjectionRule {
	return newEnvVarInjectionRule("medium", false, wfTaintMap)
}

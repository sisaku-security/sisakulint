package core

// ArgumentInjectionMedium is a type alias for backward compatibility with existing tests
// The actual implementation is in ArgumentInjectionRule
type ArgumentInjectionMedium = ArgumentInjectionRule

// ArgumentInjectionMediumRule creates a rule for detecting argument injection in normal workflow contexts
// Normal contexts include: pull_request, push, schedule, workflow_dispatch
// These triggers have limited permissions, making argument injection medium severity
func ArgumentInjectionMediumRule() *ArgumentInjectionRule {
	return newArgumentInjectionRule("medium", false)
}

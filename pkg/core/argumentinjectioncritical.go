package core

// ArgumentInjectionCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in ArgumentInjectionRule
type ArgumentInjectionCritical = ArgumentInjectionRule

// ArgumentInjectionCriticalRule creates a rule for detecting argument injection in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making argument injection critical severity
func ArgumentInjectionCriticalRule() *ArgumentInjectionRule {
	return newArgumentInjectionRule("critical", true)
}

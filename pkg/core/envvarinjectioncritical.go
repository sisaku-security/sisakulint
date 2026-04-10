package core

// EnvVarInjectionCritical is a type alias for backward compatibility with existing tests
// The actual implementation is in EnvVarInjectionRule
type EnvVarInjectionCritical = EnvVarInjectionRule

// EnvVarInjectionCriticalRule creates a rule for detecting environment variable injection in privileged workflow contexts
// Privileged contexts include: pull_request_target, workflow_run, issue_comment, issues, discussion_comment
// These triggers have write access or run with secrets, making envvar injection critical severity
func EnvVarInjectionCriticalRule(wfTaintMap *WorkflowTaintMap) *EnvVarInjectionRule {
	return newEnvVarInjectionRule("critical", true, wfTaintMap)
}
